// Command rekey re-encrypts every secretcrypt-encrypted DB value under the
// active KEK, so an old (e.g. exposed) encryption key can be retired from the
// keyring. It's the companion to the secretcrypt keyring (encv2): the keyring
// makes rotation SAFE (old ciphertext stays readable), and this tool moves the
// data forward so nothing is left under the old key.
//
// Correct-by-construction: it scans every text column in the public schema for
// values carrying the secretcrypt prefix (encv1:/encv2:) that are NOT already
// sealed under the active KEK — so it can't miss a column, and there's no
// registry to maintain. Vault secrets (a different ciphertext format) and
// plaintext are ignored. Idempotent; -dry-run (the default) writes nothing.
//
// json/jsonb columns are scanned the same way: the document is walked and every
// *string* carrying the prefix is re-sealed, at any depth. That keeps the
// no-registry property — a JSON-embedded secret is recognized by its tag, not by
// a field name someone has to remember to add here. Without this, a secret in a
// JSON blob (e.g. the Ziti controller admin password in system_settings.value)
// was invisible to rotation: the keyring would move forward while that value
// stayed sealed under a key the operator believed had been retired.
//
// Usage:
//
//	ENCRYPTION_KEY=... ENCRYPTION_KEYS="1:<b64>,2:<b64>" ENCRYPTION_ACTIVE_KEK_ID=2 \
//	  DATABASE_URL=... rekey            # dry-run: report what would change
//	  ... rekey -dry-run=false          # apply
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openidx/openidx/internal/common/secretcrypt"
)

// Large text columns that never hold secretcrypt values — skipping them avoids a
// pointless full scan. Extend with -skip.
var defaultSkip = map[string]bool{
	"audit_events.details": true,
}

type colRef struct{ table, col, pk string }

func main() {
	dryRun := flag.Bool("dry-run", true, "report without writing (default true; pass -dry-run=false to apply)")
	batch := flag.Int("batch", 1000, "max rows read per column at once")
	dbURL := flag.String("database-url", os.Getenv("DATABASE_URL"), "Postgres URL (default $DATABASE_URL)")
	skipCSV := flag.String("skip", "", "extra table.column names to skip (comma-separated)")
	flag.Parse()

	if *dbURL == "" {
		fatal("DATABASE_URL (or -database-url) is required")
	}

	// Build the cipher from env; requires keyring mode (an active KEK to seal under).
	cipher, err := secretcrypt.New(os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		fatal("secretcrypt: %v", err)
	}
	active := cipher.ActiveKEKID()
	if active == 0 {
		fatal("not in keyring mode: set ENCRYPTION_KEYS + ENCRYPTION_ACTIVE_KEK_ID (no active KEK to re-encrypt under)")
	}

	skip := map[string]bool{}
	for k := range defaultSkip {
		skip[k] = true
	}
	for _, s := range strings.Split(*skipCSV, ",") {
		if s = strings.TrimSpace(s); s != "" {
			skip[s] = true
		}
	}

	ctx := context.Background()
	pool, err := openRekeyPool(ctx, *dbURL)
	if err != nil {
		fatal("connect: %v", err)
	}
	defer pool.Close()

	if !canSeeEveryTenant(ctx, pool) {
		fatal("this connection is subject to row-level security and carries no tenant scope: it would read zero " +
			"rows and report a successful rekey of nothing. Run as a role that owns the tables or one that may " +
			"set app.bypass_rls.")
	}

	fmt.Printf("rekey: active KEK id=%d  dry-run=%v\n", active, *dryRun)

	cols, err := textColumns(ctx, pool)
	if err != nil {
		fatal("enumerate columns: %v", err)
	}
	jcols, err := jsonColumns(ctx, pool)
	if err != nil {
		fatal("enumerate json columns: %v", err)
	}

	var totalResealed, totalErr, scanned int
	for _, c := range cols {
		name := c.table + "." + c.col
		if skip[name] {
			continue
		}
		scanned++
		n, e := rekeyColumn(ctx, pool, cipher, c, active, *batch, *dryRun)
		if n > 0 || e > 0 {
			fmt.Printf("  %-48s resealed=%d errors=%d\n", name, n, e)
		}
		totalResealed += n
		totalErr += e
	}
	for _, c := range jcols {
		name := c.table + "." + c.col
		if skip[name] {
			continue
		}
		scanned++
		n, e := rekeyJSONColumn(ctx, pool, cipher, c, active, *batch, *dryRun)
		if n > 0 || e > 0 {
			fmt.Printf("  %-48s resealed=%d errors=%d (json)\n", name, n, e)
		}
		totalResealed += n
		totalErr += e
	}

	verb := "would reseal"
	if !*dryRun {
		verb = "resealed"
	}
	fmt.Printf("rekey: scanned %d columns; %s %d values under KEK %d (%d errors)\n",
		scanned, verb, totalResealed, active, totalErr)
	if *dryRun && totalResealed > 0 {
		fmt.Println("dry-run: nothing written. Re-run with -dry-run=false to apply, then drop the old KEK from ENCRYPTION_KEYS.")
	}
	if totalErr > 0 {
		os.Exit(1)
	}
}

// textColumns returns every text/varchar/char column in the public schema whose
// table has a single-column primary key (needed to update rows by id).
func textColumns(ctx context.Context, pool *pgxpool.Pool) ([]colRef, error) {
	return columnsOfTypes(ctx, pool, []string{"text", "character varying", "character"})
}

// jsonColumns returns every json/jsonb column under the same PK rule.
func jsonColumns(ctx context.Context, pool *pgxpool.Pool) ([]colRef, error) {
	return columnsOfTypes(ctx, pool, []string{"json", "jsonb"})
}

// columnsOfTypes lists public-schema columns of the given data types belonging
// to a table with exactly one primary-key column.
func columnsOfTypes(ctx context.Context, pool *pgxpool.Pool, types []string) ([]colRef, error) {
	pkRows, err := pool.Query(ctx, `
		SELECT tc.table_name, kcu.column_name
		  FROM information_schema.table_constraints tc
		  JOIN information_schema.key_column_usage kcu
		    ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema
		 WHERE tc.table_schema = 'public' AND tc.constraint_type = 'PRIMARY KEY'`)
	if err != nil {
		return nil, err
	}
	pkCount := map[string]int{}
	pkCol := map[string]string{}
	for pkRows.Next() {
		var t, c string
		if pkRows.Scan(&t, &c) == nil {
			pkCount[t]++
			pkCol[t] = c
		}
	}
	pkRows.Close()

	rows, err := pool.Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND data_type = ANY($1)
		 ORDER BY table_name, column_name`, types)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []colRef
	for rows.Next() {
		var t, c string
		if rows.Scan(&t, &c) == nil && pkCount[t] == 1 {
			out = append(out, colRef{table: t, col: c, pk: pkCol[t]})
		}
	}
	return out, rows.Err()
}

// rekeyColumn re-seals every value in one column that isn't already under the
// active KEK. The PK is compared as text so any PK type (uuid/int/text) works.
func rekeyColumn(ctx context.Context, pool *pgxpool.Pool, cipher *secretcrypt.Cipher, c colRef, active, batch int, dryRun bool) (resealed, errs int) {
	tbl := pgx.Identifier{c.table}.Sanitize()
	col := pgx.Identifier{c.col}.Sanitize()
	pk := pgx.Identifier{c.pk}.Sanitize()
	activePrefix := fmt.Sprintf("encv2:%d:", active)

	q := fmt.Sprintf(`SELECT %s::text, %s FROM %s
		 WHERE %s LIKE 'encv1:%%' OR (%s LIKE 'encv2:%%' AND %s NOT LIKE $1)
		 LIMIT %d`, pk, col, tbl, col, col, col, batch)

	for {
		rows, err := pool.Query(ctx, q, activePrefix+"%")
		if err != nil {
			return resealed, errs + 1
		}
		type item struct{ id, val string }
		var items []item
		for rows.Next() {
			var id, v string
			if rows.Scan(&id, &v) == nil {
				items = append(items, item{id, v})
			}
		}
		rows.Close()
		if len(items) == 0 {
			return resealed, errs
		}

		u := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s::text = $2", tbl, col, pk)
		progress := 0 // rows resealed (or would-reseal) this batch
		for _, it := range items {
			pt, derr := cipher.Decrypt(it.val)
			if derr != nil {
				errs++
				continue
			}
			nv, eerr := cipher.Encrypt(pt)
			if eerr != nil || nv == it.val {
				if eerr != nil {
					errs++
				}
				continue
			}
			if dryRun {
				resealed++
				progress++
				continue
			}
			if _, uerr := pool.Exec(ctx, u, nv, it.id); uerr != nil {
				errs++
				continue
			}
			resealed++
			progress++
		}
		// Exit conditions:
		//   - dry-run writes nothing, so re-querying returns the same rows — stop
		//     after one batch (secret columns hold tens of rows, well under batch,
		//     so this is the true count in practice).
		//   - short read → last batch.
		//   - apply mode with zero progress → an error-only batch that would
		//     otherwise be re-selected forever.
		if dryRun || len(items) < batch || progress == 0 {
			return resealed, errs
		}
	}
}

// rekeyJSONColumn re-seals secretcrypt values embedded anywhere inside a
// json/jsonb column. Rows are pre-filtered in SQL on the tag appearing in the
// serialized document — the tag and its base64 payload are never JSON-escaped,
// so a tagged value always shows up literally — and the decision for each
// individual string is made during the walk, not by the LIKE.
func rekeyJSONColumn(ctx context.Context, pool *pgxpool.Pool, cipher *secretcrypt.Cipher, c colRef, active, batch int, dryRun bool) (resealed, errs int) {
	tbl := pgx.Identifier{c.table}.Sanitize()
	col := pgx.Identifier{c.col}.Sanitize()
	pk := pgx.Identifier{c.pk}.Sanitize()
	activePrefix := fmt.Sprintf("encv2:%d:", active)

	q := fmt.Sprintf(`SELECT %s::text, %s::text FROM %s
		 WHERE %s::text LIKE '%%encv1:%%' OR %s::text LIKE '%%encv2:%%'
		 LIMIT %d`, pk, col, tbl, col, col, batch)

	for {
		rows, err := pool.Query(ctx, q)
		if err != nil {
			return resealed, errs + 1
		}
		type item struct{ id, doc string }
		var items []item
		for rows.Next() {
			var id, d string
			if rows.Scan(&id, &d) == nil {
				items = append(items, item{id, d})
			}
		}
		rows.Close()
		if len(items) == 0 {
			return resealed, errs
		}

		u := fmt.Sprintf("UPDATE %s SET %s = $1 WHERE %s::text = $2", tbl, col, pk)
		progress := 0
		for _, it := range items {
			// UseNumber keeps integers exact: decoding into float64 would rewrite
			// a large id as 1.2345678901234568e+18 and corrupt untouched data.
			dec := json.NewDecoder(strings.NewReader(it.doc))
			dec.UseNumber()
			var doc any
			if err := dec.Decode(&doc); err != nil {
				errs++
				continue
			}
			next, n, e := resealJSON(doc, cipher, activePrefix)
			errs += e
			if n == 0 {
				continue
			}
			blob, merr := json.Marshal(next)
			if merr != nil {
				errs++
				continue
			}
			if dryRun {
				resealed += n
				progress++
				continue
			}
			if _, uerr := pool.Exec(ctx, u, string(blob), it.id); uerr != nil {
				errs++
				continue
			}
			resealed += n
			progress++
		}
		if dryRun || len(items) < batch || progress == 0 {
			return resealed, errs
		}
	}
}

// resealJSON walks a decoded JSON value and re-seals every string that carries a
// secretcrypt tag and is not already under the active KEK. Non-string leaves are
// returned untouched, so unrelated fields survive the round trip byte-for-byte.
func resealJSON(v any, cipher *secretcrypt.Cipher, activePrefix string) (out any, resealed, errs int) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			nv, n, e := resealJSON(val, cipher, activePrefix)
			t[k] = nv
			resealed += n
			errs += e
		}
		return t, resealed, errs
	case []any:
		for i, val := range t {
			nv, n, e := resealJSON(val, cipher, activePrefix)
			t[i] = nv
			resealed += n
			errs += e
		}
		return t, resealed, errs
	case string:
		if !secretcrypt.IsEncrypted(t) || strings.HasPrefix(t, activePrefix) {
			return t, 0, 0
		}
		pt, derr := cipher.Decrypt(t)
		if derr != nil {
			return t, 0, 1
		}
		nv, eerr := cipher.Encrypt(pt)
		if eerr != nil {
			return t, 0, 1
		}
		if nv == t {
			return t, 0, 0
		}
		return nv, 1, 0
	default:
		return v, 0, 0
	}
}

// openRekeyPool builds the pool this binary works through, with the
// cross-tenant bypass on EVERY connection it will ever open.
//
// THE BUG THIS REPLACES, AND HOW IT WAS MEASURED. The bypass used to be taken
// with a single pool.Exec, best-effort, error discarded. set_config(..., false)
// is SESSION-scoped -- it belongs to one backend -- and a pool is many
// backends. Probed against a real server: after that one Exec, the connection
// that served it reported app.bypass_rls = "on" and a second connection from
// the same pool reported "". Every query that lands on a connection opened
// later therefore runs with no bypass, and under FORCE ROW LEVEL SECURITY that
// is not an error: it is ZERO ROWS. A rekey that sees nothing rewrites nothing,
// prints "0 rekeyed" and exits 0, and the next KEK rotation retires a key that
// is still decrypting live data.
//
// Whether that bites on any given run depended on whether the pool happened to
// hand back the same connection -- which it usually does for this binary's
// sequential work, and stops doing the moment a connection ages out, a health
// check churns one, or anything runs concurrently. A correctness that rests on
// the pool's mood is the kind this repository writes down rather than relies
// on.
//
// AfterConnect is the fix that cannot be got wrong by a later edit: it runs on
// every connection the pool opens, including replacements, so there is no
// window in which a fresh backend serves a query unscoped.
func openRekeyPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		// An error here is worth failing the connection for: a backend without
		// the bypass is a backend that would silently read nothing.
		_, err := conn.Exec(ctx, "SELECT set_config('app.bypass_rls','on',false)")
		return err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

// canSeeEveryTenant reports whether this pool can actually read across tenants
// -- either because the bypass took on the connection it is asked over, or
// because the role is exempt from row-level security to begin with (an owner
// without FORCE, a superuser, or a role with BYPASSRLS).
//
// The question is deliberately about what the DATABASE says rather than about
// whether a statement succeeded: "SET returned no error" and "I can see the
// rows" are different claims, and only the second is what a rekey depends on.
// With AfterConnect doing the setting, every connection answers the same way,
// which is what makes one probe meaningful for the whole run.
func canSeeEveryTenant(ctx context.Context, pool *pgxpool.Pool) bool {
	var bypass string
	if err := pool.QueryRow(ctx,
		"SELECT COALESCE(current_setting('app.bypass_rls', true), '')").Scan(&bypass); err == nil {
		if bypass == "on" {
			return true
		}
	}
	var exempt bool
	if err := pool.QueryRow(ctx,
		"SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&exempt); err == nil && exempt {
		return true
	}
	return false
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "rekey: "+format+"\n", a...)
	os.Exit(1)
}
