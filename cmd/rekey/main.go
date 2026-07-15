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
// Usage:
//
//	ENCRYPTION_KEY=... ENCRYPTION_KEYS="1:<b64>,2:<b64>" ENCRYPTION_ACTIVE_KEK_ID=2 \
//	  DATABASE_URL=... rekey            # dry-run: report what would change
//	  ... rekey -dry-run=false          # apply
package main

import (
	"context"
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
	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		fatal("connect: %v", err)
	}
	defer pool.Close()
	// Cross-org maintenance: bypass RLS (best-effort; owner may already bypass).
	_, _ = pool.Exec(ctx, "SELECT set_config('app.bypass_rls','on',false)")

	fmt.Printf("rekey: active KEK id=%d  dry-run=%v\n", active, *dryRun)

	cols, err := textColumns(ctx, pool)
	if err != nil {
		fatal("enumerate columns: %v", err)
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
		   AND data_type IN ('text','character varying','character')
		 ORDER BY table_name, column_name`)
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

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "rekey: "+format+"\n", a...)
	os.Exit(1)
}
