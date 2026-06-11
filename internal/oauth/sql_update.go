package oauth

import (
	"fmt"
	"regexp"
	"strconv"
)

// sqlUpdateField is the (column, value, present?) triple the dynamic
// UPDATE builders feed buildUpdateClause. Column names are required to
// be package-local string literals; buildUpdateClause checks each one
// against the caller-supplied allow-list AND a strict identifier regex
// before letting it into SQL.
type sqlUpdateField struct {
	col string
	val interface{}
	set bool
}

// buildUpdateClause walks fields, keeps only the ones with set == true,
// and returns parallel slices for the SET clause and the args. Every
// column name is checked against allowed (a closed map of valid column
// names) AND identRE (a strict identifier regex) before it appears in
// the SQL string. A column that fails either check is a programmer
// error — buildUpdateClause refuses to build the query at all rather
// than silently dropping the field, so the caller never gets a partial
// UPDATE that was missing the column that just got rejected.
//
// The returned setClauses slice contains entries like
// `column = $1`, `other = $2`. Args are 1-indexed because that's
// pgx's placeholder convention. The caller is expected to append any
// additional values (updated_at, the WHERE-clause id) after this.
func buildUpdateClause(
	fields []sqlUpdateField,
	allowed map[string]struct{},
	identRE *regexp.Regexp,
) (setClauses []string, args []interface{}, err error) {
	args = make([]interface{}, 0, len(fields))
	for _, f := range fields {
		if !f.set {
			continue
		}
		if _, ok := allowed[f.col]; !ok {
			return nil, nil, fmt.Errorf(
				"buildUpdateClause: column %q not in allow-list (SQL-injection guard)",
				f.col,
			)
		}
		if !identRE.MatchString(f.col) {
			return nil, nil, fmt.Errorf(
				"buildUpdateClause: column %q does not match identifier regex (SQL-injection guard)",
				f.col,
			)
		}
		args = append(args, f.val)
		setClauses = append(setClauses, f.col+" = $"+strconv.Itoa(len(args)))
	}
	return setClauses, args, nil
}
