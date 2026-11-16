package doctor

import (
	"fmt"
	"io"
)

// Render writes the bundle as text a non-technical user can act on.
func Render(w io.Writer, b Bundle, l Lang) {
	t := table(l)
	fmt.Fprintf(w, "%s — %s UTC\n", t.heading, b.CollectedAt.UTC().Format("2006-01-02 15:04"))
	for _, c := range b.Checks {
		mark, tail := "✓", ""
		switch c.Status {
		case StatusFail:
			mark, tail = "✗", c.Code
		case StatusWarn:
			mark, tail = "!", c.Code
		case StatusSkipped:
			mark, tail = "–", "("+t.skipped+")"
		}
		fmt.Fprintf(w, "  %s %-22s %s\n", mark, t.checks[c.ID], tail)
	}
	fmt.Fprintln(w)

	for _, c := range b.Checks {
		m := MessageFor(c.Code, l)
		switch c.Status {
		case StatusFail:
			fmt.Fprintf(w, "%s: %s\n%s: %s\n\n", t.problem, m.Title, t.action, m.Action)
		case StatusWarn:
			fmt.Fprintf(w, "%s: %s %s\n\n", t.note, m.Title, m.Action)
		}
	}
	for _, r := range b.Repairs {
		fmt.Fprintf(w, "%s: %s — %s\n", t.repair, t.repairs[r.ID], t.outcomes[r.Outcome])
	}
	if b.Healthy() {
		fmt.Fprintln(w, t.healthy)
		return
	}
	fmt.Fprintf(w, "\n%s: %s\n", t.support, SupportCode(b))
}
