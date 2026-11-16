package doctor

import (
	"fmt"
	"io"
)

// Report is the bundle put into words, for a surface that draws its own
// screen (the desktop and mobile client) rather than printing text.
type Report struct {
	Healthy     bool           `json:"healthy"`
	SupportCode string         `json:"support_code"`
	Items       []ReportItem   `json:"items"`
	Repairs     []ReportRepair `json:"repairs"`
	Bundle      Bundle         `json:"bundle"`
}

// ReportItem is one check, labelled, with its explanation when it is not a pass.
type ReportItem struct {
	Check  string      `json:"check"`
	Label  string      `json:"label"`
	Status CheckStatus `json:"status"`
	Code   string      `json:"code,omitempty"`
	Title  string      `json:"title,omitempty"`
	Action string      `json:"action,omitempty"`
}

// ReportRepair is one repair, labelled.
type ReportRepair struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Outcome string `json:"outcome"`
	Result  string `json:"result"`
}

// NewReport words the bundle in l.
func NewReport(b Bundle, l Lang) Report {
	t := table(l)
	r := Report{Healthy: b.Healthy(), SupportCode: SupportCode(b), Items: []ReportItem{}, Repairs: []ReportRepair{}, Bundle: b}
	for _, c := range b.Checks {
		it := ReportItem{Check: c.ID, Label: t.checks[c.ID], Status: c.Status, Code: c.Code}
		if c.Status == StatusFail || c.Status == StatusWarn {
			m := MessageFor(c.Code, l)
			it.Title, it.Action = m.Title, m.Action
		}
		r.Items = append(r.Items, it)
	}
	for _, rp := range b.Repairs {
		r.Repairs = append(r.Repairs, ReportRepair{ID: rp.ID, Label: t.repairs[rp.ID], Outcome: rp.Outcome, Result: t.outcomes[rp.Outcome]})
	}
	return r
}

// Summary writes only what is wrong and what to do: the short form for a
// dialog, where the table of checks would be noise.
func Summary(w io.Writer, b Bundle, l Lang) {
	t := table(l)
	if b.Healthy() {
		fmt.Fprintln(w, t.healthy)
		return
	}
	for _, c := range b.Failing() {
		m := MessageFor(c.Code, l)
		fmt.Fprintf(w, "%s\n→ %s\n\n", m.Title, m.Action)
	}
	fmt.Fprintf(w, "%s: %s\n", t.support, SupportCode(b))
}
