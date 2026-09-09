// Package switchfixture is the inertswitch gate's own subject: a request struct
// carrying one switch of each shape the census has to tell apart.
//
// It lives under testdata so `go build ./...` and the gate's own run over the
// module never see it — a fixture whose whole point is to be a finding would
// otherwise fail the gate it exists to test.
package switchfixture

// binder stands in for *gin.Context. The census keys on the method NAME, not on
// gin's type, so this is enough to mark Request as bound from a caller and does
// not drag the web framework into a fixture.
type binder struct{}

func (binder) ShouldBindJSON(v interface{}) error { return nil }

type pool struct{}

func (pool) Exec(query string, args ...interface{}) error { return nil }

// Request is what a caller can set.
type Request struct {
	// Decided is compared, so it is honest.
	Decided bool `json:"decided"`
	// Transferred is copied into Model.Kept, which is compared. The value
	// reaches a decision one hop away, which is the ordinary shape.
	Transferred bool `json:"transferred"`
	// Inert is stored and never looked at again. This is the finding.
	Inert bool `json:"inert"`
	// NotABool is not this census's business however inert it is: a string can
	// honestly be data.
	NotABool string `json:"not_a_bool"`
}

// Model is what reaches the database.
type Model struct {
	Kept  bool
	Inert bool
}

func Handle(c binder, db pool) error {
	var req Request
	if err := c.ShouldBindJSON(&req); err != nil {
		return err
	}

	// A decision.
	if req.Decided {
		return nil
	}

	m := Model{Kept: req.Transferred, Inert: req.Inert}

	// A store. Neither field is decided here.
	return db.Exec(`INSERT INTO t (kept, inert) VALUES ($1, $2)`, m.Kept, m.Inert)
}

// Decide is where the transferred value is finally looked at.
func Decide(m Model) string {
	if m.Kept {
		return "kept"
	}
	return "not kept"
}
