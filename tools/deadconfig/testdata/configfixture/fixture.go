// Package configfixture is the deadconfig gate's own subject: a configuration
// struct with one field something reads and one field nothing does.
//
// It lives under testdata so `go build ./...` and the gate's own run over the
// module never see it — a fixture whose whole point is to be a finding would
// otherwise fail the gate it exists to test.
package configfixture

// Fixture is the root config struct.
type Fixture struct {
	Read   string  `mapstructure:"read"`
	Unread string  `mapstructure:"unread"`
	Nested Section `mapstructure:"section"`

	// NotBound carries no mapstructure tag, so no operator can set it and it is
	// not this census's business however unread it is.
	NotBound string
}

// Section is nested under Fixture, so its keys are dotted.
type Section struct {
	Deep       string `mapstructure:"deep"`
	DeepUnread string `mapstructure:"deep_unread"`
}

// Use reads two of the four settable fields. The other two are the findings.
func Use(f Fixture) string {
	return f.Read + f.Nested.Deep
}
