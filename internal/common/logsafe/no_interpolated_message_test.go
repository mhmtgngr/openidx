package logsafe_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// encoder_test.go measures which half of a zap entry an attacker can forge a
// line in: not the fields, which both encoders escape, but the MESSAGE, which
// the console encoder writes raw. A message is safe as long as it is a constant
// the author wrote, and unsafe the moment a value is interpolated into it —
// logger.Warn(fmt.Sprintf("rejected %s", clientID)) puts whatever the client
// sent where the escaping is not.
//
// The tree has no such call today, and that is an accident of style rather than
// a rule: nothing stopped one, and nothing would have noticed. So state the rule
// and check it. logsafe.String cannot help here, because the point is that the
// value must not be in the message at all — the fix is always to move it into a
// field, which is better logging anyway (a field is greppable; an interpolated
// message is not).
//
// What counts as interpolation is deliberately narrow: building a string at the
// call site. A logging ADAPTER that forwards a msg string parameter to the
// logger underneath is not building anything, and flagging it would push callers
// to route around the guard.
var interpolators = map[string]bool{
	"fmt.Sprintf":  true,
	"fmt.Sprint":   true,
	"fmt.Sprintln": true,
	"strings.Join": true,
}

var zapLevels = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DPanic": true, "Panic": true, "Fatal": true,
}

// interpolatedMessage reports how e builds a string, or "" if it does not.
func interpolatedMessage(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return interpolatedMessage(v.X)
	case *ast.CallExpr:
		sel, ok := v.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return ""
		}
		if name := pkg.Name + "." + sel.Sel.Name; interpolators[name] {
			return name
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD && !literalConcat(v) {
			return "string concatenation"
		}
	}
	return ""
}

// literalConcat reports whether e is a concatenation of string literals only —
// the way a long constant message is wrapped across source lines.
func literalConcat(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.ParenExpr:
		return literalConcat(v.X)
	case *ast.BinaryExpr:
		return v.Op == token.ADD && literalConcat(v.X) && literalConcat(v.Y)
	}
	return false
}

// rightmostName returns the last identifier of a selector chain, so that both
// `logger.Warn` and `g.logger.Warn` and `cfg.Logger.Warn` answer "logger".
func rightmostName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.CallExpr:
		return rightmostName(v.Fun)
	case *ast.IndexExpr:
		return rightmostName(v.X)
	}
	return ""
}

// findInterpolatedMessages returns "file:line: how" for every logger call in
// src whose message is built rather than written.
//
// Receivers are matched by NAME containing "log", which is what distinguishes
// logger.Error from t.Error and require.Error without loading type information
// for the whole module. The repo uses only the structured zap logger (no
// SugaredLogger, checked below), so the level names are unambiguous once the
// receiver is.
func findInterpolatedMessages(fset *token.FileSet, f *ast.File, rel string) []string {
	var found []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !zapLevels[sel.Sel.Name] || len(call.Args) == 0 {
			return true
		}
		if !strings.Contains(strings.ToLower(rightmostName(sel.X)), "log") {
			return true
		}
		how := interpolatedMessage(call.Args[0])
		if how == "" {
			return true
		}
		found = append(found, rel+":"+strconv.Itoa(fset.Position(call.Args[0].Pos()).Line)+
			": "+rightmostName(sel.X)+"."+sel.Sel.Name+" builds its message with "+how)
		return true
	})
	return found
}

func TestNoInterpolatedLogMessages(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var found []string
	scanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		// Tests are exempt: a test's log lines are read by the person who ran it,
		// and t.Logf-style formatting there is normal.
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // not this guard's business
		}
		scanned++
		rel, _ := filepath.Rel(root, path)
		found = append(found, findInterpolatedMessages(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// A guard that greens because it scanned nothing is the failure mode this
	// repo has already been bitten by once.
	if scanned < 100 {
		t.Fatalf("scanned only %d non-test Go files — the walk is looking in the wrong place", scanned)
	}

	if len(found) != 0 {
		t.Errorf("log message(s) built from a value instead of written as a constant — "+
			"move the value into a zap field (logsafe.String if it came from outside):\n  %s",
			strings.Join(found, "\n  "))
	}
}

// The guard rests on two premises. First, that it can see the shape it forbids.
func TestGuardDetectsAnInterpolatedMessage(t *testing.T) {
	cases := map[string]struct {
		src  string
		want int
	}{
		"fmt.Sprintf into the message": {
			src: `package p
func f() { logger.Warn(fmt.Sprintf("rejected %s", clientID)) }`,
			want: 1,
		},
		"concatenation with a variable": {
			src: `package p
func f() { g.logger.Info("listening on " + addr) }`,
			want: 1,
		},
		// A long constant message wrapped across lines is not interpolation.
		"a constant wrapped across two lines": {
			src: `package p
func f() { cfg.Logger.Warn("X-Org-ID ignored: the resolver ran before auth. " +
	"Mount it after the auth middleware.") }`,
			want: 0,
		},
		// An adapter forwarding its own parameter builds nothing; the call that
		// produced msg is where the guard looks.
		"an adapter forwarding a msg parameter": {
			src: `package p
func (l *Adapter) Warn(msg string, f ...zap.Field) { l.logger.Warn(msg, f...) }`,
			want: 0,
		},
		// Fields are escaped by both encoders, so formatting one is fine.
		"fmt.Sprintf inside a field": {
			src: `package p
func f() { logger.Warn("rejected", zap.String("why", fmt.Sprintf("%d of %d", a, b))) }`,
			want: 0,
		},
		// The receiver test is what keeps testing.T out of it.
		"t.Errorf-shaped call on a non-logger": {
			src: `package p
func f() { t.Error(fmt.Sprintf("got %v", x)) }`,
			want: 0,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "a.go")
			if err := os.WriteFile(p, []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := findInterpolatedMessages(fset, f, "a.go")
			if len(got) != tc.want {
				t.Fatalf("findings = %d, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

// Second, that the level names it matches are zap's structured API and not
// something else. zap's SugaredLogger has Infof/Warnf/Errorf, which take a
// format string by design — a guard on Info/Warn/Error would say nothing about
// those, so if one ever appears the rule above needs extending rather than
// quietly covering less of the tree.
//
// Checked over the AST rather than the file text, because the sentence above
// names the thing it forbids and a text scan would report this file.
func TestRepoUsesOnlyTheStructuredLogger(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var sugar []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, isIdent := sel.X.(*ast.Ident)
			switch {
			case isIdent && pkg.Name == "zap" && sel.Sel.Name == "SugaredLogger":
			case sel.Sel.Name == "Sugar":
			default:
				return true
			}
			sugar = append(sugar, rel+":"+strconv.Itoa(fset.Position(sel.Pos()).Line))
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(sugar) != 0 {
		t.Errorf("zap SugaredLogger in use — its Infof/Warnf/Errorf take a format string, "+
			"which TestNoInterpolatedLogMessages does not check; extend zapLevels before "+
			"these land:\n  %s", strings.Join(sugar, "\n  "))
	}
}

// correlationHeaders are the client-supplied tracing headers this platform
// ADOPTS rather than merely reads: it echoes them back, keeps them on the
// request context, stamps them on every log line for the request, and sets them
// on the outbound request to each backend.
var correlationHeaders = []string{"X-Request-ID", "X-Correlation-ID", "traceparent"}

// TestCorrelationHeadersAreValidatedWhereTheyAreRead is the same lesson this
// package was created for, one level up. logsafe exists because five packages
// had each grown their own log sanitiser and the weakest one decided what an
// attacker could do. Reading X-Request-ID had grown FOUR copies — two in
// internal/middleware/requestid.go, one in internal/common/middleware/logging.go,
// one in internal/common/middleware/middleware.go — plus a correlation-ID
// variant in the gateway and a relay in the reverse proxy, and every one of them
// took whatever arrived.
//
// So the rule is not "call the validator" (unenforceable) but the narrower
// checkable thing: a function that READS one of these headers must also mention
// logsafe.PlausibleID. That is coarse — it cannot tell that the result was acted
// on — and it is the honest limit of a syntactic check. What it does catch is the
// fifth copy, written by someone who did not know the other four existed, which
// is exactly how the first four happened.
func TestCorrelationHeadersAreValidatedWhereTheyAreRead(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var unvalidated []string
	readers := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "third_party", "web", "client", "agent", "docs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			header, reads := readsCorrelationHeader(fn.Body)
			if !reads {
				continue
			}
			readers++
			if !mentionsPlausibleID(fn.Body) {
				unvalidated = append(unvalidated, rel+":"+
					strconv.Itoa(fset.Position(fn.Pos()).Line)+": "+fn.Name.Name+" reads "+header)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	// The header is read in several places by design; zero readers means the walk
	// or the matcher broke, not that the tree got safer.
	if readers < 4 {
		t.Fatalf("found only %d functions reading a correlation header — the matcher is not seeing the tree", readers)
	}
	if len(unvalidated) != 0 {
		t.Errorf("correlation header adopted without logsafe.PlausibleID — the value is echoed to the "+
			"client, logged, and forwarded to backends, so it cannot be whatever arrived:\n  %s",
			strings.Join(unvalidated, "\n  "))
	}
}

// readsCorrelationHeader reports whether body calls GetHeader / Header.Get with
// one of the correlation header names, and which one.
func readsCorrelationHeader(body *ast.BlockStmt) (string, bool) {
	var found string
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "GetHeader" && sel.Sel.Name != "Get") {
			return true
		}
		name, ok := headerArgName(call.Args[0])
		if !ok {
			return true
		}
		for _, h := range correlationHeaders {
			if strings.EqualFold(name, h) {
				found = h
				return false
			}
		}
		return true
	})
	return found, found != ""
}

// headerArgName resolves the argument to GetHeader when it is a string literal
// or one of the package-level header-name constants (CorrelationIDHeader,
// RequestIDHeader, HeaderXRequestID), whose names all end in the header they
// hold.
func headerArgName(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			return strings.Trim(v.Value, `"`), true
		}
	case *ast.Ident:
		switch v.Name {
		case "CorrelationIDHeader":
			return "X-Correlation-ID", true
		case "RequestIDHeader", "HeaderXRequestID":
			return "X-Request-ID", true
		}
	}
	return "", false
}

func mentionsPlausibleID(body *ast.BlockStmt) bool {
	seen := false
	ast.Inspect(body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "PlausibleID" {
			seen = true
			return false
		}
		return true
	})
	return seen
}
