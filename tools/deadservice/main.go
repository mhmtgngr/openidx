// Command deadservice finds whole services no binary in this repository can
// reach.
//
// Usage:
//
//	deadservice [-fail] [-census] [-roots <pattern>]
//
// THE SHAPE. internal/governance/request.go is 676 lines: SubmitRequest,
// ApproveRequest, DenyRequest, CancelRequest, a manager-resolution step, a
// notification-hook registry, and a StartEscalationChecker goroutine that
// sweeps every org for requests past their approval SLA and adds the escalation
// approvers. It has tests. It is the only code in the tree that writes
// request_approval_chains, and two migrations exist to create that table and
// put it under the RLS belt.
//
// NewRequestService is called nowhere. Not by cmd/governance-service, not by
// anything else. The live approval workflow is a DIFFERENT implementation in
// workflows.go with different semantics, and it never writes the chain table --
// so the escalation sweep's INNER JOIN matches zero rows on every install, and
// would keep matching zero rows even if somebody started the checker.
//
// Nothing in the repository could see this:
//
//   - it compiles, so the build passes it;
//   - the SQL is valid and carries its tenant predicate, so sqlprepare and
//     orgscope pass it;
//   - the tests are real tests that exercise real code, so the inert-test guard
//     passes it;
//   - tablewriters counts the INSERT as a writer, because a census of SQL
//     literals cannot tell a statement that runs from one that cannot.
//
// So the escalation feature reads as shipped, the table reads as written, and
// an earlier fix in this very repository spent its effort on a bug inside
// checkEscalations -- code that has never executed on any install.
//
// The only thing that can see it is reachability: build the call graph from the
// program entry points and ask which functions it never reaches.
//
// WHAT COUNTS AS A FINDING. Not every unreachable function: a helper nobody
// calls yet, an unused error constructor and a spare accessor are noise, and a
// gate that reports noise is a gate somebody turns off. The finding is the
// shape that MISLEADS -- an entire service:
//
//	its constructor (func NewT) is unreachable, AND
//	every one of its methods is unreachable, AND
//	it has at least minMethods of them.
//
// A type like that is not a loose end. It is a feature that looks finished in
// review, has tests, has migrations, has a name people say in meetings, and
// cannot run. Partially-used types are deliberately not reported: a live type
// with one spare method is an ordinary loose end, not a lie about the product.
//
// HOW REACHABILITY IS COMPUTED. Rapid Type Analysis over the SSA form of every
// main package under -roots (all of ./cmd/... by default), which is what
// golang.org/x/tools/cmd/deadcode uses. RTA is conservative in the safe
// direction here: it over-approximates the set of reachable functions (an
// interface method is live as soon as SOME reachable code could hold that
// dynamic type), so a function it calls unreachable really is unreachable from
// main. False "this is dead" is therefore not a failure mode; false "this is
// alive" is, and that only costs a finding this tool does not make.
//
// TESTS ARE NOT ROOTS, DELIBERATELY. A service whose only caller is its own
// test is exactly the defect: the tests are what make it look alive. Reachable
// only from _test.go is dead in production, and this tool says so.
//
// Findings are registered in known.go with a verdict apiece: what the service
// looks like it does, what actually happens, and whether the answer is to wire
// it or delete it. A finding absent from the register fails the run; an entry
// that no longer reproduces fails it too, so the register can only shrink, and
// an empty register is the finished state rather than a disabled check.
package main

import (
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// minMethods is the floor for calling a dead type a dead SERVICE. Below it the
// type is a struct with a couple of helpers, and reporting those would bury the
// findings that matter under ones that do not.
const minMethods = 3

// service is one candidate type: a named type declared in the tree, with its
// methods and the constructor that would build it.
type service struct {
	Pkg      string // import path, e.g. github.com/openidx/openidx/internal/governance
	Name     string // type name, e.g. RequestService
	Pos      string // file:line of the type declaration
	Methods  []string
	CtorName string // "NewRequestService", or "" if the package declares none
	Ctor     *ssa.Function
	Funcs    map[string]*ssa.Function // method name -> function
}

// key is the register key: the import path's tail plus the type name, e.g.
// "internal/governance.RequestService". Stable across moves within a package
// and readable in a register entry.
func (s *service) key() string {
	p := s.Pkg
	if i := strings.Index(p, "/internal/"); i >= 0 {
		p = p[i+1:]
	}
	return p + "." + s.Name
}

func main() {
	failOnFindings := flag.Bool("fail", false, "exit 1 on an unregistered finding or a stale register entry")
	census := flag.Bool("census", false, "print every candidate service with its reachable/unreachable method counts")
	roots := flag.String("roots", "./cmd/...", "package pattern for the program entry points")
	flag.Parse()

	services, reachable, err := analyze(*roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "deadservice: %v\n", err)
		os.Exit(2)
	}

	if *census {
		printCensus(services, reachable)
		return
	}

	findings := report(services, reachable)

	found := make(map[string]bool, len(findings))
	for _, f := range findings {
		found[f] = true
	}

	// A register entry that no longer reproduces is as much a defect as an
	// unregistered finding: it means the tool stopped seeing something, and a
	// checker that quietly stops checking is the failure mode this repository
	// keeps finding.
	var stale []string
	for k := range knownDead {
		if !found[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)

	var unregistered []string
	for _, f := range findings {
		if _, ok := knownDead[f]; !ok {
			unregistered = append(unregistered, f)
		}
	}

	byKey := make(map[string]*service, len(services))
	for _, s := range services {
		byKey[s.key()] = s
	}
	for _, f := range unregistered {
		s := byKey[f]
		fmt.Printf("%s: no binary can reach this service\n", f)
		fmt.Printf("    declared at %s\n", s.Pos)
		fmt.Printf("    %s is never called, and all %d of its methods are unreachable from any main\n",
			ctorLabel(s), len(s.Methods))
		fmt.Printf("    wire it or delete it, then record the verdict in tools/deadservice/known.go\n")
	}
	for _, k := range stale {
		fmt.Printf("%s: registered as unreachable, but a binary reaches it now\n", k)
		fmt.Printf("    remove its entry from tools/deadservice/known.go\n")
	}

	fmt.Fprintf(os.Stderr, "deadservice: %d candidate service type(s), %d unreachable, %d registered, %d new, %d stale\n",
		len(services), len(findings), len(knownDead), len(unregistered), len(stale))

	if *failOnFindings && (len(unregistered) > 0 || len(stale) > 0) {
		os.Exit(1)
	}
}

func ctorLabel(s *service) string {
	if s.CtorName == "" {
		return "it is constructed nowhere"
	}
	return s.CtorName
}

// analyze loads the roots, builds SSA, runs RTA from every main, and returns
// the candidate services alongside the set of reachable functions.
func analyze(roots string) ([]*service, map[*ssa.Function]bool, error) {
	cfg := &packages.Config{Mode: packages.LoadAllSyntax}
	initial, err := packages.Load(cfg, roots)
	if err != nil {
		return nil, nil, fmt.Errorf("load %s: %w", roots, err)
	}
	if packages.PrintErrors(initial) > 0 {
		return nil, nil, fmt.Errorf("packages contain errors")
	}

	prog, _ := ssautil.AllPackages(initial, ssa.InstantiateGenerics)
	prog.Build()

	var mains []*ssa.Function
	for _, p := range prog.AllPackages() {
		if p.Pkg.Name() == "main" {
			if fn := p.Func("main"); fn != nil {
				mains = append(mains, fn)
			}
		}
	}
	if len(mains) == 0 {
		return nil, nil, fmt.Errorf("no main packages under %s", roots)
	}

	res := rta.Analyze(mains, true)
	reachable := make(map[*ssa.Function]bool, len(res.Reachable))
	for fn := range res.Reachable {
		reachable[fn] = true
	}

	return collectServices(prog), reachable, nil
}

// collectServices walks every package the program contains and gathers the
// named types declared in this module's internal tree, with their methods and
// their New* constructor if one exists.
func collectServices(prog *ssa.Program) []*service {
	var out []*service
	for _, p := range prog.AllPackages() {
		path := p.Pkg.Path()
		if !strings.Contains(path, "/internal/") && !strings.HasSuffix(path, "/internal") {
			continue
		}
		if !strings.HasPrefix(path, "github.com/openidx/openidx/") {
			continue
		}
		scope := p.Pkg.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			s := &service{
				Pkg:   path,
				Name:  name,
				Pos:   position(prog, tn.Pos()),
				Funcs: map[string]*ssa.Function{},
			}
			// Methods are looked up on the pointer type: a service's methods
			// almost always take a pointer receiver, and the method set of *T
			// includes T's.
			ptr := types.NewPointer(named)
			ms := types.NewMethodSet(ptr)
			for i := 0; i < ms.Len(); i++ {
				sel := ms.At(i)
				m, _ := sel.Obj().(*types.Func)
				if m == nil || m.Pkg() != p.Pkg {
					continue // promoted from an embedded type declared elsewhere
				}
				fn := prog.FuncValue(m)
				if fn == nil {
					continue
				}
				s.Methods = append(s.Methods, m.Name())
				s.Funcs[m.Name()] = fn
			}
			if len(s.Methods) < minMethods {
				continue
			}
			sort.Strings(s.Methods)
			if ctor, _ := scope.Lookup("New" + name).(*types.Func); ctor != nil {
				s.CtorName = ctor.Name()
				s.Ctor = prog.FuncValue(ctor)
			}
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

func position(prog *ssa.Program, pos token.Pos) string {
	p := prog.Fset.Position(pos)
	if i := strings.Index(p.Filename, "/openidx/"); i >= 0 {
		p.Filename = p.Filename[i+len("/openidx/"):]
	}
	return fmt.Sprintf("%s:%d", p.Filename, p.Line)
}

// report returns the register keys of every entirely-unreachable service.
func report(services []*service, reachable map[*ssa.Function]bool) []string {
	var out []string
	for _, s := range services {
		if s.Ctor != nil && reachable[s.Ctor] {
			continue
		}
		allDead := true
		for _, m := range s.Methods {
			if reachable[s.Funcs[m]] {
				allDead = false
				break
			}
		}
		if allDead {
			out = append(out, s.key())
		}
	}
	sort.Strings(out)
	return out
}

func printCensus(services []*service, reachable map[*ssa.Function]bool) {
	for _, s := range services {
		live := 0
		for _, m := range s.Methods {
			if reachable[s.Funcs[m]] {
				live++
			}
		}
		ctor := "no ctor"
		if s.Ctor != nil {
			ctor = s.CtorName
			if reachable[s.Ctor] {
				ctor += " (reached)"
			} else {
				ctor += " (unreached)"
			}
		}
		fmt.Printf("%-60s %2d/%2d methods reachable  %s\n", s.key(), live, len(s.Methods), ctor)
	}
}
