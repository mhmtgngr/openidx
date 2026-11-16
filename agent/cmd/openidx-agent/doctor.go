package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/openidx/openidx/agent/internal/agent"
	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/ipc"
	"github.com/openidx/openidx/agent/internal/transport"
)

type doctorFlags struct {
	JSON   bool
	Fix    bool
	Export string
	Lang   string
}

// doctorDeps are the doctor command's seams.
type doctorDeps struct {
	loadConfig func(dir string) (*agent.AgentConfig, error)
	queryIPC   func() (*ipc.Status, error)
	probes     doctor.Probes
	actions    doctor.Actions
	stdout     io.Writer
	// settle is how long to wait after a repair before checking again.
	settle time.Duration
}

var doctorOpts doctorFlags

// doctorCmd diagnoses, on this device alone, why the agent cannot connect.
var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Find out why this device cannot connect, and fix what is safe to fix",
	Long: "Checks the agent's setup, the path to the server, the device's identity and the\n" +
		"secure tunnel, and says in plain language what is wrong. It needs no server.\n\n" +
		"Exit status: 0 no problems, 1 a problem was found, 2 the check itself failed.",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	Run: func(cmd *cobra.Command, args []string) {
		deps := doctorDeps{
			loadConfig: agent.LoadConfig,
			queryIPC:   ipc.Query,
			probes:     doctor.NewProbes(),
			actions:    doctor.NewActions(),
			stdout:     os.Stdout,
			settle:     8 * time.Second,
		}
		code, err := runDoctor(cmd.Context(), deps, configDir, doctorOpts)
		if err != nil {
			fmt.Fprintln(os.Stderr, "doctor:", err)
		}
		if code != 0 {
			os.Exit(code)
		}
	},
}

func init() {
	f := doctorCmd.Flags()
	f.BoolVar(&doctorOpts.JSON, "json", false, "print the diagnostic bundle as JSON")
	f.BoolVar(&doctorOpts.Fix, "fix", false, "apply the safe repairs, then check again")
	f.StringVar(&doctorOpts.Export, "export", "", "also write the bundle to this new file")
	f.StringVar(&doctorOpts.Lang, "lang", "", "output language: en or tr (default: yours)")
	rootCmd.AddCommand(doctorCmd)
}

// gatherInputs collects what the device knows about itself: agent.json when
// this account may read it, and the service's status pipe when it answers.
func gatherInputs(d doctorDeps, dir string) doctor.Inputs {
	in := doctor.Inputs{AgentVersion: strings.TrimPrefix(strings.TrimSpace(Version), "v")}

	cfg, err := d.loadConfig(dir)
	if err == nil {
		in.AgentID = cfg.AgentID
		in.ServerURL = cfg.ServerURL
		in.ProxyURL = cfg.ProxyURL
		in.Enrolled = cfg.AgentID != ""
		in.IdentityFile = cfg.ZitiIdentityFile
		in.TunnelExpected = cfg.Tunnel != nil && cfg.Tunnel.Enabled
		// Probe the way the agent connects: same proxy, same server CA.
		_ = transport.SetNetworkOptions(cfg.NetworkOptions())
	} else {
		in.ConfigErr = err
	}

	st, qerr := d.queryIPC()
	switch {
	case qerr == nil && st != nil:
		running := true
		in.ServiceRunning = &running
		in.AuthInvalid, in.Revoked, in.Tunnel = st.AuthInvalid, st.Revoked, st.Tunnel
		if st.Tunnel != nil {
			in.TunnelExpected = in.TunnelExpected || st.Tunnel.State != "off"
		}
		if err != nil {
			// The service can read what this account cannot.
			in.AgentID, in.ServerURL, in.Enrolled = st.AgentID, st.ServerURL, st.Enrolled
			in.ConfigErr = nil
		}
	case runtime.GOOS != "windows":
		// No status pipe on this platform: the service's state is unknown.
	default:
		running := false
		in.ServiceRunning = &running
	}
	return in
}

// runDoctor runs the diagnosis and prints it. The exit code is 0 when
// healthy, 1 when a check failed and 2 when the command itself could not run.
func runDoctor(ctx context.Context, d doctorDeps, dir string, flags doctorFlags) (int, error) {
	lang, err := doctor.ParseLang(flags.Lang)
	if err != nil {
		return 2, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	b := doctor.Run(ctx, gatherInputs(d, dir), d.probes, doctor.Options{})
	if flags.Fix {
		repairs := doctor.ApplyRepairs(ctx, b, d.actions)
		if anyApplied(repairs) {
			select {
			case <-ctx.Done():
			case <-time.After(d.settle):
			}
			b = doctor.Run(ctx, gatherInputs(d, dir), d.probes, doctor.Options{})
		}
		b.Repairs = repairs
	} else {
		b.Repairs = doctor.PlanRepairs(b)
	}

	if flags.Export != "" {
		if err := exportBundle(flags.Export, b); err != nil {
			return 2, err
		}
	}
	if flags.JSON {
		enc := json.NewEncoder(d.stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(b); err != nil {
			return 2, err
		}
	} else {
		doctor.Render(d.stdout, b, lang)
	}
	if !b.Healthy() {
		return 1, nil
	}
	return 0, nil
}

func anyApplied(rs []doctor.Repair) bool {
	for _, r := range rs {
		if r.Outcome == doctor.OutcomeApplied {
			return true
		}
	}
	return false
}

// exportBundle writes the bundle to a new owner-only file. It never replaces
// an existing file: the path comes from a command line, often run elevated.
func exportBundle(path string, b doctor.Bundle) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("writing bundle: %w", err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("writing bundle: %w", err)
	}
	return f.Close()
}
