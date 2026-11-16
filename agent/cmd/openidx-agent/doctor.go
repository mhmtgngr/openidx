package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/openidx/openidx/agent/internal/doctor"
	"github.com/openidx/openidx/agent/internal/doctor/collect"
)

type doctorFlags struct {
	JSON   bool
	Fix    bool
	Export string
	Lang   string
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
		code, err := runDoctor(cmd.Context(), collect.DefaultDeps(), os.Stdout, configDir, doctorOpts)
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

// runDoctor runs the diagnosis and prints it. The exit code is 0 when
// healthy, 1 when a check failed and 2 when the command itself could not run.
func runDoctor(ctx context.Context, d collect.Deps, out io.Writer, dir string, flags doctorFlags) (int, error) {
	lang, err := doctor.ParseLang(flags.Lang)
	if err != nil {
		return 2, err
	}
	b := collect.Run(ctx, d, dir, strings.TrimPrefix(strings.TrimSpace(Version), "v"), flags.Fix)

	if flags.Export != "" {
		if err := exportBundle(flags.Export, b); err != nil {
			return 2, err
		}
	}
	if flags.JSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(b); err != nil {
			return 2, err
		}
	} else {
		doctor.Render(out, b, lang)
	}
	if !b.Healthy() {
		return 1, nil
	}
	return 0, nil
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
