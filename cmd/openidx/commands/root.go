// Package commands provides the CLI commands for the OpenIDX developer CLI
package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// CommandContext provides shared context for commands
type CommandContext struct {
	RootDir  string
	Verbose  bool
	NoColor  bool
	DryRun   bool
}

// NewCommandContext creates a new command context from cobra command
func NewCommandContext(cmd *cobra.Command) *CommandContext {
	rootDir, _ := cmd.Flags().GetString("dir")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noColor, _ := cmd.Flags().GetBool("no-color")

	return &CommandContext{
		RootDir: rootDir,
		Verbose: verbose,
		NoColor: noColor,
	}
}

// GetColors returns color functions based on no-color setting
func (c *CommandContext) GetColors() (success, error, warning, info, header *color.Color) {
	if c.NoColor {
		noColor := color.New(color.Reset)
		return noColor, noColor, noColor, noColor, noColor
	}

	return color.New(color.FgGreen, color.Bold),
		color.New(color.FgRed, color.Bold),
		color.New(color.FgYellow, color.Bold),
		color.New(color.FgCyan),
		color.New(color.FgWhite, color.Bold)
}

// RunCommand executes a shell command with optional dry run
func (c *CommandContext) RunCommand(name string, args ...string) error {
	return c.RunCommandInDir(c.RootDir, name, args...)
}

// RunCommandInDir executes a command in a specific directory
func (c *CommandContext) RunCommandInDir(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	if c.Verbose {
		success, _, _, _, _ := c.GetColors()
		success.Printf("  $ %s %s\n", name, strings.Join(args, " "))
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// RunCommandOutput executes a command and returns its output
func (c *CommandContext) RunCommandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = c.RootDir

	if c.Verbose {
		success, _, _, _, _ := c.GetColors()
		success.Printf("  $ %s %s\n", name, strings.Join(args, " "))
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// RunMake executes a make target
func (c *CommandContext) RunMake(target string) error {
	return c.RunCommand("make", target)
}

// Path returns a path relative to the project root
func (c *CommandContext) Path(rel ...string) string {
	parts := append([]string{c.RootDir}, rel...)
	return filepath.Join(parts...)
}

// Exists checks if a path exists
func (c *CommandContext) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetGoVersion returns the Go version
func GetGoVersion() string {
	return runtime.Version()
}

// GetProjectInfo returns project information
func GetProjectInfo() map[string]string {
	return map[string]string{
		"name":        "OpenIDX",
		"description": "Zero Trust Access Platform",
		"repository":  "https://github.com/openidx/openidx",
		"license":     "MIT",
		"docs":        "https://docs.openidx.io",
	}
}

// FormatTable formats a table with headers and rows
func FormatTable(headers []string, rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var sb strings.Builder

	// Print header separator
	sb.WriteString("\n")
	for i, w := range widths {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(strings.Repeat("─", w+2))
	}
	sb.WriteString("\n")

	// Print headers
	for i, h := range headers {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(fmt.Sprintf(" %-*s ", widths[i], h))
	}
	sb.WriteString("\n")

	// Print header separator
	for i, w := range widths {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(strings.Repeat("─", w+2))
	}
	sb.WriteString("\n")

	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				sb.WriteString("  ")
			}
			sb.WriteString(fmt.Sprintf(" %-*s ", widths[i], cell))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
