package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// NewCompletionCommand creates the completion command
func NewCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `Generate shell completion script for OpenIDX CLI.

To load completions:

Bash:
  $ source <(openidx completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ openidx completion bash > /etc/bash_completion.d/openidx
  # macOS:
  $ openidx completion bash > /usr/local/etc/bash_completion.d/openidx

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ openidx completion zsh > "${fpath[1]}/_openidx"

  # You will need to start a new shell for this setup to take effect.

fish:
  $ openidx completion fish | source

  # To load completions for each session, execute once:
  $ openidx completion fish > ~/.config/fish/completions/openidx.fish

PowerShell:
  PS> openidx completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> openidx completion powershell > openidx.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactValidArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell type: %s", args[0])
			}
		},
	}

	return cmd
}

// NewInstallCompletionCommand creates the install-completion command
func NewInstallCompletionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install-completion [bash|zsh|fish|powershell]",
		Short: "Install shell completion",
		Long: `Install shell completion for the current shell.

This will detect your current shell and install completions automatically.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := NewCommandContext(cmd)
			success, errColor, _, _, _ := ctx.GetColors()

			shell := detectShell()
			if len(args) > 0 {
				shell = args[0]
			}

			success.Printf("Installing completion for %s...\n", shell)

			switch shell {
			case "bash":
				return installBashCompletion(ctx)
			case "zsh":
				return installZshCompletion(ctx)
			case "fish":
				return installFishCompletion(ctx)
			case "powershell":
				return installPowerShellCompletion(ctx)
			default:
				errColor.Printf("Unsupported shell: %s\n", shell)
				return fmt.Errorf("unsupported shell: %s", shell)
			}
		},
	}

	return cmd
}

func detectShell() string {
	shell := os.Getenv("SHELL")
	if shell != "" {
		switch {
		case strings.Contains(shell, "bash"):
			return "bash"
		case strings.Contains(shell, "zsh"):
			return "zsh"
		case strings.Contains(shell, "fish"):
			return "fish"
		}
	}

	// Check on Windows
	if os.Getenv("PSModulePath") != "" {
		return "powershell"
	}

	return "bash" // Default
}

func installBashCompletion(ctx *CommandContext) error {
	success, errColor, _, _, _ := ctx.GetColors()

	// Try common completion directories
	dirs := []string{
		"/etc/bash_completion.d",
		"/usr/local/etc/bash_completion.d",
		os.ExpandEnv("$HOME/.local/share/bash-completion/completions"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err == nil {
			dest := dir + "/openidx"
			if err := writeCompletionToFile(ctx, "bash", dest); err == nil {
				success.Printf("✓ Bash completion installed to %s\n", dest)
				success.Println("  Start a new shell or run: source ~/.bashrc")
				return nil
			}
		}
	}

	// Fallback: add to .bashrc
	bashrc := os.ExpandEnv("$HOME/.bashrc")
	if err := appendToCompletionFile(ctx, "bash", bashrc); err == nil {
		success.Printf("✓ Added completion to %s\n", bashrc)
		return nil
	}

	errColor.Println("✗ Failed to install bash completion")
	return fmt.Errorf("failed to install bash completion")
}

func installZshCompletion(ctx *CommandContext) error {
	success, errColor, _, _, _ := ctx.GetColors()

	// Try zsh function directories
	dirs := []string{
		os.ExpandEnv("$HOME/.zsh/completion"),
		os.ExpandEnv("$HOME/.zsh/functions"),
		"/usr/local/share/zsh/site-functions",
		os.ExpandEnv("$HOME/.local/share/zsh/site-functions"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err == nil {
			dest := dir + "/_openidx"
			if err := writeCompletionToFile(ctx, "zsh", dest); err == nil {
				success.Printf("✓ Zsh completion installed to %s\n", dest)
				success.Println("  Start a new shell or run: exec zsh")
				return nil
			}
		}
	}

	// Fallback: add to .zshrc
	zshrc := os.ExpandEnv("$HOME/.zshrc")
	if err := appendToCompletionFile(ctx, "zsh", zshrc); err == nil {
		success.Printf("✓ Added completion to %s\n", zshrc)
		return nil
	}

	errColor.Println("✗ Failed to install zsh completion")
	return fmt.Errorf("failed to install zsh completion")
}

func installFishCompletion(ctx *CommandContext) error {
	success, errColor, _, _, _ := ctx.GetColors()

	dir := os.ExpandEnv("$HOME/.config/fish/completions")
	if err := os.MkdirAll(dir, 0755); err != nil {
		errColor.Printf("Failed to create directory: %v\n", err)
		return err
	}

	dest := dir + "/openidx.fish"
	if err := writeCompletionToFile(ctx, "fish", dest); err != nil {
		errColor.Printf("Failed to write completion: %v\n", err)
		return err
	}

	success.Printf("✓ Fish completion installed to %s\n", dest)
	success.Println("  Start a new shell or run: exec fish")
	return nil
}

func installPowerShellCompletion(ctx *CommandContext) error {
	success, errColor, _, _, _ := ctx.GetColors()

	profileDir := os.ExpandEnv("$HOME/Documents/PowerShell")
	if os.Getenv("OS") == "Windows_NT" {
		profileDir = os.ExpandEnv("$PROFILE")
	}

	dest := profileDir + "/openidx.ps1"
	if err := writeCompletionToFile(ctx, "powershell", dest); err != nil {
		errColor.Printf("Failed to write completion: %v\n", err)
		return err
	}

	success.Printf("✓ PowerShell completion installed to %s\n", dest)
	success.Println("  Add this to your PowerShell profile:")
	success.Printf("  Invoke-Expression -Command $(%s completion powershell)\n", "openidx")
	return nil
}

func writeCompletionToFile(ctx *CommandContext, shell, dest string) error {
	// Generate completion script
	cliPath := "openidx"
	if len(os.Args) > 0 {
		cliPath = os.Args[0]
	}
	cmd := exec.Command(cliPath, "completion", shell)
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(dest, output, 0644)
}

func appendToCompletionFile(ctx *CommandContext, shell, configFile string) error {
	// Generate completion script
	cliPath := "openidx"
	if len(os.Args) > 0 {
		cliPath = os.Args[0]
	}
	cmd := exec.Command(cliPath, "completion", shell)
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Append to config file
	f, err := os.OpenFile(configFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte("\n# OpenIDX completion\n"))
	if err != nil {
		return err
	}

	_, err = f.Write(output)
	return err
}

