package main

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for dotsecenv.

To load completions:

Bash:
  $ source <(dotsecenv completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ dotsecenv completion bash > /etc/bash_completion.d/dotsecenv
  # macOS:
  $ dotsecenv completion bash > $(brew --prefix)/etc/bash_completion.d/dotsecenv

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ dotsecenv completion zsh > "${fpath[1]}/_dotsecenv"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ dotsecenv completion fish | source

  # To load completions for each session, execute once:
  $ dotsecenv completion fish > ~/.config/fish/completions/dotsecenv.fish
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish"},
	Args:                  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			_ = cmd.Help()
			return
		}
		switch args[0] {
		case "bash":
			_ = cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			_ = cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			_ = cmd.Root().GenFishCompletion(os.Stdout, true)
		default:
			_ = cmd.Help()
		}
	},
}
