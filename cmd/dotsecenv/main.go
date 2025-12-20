//go:build !gendocs

package main

import (
	"fmt"
	"os"

	clilib "github.com/dotsecenv/dotsecenv/internal/cli"
)

// main runs the CLI
func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		_ = rootCmd.Help()
		os.Exit(int(clilib.ExitGeneralError))
	}
}
