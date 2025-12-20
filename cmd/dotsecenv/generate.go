//go:build gendocs

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra/doc"
)

func main() {
	outputDir := "man/man1"
	format := "man"

	for i, arg := range os.Args {
		if arg == "-o" && i+1 < len(os.Args) {
			outputDir = os.Args[i+1]
		}
		if arg == "markdown" {
			format = "markdown"
		}
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create output directory: %v\n", err)
		os.Exit(1)
	}

	switch format {
	case "man":
		header := &doc.GenManHeader{
			Title:   "DOTSECENV",
			Section: "1",
			Source:  "dotsecenv " + version,
		}
		if err := doc.GenManTree(rootCmd, header, outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate man pages: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Man pages generated in: %s\n", outputDir)

	case "markdown":
		if err := doc.GenMarkdownTree(rootCmd, outputDir); err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate markdown: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Markdown docs generated in: %s\n", outputDir)
	}
}
