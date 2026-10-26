package main

import (
	"github.com/r4venrudy/rudy-layerscope/internal/cli"
	"os"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr)) }
