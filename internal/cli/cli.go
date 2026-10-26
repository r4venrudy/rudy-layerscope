package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	ls "github.com/r4venrudy/rudy-layerscope"
	"github.com/r4venrudy/rudy-layerscope/internal/demo"
)

const help = `Rudy LayerScope — offline Linux OCI layer forensics

  layerscope scan [options] LAYOUT
  layerscope history --path RELATIVE_PATH [options] LAYOUT
  layerscope diff [options] BEFORE_LAYOUT AFTER_LAYOUT
  layerscope demo NEW_DIRECTORY
  layerscope version

Options precede positional paths. scan formats: text, json, sarif, html.
history/diff formats: text, json. Reports never overwrite existing files.
No daemon, registry access, extraction, payload execution or real credentials.
`

// Run is independently testable and never calls os.Exit.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, help)
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(stdout, "Rudy LayerScope "+ls.Version)
		return 0
	}
	if args[0] == "demo" {
		if len(args) != 2 {
			fmt.Fprintln(stderr, "demo requires one new directory")
			return 2
		}
		if err := demo.Create(args[1]); err != nil {
			fmt.Fprintln(stderr, err)
			return 3
		}
		fmt.Fprintln(stdout, "Created synthetic OCI fixtures: leaky/ and clean/")
		return 0
	}
	command := args[0]
	if command != "scan" && command != "history" && command != "diff" {
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "report format")
	output := fs.String("output", "", "new output file; default stdout")
	ref := fs.String("ref", "", "top-level org.opencontainers.image.ref.name")
	platform := fs.String("platform", "", "exact os/architecture[/variant]")
	filePath := fs.String("path", "", "exact relative path for history")
	failOn := fs.String("fail-on", "none", "scan: none|warning|error; diff: none|change|finding")
	limits := ls.DefaultLimits()
	blobMiB := fs.Int64("max-blob-mib", limits.BlobBytes>>20, "compressed bytes per layer, MiB")
	expandedMiB := fs.Int64("max-expanded-mib", limits.ExpandedBytes>>20, "total expanded layer bytes, MiB")
	maxEntries := fs.Int("max-entries", limits.Entries, "total archive entries and final entries")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	want := 1
	if command == "diff" {
		want = 2
	}
	if fs.NArg() != want {
		fmt.Fprintln(stderr, "wrong number of paths; options must precede paths")
		return 2
	}
	if command == "scan" {
		if *format != "text" && *format != "json" && *format != "sarif" && *format != "html" {
			fmt.Fprintln(stderr, "unsupported scan format")
			return 2
		}
		if *failOn != "none" && *failOn != "warning" && *failOn != "error" {
			fmt.Fprintln(stderr, "invalid scan gate")
			return 2
		}
	} else {
		if *format != "text" && *format != "json" {
			fmt.Fprintln(stderr, "this command supports text/json")
			return 2
		}
		if command == "diff" {
			if *failOn != "none" && *failOn != "change" && *failOn != "finding" {
				fmt.Fprintln(stderr, "invalid diff gate")
				return 2
			}
		} else if *failOn != "none" || *filePath == "" {
			fmt.Fprintln(stderr, "history requires --path and has no gate")
			return 2
		}
	}
	if *blobMiB <= 0 || *blobMiB > 8192 || *expandedMiB <= 0 || *expandedMiB > 65536 {
		fmt.Fprintln(stderr, "invalid MiB limits")
		return 2
	}
	limits.BlobBytes = *blobMiB << 20
	limits.ExpandedBytes = *expandedMiB << 20
	limits.Entries = *maxEntries
	opts := ls.Options{Ref: *ref, Platform: *platform, Limits: limits}
	r, err := ls.Analyze(fs.Arg(0), opts)
	if err != nil {
		fmt.Fprintln(stderr, "analysis failed:", err)
		return 2
	}
	var data []byte
	gate := false
	switch command {
	case "scan":
		switch *format {
		case "text":
			data = ls.Text(r)
		case "json":
			data, err = ls.JSON(r)
		case "sarif":
			data, err = ls.SARIF(r)
		case "html":
			data, err = ls.HTML(r)
		}
		for _, f := range r.Findings {
			if *failOn == "warning" || (*failOn == "error" && f.Level == "error") {
				gate = true
			}
		}
	case "history":
		p, e := ls.NormalizePath(*filePath)
		if e != nil {
			fmt.Fprintln(stderr, e)
			return 2
		}
		entries := []ls.Entry{}
		for _, e := range r.History {
			if e.Path == p {
				entries = append(entries, e)
			}
		}
		if *format == "json" {
			data, err = ls.JSON(entries)
		} else {
			var b strings.Builder
			fmt.Fprintf(&b, "History for %q: %d revisions\n", p, len(entries))
			for _, e := range entries {
				state := "final"
				if e.RemovedBy != nil {
					state = fmt.Sprintf("%s at layer %d", e.Removal, *e.RemovedBy)
				}
				fmt.Fprintf(&b, "L%d revision=%d kind=%s mode=%04o bytes=%d %s\n  %s\n", e.Layer, e.Revision, e.Kind, e.Mode, e.Size, state, e.Digest)
			}
			data = []byte(b.String())
		}
	case "diff":
		other, e := ls.Analyze(fs.Arg(1), opts)
		if e != nil {
			fmt.Fprintln(stderr, "candidate analysis failed:", e)
			return 2
		}
		if r.Platform != other.Platform {
			fmt.Fprintln(stderr, "cannot compare different platforms")
			return 2
		}
		d := ls.Compare(r, other)
		if *format == "json" {
			data, err = ls.JSON(d)
		} else {
			data = ls.DeltaText(d)
		}
		gate = (*failOn == "change" && len(d.Changes) > 0) || (*failOn == "finding" && len(d.AddedFindings) > 0)
	}
	if err != nil {
		fmt.Fprintln(stderr, "report failed:", err)
		return 3
	}
	if *output == "" {
		_, err = stdout.Write(data)
	} else {
		var f *os.File
		f, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, err = f.Write(data)
			closeErr := f.Close()
			if err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "output failed:", err)
		return 3
	}
	if gate {
		return 1
	}
	return 0
}
