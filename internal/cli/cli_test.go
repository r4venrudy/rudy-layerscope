package cli

import (
	"bytes"
	"encoding/json"
	"github.com/r4venrudy/rudy-layerscope/internal/demo"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIContracts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixtures")
	if e := demo.Create(root); e != nil {
		t.Fatal(e)
	}
	leaky := filepath.Join(root, "leaky")
	clean := filepath.Join(root, "clean")
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"help", nil, 0}, {"version", []string{"--version"}, 0}, {"unknown", []string{"bogus"}, 2},
		{"scan", []string{"scan", leaky}, 0}, {"clean-gate", []string{"scan", "--fail-on", "warning", clean}, 0},
		{"warning-gate", []string{"scan", "--fail-on", "warning", leaky}, 1}, {"error-gate", []string{"scan", "--fail-on", "error", leaky}, 1},
		{"json", []string{"scan", "--format", "json", leaky}, 0}, {"sarif", []string{"scan", "--format", "sarif", leaky}, 0}, {"html", []string{"scan", "--format", "html", leaky}, 0},
		{"history", []string{"history", "--path", "app/.env", leaky}, 0}, {"history-json", []string{"history", "--path", "app/.env", "--format", "json", leaky}, 0},
		{"diff", []string{"diff", leaky, clean}, 0}, {"diff-json", []string{"diff", "--format", "json", leaky, clean}, 0}, {"change-gate", []string{"diff", "--fail-on", "change", leaky, clean}, 1},
		{"finding-gate", []string{"diff", "--fail-on", "finding", clean, leaky}, 1}, {"no-new-finding", []string{"diff", "--fail-on", "finding", leaky, clean}, 0},
		{"missing", []string{"scan", filepath.Join(root, "missing")}, 2}, {"wrong-format", []string{"scan", "--format", "bogus", leaky}, 2},
		{"wrong-gate", []string{"scan", "--fail-on", "change", leaky}, 2}, {"history-gate", []string{"history", "--path", "x", "--fail-on", "error", leaky}, 2},
		{"history-missing-path", []string{"history", leaky}, 2}, {"history-traversal", []string{"history", "--path", "../evil", leaky}, 2},
		{"diff-format", []string{"diff", "--format", "sarif", clean, leaky}, 2}, {"diff-gate-invalid", []string{"diff", "--fail-on", "error", clean, leaky}, 2},
		{"flags-after-path", []string{"scan", leaky, "--format", "json"}, 2}, {"zero-limit", []string{"scan", "--max-entries", "0", leaky}, 2},
		{"overflow-limit", []string{"scan", "--max-expanded-mib", "999999999999", leaky}, 2}, {"negative-limit", []string{"scan", "--max-blob-mib", "-1", leaky}, 2},
		{"demo-args", []string{"demo"}, 2}, {"demo-existing", []string{"demo", root}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, err bytes.Buffer
			if got := Run(c.args, &out, &err); got != c.code {
				t.Fatalf("exit %d want %d stderr %s", got, c.code, &err)
			}
			if c.code == 2 || c.code == 3 {
				if out.Len() != 0 {
					t.Fatal("partial success output on error")
				}
			}
			if c.name == "json" || c.name == "sarif" || c.name == "diff-json" || c.name == "history-json" {
				if !json.Valid(out.Bytes()) {
					t.Fatal("invalid JSON")
				}
			}
		})
	}
}
func TestOutputNeverOverwrites(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixtures")
	if e := demo.Create(root); e != nil {
		t.Fatal(e)
	}
	report := filepath.Join(t.TempDir(), "report.json")
	var out, err bytes.Buffer
	args := []string{"scan", "--format", "json", "--output", report, filepath.Join(root, "leaky")}
	if code := Run(args, &out, &err); code != 0 {
		t.Fatal(code, &err)
	}
	before, e := os.ReadFile(report)
	if e != nil {
		t.Fatal(e)
	}
	if code := Run(args, &out, &err); code != 3 {
		t.Fatal("overwrote report")
	}
	after, e := os.ReadFile(report)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("report changed")
	}
	args[4] = filepath.Join(root, "leaky", "index.json")
	if code := Run(args, &out, &err); code != 3 {
		t.Fatal("overwrote input")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrPermission }
func TestOutputWriterFailure(t *testing.T) {
	root := filepath.Join(t.TempDir(), "fixtures")
	if e := demo.Create(root); e != nil {
		t.Fatal(e)
	}
	var err bytes.Buffer
	if got := Run([]string{"scan", filepath.Join(root, "leaky")}, failWriter{}, &err); got != 3 {
		t.Fatal(got)
	}
}
