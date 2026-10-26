//go:build ignore

// Run from the repository root: go run scripts/package.go --out artifacts/release
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	ls "github.com/r4venrudy/rudy-layerscope"
	"github.com/r4venrudy/rudy-layerscope/internal/demo"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", "artifacts/release", "new release output files")
	flag.Parse()
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	tmp, err := os.MkdirTemp("", "layerscope-package-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	binary := "layerscope"
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	program := filepath.Join(tmp, binary)
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", program, "./cmd/layerscope")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err = build.Run(); err != nil {
		return err
	}
	fixtures := filepath.Join(tmp, "demo")
	if err = demo.Create(fixtures); err != nil {
		return err
	}
	// Smoke the exact native binary which will be archived.
	smoke := exec.Command(program, "scan", "--format", "json", filepath.Join(fixtures, "leaky"))
	b, err := smoke.Output()
	if err != nil {
		return err
	}
	var parsed ls.Report
	if err = json.Unmarshal(b, &parsed); err != nil {
		return err
	}
	if !parsed.IntegrityVerified || len(parsed.Findings) != 6 {
		return fmt.Errorf("packaged binary smoke failed")
	}
	html, err := ls.HTML(&parsed)
	if err != nil {
		return err
	}
	files := map[string][]byte{"examples/investigation.html": html, "BUILDINFO.txt": []byte(fmt.Sprintf("Rudy LayerScope %s\nToolchain: %s\nTarget: %s/%s\nCGO_ENABLED=0\ngo build -trimpath -buildvcs=false -ldflags=-s -w\n", ls.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH))}
	files[binary], err = os.ReadFile(program)
	if err != nil {
		return err
	}
	for _, name := range []string{"README.md", "LICENSE", "docs/CONTRACT.md", "docs/RULES.md", "docs/RELEASE_NOTES.md", "assets/banner.svg"} {
		files[name], err = os.ReadFile(filepath.FromSlash(name))
		if err != nil {
			return err
		}
	}
	if err = filepath.WalkDir(fixtures, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(fixtures, p)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return e
		}
		files["examples/demo/"+filepath.ToSlash(rel)] = b
		return nil
	}); err != nil {
		return err
	}
	var zipBytes bytes.Buffer
	zw := zip.NewWriter(&zipBytes)
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		h.SetMode(0644)
		if name == binary {
			h.SetMode(0755)
		}
		w, e := zw.CreateHeader(h)
		if e != nil {
			return e
		}
		if _, e = w.Write(files[name]); e != nil {
			return e
		}
	}
	if err = zw.Close(); err != nil {
		return err
	}
	if err = os.MkdirAll(*out, 0755); err != nil {
		return err
	}
	name := fmt.Sprintf("rudy-layerscope_%s_%s_%s.zip", ls.Version, runtime.GOOS, runtime.GOARCH)
	writeNew := func(name string, b []byte) error {
		f, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		c := f.Close()
		if e != nil {
			return e
		}
		return c
	}
	if err = writeNew(filepath.Join(*out, name), zipBytes.Bytes()); err != nil {
		return err
	}
	sum := sha256.Sum256(zipBytes.Bytes())
	checksum := fmt.Sprintf("%x  %s\n", sum, name)
	if err = writeNew(filepath.Join(*out, strings.TrimSuffix(name, ".zip")+".sha256"), []byte(checksum)); err != nil {
		return err
	}
	fmt.Print(checksum)
	return nil
}
