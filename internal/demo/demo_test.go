package demo

import (
	ls "github.com/r4venrudy/rudy-layerscope"
	"path/filepath"
	"testing"
)

func TestDemoExpectedFindings(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if e := Create(root); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"leaky", "clean"} {
		r, e := ls.Analyze(filepath.Join(root, name), ls.Options{})
		if e != nil {
			t.Fatal(e)
		}
		want := 0
		if name == "leaky" {
			want = 6
		}
		if len(r.Findings) != want {
			t.Fatalf("%s findings %d want %d", name, len(r.Findings), want)
		}
		if len(r.Layers) != 2 {
			t.Fatal("expected two verified layers")
		}
	}
	if e := Create(root); e == nil {
		t.Fatal("existing directory accepted")
	}
}
