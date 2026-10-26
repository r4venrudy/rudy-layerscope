package layerscope

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type testItem struct {
	name, body string
	mode       int64
	kind       byte
	link       string
	pax        map[string]string
}

func regular(name, body string) testItem {
	return testItem{name: name, body: body, mode: 0644, kind: tar.TypeReg}
}
func dir(name string) testItem { return testItem{name: name, mode: 0755, kind: tar.TypeDir} }
func link(name, target string, kind byte) testItem {
	return testItem{name: name, mode: 0777, kind: kind, link: target}
}
func tarData(t *testing.T, items []testItem) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, i := range items {
		h := &tar.Header{Name: i.name, Mode: i.mode, Typeflag: i.kind, Linkname: i.link, Size: int64(len(i.body)), PAXRecords: i.pax, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(i.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func putBlob(t *testing.T, root, media string, b []byte) Descriptor {
	t.Helper()
	d := Descriptor{MediaType: media, Digest: digestBytes(b), Size: int64(len(b))}
	name, _ := digestName(d.Digest)
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), b, 0644); err != nil {
		t.Fatal(err)
	}
	return d
}
func putJSON(t *testing.T, root, media string, v any) Descriptor {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return putBlob(t, root, media, b)
}
func writeIndex(t *testing.T, root string, descs ...Descriptor) {
	t.Helper()
	b, e := json.Marshal(index{SchemaVersion: 2, MediaType: MediaIndex, Manifests: descs})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "index.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
}
func imageRaw(t *testing.T, raw [][]byte, compressed bool, change func(*manifest, *imageConfig)) string {
	t.Helper()
	root := t.TempDir()
	if e := os.MkdirAll(filepath.Join(root, "blobs", "sha256"), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0644); e != nil {
		t.Fatal(e)
	}
	c := imageConfig{Platform: Platform{OS: "linux", Architecture: "amd64"}}
	c.RootFS.Type = "layers"
	c.Config.User = "10001"
	c.Config.Env = []string{"PATH=/bin"}
	m := manifest{SchemaVersion: 2, MediaType: MediaManifest, Layers: []Descriptor{}}
	for _, b := range raw {
		c.RootFS.DiffIDs = append(c.RootFS.DiffIDs, digestBytes(b))
		payload := b
		media := MediaTar
		if compressed {
			var gzbytes bytes.Buffer
			gz := gzip.NewWriter(&gzbytes)
			if _, e := gz.Write(b); e != nil {
				t.Fatal(e)
			}
			if e := gz.Close(); e != nil {
				t.Fatal(e)
			}
			payload = gzbytes.Bytes()
			media = MediaGzip
		}
		m.Layers = append(m.Layers, putBlob(t, root, media, payload))
	}
	if change != nil {
		change(&m, &c)
	}
	m.Config = putJSON(t, root, MediaConfig, c)
	desc := putJSON(t, root, MediaManifest, m)
	desc.Platform = &c.Platform
	desc.Annotations = map[string]string{"org.opencontainers.image.ref.name": "fixture"}
	writeIndex(t, root, desc)
	return root
}
func image(t *testing.T, layers ...[]testItem) string {
	t.Helper()
	raw := [][]byte{}
	for _, items := range layers {
		raw = append(raw, tarData(t, items))
	}
	return imageRaw(t, raw, true, nil)
}
func analyze(t *testing.T, root string) *Report {
	t.Helper()
	r, e := Analyze(root, Options{})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func files(r *Report) map[string]Entry {
	m := map[string]Entry{}
	for _, e := range r.Files {
		m[e.Path] = e
	}
	return m
}
func mustFail(t *testing.T, root string, opts Options, needle string) {
	t.Helper()
	r, e := Analyze(root, opts)
	if e == nil || r != nil {
		t.Fatalf("expected failure, got report=%v err=%v", r, e)
	}
	if !strings.Contains(e.Error(), needle) {
		t.Fatalf("error %q lacks %q", e, needle)
	}
}
func loadManifest(t *testing.T, root string) (index, manifest, imageConfig) {
	t.Helper()
	var i index
	var m manifest
	var c imageConfig
	b, e := os.ReadFile(filepath.Join(root, "index.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &i); e != nil {
		t.Fatal(e)
	}
	name, _ := digestName(i.Manifests[0].Digest)
	b, e = os.ReadFile(filepath.Join(root, name))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	name, _ = digestName(m.Config.Digest)
	b, e = os.ReadFile(filepath.Join(root, name))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	return i, m, c
}

func TestWhiteoutsOnlyAffectLowerLayers(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			add := regular("a/x", "new")
			wh := regular("a/.wh.x", "")
			items := []testItem{wh, add}
			if after {
				items = []testItem{add, wh}
			}
			r := analyze(t, image(t, []testItem{regular("a/x", "old")}, items))
			if files(r)["a/x"].Digest != digestBytes([]byte("new")) {
				t.Fatal("new content hidden by same-layer whiteout")
			}
			if r.History[0].Removal != "whiteout" {
				t.Fatal("missing deletion evidence")
			}
		})
	}
}
func TestOpaqueWhiteoutOrder(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			wh := regular("a/.wh..wh..opq", "")
			add := regular("a/b/new", "new")
			items := []testItem{wh, add}
			if after {
				items = []testItem{add, wh}
			}
			r := analyze(t, image(t, []testItem{regular("a/b/old", "old"), regular("a/sibling", "old")}, items))
			f := files(r)
			if _, ok := f["a/b/old"]; ok {
				t.Fatal("opaque child survived")
			}
			if _, ok := f["a/sibling"]; ok {
				t.Fatal("opaque sibling survived")
			}
			if _, ok := f["a/b/new"]; !ok {
				t.Fatal("same layer child hidden")
			}
		})
	}
}
func TestDirectoryReplacement(t *testing.T) {
	t.Run("with-file", func(t *testing.T) {
		r := analyze(t, image(t, []testItem{regular("a/b/c", "x")}, []testItem{regular("a", "new")}))
		if len(r.Files) != 1 || r.Files[0].Kind != "file" {
			t.Fatal(r.Files)
		}
	})
	t.Run("attributes", func(t *testing.T) {
		d := dir("a")
		d.mode = 0700
		r := analyze(t, image(t, []testItem{dir("a"), regular("a/file", "x")}, []testItem{d}))
		if files(r)["a"].Mode != 0700 || files(r)["a/file"].Digest == "" {
			t.Fatal(r.Files)
		}
	})
	t.Run("root-opaque", func(t *testing.T) {
		r := analyze(t, image(t, []testItem{regular("a/b", "x"), regular("c", "x")}, []testItem{regular(".wh..wh..opq", ""), regular("new", "x")}))
		if len(r.Files) != 1 || r.Files[0].Path != "new" {
			t.Fatal(r.Files)
		}
	})
}
func TestHardlinkSnapshot(t *testing.T) {
	r := analyze(t, image(t, []testItem{regular("source", "old")}, []testItem{link("alias", "source", tar.TypeLink), regular("source", "new")}, []testItem{regular(".wh.source", "")}))
	e := files(r)["alias"]
	if e.Digest != digestBytes([]byte("old")) || e.ContentLayer != 0 || e.Layer != 1 {
		t.Fatal(e)
	}
	if _, ok := files(r)["source"]; ok {
		t.Fatal("whiteout failed")
	}
}
func TestUnsupportedLinkTraversal(t *testing.T) {
	cases := map[string][]testItem{"forward-hardlink": {link("alias", "later", tar.TypeLink), regular("later", "x")}, "missing-hardlink": {link("alias", "absent", tar.TypeLink)}, "symlink-hardlink": {link("source", "/etc", tar.TypeSymlink), link("alias", "source", tar.TypeLink)}, "symlink-parent": {link("a", "/outside", tar.TypeSymlink), regular("a/b", "x")}}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) { mustFail(t, image(t, items), Options{}, "link") })
	}
}
func TestSymlinkNeverFollowed(t *testing.T) {
	r := analyze(t, image(t, []testItem{link("outside", "../../outside", tar.TypeSymlink)}))
	if r.Files[0].Link != "../../outside" {
		t.Fatal(r.Files)
	}
	r = analyze(t, image(t, []testItem{link("a", "/outside", tar.TypeSymlink)}, []testItem{dir("a"), regular("a/b", "x")}))
	if files(r)["a/b"].Kind != "file" {
		t.Fatal(r.Files)
	}
}

func TestPathValidation(t *testing.T) {
	for _, p := range []string{"../escape", "a/../b", "/absolute", "a\\b", "x\nnew", "a\x00b", "", string([]byte{255}), strings.Repeat("x", 4097), strings.Repeat("a/", 130) + "b"} {
		t.Run(p, func(t *testing.T) {
			if _, e := NormalizePath(p); e == nil {
				t.Fatal("accepted invalid path")
			}
		})
	}
	for p, want := range map[string]string{"./a//b": "a/b", "directory/": "directory", "café/文件": "café/文件", "./": "."} {
		if got, e := NormalizePath(p); e != nil || got != want {
			t.Fatalf("%q %q %v", p, got, e)
		}
	}
}
func TestMarkersCrossBoundaries(t *testing.T) {
	for _, marker := range privateHeaders {
		m := &markerHash{}
		for _, b := range marker {
			if _, e := m.Write([]byte{b}); e != nil {
				t.Fatal(e)
			}
		}
		if !m.found {
			t.Fatal(string(marker))
		}
	}
	r := analyze(t, image(t, []testItem{regular("payload", strings.Repeat("x", 32760)+string(privateHeaders[0])+"NOT_A_REAL_KEY")}))
	if len(r.Findings) != 1 || r.Findings[0].Rule != "LS001" {
		t.Fatal(r.Findings)
	}
}
func TestIntegrityFailures(t *testing.T) {
	t.Run("blob", func(t *testing.T) {
		root := image(t, []testItem{regular("a", "x")})
		_, m, _ := loadManifest(t, root)
		name, _ := digestName(m.Layers[0].Digest)
		p := filepath.Join(root, name)
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		b[len(b)/2] ^= 1
		if e = os.WriteFile(p, b, 0644); e != nil {
			t.Fatal(e)
		}
		mustFail(t, root, Options{}, "digest mismatch")
	})
	t.Run("diff-id", func(t *testing.T) {
		root := imageRaw(t, [][]byte{tarData(t, []testItem{regular("a", "x")})}, true, func(m *manifest, c *imageConfig) { c.RootFS.DiffIDs[0] = digestBytes([]byte("wrong")) })
		mustFail(t, root, Options{}, "diff_id mismatch")
	})
	t.Run("size", func(t *testing.T) {
		root := imageRaw(t, [][]byte{tarData(t, []testItem{regular("a", "x")})}, true, func(m *manifest, c *imageConfig) { m.Layers[0].Size++ })
		mustFail(t, root, Options{}, "size mismatch")
	})
	for _, field := range []string{"config", "manifest"} {
		t.Run(field, func(t *testing.T) {
			root := image(t, []testItem{regular("a", "x")})
			i, m, _ := loadManifest(t, root)
			d := m.Config
			if field == "manifest" {
				d = i.Manifests[0]
			}
			name, _ := digestName(d.Digest)
			p := filepath.Join(root, name)
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			b[0] = ' '
			if e = os.WriteFile(p, b, 0644); e != nil {
				t.Fatal(e)
			}
			mustFail(t, root, Options{}, "integrity mismatch")
		})
	}
}
func TestArchiveFailures(t *testing.T) {
	cases := map[string][]testItem{"path": {regular("../evil", "x")}, "duplicate": {regular("a", "x"), regular("./a", "y")}, "whiteout-body": {regular(".wh.a", "x")}, "whiteout-target": {regular(".wh..", "")}, "whiteout-dir": {{name: ".wh.a", mode: 0755, kind: tar.TypeDir}}, "file-parent": {regular("a", "x"), regular("a/b", "y")}}
	for name, items := range cases {
		t.Run(name, func(t *testing.T) { mustFail(t, image(t, items), Options{}, "") })
	}
	t.Run("trailing", func(t *testing.T) {
		raw := append(tarData(t, []testItem{regular("a", "x")}), []byte("HIDDEN SECOND ARCHIVE")...)
		mustFail(t, imageRaw(t, [][]byte{raw}, false, nil), Options{}, "after tar")
	})
	t.Run("zstd", func(t *testing.T) {
		root := imageRaw(t, [][]byte{tarData(t, nil)}, false, func(m *manifest, c *imageConfig) {
			m.Layers[0].MediaType = "application/vnd.oci.image.layer.v1.tar+zstd"
		})
		mustFail(t, root, Options{}, "unsupported layer")
	})
	t.Run("truncated", func(t *testing.T) {
		mustFail(t, imageRaw(t, [][]byte{tarData(t, []testItem{regular("a", strings.Repeat("x", 1024))})[:700]}, false, nil), Options{}, "EOF")
	})
}

func TestLimits(t *testing.T) {
	for _, which := range []string{"blob", "expanded", "entries", "metadata", "descriptors", "layers", "invalid"} {
		t.Run(which, func(t *testing.T) {
			root := image(t, []testItem{regular("a", "payload")}, []testItem{regular("b", "next")})
			l := DefaultLimits()
			switch which {
			case "blob":
				l.BlobBytes = 1
			case "expanded":
				l.ExpandedBytes = 10
			case "entries":
				l.Entries = 1
			case "metadata":
				l.MetadataBytes = 3
			case "descriptors":
				l.Descriptors = 1
			case "layers":
				l.Layers = 1
			case "invalid":
				l.Entries = 0
			}
			mustFail(t, root, Options{Limits: l}, "")
		})
	}
}
func TestDuplicateJSONKeys(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":{"x":1,"x":2}}`, `{} {}`, `[1,2] false`, string([]byte{'{', '"', 255, '"', ':', '1', '}'})} {
		var out any
		if e := decodeJSON([]byte(raw), &out); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	var out any
	if e := decodeJSON([]byte(`{"a":[1,true,null,{"b":"ok"}]}`), &out); e != nil {
		t.Fatal(e)
	}
}
func TestSelection(t *testing.T) {
	t.Run("nested-ref", func(t *testing.T) {
		root := image(t, []testItem{regular("a", "x")})
		i, _, _ := loadManifest(t, root)
		nested := putJSON(t, root, MediaIndex, i)
		nested.Annotations = map[string]string{"org.opencontainers.image.ref.name": "outer"}
		writeIndex(t, root, nested)
		if _, e := Analyze(root, Options{Ref: "outer", Platform: "linux/amd64"}); e != nil {
			t.Fatal(e)
		}
		mustFail(t, root, Options{Ref: "wrong"}, "found 0")
	})
	t.Run("platform-mismatch", func(t *testing.T) {
		root := image(t, []testItem{regular("a", "x")})
		i, _, _ := loadManifest(t, root)
		i.Manifests[0].Platform.Architecture = "arm64"
		writeIndex(t, root, i.Manifests...)
		mustFail(t, root, Options{}, "disagrees")
	})
	t.Run("ambiguous-platform", func(t *testing.T) {
		root := image(t, []testItem{regular("a", "x")})
		i, m, c := loadManifest(t, root)
		c.Architecture = "arm64"
		m.Config = putJSON(t, root, MediaConfig, c)
		arm := putJSON(t, root, MediaManifest, m)
		arm.Platform = &c.Platform
		writeIndex(t, root, i.Manifests[0], arm)
		mustFail(t, root, Options{}, "found 2")
		r, e := Analyze(root, Options{Platform: "linux/arm64"})
		if e != nil || r.Platform.Architecture != "arm64" {
			t.Fatal(r, e)
		}
	})
	t.Run("duplicate-tags", func(t *testing.T) {
		root := image(t, []testItem{regular("a", "x")})
		i, _, _ := loadManifest(t, root)
		writeIndex(t, root, i.Manifests[0], i.Manifests[0])
		analyze(t, root)
	})
	t.Run("index-depth", func(t *testing.T) {
		root := image(t, nil)
		i, _, _ := loadManifest(t, root)
		for range 10 {
			d := putJSON(t, root, MediaIndex, i)
			i = index{SchemaVersion: 2, MediaType: MediaIndex, Manifests: []Descriptor{d}}
		}
		writeIndex(t, root, i.Manifests...)
		mustFail(t, root, Options{}, "nesting")
	})
	t.Run("unknown-descriptor", func(t *testing.T) {
		root := image(t, []testItem{regular("a", "x")})
		i, _, _ := loadManifest(t, root)
		writeIndex(t, root, Descriptor{MediaType: "example/future"}, i.Manifests[0])
		analyze(t, root)
	})
}

func TestRulesAndRedactedFormats(t *testing.T) {
	key := regular("<script>alert(1)</script>", string(privateHeaders[0])+"NEVER_EXPORT_FILE_BODY")
	priv := regular("bin/priv", "x")
	priv.mode = 04777
	priv.pax = map[string]string{"SCHILY.xattr.security.capability": "test-presence-only"}
	device := testItem{name: "dev/example", kind: tar.TypeChar, mode: 0600}
	tmp := dir("badtmp")
	tmp.mode = 0777
	root := imageRaw(t, [][]byte{tarData(t, []testItem{key, priv, device, tmp, regular("app/.env", "NEVER_EXPORT_ENV_FILE")})}, true, func(m *manifest, c *imageConfig) {
		c.Config.User = "root"
		c.Config.Env = []string{"TOKEN=NEVER_EXPORT_ENV_VALUE"}
	})
	r := analyze(t, root)
	rules := map[string]bool{}
	for _, f := range r.Findings {
		rules[f.Rule] = true
	}
	if len(rules) != 8 {
		t.Fatal(rules)
	}
	formats := [][]byte{Text(r)}
	for _, fn := range []func(*Report) ([]byte, error){func(r *Report) ([]byte, error) { return JSON(r) }, HTML, SARIF} {
		b, e := fn(r)
		if e != nil {
			t.Fatal(e)
		}
		formats = append(formats, b)
	}
	for _, b := range formats {
		for _, value := range []string{"NEVER_EXPORT_FILE_BODY", "NEVER_EXPORT_ENV_FILE", "NEVER_EXPORT_ENV_VALUE"} {
			if bytes.Contains(b, []byte(value)) {
				t.Fatal("content leaked")
			}
		}
	}
	html, e := HTML(r)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(html, []byte("<script>alert(1)</script>")) {
		t.Fatal("HTML injection")
	}
}
func TestRestoredContentNotMarkedHidden(t *testing.T) {
	r := analyze(t, image(t, []testItem{regular(".env", "same")}, []testItem{regular(".env", "changed")}, []testItem{regular(".env", "same")}))
	for _, f := range r.Findings {
		if f.Fingerprint == digestBytes([]byte("LS002\x00.env\x00"+digestBytes([]byte("same")))) && f.Hidden {
			t.Fatal("restored content reported hidden")
		}
	}
}
func TestDeterminismAndDiff(t *testing.T) {
	a := analyze(t, image(t, []testItem{regular("a", "one"), regular("b", "same")}))
	b := analyze(t, image(t, []testItem{regular("b", "same"), regular("a", "one")}))
	if len(Compare(a, b).Changes) != 0 {
		t.Fatal("tar order affects diff")
	}
	c := analyze(t, image(t, []testItem{regular("a", "two"), regular("c", "new"), regular(".env", "sensitive-path")}))
	d := Compare(a, c)
	if len(d.Changes) != 4 || len(d.AddedFindings) != 1 {
		t.Fatal(d)
	}
	if len(Compare(c, a).RemovedFindings) != 1 {
		t.Fatal("finding removal absent")
	}
	one, _ := JSON(a)
	two, _ := JSON(a)
	if !bytes.Equal(one, two) {
		t.Fatal("nondeterminism")
	}
}
func TestConcurrentAnalysis(t *testing.T) {
	root := image(t, []testItem{regular("a", "x")})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, e := Analyze(root, Options{}); e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
}

func TestExpandedBudgetStaysFailed(t *testing.T) {
	r := reader{limits: DefaultLimits()}
	r.limits.ExpandedBytes = 1
	b := expandedReader{r: strings.NewReader("abcd"), owner: &r}
	buf := make([]byte, 2)
	if _, e := b.Read(buf); e == nil {
		t.Fatal("overflow accepted")
	}
	if _, e := b.Read(buf); e == nil {
		t.Fatal("overflow state resumed reading")
	}
}
func TestInvalidConfigAndDigest(t *testing.T) {
	for _, d := range []string{"../x", "sha256:ABC", "sha512:" + strings.Repeat("0", 128), "sha256:" + strings.Repeat("g", 64)} {
		if _, e := digestName(d); e == nil {
			t.Fatal(d)
		}
	}
	root := imageRaw(t, nil, false, func(m *manifest, c *imageConfig) { c.Config.Env = []string{"MALFORMED_WITHOUT_EQUALS"} })
	mustFail(t, root, Options{}, "environment")
}
func TestOuterSymlinkEscape(t *testing.T) {
	root := image(t, nil)
	outside := filepath.Join(t.TempDir(), "outside.json")
	if e := os.WriteFile(outside, []byte(`{}`), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(root, "index.json")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(root, "index.json")); e != nil {
		t.Skip("symlink creation not allowed:", e)
	}
	mustFail(t, root, Options{}, "regular file")
}

func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{"./a", "../evil", ".wh..wh..opq", "a/b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, e := NormalizePath(s)
		if e == nil {
			again, e := NormalizePath(p)
			if e != nil || again != p {
				t.Fatalf("not idempotent %q", p)
			}
		}
	})
}
func FuzzJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":[1,2]}`, `{"a":1,"a":2}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			t.Skip()
		}
		var out any
		_ = decodeJSON(b, &out)
	})
}
