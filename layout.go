package layerscope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

func digestBytes(b []byte) string { v := sha256.Sum256(b); return fmt.Sprintf("sha256:%x", v) }

func digestName(d string) (string, error) {
	if !strings.HasPrefix(d, "sha256:") || len(d) != 71 || strings.ToLower(d) != d {
		return "", errors.New("only lowercase sha256 digests are supported")
	}
	if _, err := hex.DecodeString(d[7:]); err != nil {
		return "", errors.New("invalid digest")
	}
	return "blobs/sha256/" + d[7:], nil
}

type reader struct {
	root        *os.Root
	limits      Limits
	metadata    int64
	descriptors int
	expanded    int64
	entries     int
}

func (r *reader) open(name string) (*os.File, error) {
	info, err := r.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("layout member %q must be a regular file", name)
	}
	f, err := r.root.Open(name)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("layout member %q changed or is not regular", name)
	}
	return f, nil
}

func (r *reader) jsonFile(name string, d *Descriptor, out any) ([]byte, error) {
	f, err := r.open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cap := min(int64(4<<20), r.limits.MetadataBytes-r.metadata)
	if cap <= 0 {
		return nil, errors.New("metadata budget exceeded")
	}
	b, err := io.ReadAll(io.LimitReader(f, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > cap {
		return nil, errors.New("metadata budget exceeded (4 MiB per JSON document)")
	}
	r.metadata += int64(len(b))
	if d != nil && (int64(len(b)) != d.Size || digestBytes(b) != d.Digest) {
		return nil, fmt.Errorf("descriptor integrity mismatch: %s", d.Digest)
	}
	if err = decodeJSON(b, out); err != nil {
		return nil, fmt.Errorf("invalid OCI JSON %q: %w", name, err)
	}
	return b, nil
}

// Reject duplicate object keys instead of accepting encoding/json's last value.
func decodeJSON(b []byte, out any) error {
	if !utf8.Valid(b) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("JSON nesting exceeds 64")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		v, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch v {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || keys[s] {
					return errors.New("duplicate JSON object key")
				}
				keys[s] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return json.Unmarshal(b, out)
}

func (r *reader) descriptorJSON(d Descriptor, out any) error {
	r.descriptors++
	if r.descriptors > r.limits.Descriptors {
		return errors.New("descriptor budget exceeded")
	}
	name, err := digestName(d.Digest)
	if err != nil {
		return err
	}
	if d.Size < 0 {
		return errors.New("negative descriptor size")
	}
	_, err = r.jsonFile(name, &d, out)
	return err
}

type selected struct {
	desc     Descriptor
	manifest manifest
	config   imageConfig
}

func (r *reader) selectImage(idx index, opts Options) (selected, error) {
	var candidates []selected
	var visit func(index, int, string, *Platform) error
	visit = func(idx index, depth int, inheritedRef string, inheritedPlatform *Platform) error {
		if depth > 8 {
			return errors.New("index nesting exceeds eight")
		}
		if idx.SchemaVersion != 2 || (idx.MediaType != "" && idx.MediaType != MediaIndex) {
			return errors.New("unsupported image index")
		}
		for _, d := range idx.Manifests {
			ref := inheritedRef
			if value := d.Annotations["org.opencontainers.image.ref.name"]; value != "" {
				ref = value
			}
			if depth == 0 && opts.Ref != "" && ref != opts.Ref {
				continue
			}
			p := inheritedPlatform
			if d.Platform != nil {
				p = d.Platform
			}
			switch d.MediaType {
			case MediaIndex:
				var child index
				if err := r.descriptorJSON(d, &child); err != nil {
					return err
				}
				if err := visit(child, depth+1, ref, p); err != nil {
					return err
				}
			case MediaManifest:
				var m manifest
				if err := r.descriptorJSON(d, &m); err != nil {
					return err
				}
				if m.SchemaVersion != 2 || (m.MediaType != "" && m.MediaType != MediaManifest) {
					return errors.New("unsupported manifest")
				}
				if m.ArtifactType != "" || m.Config.MediaType != MediaConfig {
					continue
				}
				var c imageConfig
				if err := r.descriptorJSON(m.Config, &c); err != nil {
					return err
				}
				if p != nil && (p.OS != c.OS || p.Architecture != c.Architecture || (p.Variant != "" && p.Variant != c.Variant)) {
					return errors.New("descriptor platform disagrees with config")
				}
				if opts.Platform != "" && c.Platform.String() != opts.Platform {
					continue
				}
				if c.OS == "linux" {
					candidates = append(candidates, selected{d, m, c})
				}
			default: // Unknown artifact descriptors are outside image selection.
			}
		}
		return nil
	}
	if err := visit(idx, 0, "", nil); err != nil {
		return selected{}, err
	}
	// Identical content referenced by multiple tags is one image candidate.
	unique := map[string]selected{}
	for _, c := range candidates {
		unique[c.desc.Digest] = c
	}
	if len(unique) != 1 {
		return selected{}, fmt.Errorf("expected one Linux image, found %d; select --ref and/or --platform", len(unique))
	}
	for _, c := range unique {
		return c, nil
	}
	panic("unreachable")
}

// Analyze opens a stable, local OCI layout. It emits no partial success on any
// integrity, unsupported-layer, ambiguous-filesystem, or resource-limit failure.
func Analyze(directory string, opts Options) (*Report, error) {
	if opts.Limits == (Limits{}) {
		opts.Limits = DefaultLimits()
	}
	l := opts.Limits
	if l.BlobBytes <= 0 || l.BlobBytes > 8<<30 || l.ExpandedBytes <= 0 || l.ExpandedBytes > 64<<30 || l.MetadataBytes <= 0 || l.MetadataBytes > 256<<20 || l.Entries <= 0 || l.Entries > 1000000 || l.Layers <= 0 || l.Layers > 1024 || l.Descriptors <= 0 || l.Descriptors > 16384 {
		return nil, errors.New("invalid limits")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	r := reader{root: root, limits: l}
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if _, err = r.jsonFile("oci-layout", nil, &layout); err != nil {
		return nil, err
	}
	if layout.Version != "1.0.0" {
		return nil, errors.New("unsupported OCI layout version")
	}
	var idx index
	idxData, err := r.jsonFile("index.json", nil, &idx)
	if err != nil {
		return nil, err
	}
	s, err := r.selectImage(idx, opts)
	if err != nil {
		return nil, err
	}
	if len(s.manifest.Layers) > l.Layers || s.config.RootFS.Type != "layers" || len(s.config.RootFS.DiffIDs) != len(s.manifest.Layers) {
		return nil, errors.New("layer count/rootfs/diff_ids mismatch or limit")
	}
	report := &Report{Schema: "rudy.layerscope/v1", ToolVersion: Version, IndexDigest: digestBytes(idxData), ManifestDigest: s.desc.Digest, ConfigDigest: s.manifest.Config.Digest, Platform: s.config.Platform, User: s.config.Config.User, Limits: l, Layers: []Layer{}, Files: []Entry{}, History: []Entry{}, Findings: []Finding{}, EnvironmentNames: []string{}}
	envNames := map[string]bool{}
	for _, value := range s.config.Config.Env {
		key, _, ok := strings.Cut(value, "=")
		if !ok || key == "" || strings.ContainsAny(key, "\x00\r\n") {
			return nil, errors.New("invalid config environment entry")
		}
		envNames[key] = true
	}
	for key := range envNames {
		report.EnvironmentNames = append(report.EnvironmentNames, key)
	}
	sort.Strings(report.EnvironmentNames)
	state := fsState{files: map[string]*Entry{}}
	chain := ""
	for i, d := range s.manifest.Layers {
		entries, layer, err := r.readLayer(d, s.config.RootFS.DiffIDs[i], i)
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
		if err = state.apply(entries, i, l.Entries); err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
		if chain == "" {
			chain = layer.DiffID
		} else {
			chain = digestBytes([]byte(chain + " " + layer.DiffID))
		}
		layer.ChainID = chain
		report.Layers = append(report.Layers, layer)
	}
	for _, e := range state.history {
		report.History = append(report.History, *e)
	}
	for _, e := range state.files {
		report.Files = append(report.Files, *e)
	}
	sort.Slice(report.Files, func(i, j int) bool { return report.Files[i].Path < report.Files[j].Path })
	report.IntegrityVerified = true
	report.finish()
	return report, nil
}
