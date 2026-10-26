package layerscope

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

type Rule struct {
	ID          string
	Name        string
	Description string
}

var Rules = []Rule{
	{"LS001", "Private key header", "Selected PEM private-key header occurs in a file revision; content is never printed."},
	{"LS002", "Credential-like path", "Path resembles credential material; this is a heuristic, not a verified secret."},
	{"LS003", "Privileged executable", "Final regular file has execute bits and setuid or setgid bits."},
	{"LS004", "World writable", "Final regular file is world writable, or directory is world writable without sticky bit."},
	{"LS005", "Root default user", "Image config User is empty, root, or UID 0; runtime may override it."},
	{"LS006", "Sensitive environment name", "Image config contains a credential-like environment key; values are omitted."},
	{"LS007", "File capabilities", "Final regular file declares a nonempty security.capability PAX xattr; bits are not interpreted."},
	{"LS008", "Device entry", "Final image contains a block or character device entry."},
}

func credentialPath(p string) bool {
	b := strings.ToLower(path.Base(p))
	p = "/" + strings.ToLower(p)
	if b == ".env" || (strings.HasPrefix(b, ".env.") && b != ".env.example" && b != ".env.sample" && b != ".env.template") {
		return true
	}
	switch b {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc", ".netrc":
		return true
	}
	return strings.HasSuffix(p, "/.aws/credentials") || strings.HasSuffix(p, "/.docker/config.json") || strings.HasSuffix(p, "/.kube/config")
}

func sensitiveEnv(key string) bool {
	k := strings.ToUpper(key)
	for _, needle := range []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "PRIVATE_KEY", "API_KEY", "ACCESS_KEY"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}

func (r *Report) finish() {
	add := func(rule, level, p string, layer int, message, digest string, hidden bool) {
		fp := digestBytes([]byte(rule + "\x00" + p + "\x00" + digest))
		r.Findings = append(r.Findings, Finding{rule, level, p, layer, message, fp, hidden})
	}
	seen := map[string]bool{}
	active := map[string]bool{}
	for _, e := range r.Files {
		if e.Kind == "file" {
			active[e.Path+"\x00"+e.Digest] = true
		}
	}
	for _, e := range r.History {
		r.Summary.FileRevisions++
		if e.Kind == "file" && e.Link == "" {
			r.Summary.PayloadBytes += e.Size
		}
		if e.RemovedBy != nil {
			r.Summary.HiddenRevisions++
			if e.Kind == "file" && e.Link == "" {
				r.Summary.HiddenPayloadBytes += e.Size
			}
		}
		if e.Kind != "file" {
			continue
		}
		for _, rule := range []string{"LS001", "LS002"} {
			match := rule == "LS001" && e.PrivateKeyHeader || rule == "LS002" && credentialPath(e.Path)
			if !match {
				continue
			}
			key := rule + "\x00" + e.Path + "\x00" + e.Digest
			if seen[key] {
				continue
			}
			seen[key] = true
			level, msg := "warning", "Credential-like path appears in an image layer; review the file at its source."
			if rule == "LS001" {
				level = "error"
				msg = "Private-key header appears in an image layer; inspect and rotate any real key at its source."
			}
			hidden := !active[e.Path+"\x00"+e.Digest]
			if hidden {
				msg += " This revision is hidden from the final filesystem but its bytes remain in a referenced layer."
			}
			add(rule, level, e.Path, e.ContentLayer, msg, e.Digest, hidden)
		}
	}
	for _, e := range r.Files {
		if e.Implicit {
			continue
		}
		if e.Kind == "file" && e.Mode&06000 != 0 && e.Mode&0111 != 0 {
			add("LS003", "warning", e.Path, e.Layer, "Privileged executable mode declared in final image.", e.Digest, false)
		}
		if (e.Kind == "file" && e.Mode&0002 != 0) || (e.Kind == "directory" && e.Mode&0002 != 0 && e.Mode&01000 == 0) {
			add("LS004", "warning", e.Path, e.Layer, "World-writable file or non-sticky directory in final image.", fmt.Sprint(e.Mode), false)
		}
		if e.Kind == "file" && e.Capability {
			add("LS007", "warning", e.Path, e.Layer, "File capability xattr declared in final image.", e.Digest, false)
		}
		if e.Kind == "block-device" || e.Kind == "character-device" {
			add("LS008", "warning", e.Path, e.Layer, "Device entry declared in final image.", e.Kind, false)
		}
	}
	user, _, _ := strings.Cut(r.User, ":")
	if user == "" || user == "root" || strings.TrimLeft(user, "0") == "" {
		add("LS005", "warning", "", -1, "Image config defaults to root. Runtime settings can override this.", "root", false)
	}
	for _, key := range r.EnvironmentNames {
		if sensitiveEnv(key) {
			add("LS006", "warning", "", -1, fmt.Sprintf("Credential-like environment key %q is stored in image config; value omitted.", key), key, false)
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Layer != b.Layer {
			return a.Layer < b.Layer
		}
		return a.Fingerprint < b.Fingerprint
	})
	r.Summary.FinalEntries = len(r.Files)
	r.Summary.Findings = len(r.Findings)
}

type Change struct {
	Path   string `json:"path"`
	Kind   string `json:"change"`
	Before *Entry `json:"before,omitempty"`
	After  *Entry `json:"after,omitempty"`
}
type Delta struct {
	Schema          string    `json:"schema"`
	Before          string    `json:"before_manifest"`
	After           string    `json:"after_manifest"`
	Changes         []Change  `json:"changes"`
	AddedFindings   []Finding `json:"added_findings"`
	RemovedFindings []Finding `json:"removed_findings"`
}

// Compare ignores tar order, timestamps and layer origins when comparing final
// entries. Findings are compared by stable rule/path/content fingerprints.
func Compare(a, b *Report) Delta {
	d := Delta{Schema: "rudy.layerscope.delta/v1", Before: a.ManifestDigest, After: b.ManifestDigest, Changes: []Change{}, AddedFindings: []Finding{}, RemovedFindings: []Finding{}}
	left, right := map[string]Entry{}, map[string]Entry{}
	keys := map[string]bool{}
	for _, e := range a.Files {
		left[e.Path] = e
		keys[e.Path] = true
	}
	for _, e := range b.Files {
		right[e.Path] = e
		keys[e.Path] = true
	}
	for key := range keys {
		x, xok := left[key]
		y, yok := right[key]
		c := Change{Path: key}
		if !xok {
			c.Kind = "added"
			c.After = &y
		} else if !yok {
			c.Kind = "removed"
			c.Before = &x
		} else {
			if x.Kind == y.Kind && x.Mode == y.Mode && x.UID == y.UID && x.GID == y.GID && x.Size == y.Size && x.Digest == y.Digest && x.Link == y.Link && x.Capability == y.Capability && x.DeviceMajor == y.DeviceMajor && x.DeviceMinor == y.DeviceMinor {
				continue
			}
			c.Kind = "modified"
			c.Before = &x
			c.After = &y
		}
		d.Changes = append(d.Changes, c)
	}
	sort.Slice(d.Changes, func(i, j int) bool { return d.Changes[i].Path < d.Changes[j].Path })
	af, bf := map[string]bool{}, map[string]bool{}
	for _, f := range a.Findings {
		af[f.Fingerprint] = true
	}
	for _, f := range b.Findings {
		bf[f.Fingerprint] = true
	}
	for _, f := range b.Findings {
		if !af[f.Fingerprint] {
			d.AddedFindings = append(d.AddedFindings, f)
		}
	}
	for _, f := range a.Findings {
		if !bf[f.Fingerprint] {
			d.RemovedFindings = append(d.RemovedFindings, f)
		}
	}
	return d
}
