// Package demo creates small synthetic OCI fixtures. The key-looking payload is
// deliberately invalid: no real credential or executable is embedded.
package demo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	ls "github.com/r4venrudy/rudy-layerscope"
)

type item struct {
	name, body string
	mode       int64
	kind       byte
	link       string
}

func Create(destination string) error {
	if err := os.Mkdir(destination, 0755); err != nil {
		return err
	}
	for _, variant := range []string{"leaky", "clean"} {
		if err := writeImage(filepath.Join(destination, variant), variant == "leaky"); err != nil {
			return err
		}
	}
	return nil
}

func writeImage(dir string, leaky bool) error {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0755); err != nil {
		return err
	}
	put := func(b []byte, media string) (ls.Descriptor, error) {
		sum := sha256.Sum256(b)
		digest := fmt.Sprintf("%x", sum)
		err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", digest), b, 0644)
		return ls.Descriptor{Digest: "sha256:" + digest, Size: int64(len(b)), MediaType: media}, err
	}
	marshal := func(v any) ([]byte, error) { return json.Marshal(v) }
	var layers []ls.Descriptor
	var diffIDs []string
	base := []item{{"app/service", "synthetic application v1\n", 0755, tar.TypeReg, ""}, {"app/cache/old", "obsolete\n", 0644, tar.TypeReg, ""}, {"tmp/", "", 01777, tar.TypeDir, ""}}
	if leaky {
		base = append(base, item{"app/.env", "DEMO_TOKEN=synthetic-value-not-a-secret\n", 0600, tar.TypeReg, ""}, item{"root/.ssh/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nINVALID-SYNTHETIC-DEMO\n", 0600, tar.TypeReg, ""})
	}
	update := []item{{"app/service", "synthetic application v2\n", 0755, tar.TypeReg, ""}, {"app/cache/new", "new cache\n", 0644, tar.TypeReg, ""}, {"app/cache/.wh..wh..opq", "", 0644, tar.TypeReg, ""}}
	if leaky {
		update = append(update, item{"app/.wh..env", "", 0644, tar.TypeReg, ""}, item{"root/.wh..ssh", "", 0644, tar.TypeReg, ""}, item{"usr/bin/demo-helper", "not an executable; metadata example\n", 04755, tar.TypeReg, ""})
	}
	for _, items := range [][]item{base, update} {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for _, i := range items {
			h := &tar.Header{Name: i.name, Mode: i.mode, Typeflag: i.kind, Linkname: i.link, Size: int64(len(i.body)), Format: tar.FormatPAX}
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if _, err := tw.Write([]byte(i.body)); err != nil {
				return err
			}
		}
		if err := tw.Close(); err != nil {
			return err
		}
		sum := sha256.Sum256(b.Bytes())
		diffIDs = append(diffIDs, fmt.Sprintf("sha256:%x", sum))
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		if _, err := gz.Write(b.Bytes()); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		d, err := put(compressed.Bytes(), ls.MediaGzip)
		if err != nil {
			return err
		}
		layers = append(layers, d)
	}
	user := "10001:10001"
	env := []string{"PATH=/usr/bin"}
	if leaky {
		user = ""
		env = append(env, "DEMO_API_TOKEN=synthetic-value-not-a-secret")
	}
	configBytes, err := marshal(map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}, "config": map[string]any{"User": user, "Env": env}})
	if err != nil {
		return err
	}
	c, err := put(configBytes, ls.MediaConfig)
	if err != nil {
		return err
	}
	mBytes, err := marshal(map[string]any{"schemaVersion": 2, "mediaType": ls.MediaManifest, "config": c, "layers": layers})
	if err != nil {
		return err
	}
	m, err := put(mBytes, ls.MediaManifest)
	if err != nil {
		return err
	}
	m.Platform = &ls.Platform{OS: "linux", Architecture: "amd64"}
	m.Annotations = map[string]string{"org.opencontainers.image.ref.name": "demo"}
	idx, err := marshal(map[string]any{"schemaVersion": 2, "mediaType": ls.MediaIndex, "manifests": []ls.Descriptor{m}})
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "index.json"), idx, 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0644)
}
