// Package layerscope verifies and models local Linux OCI image layouts without
// extracting or executing their contents. See docs/CONTRACT.md for the subset.
package layerscope

const Version = "0.1.0-preview"

const (
	MediaIndex    = "application/vnd.oci.image.index.v1+json"
	MediaManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaConfig   = "application/vnd.oci.image.config.v1+json"
	MediaTar      = "application/vnd.oci.image.layer.v1.tar"
	MediaGzip     = "application/vnd.oci.image.layer.v1.tar+gzip"
)

// Limits are hard failure boundaries, never silent truncation. Zero Options.Limits
// selects DefaultLimits; partial custom limits are rejected.
type Limits struct {
	BlobBytes     int64
	ExpandedBytes int64
	MetadataBytes int64
	Entries       int
	Layers        int
	Descriptors   int
}

func DefaultLimits() Limits {
	return Limits{512 << 20, 4 << 30, 32 << 20, 200000, 256, 4096}
}

type Options struct {
	Ref      string
	Platform string
	Limits   Limits
}

type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

func (p Platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Platform    *Platform         `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}
type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	ArtifactType  string       `json:"artifactType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}
type imageConfig struct {
	Platform
	Config struct {
		User string   `json:"User"`
		Env  []string `json:"Env"`
	} `json:"config"`
	RootFS struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// Entry contains metadata and content digests only. No file bodies are retained.
// Layer numbers are zero-based; RemovedBy is nil for final explicit entries.
type Entry struct {
	Path             string `json:"path"`
	Kind             string `json:"kind"`
	Mode             int64  `json:"mode"`
	UID              int    `json:"uid"`
	GID              int    `json:"gid"`
	Size             int64  `json:"size"`
	Digest           string `json:"digest,omitempty"`
	Link             string `json:"link,omitempty"`
	DeviceMajor      int64  `json:"device_major,omitempty"`
	DeviceMinor      int64  `json:"device_minor,omitempty"`
	Layer            int    `json:"layer"`
	ContentLayer     int    `json:"content_layer"`
	Revision         int    `json:"revision"`
	Implicit         bool   `json:"implicit,omitempty"`
	PrivateKeyHeader bool   `json:"private_key_header,omitempty"`
	Capability       bool   `json:"capability_xattr,omitempty"`
	RemovedBy        *int   `json:"removed_by_layer,omitempty"`
	Removal          string `json:"removal,omitempty"`
}

type Layer struct {
	Number          int      `json:"number"`
	Digest          string   `json:"digest"`
	DiffID          string   `json:"diff_id"`
	ChainID         string   `json:"chain_id"`
	CompressedBytes int64    `json:"compressed_bytes"`
	ExpandedBytes   int64    `json:"expanded_bytes"`
	PayloadBytes    int64    `json:"payload_bytes"`
	Entries         int      `json:"entries"`
	Whiteouts       []string `json:"whiteouts"`
}

type Finding struct {
	Rule        string `json:"rule"`
	Level       string `json:"level"`
	Path        string `json:"path,omitempty"`
	Layer       int    `json:"layer"`
	Message     string `json:"message"`
	Fingerprint string `json:"fingerprint"`
	Hidden      bool   `json:"hidden"`
}

type Summary struct {
	FinalEntries       int   `json:"final_entries"`
	FileRevisions      int   `json:"file_revisions"`
	HiddenRevisions    int   `json:"hidden_revisions"`
	PayloadBytes       int64 `json:"payload_bytes"`
	HiddenPayloadBytes int64 `json:"hidden_payload_bytes"`
	Findings           int   `json:"findings"`
}

type Report struct {
	Schema            string    `json:"schema"`
	ToolVersion       string    `json:"tool_version"`
	IndexDigest       string    `json:"index_digest"`
	ManifestDigest    string    `json:"manifest_digest"`
	ConfigDigest      string    `json:"config_digest"`
	Platform          Platform  `json:"platform"`
	User              string    `json:"user"`
	EnvironmentNames  []string  `json:"environment_names"`
	IntegrityVerified bool      `json:"integrity_verified"`
	Limits            Limits    `json:"limits"`
	Layers            []Layer   `json:"layers"`
	Files             []Entry   `json:"files"`
	History           []Entry   `json:"history"`
	Findings          []Finding `json:"findings"`
	Summary           Summary   `json:"summary"`
}
