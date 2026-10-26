package layerscope

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

type staged struct {
	entry    Entry
	whiteout bool
	opaque   bool
}

// NormalizePath accepts OCI relative names, not host paths. Dot-dot components,
// backslashes, invalid UTF-8 and control characters are rejected before cleaning.
func NormalizePath(name string) (string, error) {
	if len(name) > 4096 || name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || !utf8.ValidString(name) {
		return "", errors.New("invalid OCI path")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", errors.New("parent traversal in OCI path")
		}
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return "", errors.New("control character in OCI path")
		}
	}
	value := path.Clean(name)
	if strings.Count(value, "/") > 128 {
		return "", errors.New("path depth exceeds 128")
	}
	return value, nil
}

type expandedReader struct {
	r     io.Reader
	local int64
	owner *reader
}

func (b *expandedReader) Read(p []byte) (int, error) {
	// Read at most one byte over the global budget to detect overflow.
	remaining := b.owner.limits.ExpandedBytes - b.owner.expanded
	if remaining < 0 {
		return 0, errors.New("expanded byte budget exceeded")
	}
	if int64(len(p)) > remaining+1 {
		p = p[:remaining+1]
	}
	n, err := b.r.Read(p)
	b.local += int64(n)
	b.owner.expanded += int64(n)
	if b.owner.expanded > b.owner.limits.ExpandedBytes {
		return n, errors.New("expanded byte budget exceeded")
	}
	return n, err
}

var privateHeaders = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"), []byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"), []byte("-----BEGIN DSA PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"), []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
}

// markerHash hashes complete payloads and detects selected PEM headers across
// read boundaries. Retained scanning memory is bounded to a 64-byte tail.
type markerHash struct {
	tail  []byte
	found bool
}

func (w *markerHash) Write(p []byte) (int, error) {
	if !w.found {
		// Chunk independently: io.Copy may supply a large WriterTo buffer.
		for pos := 0; pos < len(p); {
			end := min(pos+32768, len(p))
			chunk := append(w.tail, p[pos:end]...)
			for _, marker := range privateHeaders {
				if bytes.Contains(chunk, marker) {
					w.found = true
					break
				}
			}
			w.tail = append(w.tail[:0], chunk[max(0, len(chunk)-64):]...)
			pos = end
		}
	}
	return len(p), nil
}

func (r *reader) readLayer(d Descriptor, diffID string, number int) ([]staged, Layer, error) {
	var layer Layer
	if _, err := digestName(diffID); err != nil {
		return nil, layer, fmt.Errorf("invalid diff_id: %w", err)
	}
	name, err := digestName(d.Digest)
	if err != nil {
		return nil, layer, err
	}
	if d.Size < 0 || d.Size > r.limits.BlobBytes {
		return nil, layer, errors.New("layer blob byte budget exceeded")
	}
	compressed := false
	switch d.MediaType {
	case MediaTar, "application/vnd.oci.image.layer.nondistributable.v1.tar":
	case MediaGzip, "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip":
		compressed = true
	default:
		return nil, layer, fmt.Errorf("unsupported layer media type %q (tar/gzip only)", d.MediaType)
	}
	f, err := r.open(name)
	if err != nil {
		return nil, layer, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, layer, err
	}
	if info.Size() != d.Size {
		return nil, layer, errors.New("layer descriptor size mismatch")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, d.Size+1))
	if err != nil {
		return nil, layer, err
	}
	if n != d.Size || fmt.Sprintf("sha256:%x", hash.Sum(nil)) != d.Digest {
		return nil, layer, errors.New("layer descriptor digest mismatch")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return nil, layer, err
	}
	// Verify a second digest over exactly the stream being parsed, too.
	hash.Reset()
	raw := io.TeeReader(io.LimitReader(f, d.Size+1), hash)
	var source io.Reader = raw
	if compressed {
		gz, e := gzip.NewReader(raw)
		if e != nil {
			return nil, layer, e
		}
		defer gz.Close()
		source = gz
	}
	uncompressedHash := sha256.New()
	budget := &expandedReader{r: source, owner: r}
	stream := io.TeeReader(budget, uncompressedHash)
	tr := tar.NewReader(stream)
	var entries []staged
	seen := map[string]bool{}
	layer = Layer{Number: number, Digest: d.Digest, DiffID: diffID, CompressedBytes: d.Size, Whiteouts: []string{}}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, layer, err
		}
		r.entries++
		if r.entries > r.limits.Entries {
			return nil, layer, errors.New("archive entry budget exceeded")
		}
		p, err := NormalizePath(h.Name)
		if err != nil {
			return nil, layer, err
		}
		if seen[p] {
			return nil, layer, fmt.Errorf("duplicate normalized layer path %q", p)
		}
		seen[p] = true
		if h.Typeflag == tar.TypeGNUSparse {
			return nil, layer, errors.New("sparse files unsupported")
		}
		for k := range h.PAXRecords {
			if strings.HasPrefix(k, "GNU.sparse") {
				return nil, layer, errors.New("sparse files unsupported")
			}
		}
		if p == "." {
			if h.Typeflag != tar.TypeDir {
				return nil, layer, errors.New("root entry must be a directory")
			}
			continue
		}
		if h.Uid < 0 || h.Gid < 0 || h.Mode < 0 || h.Mode > 07777 || h.Size < 0 {
			return nil, layer, errors.New("invalid mode/owner/size")
		}
		e := Entry{Path: p, Mode: h.Mode, UID: h.Uid, GID: h.Gid, Size: h.Size, Layer: number, ContentLayer: number}
		base := path.Base(p)
		if strings.HasPrefix(base, ".wh.") {
			if h.Typeflag != tar.TypeReg || h.Size != 0 {
				return nil, layer, errors.New("whiteout must be empty regular file")
			}
			opaque := base == ".wh..wh..opq"
			if !opaque && (strings.TrimPrefix(base, ".wh.") == "" || strings.TrimPrefix(base, ".wh.") == "." || strings.TrimPrefix(base, ".wh.") == "..") {
				return nil, layer, errors.New("invalid whiteout target")
			}
			entries = append(entries, staged{entry: e, whiteout: true, opaque: opaque})
			layer.Whiteouts = append(layer.Whiteouts, p)
			continue
		}
		for ancestor := path.Dir(p); ancestor != "."; ancestor = path.Dir(ancestor) {
			if strings.HasPrefix(path.Base(ancestor), ".wh.") {
				return nil, layer, errors.New("whiteout ancestor is invalid")
			}
		}
		if h.Typeflag != tar.TypeReg && h.Size != 0 {
			return nil, layer, errors.New("non-regular entry has payload")
		}
		switch h.Typeflag {
		case tar.TypeReg:
			e.Kind = "file"
			payloadHash := sha256.New()
			marker := &markerHash{}
			n, err := io.Copy(io.MultiWriter(payloadHash, marker), tr)
			if err != nil {
				return nil, layer, err
			}
			if n != h.Size {
				return nil, layer, io.ErrUnexpectedEOF
			}
			e.Digest = fmt.Sprintf("sha256:%x", payloadHash.Sum(nil))
			e.PrivateKeyHeader = marker.found
			e.Capability = h.PAXRecords["SCHILY.xattr.security.capability"] != ""
			layer.PayloadBytes += n
		case tar.TypeDir:
			e.Kind = "directory"
		case tar.TypeSymlink:
			if len(h.Linkname) > 4096 || !utf8.ValidString(h.Linkname) {
				return nil, layer, errors.New("invalid symlink target")
			}
			for _, c := range h.Linkname {
				if unicode.IsControl(c) {
					return nil, layer, errors.New("control character in link target")
				}
			}
			e.Kind = "symlink"
			e.Link = h.Linkname
		case tar.TypeLink:
			e.Kind = "hardlink"
			e.Link, err = NormalizePath(h.Linkname)
			if err != nil {
				return nil, layer, err
			}
		case tar.TypeChar:
			e.Kind = "character-device"
			e.DeviceMajor = h.Devmajor
			e.DeviceMinor = h.Devminor
		case tar.TypeBlock:
			e.Kind = "block-device"
			e.DeviceMajor = h.Devmajor
			e.DeviceMinor = h.Devminor
		case tar.TypeFifo:
			e.Kind = "fifo"
		default:
			return nil, layer, fmt.Errorf("unsupported tar entry type %d", h.Typeflag)
		}
		entries = append(entries, staged{entry: e})
	}
	// Consume padding after tar's end marker, hashing the entire DiffID stream.
	// Nonzero trailing bytes/concatenated tars are rejected, never silently skipped.
	buf := make([]byte, 32768)
	for {
		n, err := stream.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return nil, layer, errors.New("nonzero bytes after tar end marker")
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, layer, err
		}
	}
	if fmt.Sprintf("sha256:%x", uncompressedHash.Sum(nil)) != diffID {
		return nil, layer, errors.New("uncompressed diff_id mismatch")
	}
	if fmt.Sprintf("sha256:%x", hash.Sum(nil)) != d.Digest {
		return nil, layer, errors.New("layer changed while parsing")
	}
	layer.ExpandedBytes = budget.local
	layer.Entries = len(entries)
	return entries, layer, nil
}
