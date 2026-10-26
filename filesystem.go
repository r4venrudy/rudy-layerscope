package layerscope

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

type fsState struct {
	files    map[string]*Entry
	history  []*Entry
	children map[string]map[string]bool
}

func (s *fsState) put(e *Entry) {
	s.files[e.Path] = e
	p := path.Dir(e.Path)
	if s.children[p] == nil {
		s.children[p] = map[string]bool{}
	}
	s.children[p][e.Path] = true
}

func (s *fsState) remove(p string, descendantsOnly bool, layer int, reason string) {
	for key := range s.children[p] {
		s.remove(key, false, layer, reason)
	}
	if !descendantsOnly {
		if e, ok := s.files[p]; ok {
			if !e.Implicit {
				value := layer
				e.RemovedBy = &value
				e.Removal = reason
			}
			delete(s.files, p)
			delete(s.children[path.Dir(p)], p)
		}
		delete(s.children, p)
	}
}

func (s *fsState) apply(records []staged, layer, maxEntries int) error {
	if s.children == nil {
		s.children = map[string]map[string]bool{}
		for _, e := range s.files {
			s.put(e)
		}
	}
	// Stage deletions before additions: a whiteout only hides lower layers,
	// regardless of its position in the tar stream.
	for _, r := range records {
		if !r.whiteout {
			continue
		}
		if r.opaque {
			s.remove(path.Dir(r.entry.Path), true, layer, "opaque-whiteout")
		} else {
			target := path.Join(path.Dir(r.entry.Path), strings.TrimPrefix(path.Base(r.entry.Path), ".wh."))
			s.remove(target, false, layer, "whiteout")
		}
	}
	for _, r := range records {
		if r.whiteout {
			continue
		}
		e := r.entry
		parents := []string{}
		for p := path.Dir(e.Path); p != "."; p = path.Dir(p) {
			parents = append(parents, p)
		}
		for i := len(parents) - 1; i >= 0; i-- {
			p := parents[i]
			if old, ok := s.files[p]; ok {
				if old.Kind != "directory" {
					return fmt.Errorf("entry %q traverses non-directory ancestor %q; symlink traversal is unsupported", e.Path, p)
				}
			} else {
				s.put(&Entry{Path: p, Kind: "directory", Mode: 0755, Layer: layer, ContentLayer: layer, Implicit: true})
			}
		}
		if e.Kind == "hardlink" {
			if e.Link == e.Path {
				return errors.New("self-referential hardlink is unsupported")
			}
			target, ok := s.files[e.Link]
			if !ok || target.Kind != "file" {
				return fmt.Errorf("hardlink %q needs an earlier regular target %q", e.Path, e.Link)
			}
			// The target inode survives later unlink/recreate of its original path.
			p, link := e.Path, e.Link
			e = *target
			e.Path = p
			e.Link = link
			e.Layer = layer
			e.RemovedBy = nil
			e.Removal = ""
			e.Implicit = false
		}
		if old, ok := s.files[e.Path]; ok {
			if e.Kind == "directory" && old.Kind == "directory" {
				if !old.Implicit {
					value := layer
					old.RemovedBy = &value
					old.Removal = "metadata-replaced"
				}
			} else {
				s.remove(e.Path, false, layer, "replaced")
			}
		}
		e.Revision = len(s.history) + 1
		owned := new(Entry)
		*owned = e
		s.put(owned)
		s.history = append(s.history, owned)
		if len(s.files) > maxEntries {
			return errors.New("final filesystem entry budget exceeded (including implicit directories)")
		}
	}
	return nil
}
