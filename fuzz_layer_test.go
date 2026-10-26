package layerscope

import "testing"

func FuzzLayer(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 1024))
	f.Add([]byte("not a tar archive"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			t.Skip()
		}
		root := imageRaw(t, [][]byte{b}, false, nil)
		l := DefaultLimits()
		l.ExpandedBytes = 1 << 20
		l.Entries = 128
		_, _ = Analyze(root, Options{Limits: l})
	})
}
