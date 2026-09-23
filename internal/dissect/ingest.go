package dissect

import (
	"fmt"
	"os"
	"path/filepath"
)

// IngestClientHello writes raw ClientHello record bytes into testdata/corpus
// under the given basename (e.g. "clienthello-chrome_131.bin"). Callers must
// keep Catalog Source/Notes honest (live-browser vs utls-synth).
func IngestClientHello(basename string, raw []byte) (string, error) {
	if len(raw) < 6 || raw[0] != 0x16 {
		return "", fmt.Errorf("ingest: not a TLS handshake record (need content_type=0x16)")
	}
	rec := ExtractFirstRecord(raw)
	if rec == nil {
		return "", fmt.Errorf("ingest: truncated TLS record")
	}
	dir, err := CorpusDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, basename)
	if err := os.WriteFile(path, rec, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ExtractFirstRecord returns the first complete TLS record in b.
func ExtractFirstRecord(b []byte) []byte {
	if len(b) < 5 {
		return nil
	}
	recLen := int(b[3])<<8 | int(b[4])
	need := 5 + recLen
	if len(b) < need {
		return nil
	}
	return append([]byte(nil), b[:need]...)
}
