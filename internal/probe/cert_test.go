package probe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDurableCertDirEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("COHERENCELAB_CERT_DIR", dir)
	if got := DurableCertDir(); got != dir {
		t.Fatalf("DurableCertDir=%q want %q", got, dir)
	}
}

func TestLoadAndMirrorCertPEMs(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()

	// Mint via buildCerts path would need Once; write a tiny valid pair by
	// generating through generateSelfSignedX509 once then reading cache is OK
	// if this is the first cert touch in the package test process.
	t.Setenv("COHERENCELAB_CERT_DIR", src)
	SetCertPersistDir(src)
	if _, err := generateSelfSignedX509(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := WriteCertPEMs(dst); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(src, "probe-cert.pem"))
	b, _ := os.ReadFile(filepath.Join(dst, "probe-cert.pem"))
	if len(a) == 0 || string(a) != string(b) {
		t.Fatalf("mirrored PEMs differ (%d vs %d bytes)", len(a), len(b))
	}
}
