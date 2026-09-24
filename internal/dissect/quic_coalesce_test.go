package dissect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDecryptInitialCoalescedDatagram(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(CorpusDirMust(), "quic-initial-chrome-live.bin"))
	if err != nil {
		t.Fatal(err)
	}
	// Append fake coalesced bytes (as Firefox often does after Length).
	coalesced := append(append([]byte(nil), raw...), bytesRepeat(0xab, 200)...)
	d1, err := DecryptInitial(raw)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DecryptInitial(coalesced)
	if err != nil {
		t.Fatalf("coalesced decrypt failed (Length truncate bug?): %v", err)
	}
	if d1.PacketNumber != d2.PacketNumber {
		t.Fatalf("pn %d vs %d", d1.PacketNumber, d2.PacketNumber)
	}
	if d1.ClientHello == nil || d2.ClientHello == nil {
		t.Fatal("missing ClientHello")
	}
	if d1.ClientHello.JA3Hash() != d2.ClientHello.JA3Hash() {
		t.Fatal("JA3 mismatch after coalesce")
	}
}

func TestInitialFlightRoundTrip(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(CorpusDirMust(), "quic-initial-chrome-live.bin"))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncodeInitialFlight([][]byte{raw, append(append([]byte(nil), raw...), 0xab)})
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecryptInitialCapture(enc)
	if err != nil {
		t.Fatal(err)
	}
	if d.ClientHello == nil || d.ClientHello.SNI != "example.com" {
		t.Fatalf("flight CH=%v", d.ClientHello)
	}
}

func CorpusDirMust() string {
	d, err := CorpusDir()
	if err != nil {
		panic(err)
	}
	return d
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestFirefoxLiveInitialCRYPTOCoverage(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(CorpusDirMust(), "quic-initial-firefox-live.bin"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecryptInitialCapture(raw)
	if err != nil {
		t.Fatalf("firefox Initial should decrypt: %v", err)
	}
	if d.ClientHello == nil {
		t.Fatal("expected reassembled ClientHello")
	}
	fp := TransportFingerprint(d.Transport)
	if d.ClientHello.SNI != "example.com" {
		t.Fatalf("SNI=%q", d.ClientHello.SNI)
	}
	if !IsInitialFlight(raw) {
		t.Fatal("firefox live fixture should be CLQI flight (fragmented CRYPTO)")
	}
	t.Logf("firefox flight SNI=%q tp=%s ja3=%s", d.ClientHello.SNI, fp, d.ClientHello.JA3Hash())
}
