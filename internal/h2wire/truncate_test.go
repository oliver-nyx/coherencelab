package h2wire

import (
	"testing"

	"golang.org/x/net/http2"
)

func TestTruncateKeepsPriorityUpdateAroundHeaders(t *testing.T) {
	// SETTINGS + WINDOW_UPDATE + PRIORITY_UPDATE + HEADERS + PRIORITY_UPDATE + DATA
	var b []byte
	b = append(b, []byte(http2.ClientPreface)...)
	b = append(b, frame(0x4, 0, 0, []byte{
		0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // HEADER_TABLE_SIZE=4096
	})...)
	b = append(b, frame(0x8, 0, 0, []byte{0x00, 0x00, 0x01, 0x00})...) // WINDOW_UPDATE
	b = append(b, frame(0x10, 0, 0, append([]byte{0x00, 0x00, 0x00, 0x01}, []byte("u=0, i")...))...)
	hdrPayload := []byte{0x82} // :method GET indexed
	b = append(b, frame(0x1, 0x4|0x1, 1, hdrPayload)...) // HEADERS END_HEADERS|END_STREAM
	b = append(b, frame(0x10, 0, 0, append([]byte{0x00, 0x00, 0x00, 0x03}, []byte("u=3")...))...)
	b = append(b, frame(0x0, 0x1, 1, []byte("x"))...) // DATA — should stop before this

	got := truncateThroughControlFlight(b)
	if len(got) >= len(b) {
		t.Fatalf("should stop before DATA, got %d want < %d", len(got), len(b))
	}
	if !containsBytes(got, []byte("u=0, i")) || !containsBytes(got, []byte("u=3")) {
		t.Fatalf("expected both PRIORITY_UPDATE values in %x", got)
	}
	if containsBytes(got, []byte("x")) {
		t.Fatal("DATA payload should be truncated out")
	}
}

func frame(ftype, flags byte, stream uint32, payload []byte) []byte {
	n := len(payload)
	out := []byte{byte(n >> 16), byte(n >> 8), byte(n), ftype, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	return append(out, payload...)
}

func containsBytes(b, sub []byte) bool {
	for i := 0; i+len(sub) <= len(b); i++ {
		ok := true
		for j := range sub {
			if b[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
