package h2wire

import (
	"bytes"
	"testing"
)

func TestTruncateThroughControlFlightKeepsPriorityAndHeaders(t *testing.T) {
	// preface + SETTINGS(empty 0 settings) + WINDOW_UPDATE + PRIORITY_UPDATE + HEADERS(END_HEADERS)
	var b bytes.Buffer
	b.WriteString("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	// SETTINGS len=0
	b.Write([]byte{0, 0, 0, 0x4, 0, 0, 0, 0, 0})
	// WINDOW_UPDATE
	b.Write([]byte{0, 0, 4, 0x8, 0, 0, 0, 0, 0, 0, 0xef, 0, 1})
	// PRIORITY_UPDATE stream=0, prioritized=1, "u=0, i"
	pu := append([]byte{0, 0, 0, 1}, []byte("u=0, i")...)
	b.Write([]byte{0, 0, byte(len(pu)), 0x10, 0, 0, 0, 0, 0})
	b.Write(pu)
	// HEADERS END_HEADERS|END_STREAM stream=1 len=4
	b.Write([]byte{0, 0, 4, 0x1, 0x5, 0, 0, 0, 1, 0x82, 0x86, 0x84, 0x41})
	out := truncateThroughControlFlight(b.Bytes())
	if len(out) != b.Len() {
		t.Fatalf("truncate len=%d want %d", len(out), b.Len())
	}
	// preface-only should stay preface-only
	prefaceOnly := b.Bytes()[:24+9+13] // preface+SETTINGS+WU
	got := truncateThroughControlFlight(prefaceOnly)
	if len(got) != len(prefaceOnly) {
		t.Fatalf("preface-only len=%d want %d", len(got), len(prefaceOnly))
	}
}
