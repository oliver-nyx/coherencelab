package probe

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestHelloCaptureConnRecordsFirstRecord(t *testing.T) {
	rec := []byte{0x16, 0x03, 0x01, 0x00, 0x03, 0x01, 0x00, 0x00}
	extra := []byte{0xaa, 0xbb}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	hc := NewHelloCaptureConn(c1)
	go func() {
		_, _ = c2.Write(append(append([]byte{}, rec...), extra...))
		_ = c2.Close()
	}()

	got, err := io.ReadAll(hc)
	if err != nil {
		t.Fatal(err)
	}
	hello := hc.ClientHello()
	if !bytes.Equal(hello, rec) {
		t.Fatalf("hello=%x want=%x", hello, rec)
	}
	if !bytes.Equal(got, append(rec, extra...)) {
		t.Fatalf("replay=%x", got)
	}
}

func TestHelloCaptureConnFragmented(t *testing.T) {
	rec := []byte{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	hc := NewHelloCaptureConn(c1)
	go func() {
		_, _ = c2.Write(rec[:3])
		_, _ = c2.Write(rec[3:6])
		_, _ = c2.Write(rec[6:])
		_ = c2.Close()
	}()

	_, _ = io.ReadAll(hc)
	if !bytes.Equal(hc.ClientHello(), rec) {
		t.Fatalf("got %x", hc.ClientHello())
	}
}

func TestExtractClientHelloRecord(t *testing.T) {
	rec := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}
	if got := ExtractClientHelloRecord(append(rec, 0xff)); !bytes.Equal(got, rec) {
		t.Fatalf("%x", got)
	}
	if ExtractClientHelloRecord(rec[:4]) != nil {
		t.Fatal("expected nil for truncated")
	}
}
