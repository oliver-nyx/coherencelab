//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/oliver-nyx/coherencelab/internal/dissect"
)

func main() {
	dir := "testdata/corpus"
	_ = os.MkdirAll(dir, 0o755)
	hellos := []struct{ id, file string }{
		{"chrome_131", "clienthello-chrome_131_utls.bin"}, // parrot baseline â€” never overwrite live chrome_131
		{"firefox_133", "clienthello-firefox_133.bin"},
		{"safari_18", "clienthello-safari_18.bin"},
		{"ios_14", "clienthello-safari_ios.bin"},
	}
	for _, h := range hellos {
		raw, err := dissect.SynthClientHello(h.id, "example.com")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", h.id, err)
			os.Exit(1)
		}
		path := filepath.Join(dir, h.file)
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			panic(err)
		}
		fmt.Println("wrote", path, len(raw), "bytes")
	}

	block, err := dissect.EncodeIndexedPseudoBlock(dissect.PseudoChrome, "example.com")
	if err != nil {
		panic(err)
	}
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settings := []byte{
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE=65536
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH=0
		0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // INITIAL_WINDOW_SIZE=6291456
		0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE=262144
		0x00, 0x09, 0x00, 0x00, 0x00, 0x01, // NO_RFC7540_PRIORITIES=1
	}
	sf := frame(0x4, 0x00, 0, settings)
	wu := frame(0x8, 0x00, 0, []byte{0x00, 0xef, 0x00, 0x01})
	// PRIORITY_UPDATE: header stream=0, prioritized stream=1, value=u=0, i
	puPayload := append([]byte{0x00, 0x00, 0x00, 0x01}, []byte("u=0, i")...)
	pu := frame(0x10, 0x00, 0, puPayload)
	h1 := frame(0x1, 0x00, 1, block[:2])
	c1 := frame(0x9, 0x04, 1, block[2:])
	h2path := filepath.Join(dir, "h2-chrome-like.bin")
	buf := append(append(append(append(append(preface, sf...), wu...), pu...), h1...), c1...)
	_ = os.WriteFile(h2path, buf, 0o644)
	fmt.Println("wrote", h2path, len(buf), "bytes")

	ffBlock, _ := dissect.EncodeIndexedPseudoBlock(dissect.PseudoFirefox, "example.com")
	ffSettings := []byte{
		0x00, 0x01, 0x00, 0x00, 0xff, 0xff,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
	}
	ff := append(append(preface, frame(0x4, 0x00, 0, ffSettings)...), frame(0x1, 0x04, 1, ffBlock)...)
	ffPath := filepath.Join(dir, "h2-firefox-like.bin")
	_ = os.WriteFile(ffPath, ff, 0o644)
	fmt.Println("wrote", ffPath, len(ff), "bytes")

	// HTTP/3 chrome-like control-stream frames (post-decrypt): SETTINGS+GREASE+PRIORITY_UPDATE+QPACK HEADERS
	h3Chrome := craftH3ChromeLike()
	h3ChromePath := filepath.Join(dir, "h3-chrome-like.bin")
	_ = os.WriteFile(h3ChromePath, h3Chrome, 0o644)
	fmt.Println("wrote", h3ChromePath, len(h3Chrome), "bytes")

	h3Min := craftH3Minimal()
	h3MinPath := filepath.Join(dir, "h3-minimal.bin")
	_ = os.WriteFile(h3MinPath, h3Min, 0o644)
	fmt.Println("wrote", h3MinPath, len(h3Min), "bytes")

	for _, q := range []struct{ order, file string }{
		{dissect.PseudoChrome, "qpack-chrome.bin"},
		{dissect.PseudoFirefox, "qpack-firefox.bin"},
		{dissect.PseudoSafari, "qpack-safari.bin"},
	} {
		qb, err := dissect.EncodeQPACKPseudoBlock(q.order, "example.com")
		if err != nil {
			panic(err)
		}
		qp := filepath.Join(dir, q.file)
		_ = os.WriteFile(qp, qb, 0o644)
		fmt.Println("wrote", qp, len(qb), "bytes")
	}

	quicInit, err := dissect.CraftChromeLikeInitial()
	if err != nil {
		panic(err)
	}
	quicPath := filepath.Join(dir, "quic-initial-chrome-like.bin")
	_ = os.WriteFile(quicPath, quicInit, 0o644)
	fmt.Println("wrote", quicPath, len(quicInit), "bytes")

	tpMin := dissect.CraftMinimalTransportParams()
	tpPath := filepath.Join(dir, "quic-tp-minimal.bin")
	_ = os.WriteFile(tpPath, tpMin, 0o644)
	fmt.Println("wrote", tpPath, len(tpMin), "bytes")

	vn := dissect.CraftVNChromeLike()
	vnPath := filepath.Join(dir, "quic-vn-grease.bin")
	_ = os.WriteFile(vnPath, vn, 0o644)
	fmt.Println("wrote", vnPath, len(vn), "bytes")

	retry, err := dissect.CraftRetryChromeLike()
	if err != nil {
		panic(err)
	}
	retryPath := filepath.Join(dir, "quic-retry.bin")
	_ = os.WriteFile(retryPath, retry, 0o644)
	fmt.Println("wrote", retryPath, len(retry), "bytes")
}

func craftH3ChromeLike() []byte {
	var settings []byte
	settings = dissect.AppendVarint(settings, 0x01) // QPACK_MAX_TABLE_CAPACITY
	settings = dissect.AppendVarint(settings, 0)
	settings = dissect.AppendVarint(settings, 0x06) // MAX_FIELD_SECTION_SIZE
	settings = dissect.AppendVarint(settings, 262144)
	settings = dissect.AppendVarint(settings, 0x07) // QPACK_BLOCKED_STREAMS
	settings = dissect.AppendVarint(settings, 100)
	settings = dissect.AppendVarint(settings, 0x21) // GREASE setting
	settings = dissect.AppendVarint(settings, 1)

	var buf []byte
	buf = dissect.AppendH3Frame(buf, 0x04, settings)
	buf = dissect.AppendH3Frame(buf, 0x21, nil)
	pu := append(dissect.EncodeVarint(0), []byte("u=0, i")...)
	buf = dissect.AppendH3Frame(buf, 0xF0700, pu)
	qpack, err := dissect.EncodeQPACKPseudoBlock(dissect.PseudoChrome, "example.com")
	if err != nil {
		panic(err)
	}
	buf = dissect.AppendH3Frame(buf, 0x01, qpack)
	return buf
}

func craftH3Minimal() []byte {
	var settings []byte
	settings = dissect.AppendVarint(settings, 0x01)
	settings = dissect.AppendVarint(settings, 0)
	settings = dissect.AppendVarint(settings, 0x06)
	settings = dissect.AppendVarint(settings, 16384)
	return dissect.AppendH3Frame(nil, 0x04, settings)
}

func frame(typ, flags uint8, stream uint32, payload []byte) []byte {
	f := make([]byte, 9+len(payload))
	f[0] = byte(len(payload) >> 16)
	f[1] = byte(len(payload) >> 8)
	f[2] = byte(len(payload))
	f[3] = typ
	f[4] = flags
	f[5] = byte(stream >> 24)
	f[6] = byte(stream >> 16)
	f[7] = byte(stream >> 8)
	f[8] = byte(stream)
	copy(f[9:], payload)
	return f
}
