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
		{"chrome_131", "clienthello-chrome_131.bin"},
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
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x04, 0x00, 0x60, 0x00, 0x00,
		0x00, 0x06, 0x00, 0x04, 0x00, 0x00,
	}
	sf := frame(0x4, 0x00, 0, settings)
	wu := frame(0x8, 0x00, 0, []byte{0x00, 0xef, 0x00, 0x01})
	h1 := frame(0x1, 0x00, 1, block[:2])
	c1 := frame(0x9, 0x04, 1, block[2:])
	h2path := filepath.Join(dir, "h2-chrome-like.bin")
	buf := append(append(append(append(preface, sf...), wu...), h1...), c1...)
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
