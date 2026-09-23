package dissect

import (
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// HeaderField is one decoded HPACK field in emit order.
type HeaderField struct {
	Name, Value string
	Sensitive   bool
}

// HeaderBlock is a decoded HEADERS/CONTINUATION payload.
type HeaderBlock struct {
	Fields      []HeaderField
	PseudoOrder string   // Akamai-style: m,a,s,p
	PseudoNames []string // :method, :authority, …
	FamilyGuess string   // chrome | firefox | safari | unknown
	Findings    []string
	Raw         []byte
}

// DecodeHeaderBlock decodes an HPACK header block (RFC 7541).
// Representation parsing is first-principles; Huffman strings use the
// standard RFC 7541 alphabet via x/net (see readString). Field order is
// preserved — that order is the fingerprint surface.
func DecodeHeaderBlock(payload []byte) (*HeaderBlock, error) {
	dec := &hpackDecoder{maxTableSize: 4096}
	fields, err := dec.decode(payload)
	if err != nil {
		return nil, err
	}
	hb := &HeaderBlock{Fields: fields, Raw: append([]byte(nil), payload...)}
	analyzePseudo(hb)
	return hb, nil
}

type hpackDecoder struct {
	dyn          []HeaderField // index 0 = most recently added
	size         int
	maxTableSize int
}

func (d *hpackDecoder) decode(p []byte) ([]HeaderField, error) {
	var out []HeaderField
	i := 0
	for i < len(p) {
		b := p[i]
		switch {
		case b&0x80 != 0: // indexed — 1xxxxxxx
			idx, n, err := readInt(p[i:], 7)
			if err != nil {
				return nil, err
			}
			i += n
			hf, err := d.lookup(idx)
			if err != nil {
				return nil, err
			}
			out = append(out, hf)
		case b&0xc0 == 0x40: // literal + incremental indexing — 01xxxxxx
			hf, n, err := d.literal(p[i:], 6, true, false)
			if err != nil {
				return nil, err
			}
			i += n
			out = append(out, hf)
		case b&0xe0 == 0x20: // dynamic table size update — 001xxxxx
			size, n, err := readInt(p[i:], 5)
			if err != nil {
				return nil, err
			}
			i += n
			if int(size) > 4096*2 { // soft cap for lab safety
				return nil, fmt.Errorf("hpack: dynamic table size %d unreasonable", size)
			}
			d.maxTableSize = int(size)
			d.evict()
		case b&0xf0 == 0x10: // literal never indexed — 0001xxxx
			hf, n, err := d.literal(p[i:], 4, false, true)
			if err != nil {
				return nil, err
			}
			i += n
			out = append(out, hf)
		case b&0xf0 == 0x00: // literal without indexing — 0000xxxx
			hf, n, err := d.literal(p[i:], 4, false, false)
			if err != nil {
				return nil, err
			}
			i += n
			out = append(out, hf)
		default:
			return nil, fmt.Errorf("hpack: unknown representation 0x%02x at %d", b, i)
		}
	}
	return out, nil
}

func (d *hpackDecoder) lookup(idx uint64) (HeaderField, error) {
	if idx == 0 {
		return HeaderField{}, fmt.Errorf("hpack: invalid index 0")
	}
	staticCount := uint64(len(hpackStatic) - 1) // 61
	if idx <= staticCount {
		e := hpackStatic[idx]
		return HeaderField{Name: e[0], Value: e[1]}, nil
	}
	di := int(idx - staticCount) // 1 = most recent
	if di < 1 || di > len(d.dyn) {
		return HeaderField{}, fmt.Errorf("hpack: index %d out of range (dynamic entries=%d)", idx, len(d.dyn))
	}
	return d.dyn[di-1], nil
}

func (d *hpackDecoder) literal(p []byte, nbits int, index, never bool) (HeaderField, int, error) {
	nameIdx, n, err := readInt(p, nbits)
	if err != nil {
		return HeaderField{}, 0, err
	}
	o := n
	var name string
	if nameIdx == 0 {
		var nn int
		name, nn, err = readString(p[o:])
		if err != nil {
			return HeaderField{}, 0, err
		}
		o += nn
	} else {
		hf, err := d.lookup(nameIdx)
		if err != nil {
			return HeaderField{}, 0, err
		}
		name = hf.Name
	}
	val, nn, err := readString(p[o:])
	if err != nil {
		return HeaderField{}, 0, err
	}
	o += nn
	hf := HeaderField{Name: name, Value: val, Sensitive: never}
	if index {
		d.add(hf)
	}
	return hf, o, nil
}

func (d *hpackDecoder) add(hf HeaderField) {
	d.dyn = append([]HeaderField{hf}, d.dyn...)
	d.size += 32 + len(hf.Name) + len(hf.Value)
	d.evict()
}

func (d *hpackDecoder) evict() {
	for d.size > d.maxTableSize && len(d.dyn) > 0 {
		last := d.dyn[len(d.dyn)-1]
		d.size -= 32 + len(last.Name) + len(last.Value)
		d.dyn = d.dyn[:len(d.dyn)-1]
	}
}

func readInt(p []byte, prefixBits int) (uint64, int, error) {
	if len(p) == 0 {
		return 0, 0, fmt.Errorf("hpack: truncated integer")
	}
	mask := uint8((1 << prefixBits) - 1)
	v := uint64(p[0] & mask)
	if v < uint64(mask) {
		return v, 1, nil
	}
	i := 1
	var m uint64
	for i < len(p) {
		b := p[i]
		i++
		v += uint64(b&0x7f) << m
		m += 7
		if b&0x80 == 0 {
			return v, i, nil
		}
		if m > 63 {
			return 0, 0, fmt.Errorf("hpack: integer overflow")
		}
	}
	return 0, 0, fmt.Errorf("hpack: truncated integer continuation")
}

func readString(p []byte) (string, int, error) {
	if len(p) == 0 {
		return "", 0, fmt.Errorf("hpack: truncated string")
	}
	huffman := p[0]&0x80 != 0
	n, nb, err := readInt(p, 7)
	if err != nil {
		return "", 0, err
	}
	o := nb
	if o+int(n) > len(p) {
		return "", 0, fmt.Errorf("hpack: truncated string data")
	}
	data := p[o : o+int(n)]
	o += int(n)
	if !huffman {
		return string(data), o, nil
	}
	// Huffman alphabet is large (RFC 7541 App B). We decode via the standard
	// implementation; representation framing above is ours — read both.
	s, err := hpack.HuffmanDecodeToString(data)
	if err != nil {
		return "", 0, fmt.Errorf("hpack: huffman: %w", err)
	}
	return s, o, nil
}

// EncodeIndexedPseudoBlock builds a minimal HPACK block for lab tests.
// order is "m,a,s,p" / "m,p,a,s" / "m,s,p,a".
func EncodeIndexedPseudoBlock(order, authority string) ([]byte, error) {
	parts := strings.Split(order, ",")
	var out []byte
	emit := func(letter string) error {
		switch letter {
		case "m":
			out = append(out, 0x82) // :method GET
		case "p":
			out = append(out, 0x84) // :path /
		case "s":
			out = append(out, 0x87) // :scheme https
		case "a":
			// literal without indexing, name index 1 (:authority)
			out = append(out, 0x01)
			if len(authority) > 127 {
				return fmt.Errorf("authority too long for lab encoder")
			}
			out = append(out, byte(len(authority)))
			out = append(out, authority...)
		default:
			return fmt.Errorf("unknown pseudo letter %q", letter)
		}
		return nil
	}
	for _, p := range parts {
		if err := emit(strings.TrimSpace(p)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
