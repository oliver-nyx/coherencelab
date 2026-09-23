package dissect

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// QPACKFieldSection is a decoded HTTP/3 HEADERS / PUSH_PROMISE field section (RFC 9204).
// Lab focus: Required Insert Count = 0 (static table + literals) — the common case when
// QPACK_MAX_TABLE_CAPACITY=0 on the control stream (Chromium default for many builds).
type QPACKFieldSection struct {
	RequiredInsertCount uint64
	Base                uint64
	Sign                bool // S bit from Delta Base encoding
	DeltaBase           uint64
	Fields              []HeaderField
	PseudoOrder         string
	PseudoNames         []string
	FamilyGuess         string
	Findings            []string
	Raw                 []byte
}

// DecodeQPACKFieldSection decodes an Encoded Field Section (RFC 9204 §4.5).
// Dynamic-table references require a non-zero Required Insert Count and a prior
// encoder stream; this lab errors clearly when those appear so REs learn the
// boundary between static-only and full QPACK.
func DecodeQPACKFieldSection(payload []byte) (*QPACKFieldSection, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("qpack: empty field section")
	}
	sec := &QPACKFieldSection{Raw: append([]byte(nil), payload...)}
	i := 0

	ric, n, err := readInt(payload[i:], 8)
	if err != nil {
		return nil, fmt.Errorf("qpack: Required Insert Count: %w", err)
	}
	i += n
	sec.RequiredInsertCount = ric

	if i >= len(payload) {
		return nil, fmt.Errorf("qpack: truncated after Required Insert Count")
	}
	sBit := payload[i]&0x80 != 0
	delta, n, err := readInt(payload[i:], 7)
	if err != nil {
		return nil, fmt.Errorf("qpack: Delta Base: %w", err)
	}
	i += n
	sec.Sign = sBit
	sec.DeltaBase = delta
	if ric == 0 {
		sec.Base = 0
		if sBit || delta != 0 {
			sec.Findings = append(sec.Findings,
				"RIC=0 but S/Delta Base non-zero — unusual; Base forced to 0 for static-only decode")
		}
	} else {
		sec.Findings = append(sec.Findings,
			fmt.Sprintf("Required Insert Count=%d — dynamic table references need the encoder stream", ric))
		return nil, fmt.Errorf("qpack: dynamic table (RIC=%d) not supported in Lab 12 static decoder — capture encoder stream or use RIC=0 fixtures", ric)
	}

	for i < len(payload) {
		b := payload[i]
		switch {
		case b&0x80 != 0: // Indexed Field Line — 1TIIIIII
			static := b&0x40 != 0
			idx, n, err := readInt(payload[i:], 6)
			if err != nil {
				return nil, err
			}
			i += n
			hf, err := qpackLookup(static, idx)
			if err != nil {
				return nil, err
			}
			sec.Fields = append(sec.Fields, hf)
		case b&0xc0 == 0x40: // Literal Field Line With Name Reference — 01NTIIII
			neverIdx := b&0x20 != 0
			static := b&0x10 != 0
			nameIdx, n, err := readInt(payload[i:], 4)
			if err != nil {
				return nil, err
			}
			i += n
			name, err := qpackNameOnly(static, nameIdx)
			if err != nil {
				return nil, err
			}
			val, n, err := readString(payload[i:])
			if err != nil {
				return nil, fmt.Errorf("qpack value: %w", err)
			}
			i += n
			sec.Fields = append(sec.Fields, HeaderField{Name: name, Value: val, Sensitive: neverIdx})
		case b&0xe0 == 0x20: // Literal Field Line With Literal Name — 001N H Len(3+)
			neverIdx := b&0x10 != 0
			huffman := b&0x08 != 0
			nlen, n, err := readInt(payload[i:], 3)
			if err != nil {
				return nil, err
			}
			i += n
			if uint64(len(payload)-i) < nlen {
				return nil, fmt.Errorf("qpack: literal name truncated")
			}
			nameRaw := payload[i : i+int(nlen)]
			i += int(nlen)
			name := string(nameRaw)
			if huffman {
				name, err = hpack.HuffmanDecodeToString(nameRaw)
				if err != nil {
					return nil, fmt.Errorf("qpack name huffman: %w", err)
				}
			}
			val, n, err := readString(payload[i:])
			if err != nil {
				return nil, fmt.Errorf("qpack value: %w", err)
			}
			i += n
			sec.Fields = append(sec.Fields, HeaderField{Name: strings.ToLower(name), Value: val, Sensitive: neverIdx})
		case b&0xf0 == 0x10:
			return nil, fmt.Errorf("qpack: post-base indexed line at %d requires dynamic table (RIC>0)", i)
		case b&0xf0 == 0x00:
			return nil, fmt.Errorf("qpack: post-base name reference at %d requires dynamic table (RIC>0)", i)
		default:
			return nil, fmt.Errorf("qpack: unknown representation 0x%02x at %d", b, i)
		}
	}

	hb := &HeaderBlock{Fields: sec.Fields}
	analyzePseudo(hb)
	sec.PseudoOrder = hb.PseudoOrder
	sec.PseudoNames = hb.PseudoNames
	sec.FamilyGuess = hb.FamilyGuess
	sec.Findings = append([]string{
		"QPACK Encoded Field Section (RFC 9204) — static table indices differ from HPACK (Lab 03)",
		fmt.Sprintf("Prefix: Required Insert Count=%d Base=%d", sec.RequiredInsertCount, sec.Base),
		"RIC=0 — no dynamic inserts referenced; matches QPACK_MAX_TABLE_CAPACITY=0 control SETTINGS",
	}, sec.Findings...)
	sec.Findings = append(sec.Findings, hb.Findings...)
	return sec, nil
}

func qpackLookup(static bool, idx uint64) (HeaderField, error) {
	if !static {
		return HeaderField{}, fmt.Errorf("qpack: dynamic indexed id=%d needs encoder stream", idx)
	}
	if idx == 0 || int(idx) >= len(qpackStatic) {
		return HeaderField{}, fmt.Errorf("qpack: static index %d out of range", idx)
	}
	e := qpackStatic[idx]
	return HeaderField{Name: e[0], Value: e[1]}, nil
}

func qpackNameOnly(static bool, idx uint64) (string, error) {
	hf, err := qpackLookup(static, idx)
	if err != nil {
		return "", err
	}
	return hf.Name, nil
}

// EncodeQPACKPseudoBlock builds a RIC=0 static-only Encoded Field Section with
// the given pseudo-header order (chrome/firefox/safari).
func EncodeQPACKPseudoBlock(order, authority string) ([]byte, error) {
	var letters []string
	switch order {
	case PseudoChrome, "chrome", "edge", "chromium":
		letters = []string{"m", "a", "s", "p"}
	case PseudoFirefox, "firefox":
		letters = []string{"m", "p", "a", "s"}
	case PseudoSafari, "safari":
		letters = []string{"m", "s", "p", "a"}
	default:
		if strings.Contains(order, ",") {
			letters = strings.Split(order, ",")
		} else {
			return nil, fmt.Errorf("qpack demo order %q (want chrome|firefox|safari)", order)
		}
	}

	out := []byte{0x00, 0x00} // RIC=0, S=0 DeltaBase=0
	for _, letter := range letters {
		switch letter {
		case "m":
			out = append(out, encodeQPACKIndexedStatic(17)...) // :method GET
		case "p":
			out = append(out, encodeQPACKIndexedStatic(2)...) // :path /
		case "s":
			out = append(out, encodeQPACKIndexedStatic(23)...) // :scheme https
		case "a":
			if len(authority) > 127 {
				return nil, fmt.Errorf("authority too long for lab encoder")
			}
			out = append(out, encodeQPACKLiteralNameRefStatic(1, true, authority)...)
		default:
			return nil, fmt.Errorf("unknown pseudo letter %q", letter)
		}
	}
	return out, nil
}

func encodeQPACKIndexedStatic(idx uint64) []byte {
	return appendPrefixedInt(nil, idx, 6, 0xC0) // 1 T=1
}

func encodeQPACKLiteralNameRefStatic(nameIdx uint64, neverIndexed bool, value string) []byte {
	first := byte(0x50) // 01 N=0 T=1
	if neverIndexed {
		first = 0x70 // 01 N=1 T=1
	}
	out := appendPrefixedInt(nil, nameIdx, 4, first)
	out = append(out, byte(len(value))) // H=0, 7-bit length
	out = append(out, value...)
	return out
}

func appendPrefixedInt(dst []byte, i uint64, prefixBits int, firstByte byte) []byte {
	mask := uint64((1 << prefixBits) - 1)
	if i < mask {
		return append(dst, firstByte|byte(i))
	}
	dst = append(dst, firstByte|byte(mask))
	i -= mask
	for i >= 128 {
		dst = append(dst, byte(i)|0x80)
		i >>= 7
	}
	return append(dst, byte(i))
}

// FormatQPACK writes an expert-oriented QPACK field-section report.
func FormatQPACK(w io.Writer, sec *QPACKFieldSection) {
	fmt.Fprintln(w, "═══ QPACK Encoded Field Section (RFC 9204) ═══")
	fmt.Fprintf(w, "Required Insert Count: %d\n", sec.RequiredInsertCount)
	fmt.Fprintf(w, "Base: %d (S=%v DeltaBase=%d)\n", sec.Base, sec.Sign, sec.DeltaBase)
	fmt.Fprintf(w, "Pseudo order: %s  family≈%s\n", sec.PseudoOrder, sec.FamilyGuess)
	fmt.Fprintln(w, "\n── Fields (emit order) ──")
	for i, f := range sec.Fields {
		sens := ""
		if f.Sensitive {
			sens = "  [N]"
		}
		fmt.Fprintf(w, "%2d. %s: %s%s\n", i+1, f.Name, f.Value, sens)
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range sec.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

// ToHeaderBlock adapts a QPACK section for shared format helpers.
func (sec *QPACKFieldSection) ToHeaderBlock() *HeaderBlock {
	return &HeaderBlock{
		Fields:      sec.Fields,
		PseudoOrder: sec.PseudoOrder,
		PseudoNames: sec.PseudoNames,
		FamilyGuess: sec.FamilyGuess,
		Findings:    sec.Findings,
		Raw:         sec.Raw,
	}
}
