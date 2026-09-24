package dissect

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// JA3Raw returns the classic JA3 comma-joined string (GREASE stripped).
// SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
func (ch *ClientHello) JA3Raw() string {
	ver := ch.LegacyVersion
	if ver == 0 {
		ver = ch.RecordVersion
	}
	ciphers := joinNonGREASE(ch.CipherSuites)
	exts := joinNonGREASE(ch.ExtensionOrder)
	groups := joinNonGREASE(ch.SupportedGroups)
	points := joinUint8(ch.ECPointFormats)
	return fmt.Sprintf("%d,%s,%s,%s,%s", ver, ciphers, exts, groups, points)
}

// JA3Hash is MD5(JA3Raw) hex — the historically broken-but-ubiquitous hash.
func (ch *ClientHello) JA3Hash() string {
	sum := md5.Sum([]byte(ch.JA3Raw()))
	return hex.EncodeToString(sum[:])
}

// JA4 is the FoxIO JA4 fingerprint (https://github.com/FoxIO-LLC/ja4).
// QUIC hellos (ClientHello.QUIC) use the q prefix; TCP uses t.
// Cipher and extension lists are lowercase hex, sorted; GREASE is ignored.
// SNI (0x0000) and ALPN (0x0010) count toward the extension total but are
// omitted from the extension hash. Signature algorithms stay in wire order.
func (ch *ClientHello) JA4() string {
	return ja4(ch)
}

// JA4Raw is the pre-hash JA4_r form: sorted cipher hex, sorted extension hex
// (without SNI/ALPN), then signature algorithms.
func (ch *ClientHello) JA4Raw() string {
	ciphers := filterNonGREASE(ch.CipherSuites)
	exts := filterNonGREASE(ch.ExtensionOrder)
	sigs := filterNonGREASE(ch.SignatureAlgs)
	return ja4Prefix(ch) + "_" + ja4HexSorted(ciphers) + "_" + ja4ExtRaw(exts, sigs)
}

func ja4(ch *ClientHello) string {
	ciphers := filterNonGREASE(ch.CipherSuites)
	exts := filterNonGREASE(ch.ExtensionOrder)
	sigs := filterNonGREASE(ch.SignatureAlgs)
	return ja4Prefix(ch) + "_" + ja4TruncHash(ja4HexSorted(ciphers), len(ciphers) == 0) + "_" + ja4TruncHash(ja4ExtRaw(exts, sigs), ja4ExtList(exts) == "")
}

func ja4Prefix(ch *ClientHello) string {
	proto := "t"
	if ch.QUIC {
		proto = "q"
	}
	sni := "i"
	for _, t := range ch.ExtensionOrder {
		if t == 0x0000 {
			sni = "d"
			break
		}
	}
	alpn := "00"
	if len(ch.ALPN) > 0 {
		alpn = ja4ALPN(ch.ALPN[0])
	}
	ciphers := filterNonGREASE(ch.CipherSuites)
	exts := filterNonGREASE(ch.ExtensionOrder)
	return fmt.Sprintf("%s%s%s%02d%02d%s", proto, ja4Version(ch), sni, min(len(ciphers), 99), min(len(exts), 99), alpn)
}

func ja4Version(ch *ClientHello) string {
	best, has := uint16(0), false
	for _, v := range ch.SupportedVersions {
		if IsGREASE16(v) {
			continue
		}
		if !has || v > best {
			best, has = v, true
		}
	}
	if !has {
		best = ch.LegacyVersion
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ja4ALPN is the first and last alphanumeric of the first ALPN value.
// Non-alphanumeric endpoints use the first and last character of the value's hex.
func ja4ALPN(alpn string) string {
	if alpn == "" {
		return "00"
	}
	b := []byte(alpn)
	first, last := b[0], b[len(b)-1]
	if isJA4Alnum(first) && isJA4Alnum(last) {
		return string([]byte{lowerASCII(first), lowerASCII(last)})
	}
	h := hex.EncodeToString(b)
	return h[:1] + h[len(h)-1:]
}

func isJA4Alnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func ja4HexSorted(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func ja4ExtList(exts []uint16) string {
	var parts []string
	for _, v := range exts {
		if v == 0x0000 || v == 0x0010 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%04x", v))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func ja4ExtRaw(exts, sigs []uint16) string {
	list := ja4ExtList(exts)
	if list == "" {
		return ""
	}
	if len(sigs) == 0 {
		return list
	}
	sp := make([]string, len(sigs))
	for i, v := range sigs {
		sp[i] = fmt.Sprintf("%04x", v)
	}
	return list + "_" + strings.Join(sp, ",")
}

func ja4TruncHash(raw string, empty bool) string {
	if empty || raw == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:12]
}

func joinNonGREASE(vals []uint16) string {
	vals = filterNonGREASE(vals)
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func filterNonGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !IsGREASE16(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinUint8(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
