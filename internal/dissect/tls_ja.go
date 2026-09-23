package dissect

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// JA4 returns a JA4-inspired fingerprint closer to FoxIO's shape than the
// previous toy helper in tlsfp. Format:
//
//	t<ver><sni><alpn>_<cipher_hash>_<ext_hash>
//
// where ver is 12/13, sni is d/i, alpn is first protocol sorted truncated.
// This is intentionally documented as "inspired" — full JA4 has more quirks
// (QUIC, sorting rules). Experts: compare against ja4.dev test vectors before
// treating equality as gospel.
func (ch *ClientHello) JA4() string {
	proto := "t" // TCP TLS
	ver := "00"
	if hasVersion(ch.SupportedVersions, 0x0304) || ch.LegacyVersion == 0x0304 {
		ver = "13"
	} else if ch.LegacyVersion == 0x0303 || hasVersion(ch.SupportedVersions, 0x0303) {
		ver = "12"
	}
	sni := "i"
	if ch.SNI != "" {
		sni = "d"
	}
	alpn := "00"
	if len(ch.ALPN) > 0 {
		a := ch.ALPN[0]
		if len(a) >= 2 {
			alpn = fmt.Sprintf("%c%c", alpnChar(a[0]), alpnChar(a[len(a)-1]))
		}
	}
	cCount := fmt.Sprintf("%02d", min(countNonGREASE(ch.CipherSuites), 99))
	eCount := fmt.Sprintf("%02d", min(countNonGREASE(ch.ExtensionOrder), 99))

	cipherHash := shortHash(joinNonGREASESorted(ch.CipherSuites))
	extHash := shortHash(joinNonGREASESorted(ch.ExtensionOrder) + "," + joinNonGREASE(sigAlgsNoGREASE(ch)))

	return fmt.Sprintf("%s%s%s%s%s%s_%s_%s", proto, ver, sni, cCount, eCount, alpn, cipherHash, extHash)
}

func alpnChar(b byte) byte {
	if (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') {
		return b
	}
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return '0'
}

func sigAlgsNoGREASE(ch *ClientHello) []uint16 {
	return filterNonGREASE(ch.SignatureAlgs)
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

func joinNonGREASESorted(vals []uint16) string {
	vals = filterNonGREASE(vals)
	// insertion sort to avoid pulling sort pkg noise in hot path examples
	for i := 1; i < len(vals); i++ {
		for j := i; j > 0 && vals[j] < vals[j-1]; j-- {
			vals[j], vals[j-1] = vals[j-1], vals[j]
		}
	}
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, ",")
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

func countNonGREASE(vals []uint16) int {
	n := 0
	for _, v := range vals {
		if !IsGREASE16(v) {
			n++
		}
	}
	return n
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

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
