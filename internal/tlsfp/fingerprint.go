package tlsfp

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ClientHelloSpecFromProfile maps profile utls_client_id to uTLS hello spec.
func ClientHelloID(clientID string) utls.ClientHelloID {
	switch strings.ToLower(clientID) {
	case "chrome_133", "chrome-133":
		return utls.HelloChrome_133
	case "chrome_132", "chrome-132":
		// No dedicated Chrome 132 parrot in uTLS; 131 is the closest.
		return utls.HelloChrome_131
	case "chrome_131", "chrome-131":
		return utls.HelloChrome_131
	case "chrome_120", "chrome-120":
		return utls.HelloChrome_120
	case "firefox_120", "firefox-120", "firefox_133", "firefox-133":
		return utls.HelloFirefox_Auto
	case "safari_16_0", "safari-16", "safari_18", "safari-18":
		return utls.HelloSafari_Auto
	case "safari_ios_18", "safari-ios-18", "ios_14", "ios-14":
		return utls.HelloIOS_Auto
	case "edge_106", "edge-106":
		return utls.HelloEdge_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// JA3 computes JA3 hash from a uTLS ClientHelloSpec fingerprint string components.
func JA3(version uint16, cipherSuites []uint16, extensions []uint16, groups []utls.CurveID, points []uint8) string {
	parts := []string{
		strconv.Itoa(int(version)),
		joinUint16(cipherSuites),
		joinUint16(extensions),
		joinCurveIDs(groups),
		joinUint8(points),
	}
	raw := strings.Join(parts, ",")
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// JA4 produces a simplified JA4-like fingerprint from ClientHello metadata.
func JA4(version uint16, sni string, cipherSuites []uint16, extensions []uint16) string {
	proto := "t"
	if sni != "" {
		proto = "d"
	}
	ver := fmt.Sprintf("%02d%02d", version>>8, version&0xff)
	cCount := fmt.Sprintf("%02d", min(len(cipherSuites), 99))
	eCount := fmt.Sprintf("%02d", min(len(extensions), 99))
	first := fmt.Sprintf("%s%s%s%s", proto, ver, cCount, eCount)
	h := sha256.Sum256([]byte(first + sni))
	return first + "_" + hex.EncodeToString(h[:6])
}

func joinUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, "-")
}

func joinCurveIDs(vals []utls.CurveID) string {
	if len(vals) == 0 {
		return ""
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, "-")
}

func joinUint8(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	strs := make([]string, len(vals))
	for i, v := range vals {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, "-")
}

// VersionString returns human-readable TLS version.
func VersionString(v uint16) string {
	switch v {
	case utls.VersionTLS10:
		return "TLS 1.0"
	case utls.VersionTLS11:
		return "TLS 1.1"
	case utls.VersionTLS12:
		return "TLS 1.2"
	case utls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// CipherSuiteName best-effort cipher name.
func CipherSuiteName(id uint16) string {
	for _, cs := range utls.CipherSuites() {
		if cs.ID == id {
			return cs.Name
		}
	}
	return fmt.Sprintf("0x%04x", id)
}

// FingerprintFromHelloID returns JA3/JA4 hints for a client hello id.
func FingerprintFromHelloID(id utls.ClientHelloID) (ja3, ja4 string) {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		return "", ""
	}
	version := spec.TLSVersMax
	if version == 0 {
		version = utls.VersionTLS13
	}
	ja3 = JA3(version, spec.CipherSuites, nil, nil, []uint8{0})
	ja4 = JA4(version, "example.com", spec.CipherSuites, nil)
	return ja3, ja4
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
