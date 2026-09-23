package dissect

import "fmt"

// GREASE values follow draft-ietf-tls-grease: 0x?a?a pattern.
// Detectors that ignore GREASE collapse randomized Chrome hellos into one class;
// detectors that track GREASE placement/order gain entropy.

func IsGREASE16(v uint16) bool {
	// draft-ietf-tls-grease: 0x0A0A, 0x1A1A, … 0xFAFA
	return v&0x0f0f == 0x0a0a
}

func IsGREASE8(v uint8) bool {
	return v&0x0f == 0x0a
}

func greaseNote(kind string, v uint16) string {
	if !IsGREASE16(v) {
		return ""
	}
	return fmt.Sprintf("%s 0x%04x is GREASE — must be ignored for stable JA3-class hashes, but placement/order is itself a fingerprint signal", kind, v)
}
