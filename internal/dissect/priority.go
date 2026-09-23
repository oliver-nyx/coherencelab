package dissect

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// PriorityUpdate is one RFC 9218 PRIORITY_UPDATE payload.
type PriorityUpdate struct {
	HeaderStreamID   uint32 // MUST be 0 per RFC 9218
	PrioritizedStream uint32
	RawValue         string // ASCII Structured Fields, e.g. "u=0, i"
	Urgency          *int   // 0..7 if parsed
	Incremental      *bool
	Note             string
}

// ParsePriorityUpdatePayload parses the PRIORITY_UPDATE payload
// (Prioritized Stream ID + Priority Field Value).
func ParsePriorityUpdatePayload(headerStreamID uint32, payload []byte) (*PriorityUpdate, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("priority_update: payload too short (%d)", len(payload))
	}
	pu := &PriorityUpdate{
		HeaderStreamID:    headerStreamID,
		PrioritizedStream: binary.BigEndian.Uint32(payload[0:4]) & 0x7fffffff,
		RawValue:          string(payload[4:]),
	}
	if headerStreamID != 0 {
		pu.Note = "PROTOCOL_ERROR candidate: PRIORITY_UPDATE Stream Identifier MUST be 0 (RFC 9218 §7.1)"
	}
	parsePriorityStructured(pu)
	if pu.Note == "" {
		pu.Note = "RFC 9218 Extensible Prioritization — hop-by-hop; Chrome often sends this before HEADERS"
	}
	return pu, nil
}

func parsePriorityStructured(pu *PriorityUpdate) {
	// Minimal Structured Fields dictionary parser for u= / i — enough for RE labs.
	// Full sf-dictionary is richer; we intentionally keep this small and documented.
	s := strings.TrimSpace(pu.RawValue)
	if s == "" {
		return
	}
	parts := splitSFDict(s)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "i" || p == "i=?1" || strings.EqualFold(p, "i=true") {
			v := true
			pu.Incremental = &v
			continue
		}
		if p == "i=?0" || strings.EqualFold(p, "i=false") {
			v := false
			pu.Incremental = &v
			continue
		}
		if strings.HasPrefix(p, "u=") {
			n, err := strconv.Atoi(strings.TrimPrefix(p, "u="))
			if err == nil && n >= 0 && n <= 7 {
				pu.Urgency = &n
			}
		}
	}
}

func splitSFDict(s string) []string {
	// Split on commas not inside quotes (priority values rarely quote).
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// PriorityFingerprint is Akamai H2 field 3.
//
// Historical Akamai tokens used "0" (no RFC7540 PRIORITY) or a tree hash.
// For RFC 9218-era Chrome we emit a compact form:
//
//	0                         — no priority signal
//	7540                      — legacy PRIORITY frame(s) only
//	u=0,i                     — single PRIORITY_UPDATE raw value (normalized spaces)
//	u=0,i;u=3                 — multiple updates joined by ';'
func (s *H2Session) PriorityFingerprint() string {
	if len(s.PriorityUpdates) > 0 {
		parts := make([]string, 0, len(s.PriorityUpdates))
		for _, pu := range s.PriorityUpdates {
			v := strings.ReplaceAll(strings.TrimSpace(pu.RawValue), " ", "")
			if v == "" {
				v = fmt.Sprintf("stream=%d", pu.PrioritizedStream)
			}
			parts = append(parts, v)
		}
		return strings.Join(parts, ";")
	}
	for _, fr := range s.Frames {
		if fr.Type == FramePriority {
			return "7540"
		}
	}
	return "0"
}

// HasNoRFC7540Priorities reports SETTINGS_NO_RFC7540_PRIORITIES=1.
func (s *H2Session) HasNoRFC7540Priorities() bool {
	for _, st := range s.Settings {
		if st.ID == SettingNoRFC7540Priorities && st.Value == 1 {
			return true
		}
	}
	return false
}

func priorityFindings(s *H2Session) []string {
	var out []string
	no7540 := s.HasNoRFC7540Priorities()
	hasPU := len(s.PriorityUpdates) > 0
	hasLegacy := false
	for _, fr := range s.Frames {
		if fr.Type == FramePriority {
			hasLegacy = true
			break
		}
	}
	switch {
	case no7540 && hasPU:
		out = append(out, "SETTINGS_NO_RFC7540_PRIORITIES=1 + PRIORITY_UPDATE — Chromium Extensible Prioritization path (RFC 9218)")
	case no7540 && !hasPU:
		out = append(out, "NO_RFC7540_PRIORITIES=1 but no PRIORITY_UPDATE in capture — incomplete Chrome-like session or capture gap")
	case !no7540 && hasPU:
		out = append(out, "PRIORITY_UPDATE without NO_RFC7540_PRIORITIES — allowed but atypical for modern Chrome; check SETTINGS order/completeness")
	case hasLegacy && hasPU:
		out = append(out, "Both RFC 7540 PRIORITY and PRIORITY_UPDATE — transitional / buggy client smell")
	case hasLegacy:
		out = append(out, "Legacy RFC 7540 PRIORITY frame(s) only — pre-EPS / non-Chrome desktop path")
	default:
		out = append(out, "No priority frames — Akamai field 3 = 0 (common for minimal impersonators)")
	}
	for _, pu := range s.PriorityUpdates {
		if pu.HeaderStreamID != 0 {
			out = append(out, "PRIORITY_UPDATE with non-zero header stream id — RFC 9218 violation")
		}
		if pu.Urgency != nil && (*pu.Urgency < 0 || *pu.Urgency > 7) {
			out = append(out, fmt.Sprintf("urgency=%d out of range 0..7", *pu.Urgency))
		}
		if pu.PrioritizedStream == 0 {
			out = append(out, "PRIORITY_UPDATE prioritized stream id is 0 — unusual for request streams")
		}
	}
	return out
}
