package dissect

import (
	"fmt"
	"strings"
)

// HTTP/3 frame types (RFC 9114 §7.2) + RFC 9218 PRIORITY_UPDATE.
const (
	H3FrameData        uint64 = 0x00
	H3FrameHeaders     uint64 = 0x01
	H3FrameCancelPush  uint64 = 0x03
	H3FrameSettings    uint64 = 0x04
	H3FramePushPromise uint64 = 0x05
	H3FrameGoAway      uint64 = 0x07
	H3FrameMaxPushID   uint64 = 0x0d
	// RFC 9218 §7.2 — two distinct frame types (not a single 0x0f + element bits).
	H3FramePriorityUpdateRequest uint64 = 0xF0700
	H3FramePriorityUpdatePush    uint64 = 0xF0701
)

// HTTP/3 SETTINGS identifiers (RFC 9114 §7.2.4).
const (
	H3SettingQPACKMaxTableCapacity uint64 = 0x01
	H3SettingMaxFieldSectionSize   uint64 = 0x06
	H3SettingQPACKBlockedStreams   uint64 = 0x07
)

// H3Frame is one HTTP/3 frame on a (typically control or request) stream.
type H3Frame struct {
	Type    uint64
	Length  uint64
	Payload []byte
	Name    string
	Detail  string
	Note    string
	GREASE  bool
}

// H3Setting is one SETTINGS parameter.
type H3Setting struct {
	ID     uint64
	Value  uint64
	Name   string
	Note   string
	GREASE bool
}

// H3PriorityUpdate is an HTTP/3 PRIORITY_UPDATE (RFC 9218 §7.2).
type H3PriorityUpdate struct {
	FrameType   uint64 // 0xF0700 request | 0xF0701 push
	TargetKind  string // "request_stream" | "push_stream"
	TargetID    uint64 // stream ID or push ID
	RawValue    string
	Urgency     *int
	Incremental *bool
	Note        string
}

// H3Session is a dissected sequence of HTTP/3 frames (post-QUIC-decrypt stream bytes).
type H3Session struct {
	Frames          []H3Frame
	Settings        []H3Setting
	PriorityUpdates []*H3PriorityUpdate
	Findings        []string
	Raw             []byte
}

// ParseH3 dissects a sequence of HTTP/3 frames (Type/Length/Payload varints).
// This is stream-payload level — not full QUIC packet parsing. Lab fixtures and
// decrypted captures feed this path; Initial/CRYPTO/1-RTT headers are out of scope.
func ParseH3(b []byte) (*H3Session, error) {
	s := &H3Session{Raw: append([]byte(nil), b...)}
	o := 0
	for o < len(b) {
		typ, n, err := ReadVarint(b[o:])
		if err != nil {
			return s, fmt.Errorf("h3 frame type at %d: %w", o, err)
		}
		o += n
		length, n, err := ReadVarint(b[o:])
		if err != nil {
			return s, fmt.Errorf("h3 frame length at %d: %w", o, err)
		}
		o += n
		if uint64(len(b)-o) < length {
			return s, fmt.Errorf("h3 truncated frame type=0x%x want %d more bytes", typ, int(length)-(len(b)-o))
		}
		payload := append([]byte(nil), b[o:o+int(length)]...)
		o += int(length)
		fr := H3Frame{
			Type:    typ,
			Length:  length,
			Payload: payload,
			Name:    h3FrameName(typ),
			GREASE:  IsH3GREASEFrame(typ),
		}
		annotateH3Frame(s, &fr)
		s.Frames = append(s.Frames, fr)
	}
	s.Findings = h3Findings(s)
	return s, nil
}

func annotateH3Frame(s *H3Session, fr *H3Frame) {
	switch {
	case fr.GREASE:
		fr.Detail = fmt.Sprintf("GREASE type=0x%x payload=%d", fr.Type, len(fr.Payload))
		fr.Note = "HTTP/3 GREASE frame (0x1f·N+0x21) — real Chromium paints these; empty parrot stacks often omit them"
	case fr.Type == H3FrameSettings:
		settings, detail, notes := parseH3Settings(fr.Payload)
		s.Settings = append(s.Settings, settings...)
		fr.Detail = detail
		fr.Note = notes
	case fr.Type == H3FramePriorityUpdateRequest || fr.Type == H3FramePriorityUpdatePush:
		pu, err := ParseH3PriorityUpdate(fr.Type, fr.Payload)
		if err != nil {
			fr.Detail = err.Error()
			fr.Note = "Malformed HTTP/3 PRIORITY_UPDATE"
			return
		}
		s.PriorityUpdates = append(s.PriorityUpdates, pu)
		fr.Detail = fmt.Sprintf("kind=%s id=%d value=%q", pu.TargetKind, pu.TargetID, pu.RawValue)
		if pu.Urgency != nil {
			fr.Detail += fmt.Sprintf(" urgency=%d", *pu.Urgency)
		}
		if pu.Incremental != nil {
			fr.Detail += fmt.Sprintf(" incremental=%v", *pu.Incremental)
		}
		fr.Note = pu.Note
	case fr.Type == H3FrameHeaders:
		fr.Detail = fmt.Sprintf("QPACK section %d bytes (decoder not in this lab)", len(fr.Payload))
		fr.Note = "HTTP/3 HEADERS carry QPACK — different entropy surface than HPACK; order still matters after decode"
	case fr.Type == H3FrameData:
		fr.Detail = fmt.Sprintf("%d bytes", len(fr.Payload))
	case fr.Type == H3FrameGoAway:
		if id, _, err := ReadVarint(fr.Payload); err == nil {
			fr.Detail = fmt.Sprintf("id=%d", id)
		}
		fr.Note = "Client GOAWAY on control stream is unusual mid-handshake"
	default:
		fr.Detail = fmt.Sprintf("%d bytes", len(fr.Payload))
		if fr.Type == 0x0f {
			fr.Note = "Frame type 0x0f is NOT RFC 9218 PRIORITY_UPDATE — final spec uses 0xF0700 / 0xF0701 (draft residue smell)"
		}
	}
}

// ParseH3PriorityUpdate parses PRIORITY_UPDATE payload (RFC 9218 §7.2).
// Payload = Prioritized Element ID (varint) + Priority Field Value (ASCII).
func ParseH3PriorityUpdate(frameType uint64, payload []byte) (*H3PriorityUpdate, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("h3 priority_update: empty payload")
	}
	id, n, err := ReadVarint(payload)
	if err != nil {
		return nil, fmt.Errorf("h3 priority_update id: %w", err)
	}
	pu := &H3PriorityUpdate{
		FrameType: frameType,
		TargetID:  id,
		RawValue:  string(payload[n:]),
	}
	switch frameType {
	case H3FramePriorityUpdateRequest:
		pu.TargetKind = "request_stream"
		pu.Note = "PRIORITY_UPDATE type=0xF0700 (request stream) — MUST be sent on the control stream (RFC 9218)"
		// Client-initiated bidirectional QUIC streams: id % 4 == 0 (0, 4, 8, …).
		if id%4 != 0 {
			pu.Note += fmt.Sprintf("; id=%d is not client-bidi (%%4==0) — H3_ID_ERROR candidate", id)
		}
	case H3FramePriorityUpdatePush:
		pu.TargetKind = "push_stream"
		pu.Note = "PRIORITY_UPDATE type=0xF0701 (push) — rare when ENABLE push is unused"
	default:
		pu.TargetKind = fmt.Sprintf("unknown_0x%x", frameType)
		pu.Note = "Unexpected PRIORITY_UPDATE frame type"
	}
	tmp := &PriorityUpdate{RawValue: pu.RawValue}
	parsePriorityStructured(tmp)
	pu.Urgency = tmp.Urgency
	pu.Incremental = tmp.Incremental
	return pu, nil
}

func parseH3Settings(payload []byte) ([]H3Setting, string, string) {
	var out []H3Setting
	var parts []string
	o := 0
	for o < len(payload) {
		id, n, err := ReadVarint(payload[o:])
		if err != nil {
			break
		}
		o += n
		val, n, err := ReadVarint(payload[o:])
		if err != nil {
			break
		}
		o += n
		st := H3Setting{ID: id, Value: val, Name: h3SettingName(id), GREASE: IsH3GREASESetting(id)}
		st.Note = h3SettingNote(st)
		out = append(out, st)
		if st.GREASE {
			parts = append(parts, fmt.Sprintf("GREASE(0x%x)=%d", id, val))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%d", st.Name, val))
		}
	}
	note := "HTTP/3 SETTINGS — no ENABLE_PUSH / INITIAL_WINDOW_SIZE / NO_RFC7540_PRIORITIES; those are H2-only tells"
	return out, strings.Join(parts, ", "), note
}

// IsH3GREASEFrame reports HTTP/3 GREASE frame types (RFC 9114 §7.2.8): 0x1f·N + 0x21.
func IsH3GREASEFrame(t uint64) bool {
	return t >= 0x21 && (t-0x21)%0x1f == 0
}

// IsH3GREASESetting reports HTTP/3 GREASE setting identifiers (RFC 9114 §7.2.4.1).
func IsH3GREASESetting(id uint64) bool {
	return id >= 0x21 && (id-0x21)%0x1f == 0
}

func h3FrameName(t uint64) string {
	if IsH3GREASEFrame(t) {
		return fmt.Sprintf("GREASE(0x%x)", t)
	}
	switch t {
	case H3FrameData:
		return "DATA"
	case H3FrameHeaders:
		return "HEADERS"
	case H3FrameCancelPush:
		return "CANCEL_PUSH"
	case H3FrameSettings:
		return "SETTINGS"
	case H3FramePushPromise:
		return "PUSH_PROMISE"
	case H3FrameGoAway:
		return "GOAWAY"
	case H3FrameMaxPushID:
		return "MAX_PUSH_ID"
	case H3FramePriorityUpdateRequest:
		return "PRIORITY_UPDATE(request)"
	case H3FramePriorityUpdatePush:
		return "PRIORITY_UPDATE(push)"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", t)
	}
}

func h3SettingName(id uint64) string {
	if IsH3GREASESetting(id) {
		return fmt.Sprintf("GREASE(0x%x)", id)
	}
	switch id {
	case H3SettingQPACKMaxTableCapacity:
		return "QPACK_MAX_TABLE_CAPACITY"
	case H3SettingMaxFieldSectionSize:
		return "MAX_FIELD_SECTION_SIZE"
	case H3SettingQPACKBlockedStreams:
		return "QPACK_BLOCKED_STREAMS"
	default:
		return fmt.Sprintf("SETTING_0x%x", id)
	}
}

func h3SettingNote(st H3Setting) string {
	if st.GREASE {
		return "GREASE setting — browsers send reserved ids; impersonators that only emit 0x1/0x6/0x7 stand out"
	}
	switch st.ID {
	case H3SettingQPACKMaxTableCapacity:
		return "QPACK dynamic table budget (H3 analogue of HPACK HEADER_TABLE_SIZE)"
	case H3SettingMaxFieldSectionSize:
		return "Max decompressed header size (similar role to H2 MAX_HEADER_LIST_SIZE)"
	case H3SettingQPACKBlockedStreams:
		return "How many streams may block on QPACK — Chromium typically non-zero"
	default:
		return ""
	}
}

// PriorityFingerprint returns a compact field analogous to H2 Akamai field 3.
func (s *H3Session) PriorityFingerprint() string {
	if len(s.PriorityUpdates) == 0 {
		return "0"
	}
	parts := make([]string, 0, len(s.PriorityUpdates))
	for _, pu := range s.PriorityUpdates {
		v := strings.ReplaceAll(strings.TrimSpace(pu.RawValue), " ", "")
		parts = append(parts, fmt.Sprintf("%s:%d:%s", pu.TargetKind, pu.TargetID, v))
	}
	return strings.Join(parts, ";")
}

func h3Findings(s *H3Session) []string {
	var out []string
	out = append(out, "HTTP/3 frames parsed at stream-payload layer (QUIC packet headers not required for this lab)")
	hasPU := len(s.PriorityUpdates) > 0
	hasGreaseFrame := false
	hasGreaseSetting := false
	for _, fr := range s.Frames {
		if fr.GREASE {
			hasGreaseFrame = true
		}
		if fr.Type == 0x0f {
			out = append(out, "Saw frame type 0x0f — draft-era PRIORITY_UPDATE; final RFC 9218 uses 0xF0700/0xF0701")
		}
	}
	for _, st := range s.Settings {
		if st.GREASE {
			hasGreaseSetting = true
		}
	}
	if hasPU {
		out = append(out, "PRIORITY_UPDATE present — Extensible Prioritization is native on HTTP/3 (no NO_RFC7540_PRIORITIES setting exists)")
	} else {
		out = append(out, "No PRIORITY_UPDATE — some H3 clients omit urgency until a second request; Chrome navigations usually send u=/i")
	}
	if hasGreaseFrame {
		out = append(out, "GREASE frame type(s) observed — strong Chromium/QUIC identity signal")
	} else {
		out = append(out, "No GREASE frames — many naive H3 stacks forget 0x1f·N+0x21")
	}
	if hasGreaseSetting {
		out = append(out, "GREASE SETTINGS id(s) observed")
	}
	for _, pu := range s.PriorityUpdates {
		if pu.FrameType == H3FramePriorityUpdateRequest && pu.TargetID%4 != 0 {
			out = append(out, fmt.Sprintf("request PRIORITY_UPDATE id=%d is not client-bidi (id%%4==0) — H3_ID_ERROR smell", pu.TargetID))
		}
	}
	out = append(out, "Contrast Lab 07: H2 PRIORITY_UPDATE type=0x10 + header stream id 0; H3 uses type 0xF0700/0xF0701 on the control stream with a stream/push id varint")
	return out
}

// AppendH3Frame appends Type(i) Length(i) Payload to dst.
func AppendH3Frame(dst []byte, typ uint64, payload []byte) []byte {
	dst = AppendVarint(dst, typ)
	dst = AppendVarint(dst, uint64(len(payload)))
	return append(dst, payload...)
}
