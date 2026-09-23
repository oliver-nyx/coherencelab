package dissect

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// H2 frame types (RFC 7540 / 9113).
const (
	FrameData         uint8 = 0x0
	FrameHeaders      uint8 = 0x1
	FramePriority     uint8 = 0x2
	FrameRSTStream    uint8 = 0x3
	FrameSettings     uint8 = 0x4
	FramePushPromise  uint8 = 0x5
	FramePing         uint8 = 0x6
	FrameGoAway       uint8 = 0x7
	FrameWindowUpdate uint8 = 0x8
	FrameContinuation uint8 = 0x9
	FramePriorityUpdate uint8 = 0x10 // RFC 9218
)

// H2Setting IDs.
const (
	SettingHeaderTableSize      uint16 = 0x1
	SettingEnablePush           uint16 = 0x2
	SettingMaxConcurrentStreams uint16 = 0x3
	SettingInitialWindowSize    uint16 = 0x4
	SettingMaxFrameSize         uint16 = 0x5
	SettingMaxHeaderListSize    uint16 = 0x6
	SettingEnableConnect        uint16 = 0x8
	SettingNoRFC7540Priorities  uint16 = 0x9
)

// Frame is one HTTP/2 frame with teaching annotations.
type Frame struct {
	Length  uint32
	Type    uint8
	Flags   uint8
	Stream  uint32
	Payload []byte
	Name    string
	Note    string
	Detail  string
}

// H2Session is a dissected client preface + frame sequence.
type H2Session struct {
	HasPreface    bool
	Frames        []Frame
	Settings      []H2Setting
	WindowUpdates []WindowUpdate
	HeaderBlock   *HeaderBlock
	HeaderBlocks  []*HeaderBlock
	Findings      []string
	Raw           []byte
}

// H2Setting is one SETTINGS parameter.
type H2Setting struct {
	ID    uint16
	Value uint32
	Name  string
	Note  string
}

// WindowUpdate is a WINDOW_UPDATE payload.
type WindowUpdate struct {
	StreamID      uint32
	Increment     uint32
	ConnectionLvl bool
}

// ParseH2 dissects an HTTP/2 client preface (optional) followed by frames.
func ParseH2(b []byte) (*H2Session, error) {
	s := &H2Session{Raw: append([]byte(nil), b...)}
	o := 0
	const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if len(b) >= len(preface) && string(b[:len(preface)]) == preface {
		s.HasPreface = true
		o = len(preface)
	}
	for o+9 <= len(b) {
		length := uint32(b[o])<<16 | uint32(b[o+1])<<8 | uint32(b[o+2])
		typ := b[o+3]
		flags := b[o+4]
		stream := binary.BigEndian.Uint32(b[o+5:o+9]) & 0x7fffffff
		o += 9
		if o+int(length) > len(b) {
			return s, fmt.Errorf("dissect: truncated frame type=0x%02x want %d more bytes", typ, int(length)-(len(b)-o))
		}
		payload := append([]byte(nil), b[o:o+int(length)]...)
		o += int(length)
		fr := Frame{
			Length:  length,
			Type:    typ,
			Flags:   flags,
			Stream:  stream,
			Payload: payload,
			Name:    frameName(typ),
		}
		annotateFrame(s, &fr)
		s.Frames = append(s.Frames, fr)
	}
	assembleHeaderBlocks(s)
	s.Findings = h2Findings(s)
	if s.HeaderBlock != nil {
		s.Findings = append(s.Findings, s.HeaderBlock.Findings...)
	}
	return s, nil
}

func annotateFrame(s *H2Session, fr *Frame) {
	switch fr.Type {
	case FrameSettings:
		ack := fr.Flags&0x1 != 0
		if ack {
			fr.Detail = "ACK"
			fr.Note = "SETTINGS ACK carries no payload. A client that ACKs before sending its own SETTINGS is malformed."
			return
		}
		if len(fr.Payload)%6 != 0 {
			fr.Detail = "malformed settings payload"
			fr.Note = "Each setting is 6 bytes (id:u16, value:u32). Length%%6!=0 is a protocol error — or a broken impersonator."
			return
		}
		var parts []string
		for i := 0; i+6 <= len(fr.Payload); i += 6 {
			id := binary.BigEndian.Uint16(fr.Payload[i : i+2])
			val := binary.BigEndian.Uint32(fr.Payload[i+2 : i+6])
			st := H2Setting{ID: id, Value: val, Name: settingName(id), Note: settingNote(id, val)}
			s.Settings = append(s.Settings, st)
			parts = append(parts, fmt.Sprintf("%s=%d", st.Name, val))
		}
		fr.Detail = strings.Join(parts, ", ")
		fr.Note = "Client SETTINGS is one of the strongest HTTP fingerprint surfaces. Chrome: ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=6291456. Firefox differs on HEADER_TABLE_SIZE and window."
	case FrameWindowUpdate:
		if len(fr.Payload) != 4 {
			fr.Detail = "bad window_update length"
			return
		}
		inc := binary.BigEndian.Uint32(fr.Payload) & 0x7fffffff
		wu := WindowUpdate{StreamID: fr.Stream, Increment: inc, ConnectionLvl: fr.Stream == 0}
		s.WindowUpdates = append(s.WindowUpdates, wu)
		fr.Detail = fmt.Sprintf("increment=%d stream=%d", inc, fr.Stream)
		fr.Note = "Connection-level WINDOW_UPDATE right after preface is a browser tell (often 15663105 for Chromium). Naive stacks skip it."
	case FramePriority:
		fr.Note = "RFC 7540 PRIORITY on headers is obsolete in browsers migrating to RFC 9218 PRIORITY_UPDATE / NO_RFC7540_PRIORITIES."
		fr.Detail = fmt.Sprintf("%d bytes", len(fr.Payload))
	case FramePriorityUpdate:
		fr.Note = "RFC 9218 PRIORITY_UPDATE — Chromium ships this. Absence on a Chrome claim is a coherence failure at the H2 layer."
		fr.Detail = string(fr.Payload)
	case FrameHeaders:
		fr.Detail = fmt.Sprintf("flags=0x%02x payload=%d bytes", fr.Flags, len(fr.Payload))
		if fr.Flags&0x4 == 0 {
			fr.Note = "END_HEADERS unset — CONTINUATION frames must follow immediately on this stream (RFC 9113)"
		} else {
			fr.Note = "Single-frame header block (END_HEADERS set)"
		}
	case FrameContinuation:
		fr.Detail = fmt.Sprintf("flags=0x%02x payload=%d bytes", fr.Flags, len(fr.Payload))
		fr.Note = "CONTINUATION carries more HPACK bytes; must be contiguous after HEADERS. Detectors that only parse the first HEADERS frame miss fields / mis-order pseudos."
	case FramePing:
		fr.Note = "PING early in the session can be a middlebox/keepalive tell; browsers rarely PING first."
	case FrameGoAway:
		fr.Note = "Client-sent GOAWAY before request is abnormal."
	}
}

func h2Findings(s *H2Session) []string {
	var out []string
	if s.HasPreface {
		out = append(out, "Valid client connection preface (PRI * HTTP/2.0…)")
	} else {
		out = append(out, "No client preface at buffer start — capture may be mid-stream or server-side")
	}
	var enablePush *uint32
	var initWin *uint32
	var headerTable *uint32
	for _, st := range s.Settings {
		v := st.Value
		switch st.ID {
		case SettingEnablePush:
			enablePush = &v
		case SettingInitialWindowSize:
			initWin = &v
		case SettingHeaderTableSize:
			headerTable = &v
		}
	}
	if enablePush != nil {
		if *enablePush == 0 {
			out = append(out, "ENABLE_PUSH=0 — Chromium/Firefox modern default; ENABLE_PUSH=1 is a classic Go/net or old stack leak")
		} else {
			out = append(out, "ENABLE_PUSH=1 — uncommon for desktop Chrome; investigate stack")
		}
	}
	if initWin != nil {
		switch *initWin {
		case 6291456:
			out = append(out, "INITIAL_WINDOW_SIZE=6291456 — Chromium signature value")
		case 131072:
			out = append(out, "INITIAL_WINDOW_SIZE=131072 — common Firefox ballpark")
		case 65535:
			out = append(out, "INITIAL_WINDOW_SIZE=65535 — HTTP/2 default; often means the client never overrode SETTINGS (impersonation smell)")
		default:
			out = append(out, fmt.Sprintf("INITIAL_WINDOW_SIZE=%d — compare against browser corpus", *initWin))
		}
	}
	if headerTable != nil {
		switch *headerTable {
		case 65536:
			out = append(out, "HEADER_TABLE_SIZE=65536 — Chromium-like")
		case 4096:
			out = append(out, "HEADER_TABLE_SIZE=4096 — HTTP/2 default / some Safari paths")
		}
	}
	for _, wu := range s.WindowUpdates {
		if wu.ConnectionLvl && wu.Increment == 15663105 {
			out = append(out, "Connection WINDOW_UPDATE increment=15663105 — well-known Chromium post-preface behavior")
		}
	}
	for _, fr := range s.Frames {
		if fr.Type == FramePriorityUpdate {
			out = append(out, "PRIORITY_UPDATE observed — RFC 9218 path (Chromium)")
			break
		}
	}
	for _, fr := range s.Frames {
		if fr.Type == FrameContinuation {
			out = append(out, "CONTINUATION present — header block was fragmented; naive parsers that ignore CONTINUATION will mis-decode HPACK")
			break
		}
	}
	return out
}

func frameName(t uint8) string {
	switch t {
	case FrameData:
		return "DATA"
	case FrameHeaders:
		return "HEADERS"
	case FramePriority:
		return "PRIORITY"
	case FrameRSTStream:
		return "RST_STREAM"
	case FrameSettings:
		return "SETTINGS"
	case FramePushPromise:
		return "PUSH_PROMISE"
	case FramePing:
		return "PING"
	case FrameGoAway:
		return "GOAWAY"
	case FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case FrameContinuation:
		return "CONTINUATION"
	case FramePriorityUpdate:
		return "PRIORITY_UPDATE"
	default:
		return fmt.Sprintf("UNKNOWN_0x%02x", t)
	}
}

func settingName(id uint16) string {
	switch id {
	case SettingHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case SettingEnablePush:
		return "ENABLE_PUSH"
	case SettingMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case SettingInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case SettingMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case SettingMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	case SettingEnableConnect:
		return "ENABLE_CONNECT_PROTOCOL"
	case SettingNoRFC7540Priorities:
		return "NO_RFC7540_PRIORITIES"
	default:
		return fmt.Sprintf("UNKNOWN_0x%04x", id)
	}
}

func settingNote(id uint16, val uint32) string {
	switch id {
	case SettingEnablePush:
		return "0 = push disabled (browsers). 1 = often a non-browser stack."
	case SettingInitialWindowSize:
		return "Chromium 6291456 vs default 65535 is a primary H2 identity check."
	case SettingHeaderTableSize:
		return "HPACK dynamic table budget; Chromium favors 65536."
	case SettingNoRFC7540Priorities:
		return "Signals RFC 9218 priority scheme; Chromium sets this."
	default:
		return ""
	}
}

// extractHeaderFragment strips PADDED/PRIORITY framing from a HEADERS payload.
// Does not require END_HEADERS — CONTINUATION may follow.
func extractHeaderFragment(fr *Frame) (block []byte, note string) {
	p := fr.Payload
	o := 0
	if fr.Flags&0x8 != 0 { // PADDED
		if len(p) < 1 {
			return nil, "PADDED flag set but no pad length"
		}
		pad := int(p[0])
		o = 1
		if o+pad > len(p) {
			return nil, "invalid padding"
		}
		p = p[:len(p)-pad]
	}
	if fr.Flags&0x20 != 0 { // PRIORITY
		if o+5 > len(p) {
			return nil, "PRIORITY flag set but truncated"
		}
		o += 5
		note = "RFC 7540 PRIORITY dependency present on HEADERS (legacy path)"
	}
	return p[o:], note
}

// assembleHeaderBlocks merges HEADERS + contiguous CONTINUATION frames and
// runs HPACK. This is the RFC 9113 rule many fingerprint tools get wrong.
func assembleHeaderBlocks(s *H2Session) {
	for i := 0; i < len(s.Frames); i++ {
		fr := &s.Frames[i]
		if fr.Type != FrameHeaders {
			continue
		}
		frag, note := extractHeaderFragment(fr)
		if frag == nil && note != "" {
			fr.Note = note
			continue
		}
		contCount := 0
		end := fr.Flags&0x4 != 0
		j := i + 1
		for !end && j < len(s.Frames) {
			cf := &s.Frames[j]
			if cf.Type != FrameContinuation || cf.Stream != fr.Stream {
				fr.Detail = "header block incomplete — next frame is not CONTINUATION on same stream (protocol error / capture gap)"
				fr.Note = "RFC 9113: a HEADERS without END_HEADERS must be followed by CONTINUATION on the same stream with no frames in between"
				break
			}
			frag = append(frag, cf.Payload...)
			contCount++
			end = cf.Flags&0x4 != 0
			cf.Detail = fmt.Sprintf("merged into HEADERS @ frame %d (%d bytes)", i+1, len(cf.Payload))
			cf.Note = "CONTINUATION fragment — HPACK state spans frames; order of fields is still encoder order across the merge"
			j++
		}
		if !end {
			continue
		}
		hb, err := DecodeHeaderBlock(frag)
		if err != nil {
			fr.Detail = fmt.Sprintf("HPACK error after merging %d CONTINUATION: %v", contCount, err)
			fr.Note = "Merged header block failed HPACK decode"
			continue
		}
		s.HeaderBlocks = append(s.HeaderBlocks, hb)
		if s.HeaderBlock == nil {
			s.HeaderBlock = hb
		}
		fr.Detail = fmt.Sprintf("pseudo=%s family≈%s fields=%d continuations=%d", hb.PseudoOrder, hb.FamilyGuess, len(hb.Fields), contCount)
		fr.Note = "HPACK preserves encoder field order across CONTINUATION merges. Pseudo-header order is a stable browser-family fingerprint."
		if note != "" {
			fr.Note = note + " — " + fr.Note
		}
		if contCount > 0 {
			s.Findings = append(s.Findings, fmt.Sprintf("Merged HEADERS + %d CONTINUATION frame(s) before HPACK decode", contCount))
		}
		i = j - 1
	}
}

