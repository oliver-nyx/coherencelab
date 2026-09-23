package dissect

import "fmt"

// QUIC frame types used in Initial payloads (RFC 9000 §19).
const (
	QUICFramePadding = 0x00
	QUICFramePing    = 0x01
	QUICFrameCRYPTO  = 0x06
	QUICFrameACK     = 0x02
	QUICFrameConnectionClose = 0x1c
)

// QUICFrame is one frame from a decrypted packet payload.
type QUICFrame struct {
	Type    uint64
	Name    string
	Detail  string
	Offset  uint64 // CRYPTO
	Data    []byte // CRYPTO crypto data
	RawLen  int
}

// ParseQUICFrames walks a decrypted QUIC packet payload.
func ParseQUICFrames(b []byte) []QUICFrame {
	var out []QUICFrame
	o := 0
	for o < len(b) {
		start := o
		typ, n, err := ReadVarint(b[o:])
		if err != nil {
			out = append(out, QUICFrame{Name: "truncated", Detail: err.Error(), RawLen: len(b) - start})
			break
		}
		o += n
		fr := QUICFrame{Type: typ, Name: quicFrameName(typ)}
		switch typ {
		case QUICFramePadding:
			// coalesce padding run
			for o < len(b) && b[o] == 0x00 {
				o++
			}
			fr.Detail = fmt.Sprintf("%d bytes", o-start)
		case QUICFramePing:
			fr.Detail = "PING"
		case QUICFrameCRYPTO:
			off, n, err := ReadVarint(b[o:])
			if err != nil {
				fr.Detail = err.Error()
				out = append(out, fr)
				return out
			}
			o += n
			length, n, err := ReadVarint(b[o:])
			if err != nil {
				fr.Detail = err.Error()
				out = append(out, fr)
				return out
			}
			o += n
			if uint64(len(b)-o) < length {
				fr.Detail = "truncated CRYPTO"
				out = append(out, fr)
				return out
			}
			fr.Offset = off
			fr.Data = append([]byte(nil), b[o:o+int(length)]...)
			fr.Detail = fmt.Sprintf("offset=%d len=%d", off, length)
			o += int(length)
		default:
			// Best-effort skip unknown frames that use length-prefixed shapes is unsafe;
			// stop so we don't desync.
			fr.Detail = fmt.Sprintf("unhandled type=0x%x — remaining %d bytes not parsed", typ, len(b)-o)
			fr.RawLen = len(b) - start
			out = append(out, fr)
			return out
		}
		fr.RawLen = o - start
		out = append(out, fr)
	}
	return out
}

func quicFrameName(t uint64) string {
	switch t {
	case QUICFramePadding:
		return "PADDING"
	case QUICFramePing:
		return "PING"
	case QUICFrameCRYPTO:
		return "CRYPTO"
	case QUICFrameACK, QUICFrameACK + 1:
		return "ACK"
	case QUICFrameConnectionClose, QUICFrameConnectionClose + 1:
		return "CONNECTION_CLOSE"
	default:
		return fmt.Sprintf("FRAME_0x%x", t)
	}
}

func gatherCRYPTO(frames []QUICFrame) []byte {
	// Best-effort: concatenate in offset order for contiguous ClientHello.
	type piece struct {
		off  uint64
		data []byte
	}
	var pieces []piece
	var maxEnd uint64
	for _, fr := range frames {
		if fr.Type != QUICFrameCRYPTO || len(fr.Data) == 0 {
			continue
		}
		pieces = append(pieces, piece{off: fr.Offset, data: fr.Data})
		end := fr.Offset + uint64(len(fr.Data))
		if end > maxEnd {
			maxEnd = end
		}
	}
	if maxEnd == 0 {
		return nil
	}
	buf := make([]byte, maxEnd)
	for _, p := range pieces {
		copy(buf[p.off:], p.data)
	}
	return buf
}
