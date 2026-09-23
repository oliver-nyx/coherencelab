package dissect

import (
	"encoding/binary"
	"fmt"
)

// TLS extension type for QUIC transport parameters (RFC 9001 §8.2).
const ExtQUICTransportParameters uint16 = 0x39

// Common transport parameter IDs (RFC 9000 §18.2).
const (
	TPOriginalDestinationConnectionID uint64 = 0x00
	TPMaxIdleTimeout                  uint64 = 0x01
	TPStatelessResetToken             uint64 = 0x02
	TPMaxUDPPayloadSize               uint64 = 0x03
	TPInitialMaxData                  uint64 = 0x04
	TPInitialMaxStreamDataBidiLocal   uint64 = 0x05
	TPInitialMaxStreamDataBidiRemote  uint64 = 0x06
	TPInitialMaxStreamDataUni         uint64 = 0x07
	TPInitialMaxStreamsBidi           uint64 = 0x08
	TPInitialMaxStreamsUni            uint64 = 0x09
	TPAckDelayExponent                uint64 = 0x0a
	TPMaxAckDelay                     uint64 = 0x0b
	TPDisableActiveMigration          uint64 = 0x0c
	TPPreferredAddress                uint64 = 0x0d
	TPActiveConnectionIDLimit         uint64 = 0x0e
	TPInitialSourceConnectionID       uint64 = 0x0f
	TPRetrySourceConnectionID         uint64 = 0x10
	TPMaxDatagramFrameSize            uint64 = 0x20 // RFC 9221
	TPGreaseQUICBit                   uint64 = 0x2ab2
)

// TransportParam is one QUIC transport parameter.
type TransportParam struct {
	ID     uint64
	Name   string
	Value  []byte
	Decoded string
	GREASE bool
	Note   string
}

// ParseTransportParameters parses the extension_data of quic_transport_parameters.
func ParseTransportParameters(b []byte) ([]TransportParam, error) {
	var out []TransportParam
	o := 0
	for o < len(b) {
		id, n, err := ReadVarint(b[o:])
		if err != nil {
			return out, fmt.Errorf("tp id at %d: %w", o, err)
		}
		o += n
		length, n, err := ReadVarint(b[o:])
		if err != nil {
			return out, fmt.Errorf("tp length at %d: %w", o, err)
		}
		o += n
		if uint64(len(b)-o) < length {
			return out, fmt.Errorf("tp truncated id=0x%x", id)
		}
		val := append([]byte(nil), b[o:o+int(length)]...)
		o += int(length)
		tp := TransportParam{
			ID:     id,
			Value:  val,
			Name:   tpName(id),
			GREASE: IsTransportParamGREASE(id),
		}
		tp.Decoded, tp.Note = decodeTP(tp)
		out = append(out, tp)
	}
	return out, nil
}

// IsTransportParamGREASE reports RFC 9000 §18.1 reserved ids: 31·N + 27.
func IsTransportParamGREASE(id uint64) bool {
	return id >= 27 && (id-27)%31 == 0
}

func tpName(id uint64) string {
	if IsTransportParamGREASE(id) {
		return fmt.Sprintf("GREASE(0x%x)", id)
	}
	switch id {
	case TPOriginalDestinationConnectionID:
		return "original_destination_connection_id"
	case TPMaxIdleTimeout:
		return "max_idle_timeout"
	case TPStatelessResetToken:
		return "stateless_reset_token"
	case TPMaxUDPPayloadSize:
		return "max_udp_payload_size"
	case TPInitialMaxData:
		return "initial_max_data"
	case TPInitialMaxStreamDataBidiLocal:
		return "initial_max_stream_data_bidi_local"
	case TPInitialMaxStreamDataBidiRemote:
		return "initial_max_stream_data_bidi_remote"
	case TPInitialMaxStreamDataUni:
		return "initial_max_stream_data_uni"
	case TPInitialMaxStreamsBidi:
		return "initial_max_streams_bidi"
	case TPInitialMaxStreamsUni:
		return "initial_max_streams_uni"
	case TPAckDelayExponent:
		return "ack_delay_exponent"
	case TPMaxAckDelay:
		return "max_ack_delay"
	case TPDisableActiveMigration:
		return "disable_active_migration"
	case TPPreferredAddress:
		return "preferred_address"
	case TPActiveConnectionIDLimit:
		return "active_connection_id_limit"
	case TPInitialSourceConnectionID:
		return "initial_source_connection_id"
	case TPRetrySourceConnectionID:
		return "retry_source_connection_id"
	case TPMaxDatagramFrameSize:
		return "max_datagram_frame_size"
	case TPGreaseQUICBit:
		return "grease_quic_bit"
	default:
		return fmt.Sprintf("tp_0x%x", id)
	}
}

func decodeTP(tp TransportParam) (decoded, note string) {
	if tp.GREASE {
		return fmt.Sprintf("%d bytes", len(tp.Value)), "GREASE TP (31·N+27) — must be ignored; presence is a Chromium/modern-stack tell"
	}
	switch tp.ID {
	case TPDisableActiveMigration, TPGreaseQUICBit:
		return "(empty)", "flag parameter — presence is the signal"
	case TPStatelessResetToken:
		return fmt.Sprintf("%x", tp.Value), "16-byte reset token"
	case TPOriginalDestinationConnectionID, TPInitialSourceConnectionID, TPRetrySourceConnectionID:
		return fmt.Sprintf("%x", tp.Value), "connection id bytes"
	case TPPreferredAddress:
		return fmt.Sprintf("%d bytes", len(tp.Value)), "preferred_address structure"
	default:
		if v, ok := readTPVarintValue(tp.Value); ok {
			decoded = fmt.Sprintf("%d", v)
			note = tpValueNote(tp.ID, v)
			return decoded, note
		}
		return fmt.Sprintf("%d bytes", len(tp.Value)), ""
	}
}

func readTPVarintValue(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, true // empty = 0 / flag
	}
	v, n, err := ReadVarint(b)
	if err != nil || n != len(b) {
		// some stacks encode fixed integers; try big-endian 2/4/8
		switch len(b) {
		case 1:
			return uint64(b[0]), true
		case 2:
			return uint64(binary.BigEndian.Uint16(b)), true
		case 4:
			return uint64(binary.BigEndian.Uint32(b)), true
		case 8:
			return binary.BigEndian.Uint64(b), true
		default:
			return 0, false
		}
	}
	return v, true
}

func tpValueNote(id, v uint64) string {
	switch id {
	case TPMaxIdleTimeout:
		return "milliseconds"
	case TPMaxUDPPayloadSize:
		if v < 1200 {
			return "below QUIC minimum 1200 — invalid / middlebox smell"
		}
		return "bytes (QUIC min 1200)"
	case TPInitialMaxData, TPInitialMaxStreamDataBidiLocal, TPInitialMaxStreamDataBidiRemote, TPInitialMaxStreamDataUni:
		return "flow-control credit (bytes)"
	case TPInitialMaxStreamsBidi, TPInitialMaxStreamsUni:
		return "stream limit"
	case TPActiveConnectionIDLimit:
		return "active CID budget"
	default:
		return ""
	}
}

func extractQUICTransportParams(ch *ClientHello) []TransportParam {
	for _, ext := range ch.Extensions {
		if ext.Type == ExtQUICTransportParameters {
			tps, err := ParseTransportParameters(ext.Data)
			if err != nil || len(tps) == 0 {
				return tps
			}
			return tps
		}
	}
	return nil
}

// AppendTransportParam encodes one TP into dst.
func AppendTransportParam(dst []byte, id uint64, value []byte) []byte {
	dst = AppendVarint(dst, id)
	dst = AppendVarint(dst, uint64(len(value)))
	return append(dst, value...)
}

// EncodeVarintTPValue encodes an integer transport parameter value.
func EncodeVarintTPValue(v uint64) []byte {
	return EncodeVarint(v)
}
