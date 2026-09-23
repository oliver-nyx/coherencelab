package dissect

import "fmt"

// ReadVarint decodes a QUIC variable-length integer (RFC 9000 §16).
// Returns value, bytes consumed, error.
func ReadVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("varint: empty")
	}
	prefix := b[0] >> 6
	var n int
	switch prefix {
	case 0:
		n = 1
	case 1:
		n = 2
	case 2:
		n = 4
	case 3:
		n = 8
	}
	if len(b) < n {
		return 0, 0, fmt.Errorf("varint: need %d bytes, have %d", n, len(b))
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

// AppendVarint encodes v as a QUIC variable-length integer using the
// shortest legal encoding (teaching default — stacks may pad with longer forms).
func AppendVarint(dst []byte, v uint64) []byte {
	switch {
	case v <= 63:
		return append(dst, byte(v))
	case v <= 16383:
		return append(dst, byte(0x40|v>>8), byte(v))
	case v <= 1073741823:
		return append(dst,
			byte(0x80|v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst,
			byte(0xc0|v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// EncodeVarint returns a fresh slice encoding v.
func EncodeVarint(v uint64) []byte {
	return AppendVarint(nil, v)
}
