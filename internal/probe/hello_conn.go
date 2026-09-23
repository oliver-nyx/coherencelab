package probe

import (
	"io"
	"net"
	"sync"
)

// HelloCaptureConn wraps a raw TCP connection and records the first TLS
// record (ClientHello) before the TLS stack consumes it. Bytes are replayed
// transparently on subsequent Reads.
type HelloCaptureConn struct {
	net.Conn
	mu      sync.Mutex
	once    sync.Once
	prefix  []byte // unread captured bytes (starts as full first record + any extra)
	hello   []byte // first TLS record only
	capErr  error
}

// NewHelloCaptureConn wraps c for ClientHello recording.
func NewHelloCaptureConn(c net.Conn) *HelloCaptureConn {
	return &HelloCaptureConn{Conn: c}
}

// ClientHello returns the first TLS handshake record, or nil if capture failed.
func (c *HelloCaptureConn) ClientHello() []byte {
	c.ensure()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hello == nil {
		return nil
	}
	return append([]byte(nil), c.hello...)
}

func (c *HelloCaptureConn) ensure() {
	c.once.Do(func() {
		hello, rest, err := readFirstTLSRecord(c.Conn)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.capErr = err
		c.hello = hello
		if hello != nil {
			c.prefix = append(hello, rest...)
		} else if len(rest) > 0 {
			c.prefix = rest
		}
	})
}

// Read implements net.Conn.
func (c *HelloCaptureConn) Read(p []byte) (int, error) {
	c.ensure()
	c.mu.Lock()
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	return c.Conn.Read(p)
}

// readFirstTLSRecord reads from r until one complete TLS record is available.
// Returns (record, overflowBytes, err). On non-handshake first byte, returns
// whatever was read as overflow so the TLS stack can still fail naturally.
func readFirstTLSRecord(r io.Reader) (record, overflow []byte, err error) {
	hdr := make([]byte, 5)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return nil, hdr[:0], err
	}
	if hdr[0] != 0x16 {
		return nil, hdr, nil
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	frag := make([]byte, recLen)
	if _, err = io.ReadFull(r, frag); err != nil {
		return nil, append(hdr, frag...), err
	}
	return append(hdr, frag...), nil, nil
}

// ExtractClientHelloRecord slices the first complete TLS handshake record
// from b, or returns nil if incomplete / not handshake.
func ExtractClientHelloRecord(b []byte) []byte {
	if len(b) < 5 || b[0] != 0x16 {
		return nil
	}
	recLen := int(b[3])<<8 | int(b[4])
	need := 5 + recLen
	if len(b) < need {
		return nil
	}
	return append([]byte(nil), b[:need]...)
}
