package client

import (
	"net"
	"sync"
)

// writeHelloConn captures the first TLS handshake record written by a client
// (uTLS ClientHello) so fingerprints come from wire bytes, not a partial spec.
type writeHelloConn struct {
	net.Conn
	mu    sync.Mutex
	hello []byte
	buf   []byte
	done  bool
}

func (c *writeHelloConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.note(p[:n])
	}
	return n, err
}

func (c *writeHelloConn) note(chunk []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.buf = append(c.buf, chunk...)
	if len(c.buf) < 5 {
		return
	}
	if c.buf[0] != 0x16 { // not handshake record — give up
		c.done = true
		return
	}
	recLen := int(c.buf[3])<<8 | int(c.buf[4])
	need := 5 + recLen
	if len(c.buf) < need {
		return
	}
	c.hello = append([]byte(nil), c.buf[:need]...)
	c.done = true
}

func (c *writeHelloConn) ClientHello() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hello == nil {
		return nil
	}
	return append([]byte(nil), c.hello...)
}
