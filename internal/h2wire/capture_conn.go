package h2wire

import (
	"bytes"
	"net"
	"sync"

	"github.com/oliver-nyx/coherencelab/internal/signal"
)

// CaptureConn wraps a connection and captures client-sent HTTP/2 SETTINGS from writes
// or reads (server-side observation).
type CaptureConn struct {
	net.Conn
	mu      sync.Mutex
	writeBuf bytes.Buffer
	readBuf  bytes.Buffer
	obs     *signal.H2Observation
}

// NewCaptureConn wraps conn for HTTP/2 SETTINGS capture.
func NewCaptureConn(conn net.Conn) *CaptureConn {
	return &CaptureConn{Conn: conn}
}

// Observation returns captured SETTINGS, or nil if not yet available.
func (c *CaptureConn) Observation() *signal.H2Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.obs
}

// Write implements net.Conn and captures outgoing client SETTINGS.
func (c *CaptureConn) Write(b []byte) (int, error) {
	c.tryCapture(b, true)
	return c.Conn.Write(b)
}

// Read implements net.Conn and captures incoming client SETTINGS (server-side).
func (c *CaptureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.tryCapture(b[:n], false)
	}
	return n, err
}

func (c *CaptureConn) tryCapture(chunk []byte, fromWrite bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.obs != nil {
		return
	}

	buf := &c.writeBuf
	if !fromWrite {
		buf = &c.readBuf
	}
	buf.Write(chunk)

	obs, err := tryParseClientSettings(buf.Bytes())
	if err == nil && obs != nil {
		c.obs = obs
	}
}
