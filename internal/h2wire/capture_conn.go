package h2wire

import (
	"bytes"
	"net"
	"sync"

	"golang.org/x/net/http2"

	"github.com/oliver-nyx/coherencelab/internal/signal"
)

// CaptureConn wraps a connection and captures client-sent HTTP/2 SETTINGS from writes
// or reads (server-side observation).
type CaptureConn struct {
	net.Conn
	mu       sync.Mutex
	writeBuf bytes.Buffer
	readBuf  bytes.Buffer
	obs      *signal.H2Observation
	raw      []byte // preface + frames through first SETTINGS (wire bytes for corpus)
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

// RawClientFlight returns preface + frames through the first non-ACK SETTINGS.
func (c *CaptureConn) RawClientFlight() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw == nil {
		return nil
	}
	return append([]byte(nil), c.raw...)
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

	buf := &c.writeBuf
	if !fromWrite {
		buf = &c.readBuf
	}
	buf.Write(chunk)
	raw := buf.Bytes()

	if c.obs == nil {
		obs, err := tryParseClientSettings(raw)
		if err == nil && obs != nil {
			c.obs = obs
		}
	}
	if c.obs != nil {
		c.raw = truncateThroughControlFlight(raw)
	}
}

// truncateThroughControlFlight returns preface + control frames up to (not including) HEADERS.
func truncateThroughControlFlight(data []byte) []byte {
	prefaceLen := len(http2.ClientPreface)
	if len(data) < prefaceLen {
		return append([]byte(nil), data...)
	}
	off := prefaceLen
	lastKeep := off
	sawSettings := false
	for off+9 <= len(data) {
		length := int(data[off])<<16 | int(data[off+1])<<8 | int(data[off+2])
		ftype := data[off+3]
		end := off + 9 + length
		if end > len(data) {
			break
		}
		switch ftype {
		case 0x1: // HEADERS — stop before
			if sawSettings {
				return append([]byte(nil), data[:lastKeep]...)
			}
			return append([]byte(nil), data[:end]...)
		case 0x4: // SETTINGS
			sawSettings = true
			lastKeep = end
		case 0x8, 0x10: // WINDOW_UPDATE, PRIORITY_UPDATE
			if sawSettings {
				lastKeep = end
			}
		default:
			if sawSettings && ftype != 0x6 { // ignore PING
				// unknown post-settings control — keep if before HEADERS
				lastKeep = end
			}
		}
		off = end
	}
	if lastKeep > prefaceLen {
		return append([]byte(nil), data[:lastKeep]...)
	}
	return append([]byte(nil), data...)
}
