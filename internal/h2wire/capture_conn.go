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
	mu          sync.Mutex
	writeBuf    bytes.Buffer
	readBuf     bytes.Buffer
	obs         *signal.H2Observation
	raw         []byte // client flight bytes for corpus
	rawFromWrite bool  // which buffer owns obs/raw
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

// RawClientFlight returns preface + frames through the first request flight.
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
			c.rawFromWrite = fromWrite
		}
	}
	// Only refresh raw from the same direction that produced the observation —
	// otherwise server writes (e.g. HTTP/1.1 error pages) clobber the client flight.
	if c.obs != nil && c.rawFromWrite == fromWrite {
		c.raw = truncateThroughControlFlight(raw)
	}
}

// truncateThroughControlFlight returns preface + frames through the first
// HEADERS(+CONTINUATION) block and any PRIORITY_UPDATE that follows before DATA,
// so live captures can include RFC 9218 EPS (Akamai field 3).
func truncateThroughControlFlight(data []byte) []byte {
	prefaceLen := len(http2.ClientPreface)
	if len(data) < prefaceLen {
		return append([]byte(nil), data...)
	}
	off := prefaceLen
	lastKeep := off
	sawSettings := false
	sawHeadersEnd := false
	inHeaders := false
	headersStream := uint32(0)
	for off+9 <= len(data) {
		length := int(data[off])<<16 | int(data[off+1])<<8 | int(data[off+2])
		ftype := data[off+3]
		flags := data[off+4]
		stream := uint32(data[off+5])<<24 | uint32(data[off+6])<<16 | uint32(data[off+7])<<8 | uint32(data[off+8])
		end := off + 9 + length
		if end > len(data) {
			break
		}
		switch ftype {
		case 0x0: // DATA — end of control/request-header flight
			if sawHeadersEnd {
				return append([]byte(nil), data[:lastKeep]...)
			}
			lastKeep = end
		case 0x1: // HEADERS
			if sawHeadersEnd {
				// Next request on this connection — stop so HPACK stays coherent.
				return append([]byte(nil), data[:lastKeep]...)
			}
			sawSettings = true
			inHeaders = true
			headersStream = stream
			lastKeep = end
			if flags&0x4 != 0 { // END_HEADERS
				sawHeadersEnd = true
				inHeaders = false
			}
		case 0x9: // CONTINUATION
			if inHeaders && stream == headersStream {
				lastKeep = end
				if flags&0x4 != 0 {
					sawHeadersEnd = true
					inHeaders = false
				}
			}
		case 0x4: // SETTINGS
			sawSettings = true
			lastKeep = end
		case 0x8, 0x10: // WINDOW_UPDATE, PRIORITY_UPDATE
			if sawSettings || sawHeadersEnd || inHeaders {
				lastKeep = end
			}
		default:
			if sawSettings || sawHeadersEnd || inHeaders {
				if ftype != 0x6 { // skip PING noise after headers
					lastKeep = end
				}
			}
		}
		off = end
	}
	if lastKeep > prefaceLen {
		return append([]byte(nil), data[:lastKeep]...)
	}
	return append([]byte(nil), data...)
}
