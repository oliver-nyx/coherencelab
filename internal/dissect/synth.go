package dissect

import (
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/oliver-nyx/coherencelab/internal/tlsfp"
)

// SynthClientHello builds a ClientHello for a uTLS client id by performing a
// handshake against an in-process recorder and returning the raw record bytes.
// This shows what an impersonating stack *actually* emits — not what YAML claims.
func SynthClientHello(utlsClientID, serverName string) ([]byte, error) {
	if serverName == "" {
		serverName = "example.com"
	}
	helloID := tlsfp.ClientHelloID(utlsClientID)
	cert := mustSelfSigned()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	rec := &recordingConn{Conn: c1}
	errCh := make(chan error, 1)
	go func() {
		srv := utls.Server(c2, &utls.Config{
			Certificates: []utls.Certificate{*cert},
			NextProtos:   []string{"h2", "http/1.1"},
		})
		_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
		errCh <- srv.Handshake()
		_ = srv.Close()
	}()

	cli := utls.UClient(rec, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, helloID)
	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
	herr := cli.Handshake()
	_ = cli.Close()
	<-errCh

	raw := rec.Bytes()
	if len(raw) < 6 || raw[0] != 0x16 {
		return nil, fmt.Errorf("dissect: failed to capture ClientHello for %s (got %d bytes, handshake err=%v)", utlsClientID, len(raw), herr)
	}
	recLen := int(raw[3])<<8 | int(raw[4])
	end := 5 + recLen
	if end > len(raw) {
		end = len(raw)
	}
	return append([]byte(nil), raw[:end]...), nil
}

type recordingConn struct {
	net.Conn
	buf []byte
}

func (r *recordingConn) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	return r.Conn.Write(p)
}

func (r *recordingConn) Bytes() []byte { return r.buf }

var cachedCert *utls.Certificate

func mustSelfSigned() *utls.Certificate {
	if cachedCert != nil {
		return cachedCert
	}
	cert, err := synthesizeTLSCert()
	if err != nil {
		panic(err)
	}
	cachedCert = cert
	return cachedCert
}
