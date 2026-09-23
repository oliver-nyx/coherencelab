package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oliver-nyx/coherencelab/internal/dissect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// startQUICCapture runs HTTP/3 and captures the client control stream by
// reading uni streams before/alongside a minimal response path.
func (s *Server) startQUICCapture(cert tls.Certificate) error {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	udpAddr := net.JoinHostPort(host, port)
	pc, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("udp listen %s: %w", udpAddr, err)
	}
	udp, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return fmt.Errorf("udp listen: expected *net.UDPConn")
	}

	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})

	tr := &quic.Transport{Conn: udp}
	ln, err := tr.ListenEarly(tlsConf, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("quic listen: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.quicStop = func() {
		cancel()
		_ = ln.Close()
		_ = tr.Close()
		_ = udp.Close()
	}
	log.Printf("HTTP/3 + control-stream capture on udp://%s (Alt-Svc h3)", udpAddr)
	go s.quicAcceptLoopManual(ctx, ln)
	return nil
}

func (s *Server) quicAcceptLoopManual(ctx context.Context, ln *quic.EarlyListener) {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		log.Printf("quic accepted from %s", conn.RemoteAddr())
		go s.handleH3ConnManual(ctx, conn)
	}
}

func (s *Server) handleH3ConnManual(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "done")

	select {
	case <-conn.HandshakeComplete():
		log.Printf("h3 handshake ok from %s alpn=%s", conn.RemoteAddr(), conn.ConnectionState().TLS.NegotiatedProtocol)
	case <-conn.Context().Done():
		log.Printf("h3 conn closed before handshake: %v", context.Cause(conn.Context()))
		return
	case <-time.After(10 * time.Second):
		log.Printf("h3 handshake timeout from %s", conn.RemoteAddr())
		return
	}

	ctrl, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		log.Printf("h3 open control: %v", err)
		return
	}
	var settings []byte
	settings = dissect.AppendVarint(settings, 0x01)
	settings = dissect.AppendVarint(settings, 0)
	settings = dissect.AppendVarint(settings, 0x07)
	settings = dissect.AppendVarint(settings, 100)
	var open []byte
	open = dissect.AppendVarint(open, 0x00)
	open = dissect.AppendH3Frame(open, 0x04, settings)
	_, _ = ctrl.Write(open)

	capCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s.captureH3ControlStream(capCtx, conn)
	}()
	go func() {
		defer wg.Done()
		s.serveH3Requests(capCtx, conn)
	}()
	wg.Wait()
}

func (s *Server) captureH3ControlStream(ctx context.Context, conn *quic.Conn) {
	for {
		str, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		go func(str *quic.ReceiveStream) {
			_ = str.SetReadDeadline(time.Now().Add(5 * time.Second))
			typ, _, err := readVarint(str)
			if err != nil {
				return
			}
			log.Printf("h3 uni stream type=0x%x id=%d", typ, str.StreamID())
			if typ != 0x00 {
				_, _ = io.Copy(io.Discard, io.LimitReader(str, 64<<10))
				return
			}
			body, _ := io.ReadAll(io.LimitReader(str, 256<<10))
			if len(body) == 0 {
				return
			}
			s.persistH3Control(body)
		}(str)
	}
}

func (s *Server) serveH3Requests(ctx context.Context, conn *quic.Conn) {
	for {
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(str *quic.Stream) {
			defer str.Close()
			_ = str.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.Copy(io.Discard, io.LimitReader(str, 256<<10))
			qpack := []byte{0x00, 0x00, 0xd9}
			var resp []byte
			resp = dissect.AppendH3Frame(resp, 0x01, qpack)
			resp = dissect.AppendH3Frame(resp, 0x00, []byte("ok\n"))
			_, _ = str.Write(resp)
		}(str)
	}
}

func (s *Server) persistH3Control(frames []byte) {
	dir := s.CaptureDir
	if dir == "" || len(frames) == 0 {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, fmt.Sprintf("probe-%d.h3.bin", time.Now().UnixNano()))
	if err := os.WriteFile(path, frames, 0o644); err != nil {
		return
	}
	log.Printf("wrote H3 control stream %d bytes → %s", len(frames), path)
	if sess, err := dissect.ParseH3(frames); err == nil {
		log.Printf("  H3 golden: %s", dissect.H3Fingerprint(sess))
	}
}

func readVarint(r io.Reader) (uint64, int, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, 0, err
	}
	l := 1 << ((b[0] & 0xc0) >> 6)
	buf := make([]byte, l)
	buf[0] = b[0]
	if l > 1 {
		if _, err := io.ReadFull(r, buf[1:]); err != nil {
			return 0, 0, err
		}
	}
	return dissect.ReadVarint(buf)
}

// Silence unused import if http3 is only used via ConfigureTLSConfig.
var _ = http3.NextProtoH3
