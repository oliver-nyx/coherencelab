package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/oliver-nyx/coherencelab/internal/dissect"
)

// startQUICCapture listens on the same host/port over UDP and persists real
// browser QUIC Initial datagrams. A minimal response is not required for the
// first-flight capture — Chrome/Edge send an Initial after Alt-Svc.
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
	ctx, cancel := context.WithCancel(context.Background())
	s.quicStop = func() {
		cancel()
		_ = pc.Close()
	}
	log.Printf("QUIC Initial capture listening on udp://%s (Alt-Svc h3)", udpAddr)
	_ = cert // reserved for optional quic-go H3 handshake upgrade
	go s.quicReadLoop(ctx, pc)
	return nil
}

func (s *Server) quicReadLoop(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, 65535)
	seen := make(map[string]struct{})
	for {
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		select {
		case <-ctx.Done():
			return
		default:
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if n < 20 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		class := dissect.DetectQUICPacketClass(pkt)
		if class != "initial" {
			continue
		}
		key := addr.String()
		if _, ok := seen[key]; ok {
			// Still write distinct DCID flights; key by first 32 bytes hash-ish
			key = fmt.Sprintf("%s-%x", addr.String(), pkt[min(n, 16):min(n, 24)])
			if _, ok := seen[key]; ok {
				continue
			}
		}
		seen[key] = struct{}{}
		s.persistQUICInitial(pkt)
	}
}

func (s *Server) persistQUICInitial(pkt []byte) {
	dir := s.CaptureDir
	if dir == "" {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, fmt.Sprintf("probe-%d.quic.bin", time.Now().UnixNano()))
	if err := os.WriteFile(path, pkt, 0o644); err != nil {
		return
	}
	log.Printf("wrote QUIC Initial %d bytes → %s", len(pkt), path)
	if d, err := dissect.DecryptInitial(pkt); err == nil && d.ClientHello != nil {
		log.Printf("  decrypted Initial SNI=%q TPs=%d JA3=%s", d.ClientHello.SNI, len(d.Transport), d.ClientHello.JA3Hash())
	}
}
