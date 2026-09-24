package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/oliver-nyx/coherencelab/internal/dissect"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// startQUICCapture runs HTTP/3 on the probe UDP port, tees QUICv1 Initials,
// and captures client control-stream frames for the H3 lab corpus.
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
	var packetConn net.PacketConn = udp
	if os.Getenv("COHERENCELAB_QUIC_NO_TEE") == "" {
		packetConn = &initialTeeConn{UDPConn: udp, onInitial: s.persistQUICInitial}
	} else {
		log.Printf("QUIC Initial tee disabled (COHERENCELAB_QUIC_NO_TEE)")
	}

	tlsConf := http3.ConfigureTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	h3 := &http3.Server{
		Handler:   mux,
		TLSConfig: tlsConf,
		QUICConfig: &quic.Config{
			MaxIdleTimeout: 30 * time.Second,
		},
	}

	tr := &quic.Transport{Conn: packetConn}
	// Listen (not Early): Accept returns only after TLS handshake completes.
	// Firefox multi-Initial was aborting on the Early path before CRYPTO finished.
	ln, err := tr.Listen(tlsConf, h3.QUICConfig)
	if err != nil {
		_ = udp.Close()
		return fmt.Errorf("quic listen: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.quicStop = func() {
		cancel()
		_ = h3.Close()
		_ = ln.Close()
		_ = tr.Close()
		_ = udp.Close()
	}
	log.Printf("HTTP/3 + Initial tee on udp://%s (Alt-Svc h3, Listen)", udpAddr)
	go s.quicAcceptLoop(ctx, ln, h3)
	return nil
}

func (s *Server) quicAcceptLoop(ctx context.Context, ln *quic.Listener, h3 *http3.Server) {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("quic Accept: %v", err)
			continue
		}
		log.Printf("quic accepted from %s alpn=%s", conn.RemoteAddr(), conn.ConnectionState().TLS.NegotiatedProtocol)
		go s.handleH3Conn(ctx, conn, h3)
	}
}

func (s *Server) handleH3Conn(ctx context.Context, conn *quic.Conn, _ *http3.Server) {
	// Listen already completed the TLS handshake. Capture client control
	// bytes with the manual H3 path (same as Chrome/Edge).
	log.Printf("h3 handshake ok from %s alpn=%s", conn.RemoteAddr(), conn.ConnectionState().TLS.NegotiatedProtocol)
	s.handleH3ConnManual(ctx, conn)
}

func (s *Server) handleH3ConnManual(ctx context.Context, conn *quic.Conn) {
	defer conn.CloseWithError(0, "done")

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

// quicFlightAcc merges Initials that share a DCID until ClientHello parses.
type quicFlightAcc struct {
	pkts [][]byte
	done bool
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

	d, err := dissect.DecryptInitial(pkt)
	if err != nil {
		log.Printf("  Initial decrypt: %v", err)
		return
	}
	if d.ClientHello != nil {
		log.Printf("  decrypted Initial SNI=%q TPs=%d JA3=%s", d.ClientHello.SNI, len(d.Transport), d.ClientHello.JA3Hash())
		return
	}

	// Firefox often fragments CRYPTO across Initials — accumulate by DCID.
	key := fmt.Sprintf("%x", d.Header.DCID)
	s.quicFlightMu.Lock()
	defer s.quicFlightMu.Unlock()
	if s.quicFlights == nil {
		s.quicFlights = make(map[string]*quicFlightAcc)
	}
	acc := s.quicFlights[key]
	if acc == nil {
		acc = &quicFlightAcc{}
		s.quicFlights[key] = acc
	}
	if acc.done {
		return
	}
	acc.pkts = append(acc.pkts, append([]byte(nil), pkt...))
	merged, err := dissect.DecryptInitialFlight(acc.pkts)
	if err != nil || merged.ClientHello == nil {
		log.Printf("  flight DCID=%s packets=%d (CRYPTO still incomplete)", key, len(acc.pkts))
		return
	}
	acc.done = true
	flight, err := dissect.EncodeInitialFlight(acc.pkts)
	if err != nil {
		return
	}
	fpath := filepath.Join(dir, fmt.Sprintf("probe-%d.quic-flight.bin", time.Now().UnixNano()))
	if err := os.WriteFile(fpath, flight, 0o644); err != nil {
		return
	}
	log.Printf("wrote QUIC Initial flight (%d pkts, %d bytes) → %s", len(acc.pkts), len(flight), fpath)
	log.Printf("  flight SNI=%q TPs=%d JA3=%s FP=%s",
		merged.ClientHello.SNI, len(merged.Transport), merged.ClientHello.JA3Hash(),
		dissect.TransportFingerprint(merged.Transport))
}

// initialTeeConn embeds *net.UDPConn and tees Initials without breaking OOB/ECN.
type initialTeeConn struct {
	*net.UDPConn
	onInitial func([]byte)
	mu        sync.Mutex
	seen      map[string]struct{}
}

func (c *initialTeeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(p)
	c.maybeTee(p, n, addr)
	return n, addr, err
}

func (c *initialTeeConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	n, oobn, flags, addr, err = c.UDPConn.ReadMsgUDP(b, oob)
	c.maybeTee(b, n, addr)
	return n, oobn, flags, addr, err
}

func (c *initialTeeConn) maybeTee(p []byte, n int, addr net.Addr) {
	if n < 20 || c.onInitial == nil || addr == nil {
		return
	}
	if dissect.DetectQUICPacketClass(p[:n]) != "initial" {
		return
	}
	key := fmt.Sprintf("%s-%x", addr.String(), p[:min(n, 24)])
	c.mu.Lock()
	if c.seen == nil {
		c.seen = make(map[string]struct{})
	}
	if _, ok := c.seen[key]; ok {
		c.mu.Unlock()
		return
	}
	c.seen[key] = struct{}{}
	c.mu.Unlock()
	// Copy + async: never block the UDP read path (Firefox sends multiple
	// Initials; sync decrypt/disk previously starved the handshake).
	pkt := append([]byte(nil), p[:n]...)
	go c.onInitial(pkt)
}

func (c *initialTeeConn) SyscallConn() (syscall.RawConn, error) {
	return c.UDPConn.SyscallConn()
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
