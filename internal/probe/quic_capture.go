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
	"strings"
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
	// Multi-resource HTML keeps one H3 connection warm for PRIORITY_UPDATE
	// experiments (Firefox live control streams still omit the frame in lab captures).
	pageHTML := func(title, sibling string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, `<!doctype html><html><head><title>%s</title>
<link rel="stylesheet" href="/asset/a.css">
<script src="/asset/a.js"></script></head><body>
<h1>%s</h1><img src="/asset/a.png" width="1" height="1" alt="">
<p><a href="%s">sibling</a></p>
<iframe src="/asset/frame.html" width="1" height="1"></iframe>
</body></html>`, title, title, sibling)
		}
	}
	mux.HandleFunc("/page", pageHTML("page-a", "/page2"))
	mux.HandleFunc("/page2", pageHTML("page-b", "/page"))
	mux.HandleFunc("/asset/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".css"):
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte("body{margin:0}"))
		case strings.HasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte("void 0"))
		case strings.HasSuffix(r.URL.Path, ".png"):
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte{
				0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
				0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
				0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
				0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
				0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
				0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
			})
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><body>f</body></html>"))
		}
	})
	h3 := &http3.Server{
		Handler:   mux,
		TLSConfig: tlsConf,
		QUICConfig: &quic.Config{
			MaxIdleTimeout: 45 * time.Second,
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

	// Keep the session open long enough for Firefox tab-focus PRIORITY_UPDATE.
	capCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
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
			typ, _, err := readVarint(str)
			if err != nil {
				return
			}
			log.Printf("h3 uni stream type=0x%x id=%d", typ, str.StreamID())
			if typ != 0x00 {
				_, _ = io.Copy(io.Discard, io.LimitReader(str, 64<<10))
				return
			}
			// Incremental read: Firefox may send SETTINGS+GREASE immediately and
			// PRIORITY_UPDATE only after a later tab-focus change.
			var body []byte
			buf := make([]byte, 4096)
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					if len(body) > 0 {
						s.persistH3Control(body)
					}
					return
				default:
				}
				_ = str.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				n, err := str.Read(buf)
				if n > 0 {
					body = append(body, buf[:n]...)
					s.persistH3Control(body)
					if sess, perr := dissect.ParseH3(body); perr == nil {
						for _, fr := range sess.Frames {
							if fr.Type == dissect.H3FramePriorityUpdateRequest || fr.Type == dissect.H3FramePriorityUpdatePush {
								log.Printf("h3 PRIORITY_UPDATE observed (%d control bytes)", len(body))
								return
							}
						}
					}
				}
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					break
				}
			}
			if len(body) > 0 {
				s.persistH3Control(body)
			}
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
			_ = str.SetReadDeadline(time.Now().Add(8 * time.Second))
			req, _ := io.ReadAll(io.LimitReader(str, 256<<10))
			path := h3RequestPathHint(req)
			log.Printf("h3 request stream id=%d path=%q %d bytes", str.StreamID(), path, len(req))
			if len(req) > 0 {
				s.persistH3Request(int64(str.StreamID()), req)
			}
			body, _ := h3ProbeBody(path)
			qpack := []byte{0x00, 0x00, 0xd9}
			var resp []byte
			resp = dissect.AppendH3Frame(resp, 0x01, qpack)
			// Optional hold for tab-focus PRIORITY_UPDATE experiments (COHERENCELAB_H3_HOLD=1).
			hold := os.Getenv("COHERENCELAB_H3_HOLD") != "" &&
				(strings.HasPrefix(path, "/page") || path == "/probe" || path == "/")
			if hold && len(body) > 16 {
				resp = dissect.AppendH3Frame(resp, 0x00, body[:16])
				_, _ = str.Write(resp)
				select {
				case <-ctx.Done():
				case <-time.After(18 * time.Second):
				}
				_, _ = str.Write(dissect.AppendH3Frame(nil, 0x00, body[16:]))
				return
			}
			resp = dissect.AppendH3Frame(resp, 0x00, body)
			_, _ = str.Write(resp)
		}(str)
	}
}

// h3RequestPathHint peeks QPACK HEADERS literals for :path (Firefox often
// sends custom paths as literals — enough for probe routing).
func h3RequestPathHint(req []byte) string {
	s := string(req)
	for _, p := range []string{"/asset/a.css", "/asset/a.js", "/asset/a.png", "/asset/frame.html", "/page2", "/page", "/probe", "/"} {
		if strings.Contains(s, p) {
			return p
		}
	}
	return "/probe"
}

func h3ProbeBody(path string) ([]byte, string) {
	switch path {
	case "/asset/a.css":
		return []byte("body{margin:0}"), "text/css"
	case "/asset/a.js":
		return []byte("void 0"), "application/javascript"
	case "/asset/a.png":
		return []byte{
			0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
			0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
			0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
			0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
			0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
			0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
		}, "image/png"
	case "/asset/frame.html":
		return []byte("<html><body>f</body></html>"), "text/html; charset=utf-8"
	case "/page2":
		return []byte(`<!doctype html><html><head><title>page-b</title>
<link rel="stylesheet" href="/asset/a.css"><script src="/asset/a.js"></script></head>
<body><h1>page-b</h1><img src="/asset/a.png" width="1" height="1" alt="">
<iframe src="/asset/frame.html" width="1" height="1"></iframe></body></html>`), "text/html; charset=utf-8"
	default:
		return []byte(`<!doctype html><html><head><title>page-a</title>
<link rel="stylesheet" href="/asset/a.css"><script src="/asset/a.js"></script></head>
<body><h1>page-a</h1><img src="/asset/a.png" width="1" height="1" alt="">
<iframe src="/asset/frame.html" width="1" height="1"></iframe></body></html>`), "text/html; charset=utf-8"
	}
}

func (s *Server) persistH3Request(streamID int64, frames []byte) {
	dir := s.CaptureDir
	if dir == "" || len(frames) == 0 {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, fmt.Sprintf("probe-%d.h3req-stream%d.bin", time.Now().UnixNano(), streamID))
	if err := os.WriteFile(path, frames, 0o644); err != nil {
		return
	}
	log.Printf("wrote H3 request stream %d bytes → %s", len(frames), path)
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
