package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oliver-nyx/coherencelab/internal/capture"
	"github.com/oliver-nyx/coherencelab/internal/dissect"
	"github.com/oliver-nyx/coherencelab/internal/h2wire"
	"github.com/oliver-nyx/coherencelab/internal/signal"
	"github.com/oliver-nyx/coherencelab/internal/tlsfp"
	"golang.org/x/net/http2"
)

// Observation is a recorded probe result from a client connection.
type Observation struct {
	Timestamp   time.Time              `json:"timestamp"`
	RemoteAddr  string                 `json:"remote_addr"`
	UserAgent   string                 `json:"user_agent"`
	Headers     map[string]string      `json:"headers"`
	HeaderOrder []string               `json:"header_order"`
	TLS         *signal.TLSObservation `json:"tls,omitempty"`
	H2          *signal.H2Observation  `json:"http2,omitempty"`
}

// Server is a TLS probe server that captures client identity signals.
type Server struct {
	Addr        string
	CaptureDir  string // if set, writes ClientHello / H2 / QUIC bins here
	EnableH2    bool   // negotiate h2 ALPN (default true) for live SETTINGS capture
	EnableQUIC  bool   // UDP Initial capture + Alt-Svc (default true when CaptureDir set)
	mu          sync.RWMutex
	logs        []Observation
	maxLogs     int
	h2ByAddr    map[string]*signal.H2Observation
	helloByAddr map[string][]byte
	lastCapture *capture.Input
	lastHello   []byte
	lastH2Raw   []byte
	server      *http.Server
	quicStop    context.CancelFunc
}

// New creates a probe server.
func New(addr string) *Server {
	return &Server{
		Addr:       addr,
		EnableH2:   true,
		EnableQUIC: true,
		maxLogs:    200,
		h2ByAddr:   make(map[string]*signal.H2Observation),
		helloByAddr: make(map[string][]byte),
	}
}

// Start launches the probe server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", s.handleProbe)
	mux.HandleFunc("/observations", s.handleObservations)
	mux.HandleFunc("/capture", s.handleCapturePage)
	mux.HandleFunc("/api/capture", s.handleCaptureAPI)
	mux.HandleFunc("/clienthello", s.handleClientHello)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/capture", http.StatusFound)
	})

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Capture raw ClientHello on the TCP conn before TLS consumes it.
	rawLn := &helloCaptureListener{Listener: ln, srv: s}

	// Use stdlib crypto/tls for the server stack so modern Chrome/Firefox can
	// complete the handshake. uTLS remains a client/parrot concern — here we
	// only need a compatible server that lets us observe the ClientHello.
	tlsCert, err := generateSelfSignedX509()
	if err != nil {
		return fmt.Errorf("tls cert: %w", err)
	}
	nextProtos := []string{"http/1.1"}
	if s.EnableH2 {
		nextProtos = []string{"h2", "http/1.1"}
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   nextProtos,
		MinVersion:   tls.VersionTLS12,
	}
	tlsLn := tls.NewListener(rawLn, tlsCfg)

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		TLSConfig:    tlsCfg,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connContextKey{}, c)
		},
	}
	if s.EnableH2 {
		if err := http2.ConfigureServer(s.server, &http2.Server{}); err != nil {
			return fmt.Errorf("http2: %w", err)
		}
	}
	go func() {
		if err := s.server.Serve(&h2CaptureListener{Listener: tlsLn, srv: s}); err != nil && err != http.ErrServerClosed {
			log.Printf("probe server error: %v", err)
		}
	}()
	if s.EnableQUIC && s.CaptureDir != "" {
		if err := s.startQUICCapture(*tlsCert); err != nil {
			log.Printf("quic capture disabled: %v", err)
		}
	}
	if s.CaptureDir != "" {
		if _, _, err := WriteCertPEMs(s.CaptureDir); err == nil {
			log.Printf("wrote probe cert PEMs to %s (import into Firefox to complete H2 capture)", s.CaptureDir)
		}
	}
	return nil
}

type connContextKey struct{}

// helloCaptureListener wraps Accept to record the first TLS record per conn.
type helloCaptureListener struct {
	net.Listener
	srv *Server
}

func (l *helloCaptureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &helloTrackedConn{
		HelloCaptureConn: NewHelloCaptureConn(conn),
		srv:              l.srv,
	}, nil
}

type helloTrackedConn struct {
	*HelloCaptureConn
	srv     *Server
	stored  bool
	storeMu sync.Mutex
}

func (c *helloTrackedConn) Read(p []byte) (int, error) {
	n, err := c.HelloCaptureConn.Read(p)
	c.maybeStore()
	return n, err
}

func (c *helloTrackedConn) maybeStore() {
	c.storeMu.Lock()
	defer c.storeMu.Unlock()
	if c.stored {
		return
	}
	hello := c.ClientHello()
	if hello == nil {
		return
	}
	c.stored = true
	c.srv.storeHello(c.RemoteAddr().String(), hello)
}

type h2CaptureListener struct {
	net.Listener
	srv *Server
}

func (l *h2CaptureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &h2TrackedConn{
		Conn: h2wire.NewCaptureConn(conn),
		srv:  l.srv,
	}, nil
}

type h2TrackedConn struct {
	net.Conn
	srv *Server
}

func (c *h2TrackedConn) Close() error {
	if cap, ok := c.Conn.(*h2wire.CaptureConn); ok {
		if obs := cap.Observation(); obs != nil {
			c.srv.storeH2(c.RemoteAddr().String(), obs)
		}
		if raw := cap.RawClientFlight(); len(raw) > 0 {
			c.srv.persistH2Raw(raw)
		}
	}
	return c.Conn.Close()
}

func (s *Server) storeH2(addr string, obs *signal.H2Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h2ByAddr[addr] = obs
}

func (s *Server) persistH2Raw(raw []byte) {
	s.mu.Lock()
	s.lastH2Raw = append([]byte(nil), raw...)
	dir := s.CaptureDir
	s.mu.Unlock()
	if dir == "" || len(raw) == 0 {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, fmt.Sprintf("probe-%d.h2.bin", time.Now().UnixNano()))
	if err := os.WriteFile(path, raw, 0o644); err == nil {
		log.Printf("wrote H2 client flight %d bytes → %s", len(raw), path)
	}
}

func (s *Server) takeH2(addr string) *signal.H2Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	obs := s.h2ByAddr[addr]
	delete(s.h2ByAddr, addr)
	return obs
}

func (s *Server) storeHello(addr string, hello []byte) {
	s.mu.Lock()
	s.helloByAddr[addr] = append([]byte(nil), hello...)
	s.lastHello = append([]byte(nil), hello...)
	dir := s.CaptureDir
	s.mu.Unlock()

	// Persist as soon as the first TLS record is peeked — even if the browser
	// aborts after Certificate (Firefox has no --ignore-certificate-errors).
	if dir != "" && len(hello) > 0 {
		_ = os.MkdirAll(dir, 0o755)
		path := filepath.Join(dir, fmt.Sprintf("probe-%d.clienthello.bin", time.Now().UnixNano()))
		if err := os.WriteFile(path, hello, 0o644); err == nil {
			log.Printf("wrote ClientHello %d bytes → %s", len(hello), path)
		}
	}
}

func (s *Server) takeHello(addr string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	hello := s.helloByAddr[addr]
	delete(s.helloByAddr, addr)
	if hello == nil {
		return nil
	}
	return append([]byte(nil), hello...)
}

// LastClientHello returns the most recently captured ClientHello record.
func (s *Server) LastClientHello() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastHello == nil {
		return nil
	}
	return append([]byte(nil), s.lastHello...)
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	if s.quicStop != nil {
		s.quicStop()
	}
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// Observations returns recorded observations.
func (s *Server) Observations() []Observation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Observation, len(s.logs))
	copy(out, s.logs)
	return out
}

// Last returns the most recent observation.
func (s *Server) Last() *Observation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.logs) == 0 {
		return nil
	}
	o := s.logs[len(s.logs)-1]
	return &o
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	order := extractHeaderOrder(r)
	headers := map[string]string{}
	for k, vals := range r.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}

	obs := Observation{
		Timestamp:   time.Now().UTC(),
		RemoteAddr:  r.RemoteAddr,
		UserAgent:   r.Header.Get("User-Agent"),
		Headers:     headers,
		HeaderOrder: order,
	}

	if r.TLS != nil {
		EnrichWithTLS(&obs, *r.TLS)
	}
	if hello := s.helloFromRequest(r); len(hello) > 0 && obs.TLS != nil {
		if ch, err := dissect.ParseClientHello(hello); err == nil {
			obs.TLS.JA3 = ch.JA3Hash()
			obs.TLS.JA4 = ch.JA4()
		}
	}
	if h2 := s.h2FromRequest(r); h2 != nil {
		obs.H2 = h2
	}
	// Advertise HTTP/3 so browsers send a real QUIC Initial to our UDP capture port.
	if s.EnableQUIC && s.CaptureDir != "" {
		host, port, err := net.SplitHostPort(s.Addr)
		if err == nil {
			if host == "" || host == "0.0.0.0" {
				host = "127.0.0.1"
			}
			w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%s"; ma=60`, port))
			_ = host
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok","message":"CoherenceLab probe received"}`)

	s.mu.Lock()
	s.logs = append(s.logs, obs)
	if s.maxLogs > 0 && len(s.logs) > s.maxLogs {
		s.logs = append([]Observation(nil), s.logs[len(s.logs)-s.maxLogs:]...)
	}
	s.mu.Unlock()
}

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.Observations())
}

func (s *Server) handleClientHello(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	hello := s.helloFromRequest(r)
	if hello == nil {
		hello = s.LastClientHello()
	}
	if hello == nil {
		http.Error(w, "no ClientHello captured yet — hit /probe or /capture from a browser first", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="clienthello.bin"`)
	w.Header().Set("X-ClientHello-Bytes", fmt.Sprintf("%d", len(hello)))
	_, _ = w.Write(hello)
}

func extractHeaderOrder(r *http.Request) []string {
	if order := r.Header.Get("X-Header-Order"); order != "" {
		return splitHeaderOrder(order)
	}
	var keys []string
	for k := range r.Header {
		keys = append(keys, k)
	}
	return keys
}

func splitHeaderOrder(s string) []string {
	var out []string
	for _, p := range splitComma(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitComma(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// EnrichWithTLS adds TLS metadata when available from connection state.
func EnrichWithTLS(obs *Observation, state tls.ConnectionState) {
	obs.TLS = &signal.TLSObservation{
		Version:     tlsfp.VersionString(state.Version),
		CipherSuite: tlsfp.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
		SNI:         state.ServerName,
	}
}
