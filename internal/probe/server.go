package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/coherencelab/coherencelab/internal/signal"
	"github.com/coherencelab/coherencelab/internal/tlsfp"
)

// Observation is a recorded probe result from a client connection.
type Observation struct {
	Timestamp   time.Time         `json:"timestamp"`
	RemoteAddr  string            `json:"remote_addr"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers"`
	HeaderOrder []string          `json:"header_order"`
	TLS         *signal.TLSObservation `json:"tls,omitempty"`
}

// Server is a TLS probe server that captures client identity signals.
type Server struct {
	Addr   string
	mu     sync.RWMutex
	logs   []Observation
	server *http.Server
}

// New creates a probe server.
func New(addr string) *Server {
	return &Server{Addr: addr}
}

// Start launches the probe server.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", s.handleProbe)
	mux.HandleFunc("/observations", s.handleObservations)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	tlsLn := utls.NewListener(ln, &utls.Config{
		GetCertificate: func(*utls.ClientHelloInfo) (*utls.Certificate, error) {
			cert, err := generateSelfSigned()
			if err != nil {
				return nil, err
			}
			return cert, nil
		},
		NextProtos: []string{"h2", "http/1.1"},
	})

	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	go func() {
		if err := s.server.Serve(tlsLn); err != nil && err != http.ErrServerClosed {
			log.Printf("probe server error: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
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
		RemoteAddr:    r.RemoteAddr,
		UserAgent:   r.Header.Get("User-Agent"),
		Headers:     headers,
		HeaderOrder: order,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"ok","message":"CoherenceLab probe received"}`)

	s.mu.Lock()
	s.logs = append(s.logs, obs)
	s.mu.Unlock()
}

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.Observations())
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
func EnrichWithTLS(obs *Observation, state utls.ConnectionState) {
	obs.TLS = &signal.TLSObservation{
		Version:     tlsfp.VersionString(state.Version),
		CipherSuite: tlsfp.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
		SNI:         state.ServerName,
	}
}
