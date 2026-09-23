package probe

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oliver-nyx/coherencelab/internal/capture"
	"github.com/oliver-nyx/coherencelab/internal/h2wire"
	"github.com/oliver-nyx/coherencelab/internal/signal"
)

//go:embed capture.html
var captureHTML []byte

// CaptureResult is returned after a successful browser capture.
type CaptureResult struct {
	InputPath   string `json:"input_path,omitempty"`
	ProfilePath string `json:"profile_path,omitempty"`
	ProfileID   string `json:"profile_id"`
	Browser     string `json:"browser"`
	Platform    string `json:"platform"`
	Version     string `json:"version"`
}

func (s *Server) handleCapturePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(captureHTML)
}

func (s *Server) handleCaptureAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var payload capture.BrowserPayload
	if len(body) > 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	headers := map[string]string{}
	for k, vals := range r.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}
	order := extractHeaderOrder(r)

	var tlsObs *signal.TLSObservation
	tmp := Observation{}
	if r.TLS != nil {
		EnrichWithTLS(&tmp, *r.TLS)
		tlsObs = tmp.TLS
	}
	h2 := s.h2FromRequest(r)

	in := capture.FromHTTP(r.Header.Get("User-Agent"), headers, order, tlsObs, h2, &payload)
	p, err := capture.ToProfile(in)
	if err != nil {
		http.Error(w, "profile: "+err.Error(), http.StatusBadRequest)
		return
	}

	result := CaptureResult{
		ProfileID: p.ID,
		Browser:   p.Browser,
		Platform:  p.Platform,
		Version:   p.Version,
	}

	if s.CaptureDir != "" {
		if err := os.MkdirAll(s.CaptureDir, 0o755); err != nil {
			http.Error(w, "capture dir: "+err.Error(), http.StatusInternalServerError)
			return
		}
		stamp := time.Now().UTC().Format("20060102-150405")
		base := fmt.Sprintf("%s-%s", p.ID, stamp)
		inputPath := filepath.Join(s.CaptureDir, base+".json")
		profilePath := filepath.Join(s.CaptureDir, p.ID+".yaml")

		data, err := json.MarshalIndent(in, "", "  ")
		if err != nil {
			http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(inputPath, data, 0o644); err != nil {
			http.Error(w, "write input: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := capture.WriteYAML(profilePath, p); err != nil {
			http.Error(w, "write profile: "+err.Error(), http.StatusInternalServerError)
			return
		}
		result.InputPath = inputPath
		result.ProfilePath = profilePath
	}

	s.mu.Lock()
	s.lastCapture = in
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	msg := "Capture received — set serve --capture-dir to write YAML automatically"
	if result.ProfilePath != "" {
		msg = fmt.Sprintf("Profile written to %s", result.ProfilePath)
	}
	_ = enc.Encode(map[string]any{
		"status":  "ok",
		"message": msg,
		"capture": result,
		"input":   in,
	})
}

func (s *Server) h2FromRequest(r *http.Request) *signal.H2Observation {
	if h2 := s.takeH2(r.RemoteAddr); h2 != nil {
		return h2
	}
	if conn, ok := r.Context().Value(connContextKey{}).(*h2TrackedConn); ok {
		if inner, ok := conn.Conn.(*h2wire.CaptureConn); ok {
			return inner.Observation()
		}
	}
	return nil
}

// LastCapture returns the most recent browser capture input.
func (s *Server) LastCapture() *capture.Input {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCapture
}
