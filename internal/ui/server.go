package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/oliver-nyx/coherencelab/internal/profile"
	"github.com/oliver-nyx/coherencelab/internal/scan"
)

// Server hosts the local report viewer.
type Server struct {
	Addr        string
	ProfilesDir string
	server      *http.Server
}

// New creates a UI server.
func New(addr, profilesDir string) *Server {
	return &Server{Addr: addr, ProfilesDir: profilesDir}
}

// Start begins serving HTTP.
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	s.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("ui server error: %v", err)
		}
	}()
	return nil
}

// Stop shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := profile.LoadDir(s.ProfilesDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	type item struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Browser  string `json:"browser"`
		Platform string `json:"platform"`
		Version  string `json:"version"`
	}
	out := make([]item, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, item{
			ID: p.ID, Name: p.Name, Browser: p.Browser,
			Platform: p.Platform, Version: p.Version,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, out)
}

type scanRequest struct {
	Profile  string `json:"profile"`
	Mode     string `json:"mode"`
	Mutate   string `json:"mutate"`
	ProbeURL string `json:"probe"`
	Insecure bool   `json:"insecure"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Profile == "" {
		http.Error(w, "profile required", http.StatusBadRequest)
		return
	}
	p, err := profile.FindByID(s.ProfilesDir, req.Profile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	mode := scan.Mode(req.Mode)
	if mode == "" {
		mode = scan.ModeLocal
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	rep, err := scan.Run(ctx, scan.Options{
		Profile:  p,
		Mode:     mode,
		Mutate:   req.Mutate,
		ProbeURL: req.ProbeURL,
		Insecure: req.Insecure,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, rep)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
