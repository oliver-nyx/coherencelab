package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/coherencelab/coherencelab/internal/profile"
	"github.com/coherencelab/coherencelab/internal/signal"
	"github.com/coherencelab/coherencelab/internal/tlsfp"
)

// Config configures a coherence-aware HTTP client.
type Config struct {
	Profile  *profile.Profile
	Timeout  time.Duration
	Insecure bool
}

// DialResult captures TLS + H2 metadata from the connection.
type DialResult struct {
	TLS *signal.TLSObservation
	H2  *signal.H2Observation
}

// BuildTransport creates an HTTP transport matching the profile.
func BuildTransport(cfg Config) (*http.Transport, *DialResult, error) {
	if cfg.Profile == nil {
		return nil, nil, fmt.Errorf("profile required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	result := &DialResult{}
	helloID := tlsfp.ClientHelloID(cfg.Profile.TLS.UTLSClientID)

	dialTLS := func(network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		conn, err := net.DialTimeout(network, addr, cfg.Timeout)
		if err != nil {
			return nil, err
		}
		tlsConn := utls.UClient(conn, &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: cfg.Insecure,
			NextProtos:         cfg.Profile.TLS.ALPN,
		}, helloID)

		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}

		state := tlsConn.ConnectionState()
		result.TLS = &signal.TLSObservation{
			Version:      tlsfp.VersionString(state.Version),
			CipherSuite:  tlsfp.CipherSuiteName(state.CipherSuite),
			ALPN:         state.NegotiatedProtocol,
			UTLSClientID: cfg.Profile.TLS.UTLSClientID,
			SNI:          host,
		}
		if spec, err := utls.UTLSIdToSpec(helloID); err == nil {
			result.TLS.JA3 = tlsfp.JA3(state.Version, spec.CipherSuites, nil, nil, []uint8{0})
			result.TLS.JA4 = tlsfp.JA4(state.Version, host, spec.CipherSuites, nil)
		}

		if state.NegotiatedProtocol == "h2" {
			result.H2 = h2SettingsFromProfile(cfg.Profile)
		}
		return tlsConn, nil
	}

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLS(network, addr)
		},
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			NextProtos: cfg.Profile.TLS.ALPN,
		},
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, nil, fmt.Errorf("configure http2: %w", err)
	}
	return transport, result, nil
}

func h2SettingsFromProfile(p *profile.Profile) *signal.H2Observation {
	return &signal.H2Observation{
		HeaderTableSize:   p.HTTP2.HeaderTableSize,
		EnablePush:        p.HTTP2.EnablePush,
		MaxConcurrent:     p.HTTP2.MaxConcurrent,
		InitialWindowSize: p.HTTP2.InitialWindowSize,
		MaxFrameSize:      p.HTTP2.MaxFrameSize,
		MaxHeaderListSize: p.HTTP2.MaxHeaderListSize,
	}
}

// ApplyProfileHeaders sets browser-consistent headers on a request.
func ApplyProfileHeaders(req *http.Request, p *profile.Profile) []string {
	var order []string
	set := func(key, val string) {
		if val == "" {
			return
		}
		req.Header.Set(key, val)
		order = append(order, strings.ToLower(key))
	}

	set("User-Agent", p.UserAgent.Value)
	if p.ClientHints.SecCHUA != "" {
		set("Sec-Ch-Ua", p.ClientHints.SecCHUA)
	}
	if p.ClientHints.SecCHUAMobile != "" {
		set("Sec-Ch-Ua-Mobile", p.ClientHints.SecCHUAMobile)
	}
	if p.ClientHints.SecCHUAPlatform != "" {
		set("Sec-Ch-Ua-Platform", p.ClientHints.SecCHUAPlatform)
	}
	set("Accept", p.Headers.Accept)
	set("Accept-Language", p.AcceptLanguage.Pattern)
	set("Accept-Encoding", p.Headers.AcceptEncoding)
	if p.Headers.UpgradeInsecure {
		set("Upgrade-Insecure-Requests", "1")
	}
	for k, v := range p.Headers.Required {
		set(k, v)
	}

	if len(p.Headers.Order) > 0 {
		order = make([]string, len(p.Headers.Order))
		for i, h := range p.Headers.Order {
			order[i] = strings.ToLower(h)
		}
	}
	return order
}

// Probe sends a request and returns observed signals.
func Probe(ctx context.Context, probeURL string, p *profile.Profile, insecure bool) (*signal.Snapshot, *DialResult, error) {
	transport, dialResult, err := BuildTransport(Config{Profile: p, Insecure: insecure})
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, nil, err
	}
	order := ApplyProfileHeaders(req, p)

	resp, err := client.Do(req)
	if err != nil {
		return nil, dialResult, fmt.Errorf("probe request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	snap := signal.FromRequest(req, order)
	snap.ProfileID = p.ID
	if dialResult.TLS != nil {
		snap.TLS = dialResult.TLS
	}
	if dialResult.H2 != nil {
		snap.H2 = dialResult.H2
	}
	return snap, dialResult, nil
}

// LocalSnapshot builds a snapshot from profile config without network (header-only audit).
func LocalSnapshot(p *profile.Profile) *signal.Snapshot {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	order := ApplyProfileHeaders(req, p)
	snap := signal.FromRequest(req, order)
	snap.ProfileID = p.ID
	alpn := ""
	if len(p.TLS.ALPN) > 0 {
		alpn = p.TLS.ALPN[0]
	}
	version := p.TLS.MaxVersion
	if version == "" {
		version = "TLS 1.3"
	}
	snap.TLS = &signal.TLSObservation{
		UTLSClientID: p.TLS.UTLSClientID,
		ALPN:         alpn,
		Version:      version,
	}
	snap.H2 = h2SettingsFromProfile(p)
	return snap
}
