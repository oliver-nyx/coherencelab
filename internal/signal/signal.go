package signal

import (
	"net/http"
	"strings"
)

// Snapshot captures observed identity signals from a client or probe.
type Snapshot struct {
	ProfileID string `json:"profile_id,omitempty"`

	UserAgent string            `json:"user_agent"`
	Headers   map[string]string `json:"headers"`
	HeaderOrder []string        `json:"header_order"`

	SecCHUA         string `json:"sec_ch_ua,omitempty"`
	SecCHUAMobile   string `json:"sec_ch_ua_mobile,omitempty"`
	SecCHUAPlatform string `json:"sec_ch_ua_platform,omitempty"`
	AcceptLanguage  string `json:"accept_language,omitempty"`
	Accept          string `json:"accept,omitempty"`
	AcceptEncoding  string `json:"accept_encoding,omitempty"`

	TLS *TLSObservation `json:"tls,omitempty"`
	H2  *H2Observation  `json:"http2,omitempty"`
}

type TLSObservation struct {
	Version      string   `json:"version"`
	CipherSuite  string   `json:"cipher_suite"`
	ALPN         string   `json:"alpn"`
	JA3          string   `json:"ja3"`
	JA4          string   `json:"ja4"`
	UTLSClientID string   `json:"utls_client_id,omitempty"`
	SNI          string   `json:"sni,omitempty"`
}

type H2Observation struct {
	HeaderTableSize   uint32 `json:"header_table_size"`
	EnablePush        uint32 `json:"enable_push"`
	MaxConcurrent     uint32 `json:"max_concurrent_streams"`
	InitialWindowSize uint32 `json:"initial_window_size"`
	MaxFrameSize      uint32 `json:"max_frame_size"`
	MaxHeaderListSize uint32 `json:"max_header_list_size"`
}

// FromRequest builds a snapshot from incoming HTTP headers.
func FromRequest(r *http.Request, order []string) *Snapshot {
	headers := make(map[string]string, len(r.Header))
	for k, vals := range r.Header {
		if len(vals) > 0 {
			headers[canonicalKey(k)] = vals[0]
		}
	}
	if len(order) == 0 {
		order = headerOrder(r)
	}
	return &Snapshot{
		UserAgent:       r.Header.Get("User-Agent"),
		Headers:         headers,
		HeaderOrder:     order,
		SecCHUA:         r.Header.Get("Sec-Ch-Ua"),
		SecCHUAMobile:   r.Header.Get("Sec-Ch-Ua-Mobile"),
		SecCHUAPlatform: r.Header.Get("Sec-Ch-Ua-Platform"),
		AcceptLanguage:  r.Header.Get("Accept-Language"),
		Accept:          r.Header.Get("Accept"),
		AcceptEncoding:  r.Header.Get("Accept-Encoding"),
	}
}

func headerOrder(r *http.Request) []string {
	seen := make(map[string]struct{})
	var order []string
	for k := range r.Header {
		ck := canonicalKey(k)
		if _, ok := seen[ck]; ok {
			continue
		}
		seen[ck] = struct{}{}
		order = append(order, ck)
	}
	return order
}

func canonicalKey(k string) string {
	return strings.ToLower(k)
}
