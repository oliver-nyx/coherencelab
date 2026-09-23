package client

import (
	"net/http"

	"golang.org/x/net/http2"

	"github.com/oliver-nyx/coherencelab/internal/profile"
)

func applyProfileHTTP2(tr *http.Transport, h2t *http2.Transport, p *profile.Profile) {
	if p == nil {
		return
	}
	h2 := p.HTTP2
	if h2 == (profile.HTTP2Spec{}) {
		return
	}

	cfg := &http.HTTP2Config{}
	if h2.HeaderTableSize > 0 {
		cfg.MaxDecoderHeaderTableSize = int(h2.HeaderTableSize)
		cfg.MaxEncoderHeaderTableSize = int(h2.HeaderTableSize)
	}
	if h2.MaxFrameSize > 0 {
		cfg.MaxReadFrameSize = int(h2.MaxFrameSize)
	}
	if h2.InitialWindowSize > 0 {
		cfg.MaxReceiveBufferPerStream = int(h2.InitialWindowSize)
	}
	tr.HTTP2 = cfg

	if h2t != nil && h2.MaxHeaderListSize > 0 {
		h2t.MaxHeaderListSize = h2.MaxHeaderListSize
	}
}
