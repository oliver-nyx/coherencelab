package h2wire

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/http2"

	"github.com/coherencelab/coherencelab/internal/signal"
)

// ErrIncomplete indicates more bytes are needed before a SETTINGS frame can be parsed.
var ErrIncomplete = errors.New("h2wire: incomplete client preface or settings")

// ParseClientSettings parses the HTTP/2 connection preface and first non-ACK SETTINGS frame.
func ParseClientSettings(data []byte) (*signal.H2Observation, error) {
	obs, err := tryParseClientSettings(data)
	if errors.Is(err, ErrIncomplete) {
		return nil, ErrIncomplete
	}
	return obs, err
}

func tryParseClientSettings(data []byte) (*signal.H2Observation, error) {
	prefaceLen := len(http2.ClientPreface)
	if len(data) < prefaceLen {
		return nil, ErrIncomplete
	}
	if string(data[:prefaceLen]) != http2.ClientPreface {
		return nil, fmt.Errorf("h2wire: invalid client preface")
	}

	fr := http2.NewFramer(io.Discard, bytes.NewReader(data[prefaceLen:]))
	fr.SetReuseFrames()
	for {
		frame, err := fr.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, ErrIncomplete
			}
			return nil, fmt.Errorf("h2wire: read frame: %w", err)
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			return settingsFrameToObservation(f), nil
		case *http2.WindowUpdateFrame, *http2.PingFrame:
			continue
		default:
			continue
		}
	}
}

func settingsFrameToObservation(f *http2.SettingsFrame) *signal.H2Observation {
	obs := &signal.H2Observation{
		Source:  "wire",
		Present: make(map[string]bool),
	}
	_ = f.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingHeaderTableSize:
			obs.HeaderTableSize = s.Val
			obs.Present["HEADER_TABLE_SIZE"] = true
		case http2.SettingEnablePush:
			obs.EnablePush = s.Val
			obs.Present["ENABLE_PUSH"] = true
		case http2.SettingMaxConcurrentStreams:
			obs.MaxConcurrent = s.Val
			obs.Present["MAX_CONCURRENT_STREAMS"] = true
		case http2.SettingInitialWindowSize:
			obs.InitialWindowSize = s.Val
			obs.Present["INITIAL_WINDOW_SIZE"] = true
		case http2.SettingMaxFrameSize:
			obs.MaxFrameSize = s.Val
			obs.Present["MAX_FRAME_SIZE"] = true
		case http2.SettingMaxHeaderListSize:
			obs.MaxHeaderListSize = s.Val
			obs.Present["MAX_HEADER_LIST_SIZE"] = true
		}
		return nil
	})
	return obs
}

// BuildClientPrefaceBytes constructs preface + SETTINGS frame bytes for tests.
func BuildClientPrefaceBytes(settings ...http2.Setting) []byte {
	var buf bytes.Buffer
	buf.WriteString(http2.ClientPreface)
	fr := http2.NewFramer(&buf, bytes.NewReader(nil))
	_ = fr.WriteSettings(settings...)
	return buf.Bytes()
}
