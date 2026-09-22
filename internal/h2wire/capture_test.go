package h2wire

import (
	"testing"

	"golang.org/x/net/http2"
)

func TestParseClientSettings_Chrome(t *testing.T) {
	data := BuildClientPrefaceBytes(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 6291456},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 262144},
	)

	obs, err := ParseClientSettings(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if obs.Source != "wire" {
		t.Fatalf("source = %q, want wire", obs.Source)
	}
	if obs.HeaderTableSize != 65536 {
		t.Fatalf("header_table_size = %d", obs.HeaderTableSize)
	}
	if obs.MaxConcurrent != 1000 {
		t.Fatalf("max_concurrent = %d", obs.MaxConcurrent)
	}
	if obs.InitialWindowSize != 6291456 {
		t.Fatalf("initial_window = %d", obs.InitialWindowSize)
	}
	if !obs.Present["MAX_CONCURRENT_STREAMS"] {
		t.Fatal("expected MAX_CONCURRENT_STREAMS present")
	}
}

func TestParseClientSettings_Firefox(t *testing.T) {
	data := BuildClientPrefaceBytes(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 65536},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 100},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 131072},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: 16384},
	)

	obs, err := ParseClientSettings(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if obs.MaxConcurrent != 100 {
		t.Fatalf("max_concurrent = %d", obs.MaxConcurrent)
	}
	if obs.InitialWindowSize != 131072 {
		t.Fatalf("initial_window = %d", obs.InitialWindowSize)
	}
}

func TestParseClientSettings_Incomplete(t *testing.T) {
	_, err := ParseClientSettings([]byte("PRI * HTTP/2.0\r\n\r\n"))
	if err != ErrIncomplete {
		t.Fatalf("err = %v, want ErrIncomplete", err)
	}
}

func TestCaptureConn_Write(t *testing.T) {
	client, server := netPipe(t)
	go func() {
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)
	}()

	cap := NewCaptureConn(client)
	data := BuildClientPrefaceBytes(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096},
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
	)
	if _, err := cap.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}

	obs := cap.Observation()
	if obs == nil {
		t.Fatal("expected observation")
	}
	if obs.HeaderTableSize != 4096 {
		t.Fatalf("header_table_size = %d", obs.HeaderTableSize)
	}
}
