package tlsfp

import "testing"

func TestPresetNoteApproximations(t *testing.T) {
	if PresetNote("chrome_131") != "" {
		t.Fatal("chrome_131 is a real parrot")
	}
	if PresetNote("chrome_132") == "" || PresetNote("firefox_133") == "" || PresetNote("safari_18") == "" || PresetNote("edge_106") == "" {
		t.Fatal("expected approximation notes")
	}
}
