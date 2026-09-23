package dissect

import (
	"fmt"
	"io"
)

// FormatH3 writes an expert-oriented HTTP/3 frame dissection report.
func FormatH3(w io.Writer, s *H3Session) {
	fmt.Fprintln(w, "═══ HTTP/3 wire dissection (stream frames) ═══")
	fmt.Fprintln(w, "Layer: post-decrypt HTTP/3 frames — not QUIC Long/Short headers")
	fmt.Fprintln(w, "\n── Frames ──")
	for i, fr := range s.Frames {
		fmt.Fprintf(w, "%2d. %s  type=0x%x len=%d\n", i+1, fr.Name, fr.Type, fr.Length)
		if fr.Detail != "" {
			fmt.Fprintf(w, "    %s\n", fr.Detail)
		}
		if fr.Note != "" {
			fmt.Fprintf(w, "    ※ %s\n", fr.Note)
		}
	}
	if len(s.Settings) > 0 {
		fmt.Fprintln(w, "\n── SETTINGS detail ──")
		for _, st := range s.Settings {
			fmt.Fprintf(w, "  %-28s = %-10d", st.Name, st.Value)
			if st.Note != "" {
				fmt.Fprintf(w, "  ※ %s", st.Note)
			}
			fmt.Fprintln(w)
		}
	}
	if len(s.PriorityUpdates) > 0 {
		fmt.Fprintln(w, "\n── PRIORITY_UPDATE (RFC 9218 / HTTP/3) ──")
		for i, pu := range s.PriorityUpdates {
			fmt.Fprintf(w, "%2d. kind=%s id=%d type=0x%x value=%q", i+1, pu.TargetKind, pu.TargetID, pu.FrameType, pu.RawValue)
			if pu.Urgency != nil {
				fmt.Fprintf(w, " u=%d", *pu.Urgency)
			}
			if pu.Incremental != nil {
				fmt.Fprintf(w, " i=%v", *pu.Incremental)
			}
			fmt.Fprintln(w)
			if pu.Note != "" {
				fmt.Fprintf(w, "    ※ %s\n", pu.Note)
			}
		}
		fmt.Fprintf(w, "Priority fingerprint field: %s\n", s.PriorityFingerprint())
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range s.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}
