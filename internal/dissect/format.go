package dissect

import (
	"fmt"
	"io"
)

// FormatClientHello writes an expert-oriented dissection report.
func FormatClientHello(w io.Writer, ch *ClientHello) {
	fmt.Fprintln(w, "═══ TLS ClientHello dissection ═══")
	if ch.RecordContentType != 0 {
		fmt.Fprintf(w, "Record: type=handshake ver=%s len=%d\n", tlsVersionName(ch.RecordVersion), ch.RecordLength)
	}
	fmt.Fprintf(w, "Legacy version: %s (0x%04x)\n", tlsVersionName(ch.LegacyVersion), ch.LegacyVersion)
	fmt.Fprintf(w, "Random: %x\n", ch.Random)
	fmt.Fprintf(w, "Session ID: %d bytes\n", len(ch.SessionID))
	fmt.Fprintf(w, "Cipher suites (%d):", len(ch.CipherSuites))
	for i, cs := range ch.CipherSuites {
		if i == 0 {
			fmt.Fprint(w, " ")
		} else {
			fmt.Fprint(w, ", ")
		}
		if IsGREASE16(cs) {
			fmt.Fprintf(w, "GREASE(0x%04x)", cs)
		} else {
			fmt.Fprintf(w, "0x%04x", cs)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Compression: %v\n", ch.CompressionMethods)
	fmt.Fprintln(w, "\n── Extensions (wire order) ──")
	for i, ext := range ch.Extensions {
		label := ext.Name
		if ext.GREASE {
			label = fmt.Sprintf("GREASE(0x%04x)", ext.Type)
		}
		fmt.Fprintf(w, "%2d. %s  len=%d", i+1, label, len(ext.Data))
		if ext.Decoded != "" {
			fmt.Fprintf(w, "  → %s", ext.Decoded)
		}
		fmt.Fprintln(w)
		if ext.Note != "" {
			fmt.Fprintf(w, "    ※ %s\n", ext.Note)
		}
	}
	fmt.Fprintln(w, "\n── Fingerprints ──")
	fmt.Fprintf(w, "JA3 raw:  %s\n", ch.JA3Raw())
	fmt.Fprintf(w, "JA3 hash: %s\n", ch.JA3Hash())
	fmt.Fprintf(w, "JA4*:     %s\n", ch.JA4())
	fmt.Fprintln(w, "  (* JA4-inspired; see package docs before treating as FoxIO-canonical)")
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range ch.Findings() {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

// FormatH2 writes an expert-oriented HTTP/2 dissection report.
func FormatH2(w io.Writer, s *H2Session) {
	fmt.Fprintln(w, "═══ HTTP/2 wire dissection ═══")
	fmt.Fprintf(w, "Client preface: %v\n", s.HasPreface)
	fmt.Fprintln(w, "\n── Frames ──")
	for i, fr := range s.Frames {
		fmt.Fprintf(w, "%2d. %s  stream=%d flags=0x%02x len=%d\n", i+1, fr.Name, fr.Stream, fr.Flags, fr.Length)
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
		fmt.Fprintln(w, "\n── PRIORITY_UPDATE (RFC 9218) ──")
		for i, pu := range s.PriorityUpdates {
			fmt.Fprintf(w, "%2d. prioritized_stream=%d value=%q", i+1, pu.PrioritizedStream, pu.RawValue)
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
	if s.HeaderBlock != nil {
		fmt.Fprintln(w, "\n── HPACK / pseudo-headers ──")
		FormatHeaderBlock(w, s.HeaderBlock)
		fmt.Fprintf(w, "\nAkamai-style H2 fingerprint:\n  %s\n", s.AkamaiH2Fingerprint())
	} else if len(s.PriorityUpdates) > 0 || len(s.Settings) > 0 {
		fmt.Fprintf(w, "\nAkamai-style H2 fingerprint:\n  %s\n", s.AkamaiH2Fingerprint())
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range s.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

// FormatHeaderBlock writes decoded HPACK fields + pseudo-order analysis.
func FormatHeaderBlock(w io.Writer, hb *HeaderBlock) {
	fmt.Fprintf(w, "Pseudo order: %s  (family≈%s)\n", hb.PseudoOrder, hb.FamilyGuess)
	for i, f := range hb.Fields {
		fmt.Fprintf(w, "%2d. %s: %s\n", i+1, f.Name, f.Value)
	}
	for _, f := range hb.Findings {
		fmt.Fprintf(w, "  ※ %s\n", f)
	}
}
