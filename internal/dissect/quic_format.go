package dissect

import (
	"fmt"
	"io"
)

// FormatQUICInitial writes an expert-oriented Initial dissection report.
func FormatQUICInitial(w io.Writer, d *DecryptedInitial) {
	fmt.Fprintln(w, "═══ QUIC Initial dissection (RFC 9000/9001) ═══")
	h := d.Header
	fmt.Fprintf(w, "Long header: %s  version=0x%08x  first=0x%02x\n", quicLongTypeName(h.Type), h.Version, h.FirstByte)
	fmt.Fprintf(w, "DCID (%d): %x\n", len(h.DCID), h.DCID)
	fmt.Fprintf(w, "SCID (%d): %x\n", len(h.SCID), h.SCID)
	fmt.Fprintf(w, "Token: %d bytes\n", len(h.Token))
	fmt.Fprintf(w, "Packet number: %d (len=%d)\n", d.PacketNumber, h.PNLength)
	if h.Note != "" {
		fmt.Fprintf(w, "※ %s\n", h.Note)
	}

	fmt.Fprintln(w, "\n── Frames (decrypted payload) ──")
	for i, fr := range d.Frames {
		fmt.Fprintf(w, "%2d. %s  %s\n", i+1, fr.Name, fr.Detail)
	}

	if len(d.Transport) > 0 {
		fmt.Fprintln(w, "\n── Transport parameters (from ClientHello ext 0x39) ──")
		FormatTransportParameters(w, d.Transport)
	}
	if d.ClientHello != nil {
		fmt.Fprintln(w, "\n── Embedded ClientHello (summary) ──")
		fmt.Fprintf(w, "SNI: %s\n", d.ClientHello.SNI)
		fmt.Fprintf(w, "Extensions: %d  JA3: %s\n", len(d.ClientHello.Extensions), d.ClientHello.JA3Hash())
		fmt.Fprintln(w, "(full dump: coherencelab lab clienthello --bin <crypto-export>)")
	}

	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range d.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

// FormatTransportParameters writes a TP table.
func FormatTransportParameters(w io.Writer, tps []TransportParam) {
	for i, tp := range tps {
		fmt.Fprintf(w, "%2d. %-40s id=0x%x", i+1, tp.Name, tp.ID)
		if tp.Decoded != "" {
			fmt.Fprintf(w, "  → %s", tp.Decoded)
		}
		fmt.Fprintln(w)
		if tp.Note != "" {
			fmt.Fprintf(w, "    ※ %s\n", tp.Note)
		}
	}
}

// FormatQUICLongHeader writes header-only parse (no decrypt).
func FormatQUICLongHeader(w io.Writer, h *QUICLongHeader) {
	fmt.Fprintln(w, "═══ QUIC long header (no decrypt) ═══")
	fmt.Fprintf(w, "Type: %s  version=0x%08x  first=0x%02x\n", quicLongTypeName(h.Type), h.Version, h.FirstByte)
	fmt.Fprintf(w, "DCID (%d): %x\n", len(h.DCID), h.DCID)
	fmt.Fprintf(w, "SCID (%d): %x\n", len(h.SCID), h.SCID)
	if h.Type == QUICLongInitial {
		fmt.Fprintf(w, "Token: %d bytes  Length field: %d\n", len(h.Token), h.Length)
	}
	if h.Note != "" {
		fmt.Fprintf(w, "※ %s\n", h.Note)
	}
	fmt.Fprintln(w, "Tip: use without --header-only to decrypt QUICv1 Initials (RFC 9001 salt).")
}

// FormatVersionNegotiation writes a VN dissection report.
func FormatVersionNegotiation(w io.Writer, vn *VersionNegotiation) {
	fmt.Fprintln(w, "═══ QUIC Version Negotiation ═══")
	fmt.Fprintf(w, "First byte: 0x%02x  version=0x00000000\n", vn.FirstByte)
	fmt.Fprintf(w, "DCID (%d): %x\n", len(vn.DCID), vn.DCID)
	fmt.Fprintf(w, "SCID (%d): %x\n", len(vn.SCID), vn.SCID)
	fmt.Fprintln(w, "\n── Supported versions ──")
	for i, v := range vn.Versions {
		fmt.Fprintf(w, "%2d. %s\n", i+1, formatVersion(v))
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range vn.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}

// FormatRetry writes a Retry dissection report.
func FormatRetry(w io.Writer, r *RetryPacket) {
	fmt.Fprintln(w, "═══ QUIC Retry ═══")
	h := r.Header
	fmt.Fprintf(w, "Version: 0x%08x  first=0x%02x\n", h.Version, h.FirstByte)
	fmt.Fprintf(w, "DCID (%d): %x  (echo of client SCID)\n", len(h.DCID), h.DCID)
	fmt.Fprintf(w, "SCID (%d): %x  (server-chosen → client's next DCID)\n", len(h.SCID), h.SCID)
	fmt.Fprintf(w, "Retry Token: %d bytes  %x\n", len(r.RetryToken), r.RetryToken)
	fmt.Fprintf(w, "Integrity Tag: %x\n", r.IntegrityTag)
	if r.TagValid != nil {
		if *r.TagValid {
			fmt.Fprintln(w, "Tag check: VALID")
		} else {
			fmt.Fprintln(w, "Tag check: INVALID")
		}
	} else {
		fmt.Fprintln(w, "Tag check: skipped (pass --odcid to verify)")
	}
	fmt.Fprintln(w, "\n── Findings ──")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "• %s\n", f)
	}
}
