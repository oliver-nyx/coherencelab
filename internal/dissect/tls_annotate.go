package dissect

import "fmt"

func annotateClientHello(ch *ClientHello) {
	// Record vs legacy version split — classic TLS 1.3 tell.
	for i := range ch.Extensions {
		ext := &ch.Extensions[i]
		switch {
		case ext.GREASE:
			ext.Note = greaseNote("extension type", ext.Type)
		case ext.Type == ExtSupportedVersions:
			ext.Note = "TLS 1.3 clients keep legacy_version=0x0303 (TLS 1.2) on the nose; the real offer is here. Detectors that trust only the record/legacy version misclassify 1.3 clients."
		case ext.Type == ExtKeyShare:
			ext.Note = "key_share group order + presence of X25519/MLKEM hybrids is a strong Chrome-vs-Firefox separator. GREASE groups may appear first."
		case ext.Type == ExtALPN:
			ext.Note = "ALPN order matters: h2 before http/1.1 is expected for browsers. Impersonators that omit h2 or reverse order are trivial catches."
		case ext.Type == ExtEncryptedClientHello:
			ext.Note = "ECH hides the real SNI from on-path observers. Presence alone is a Chrome/Firefox generation signal; absence on a 'Chrome 131' claim is suspicious on ECH-enabled builds."
		case ext.Type == ExtApplicationSettings, ext.Type == ExtApplicationSettingsNew:
			ext.Note = "ALPS is a Chromium tell. Safari/Firefox should not advertise it. High-value cross-layer check against User-Agent family."
		case ext.Type == ExtPadding:
			ext.Note = "padding normalizes ClientHello size (anti-traffic-analysis). Length distribution still leaks implementation family."
		case ext.Type == ExtCompressCertificate:
			ext.Note = "compress_certificate (RFC 8879) — browsers advertise it; Chromium often brotli, Firefox often zlib. Rare in curl/Go defaults."
		case ext.Type == ExtServerName:
			ext.Note = "SNI is cleartext unless ECH is used. JA4 records presence as d (domain) or i (no SNI); the value itself is not in the hash."
		}
	}

	_ = fmt.Sprintf // keep import stable if notes expand
}

// Findings returns RE teaching bullets derived from the parsed hello.
func (ch *ClientHello) Findings() []string {
	var out []string
	if ch.RecordVersion != 0 && ch.LegacyVersion == 0x0303 {
		if hasVersion(ch.SupportedVersions, 0x0304) {
			out = append(out, "Record/legacy version advertise TLS 1.2 while supported_versions offers TLS 1.3 — expected modern ClientHello shape")
		}
	}
	if ch.GREASECipherCount > 0 || ch.GREASEExtensionCount > 0 {
		out = append(out, fmt.Sprintf("GREASE present: %d cipher(s), %d extension type(s) — modern browser randomization; strip before JA3, keep for permutation analysis",
			ch.GREASECipherCount, ch.GREASEExtensionCount))
	} else {
		out = append(out, "No GREASE in ciphers/extension types — atypical for modern Chrome/Firefox; more consistent with Safari, older stacks, or naive impersonation")
	}
	if ch.HasALPS {
		out = append(out, "ALPS extension present — Chromium family signal")
	}
	if ch.HasECH {
		out = append(out, "encrypted_client_hello present — post-2023 browser generation signal")
	}
	if len(ch.ALPN) > 0 && ch.ALPN[0] != "h2" {
		out = append(out, fmt.Sprintf("ALPN[0]=%q — browsers usually list h2 first", ch.ALPN[0]))
	}
	if len(ch.SessionID) == 32 {
		out = append(out, "32-byte session_id in TLS 1.3 ClientHello — Chrome middlebox-compatibility quirk (compatibility mode)")
	}
	if len(ch.ExtensionOrder) > 0 {
		out = append(out, fmt.Sprintf("Extension order (%d): %s", len(ch.ExtensionOrder), formatExtOrder(ch.ExtensionOrder)))
	}
	return out
}

func hasVersion(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func formatExtOrder(order []uint16) string {
	parts := make([]string, 0, len(order))
	for _, t := range order {
		if IsGREASE16(t) {
			parts = append(parts, "GREASE")
			continue
		}
		parts = append(parts, extensionName(t))
	}
	// keep readable
	if len(parts) > 12 {
		return joinComma(parts[:12]) + ", …"
	}
	return joinComma(parts)
}
