package dissect

import (
	"fmt"
	"strings"
)

// Known browser pseudo-header emit orders (Akamai H2 fingerprint field 4).
// Source: Chromium CreateSpdyHeadersFromHttpRequest (m,a,s,p);
// Firefox (m,p,a,s); Safari (m,s,p,a).
const (
	PseudoChrome  = "m,a,s,p"
	PseudoFirefox = "m,p,a,s"
	PseudoSafari  = "m,s,p,a"
)

func analyzePseudo(hb *HeaderBlock) {
	var letters []string
	var names []string
	for _, f := range hb.Fields {
		if !strings.HasPrefix(f.Name, ":") {
			continue
		}
		names = append(names, f.Name)
		switch f.Name {
		case ":method":
			letters = append(letters, "m")
		case ":authority":
			letters = append(letters, "a")
		case ":scheme":
			letters = append(letters, "s")
		case ":path":
			letters = append(letters, "p")
		case ":protocol":
			letters = append(letters, "c") // CONNECT/extended
		default:
			letters = append(letters, "?")
		}
	}
	hb.PseudoNames = names
	hb.PseudoOrder = strings.Join(letters, ",")
	switch hb.PseudoOrder {
	case PseudoChrome:
		hb.FamilyGuess = "chrome"
		hb.Findings = append(hb.Findings,
			"Pseudo-header order m,a,s,p — Chromium CreateSpdyHeadersFromHttpRequest emit order")
	case PseudoFirefox:
		hb.FamilyGuess = "firefox"
		hb.Findings = append(hb.Findings,
			"Pseudo-header order m,p,a,s — Firefox/Gecko emit order")
	case PseudoSafari:
		hb.FamilyGuess = "safari"
		hb.Findings = append(hb.Findings,
			"Pseudo-header order m,s,p,a — Safari/WebKit emit order")
	case "":
		hb.FamilyGuess = "unknown"
		hb.Findings = append(hb.Findings, "No pseudo-headers in block — not a request HEADERS frame?")
	default:
		hb.FamilyGuess = "unknown"
		hb.Findings = append(hb.Findings,
			fmt.Sprintf("Pseudo-header order %s — does not match Chrome/Firefox/Safari canonical orders (impersonation smell)", hb.PseudoOrder))
	}
	// Regular headers after pseudos — Sec-Fetch / Client Hints presence notes
	var hasUA, hasCH bool
	for _, f := range hb.Fields {
		switch strings.ToLower(f.Name) {
		case "user-agent":
			hasUA = true
		case "sec-ch-ua", "sec-ch-ua-platform", "sec-ch-ua-mobile":
			hasCH = true
		}
	}
	if hasCH && hb.FamilyGuess == "firefox" {
		hb.Findings = append(hb.Findings, "Client Hints on a Firefox-ordered block — cross-layer contradiction")
	}
	if !hasUA && len(hb.Fields) > 0 {
		hb.Findings = append(hb.Findings, "No user-agent header in block (may be on a later push or omitted)")
	}
}

// AkamaiH2Fingerprint builds a four-field HTTP/2 fingerprint string inspired by
// public Akamai H2 fingerprint dumps:
//
//	SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo
//
// Field 3 is CoherenceLab-extended: when RFC 9218 PRIORITY_UPDATE is present we
// emit the structured value (e.g. u=0,i). Classic Akamai logs often collapsed
// that field to 0 / 1 / a tree-hash — compare carefully against real dumps.
//
// Example Chrome-like (RFC 9218 era):
//
//	1:65536;2:0;4:6291456;6:262144;9:1|15663105|u=0,i|m,a,s,p
func (s *H2Session) AkamaiH2Fingerprint() string {
	var settingsParts []string
	for _, st := range s.Settings {
		settingsParts = append(settingsParts, fmt.Sprintf("%d:%d", st.ID, st.Value))
	}
	settings := strings.Join(settingsParts, ";")

	win := "00"
	for _, wu := range s.WindowUpdates {
		if wu.ConnectionLvl {
			win = fmt.Sprintf("%d", wu.Increment)
			break
		}
	}

	prio := s.PriorityFingerprint()

	pseudo := ""
	if s.HeaderBlock != nil {
		pseudo = s.HeaderBlock.PseudoOrder
	}
	return fmt.Sprintf("%s|%s|%s|%s", settings, win, prio, pseudo)
}
