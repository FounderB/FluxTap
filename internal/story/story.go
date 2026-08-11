package story

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/FounderB/FluxTap/internal/security"
	"github.com/FounderB/FluxTap/internal/session"
)

// Chapter is one beat in an attack / incident narrative.
type Chapter struct {
	Index      int       `json:"index"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	Severity   string    `json:"severity"`
	Rule       string    `json:"rule"`
	FrameNo    uint64    `json:"frame_no"`
	Time       time.Time `json:"time"`
	Src        string    `json:"src"`
	Dst        string    `json:"dst"`
	SessionKey string    `json:"session_key,omitempty"`
}

// Story is a cinematic timeline stitched from findings + sessions.
type Story struct {
	Title     string    `json:"title"`
	Summary   string    `json:"summary"`
	Markdown  string    `json:"markdown"`
	Chapters  []Chapter `json:"chapters"`
	Findings  int       `json:"findings"`
	Sessions  int       `json:"sessions"`
	Generated time.Time `json:"generated"`
}

var ruleTitle = map[string]string{
	"port_scan":      "Recon — SYN scan",
	"dns_tunnel":     "Covert channel — DNS tunnel hint",
	"cleartext_auth": "Credential exposure — cleartext Basic auth",
	"weak_tls":       "Weak cryptography — outdated TLS",
}

var ruleBody = map[string]string{
	"port_scan":      "An endpoint opened a burst of SYN connections — classic port-scan footprint. Pivot to the source and freeze the session player on early SYNs.",
	"dns_tunnel":     "Unusually long DNS labels suggest tunneling or exfil. Correlate with the resolver conversation in Session Player.",
	"cleartext_auth": "HTTP Basic credentials crossed the wire without TLS. Treat the account as burned until rotated.",
	"weak_tls":       "A peer negotiated a deprecated TLS version. Downgrade attacks and passive decryption become realistic.",
}

// Build composes a short incident story from security findings and live sessions.
func Build(findings []security.Finding, sessions []*session.Session) Story {
	sorted := append([]security.Finding(nil), findings...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Time.Equal(sorted[j].Time) {
			return sorted[i].FrameNo < sorted[j].FrameNo
		}
		return sorted[i].Time.Before(sorted[j].Time)
	})

	sessByIP := indexSessions(sessions)
	chapters := make([]Chapter, 0, len(sorted))
	for i, f := range sorted {
		title := ruleTitle[f.Rule]
		if title == "" {
			title = "Signal — " + f.Rule
		}
		body := ruleBody[f.Rule]
		if body == "" {
			body = f.Message
		} else {
			body = body + "\n\nEvidence: " + f.Message
		}
		ch := Chapter{
			Index: i + 1, Title: title, Body: body,
			Severity: f.Severity, Rule: f.Rule, FrameNo: f.FrameNo,
			Time: f.Time, Src: f.Src, Dst: f.Dst,
			SessionKey: matchSession(sessByIP, f.Src, f.Dst),
		}
		chapters = append(chapters, ch)
	}

	title := "Quiet wire"
	summary := "No security chapters yet — keep tapping."
	if len(chapters) > 0 {
		title = fmt.Sprintf("Incident reel · %d chapters", len(chapters))
		rules := uniqueRules(sorted)
		summary = fmt.Sprintf("%d findings across %s. Open a chapter to jump the Session Player / packet table.",
			len(chapters), strings.Join(rules, " → "))
	}

	st := Story{
		Title: title, Summary: summary, Chapters: chapters,
		Findings: len(sorted), Sessions: len(sessions),
		Generated: time.Now().UTC(),
	}
	st.Markdown = renderMarkdown(st)
	return st
}

func indexSessions(sessions []*session.Session) map[string]string {
	out := map[string]string{}
	for _, s := range sessions {
		if s == nil {
			continue
		}
		out[s.Src+"|"+s.Dst] = s.Key
		out[s.Dst+"|"+s.Src] = s.Key
		out[s.Src] = s.Key
		out[s.Dst] = s.Key
	}
	return out
}

func matchSession(idx map[string]string, src, dst string) string {
	if k, ok := idx[src+"|"+dst]; ok {
		return k
	}
	if k, ok := idx[src]; ok {
		return k
	}
	return idx[dst]
}

func uniqueRules(findings []security.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if seen[f.Rule] {
			continue
		}
		seen[f.Rule] = true
		out = append(out, f.Rule)
	}
	return out
}

func renderMarkdown(st Story) string {
	var b strings.Builder
	b.WriteString("# " + st.Title + "\n\n")
	b.WriteString(st.Summary + "\n\n")
	for _, ch := range st.Chapters {
		b.WriteString(fmt.Sprintf("## %d. %s\n\n", ch.Index, ch.Title))
		b.WriteString(fmt.Sprintf("- **severity:** %s\n- **rule:** `%s`\n- **frame:** #%d\n- **path:** `%s` → `%s`\n",
			ch.Severity, ch.Rule, ch.FrameNo, ch.Src, ch.Dst))
		if ch.SessionKey != "" {
			b.WriteString("- **session:** `" + ch.SessionKey + "`\n")
		}
		b.WriteString("\n" + ch.Body + "\n\n")
	}
	return b.String()
}
