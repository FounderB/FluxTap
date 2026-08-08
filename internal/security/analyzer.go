package security

import (
	"strings"
	"sync"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
)

type Finding struct {
	Time     time.Time `json:"time"`
	FrameNo  uint64    `json:"frame_no"`
	Severity string    `json:"severity"` // info|warn|alert
	Rule     string    `json:"rule"`
	Message  string    `json:"message"`
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
}

type Analyzer struct {
	mu       sync.Mutex
	findings []Finding
	synCount map[string]int
	dnsLong  map[string]int
	limit    int
}

func New() *Analyzer {
	return &Analyzer{
		synCount: map[string]int{},
		dnsLong:  map[string]int{},
		limit:    500,
	}
}

// Observe inspects a frame and returns any newly raised findings.
func (a *Analyzer) Observe(f *decode.Frame) []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()

	src := f.Meta["ip_src"]
	dst := f.Meta["ip_dst"]
	var raised []Finding

	if flags := f.Meta["tcp_flags"]; strings.Contains(flags, "SYN") && !strings.Contains(flags, "ACK") {
		a.synCount[src]++
		if a.synCount[src] == 30 {
			raised = append(raised, a.add(f, "alert", "port_scan", "Possible SYN scan: "+src+" opened many SYNs", src, dst))
		}
	}

	if q := f.Meta["dns_qry"]; len(q) > 60 {
		a.dnsLong[src]++
		if a.dnsLong[src] == 3 {
			raised = append(raised, a.add(f, "warn", "dns_tunnel", "Long DNS labels from "+src+" (possible tunneling): "+trunc(q, 80), src, dst))
		}
		f.Severity = "warn"
		f.Tags = append(f.Tags, "dns-tunnel-hint")
	}

	for _, l := range f.Layers {
		if l.Name != "HTTP" {
			continue
		}
		if auth, ok := l.Fields["hdr_authorization"]; ok && strings.HasPrefix(strings.ToLower(auth), "basic ") {
			raised = append(raised, a.add(f, "alert", "cleartext_auth", "HTTP Basic auth over cleartext", src, dst))
			f.Severity = "alert"
			f.Tags = append(f.Tags, "credential-leak")
		}
	}

	for _, l := range f.Layers {
		if l.Name != "TLS" {
			continue
		}
		v := l.Fields["client_version"]
		if v == "SSL 3.0" || v == "TLS 1.0" || v == "TLS 1.1" {
			raised = append(raised, a.add(f, "warn", "weak_tls", "Outdated TLS version: "+v, src, dst))
			f.Severity = "warn"
			f.Tags = append(f.Tags, "weak-tls")
		}
	}

	if f.Protocol == "ICMP" && f.Info != "" {
		f.Tags = append(f.Tags, "icmp")
	}
	return raised
}

func (a *Analyzer) add(f *decode.Frame, sev, rule, msg, src, dst string) Finding {
	if len(a.findings) >= a.limit {
		a.findings = a.findings[len(a.findings)-a.limit/2:]
	}
	finding := Finding{
		Time: f.Timestamp, FrameNo: f.No, Severity: sev,
		Rule: rule, Message: msg, Src: src, Dst: dst,
	}
	a.findings = append(a.findings, finding)
	return finding
}

func (a *Analyzer) Findings() []Finding {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Finding, len(a.findings))
	copy(out, a.findings)
	return out
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
