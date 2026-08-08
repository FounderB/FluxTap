package session

import (
	"sync"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
)

// Event is one notable beat inside a TCP/UDP conversation.
type Event struct {
	At      time.Time `json:"at"`
	FrameNo uint64    `json:"frame_no"`
	Kind    string    `json:"kind"` // syn|http|tls|dns|data|fin|rst|...
	Summary string    `json:"summary"`
	Dir     string    `json:"dir"` // c2s|s2c|—
}

// Session is a playable conversation timeline.
type Session struct {
	Key         string    `json:"key"`
	Protocol    string    `json:"protocol"`
	App         string    `json:"app"`
	Src         string    `json:"src"`
	Dst         string    `json:"dst"`
	Sport       string    `json:"sport"`
	Dport       string    `json:"dport"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	SNI         string    `json:"sni,omitempty"`
	JA3         string    `json:"ja3,omitempty"`
	Events      []Event   `json:"events"`
	FrameNos    []uint64  `json:"frame_nos"`
	ClientBytes uint64    `json:"client_bytes"`
	ServerBytes uint64    `json:"server_bytes"`
}

type Player struct {
	mu      sync.RWMutex
	byKey   map[string]*Session
	order   []string
	limit   int
	maxEv   int
	maxFr   int
}

func NewPlayer(limit int) *Player {
	if limit <= 0 {
		limit = 2000
	}
	return &Player{
		byKey: make(map[string]*Session),
		limit: limit,
		maxEv: 80,
		maxFr: 200,
	}
}

func (p *Player) Observe(f *decode.Frame) {
	if f.FlowKey == "" {
		return
	}
	// Prefer TCP/UDP/app sessions
	proto := f.Meta["ip_proto"]
	if proto != "TCP" && proto != "UDP" && f.Protocol != "DNS" && f.Protocol != "TLS" && f.Protocol != "HTTP" && f.Protocol != "HTTP/2" && f.Protocol != "QUIC" {
		if proto == "" {
			return
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.byKey[f.FlowKey]
	if !ok {
		if len(p.byKey) >= p.limit {
			old := p.order[0]
			p.order = p.order[1:]
			delete(p.byKey, old)
		}
		s = &Session{
			Key: f.FlowKey, Protocol: proto,
			Src: f.Meta["ip_src"], Dst: f.Meta["ip_dst"],
			Sport: f.Meta["sport"], Dport: f.Meta["dport"],
			FirstSeen: f.Timestamp,
		}
		if s.Src == "" {
			s.Src = f.Src
		}
		if s.Dst == "" {
			s.Dst = f.Dst
		}
		p.byKey[f.FlowKey] = s
		p.order = append(p.order, f.FlowKey)
	}
	s.Packets++
	s.Bytes += uint64(f.Length)
	s.LastSeen = f.Timestamp
	if len(s.FrameNos) < p.maxFr {
		s.FrameNos = append(s.FrameNos, f.No)
	}
	if f.Meta["sni"] != "" {
		s.SNI = f.Meta["sni"]
	}
	if f.Meta["ja3"] != "" {
		s.JA3 = f.Meta["ja3"]
	}
	switch f.Protocol {
	case "TLS", "HTTP", "HTTP/2", "DNS", "QUIC", "SSH", "DHCP":
		s.App = f.Protocol
	}
	dir := "—"
	if f.Meta["ip_src"] == s.Src {
		dir = "c2s"
		s.ClientBytes += uint64(f.Length)
	} else if f.Meta["ip_src"] == s.Dst {
		dir = "s2c"
		s.ServerBytes += uint64(f.Length)
	}

	ev := classify(f)
	if ev.Kind != "" && len(s.Events) < p.maxEv {
		ev.At = f.Timestamp
		ev.FrameNo = f.No
		ev.Dir = dir
		s.Events = append(s.Events, ev)
	}
}

func classify(f *decode.Frame) Event {
	flags := f.Meta["tcp_flags"]
	switch {
	case flags != "" && contains(flags, "SYN") && !contains(flags, "ACK"):
		return Event{Kind: "syn", Summary: "TCP SYN"}
	case flags != "" && contains(flags, "SYN") && contains(flags, "ACK"):
		return Event{Kind: "synack", Summary: "TCP SYN-ACK"}
	case flags != "" && contains(flags, "FIN"):
		return Event{Kind: "fin", Summary: "TCP FIN"}
	case flags != "" && contains(flags, "RST"):
		return Event{Kind: "rst", Summary: "TCP RST"}
	}
	switch f.Protocol {
	case "TLS":
		sum := f.Info
		if sni := f.Meta["sni"]; sni != "" {
			sum = "TLS SNI=" + sni
		}
		if ja3 := f.Meta["ja3"]; ja3 != "" {
			sum += " JA3=" + ja3[:min(8, len(ja3))]
		}
		return Event{Kind: "tls", Summary: trunc(sum, 120)}
	case "HTTP":
		return Event{Kind: "http", Summary: trunc(f.Info, 120)}
	case "HTTP/2":
		return Event{Kind: "http2", Summary: trunc(f.Info, 120)}
	case "DNS", "mDNS":
		return Event{Kind: "dns", Summary: trunc(f.Info, 120)}
	case "QUIC":
		return Event{Kind: "quic", Summary: trunc(f.Info, 120)}
	}
	if f.Length > 60 && (f.Protocol == "TCP" || f.Protocol == "UDP") {
		return Event{Kind: "data", Summary: f.Protocol + " payload"}
	}
	return Event{}
}

func (p *Player) List(n int) []*Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Session, 0, len(p.byKey))
	for _, s := range p.byKey {
		cp := *s
		cp.Events = append([]Event(nil), s.Events...)
		cp.FrameNos = append([]uint64(nil), s.FrameNos...)
		out = append(out, &cp)
	}
	// sort by last seen desc / bytes
	for i := 0; i < len(out); i++ {
		max := i
		for j := i + 1; j < len(out); j++ {
			if out[j].Bytes > out[max].Bytes {
				max = j
			}
		}
		out[i], out[max] = out[max], out[i]
	}
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func (p *Player) Get(key string) *Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	s := p.byKey[key]
	if s == nil {
		return nil
	}
	cp := *s
	cp.Events = append([]Event(nil), s.Events...)
	cp.FrameNos = append([]uint64(nil), s.FrameNos...)
	return &cp
}

func (p *Player) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.byKey)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
