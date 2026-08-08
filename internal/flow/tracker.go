package flow

import (
	"sync"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
)

type Conversation struct {
	Key         string    `json:"key"`
	Protocol    string    `json:"protocol"`
	Src         string    `json:"src"`
	Dst         string    `json:"dst"`
	Sport       string    `json:"sport"`
	Dport       string    `json:"dport"`
	Packets     uint64    `json:"packets"`
	Bytes       uint64    `json:"bytes"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	TCPFlags    string    `json:"tcp_flags,omitempty"`
	AppProtocol string    `json:"app_protocol,omitempty"`
	SNI         string    `json:"sni,omitempty"`
	JA3         string    `json:"ja3,omitempty"`
}

type Tracker struct {
	mu    sync.RWMutex
	flows map[string]*Conversation
	order []string
	limit int
}

func NewTracker(limit int) *Tracker {
	if limit <= 0 {
		limit = 5000
	}
	return &Tracker{flows: make(map[string]*Conversation), limit: limit}
}

func (t *Tracker) Observe(f *decode.Frame) {
	if f.FlowKey == "" || f.FlowKey == "|:-:" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.flows[f.FlowKey]
	if !ok {
		if len(t.flows) >= t.limit {
			// drop oldest
			old := t.order[0]
			t.order = t.order[1:]
			delete(t.flows, old)
		}
		c = &Conversation{
			Key:       f.FlowKey,
			Protocol:  f.Meta["ip_proto"],
			Src:       f.Meta["ip_src"],
			Dst:       f.Meta["ip_dst"],
			Sport:     f.Meta["sport"],
			Dport:     f.Meta["dport"],
			FirstSeen: f.Timestamp,
		}
		if c.Src == "" {
			c.Src = f.Src
		}
		if c.Dst == "" {
			c.Dst = f.Dst
		}
		t.flows[f.FlowKey] = c
		t.order = append(t.order, f.FlowKey)
	}
	c.Packets++
	c.Bytes += uint64(f.Length)
	c.LastSeen = f.Timestamp
	if f.Meta["tcp_flags"] != "" {
		c.TCPFlags = mergeFlags(c.TCPFlags, f.Meta["tcp_flags"])
	}
	switch f.Protocol {
	case "TLS", "HTTP", "HTTP/2", "DNS", "QUIC", "SSH":
		c.AppProtocol = f.Protocol
	}
	if sni := f.Meta["sni"]; sni != "" {
		c.SNI = sni
	}
	if ja3 := f.Meta["ja3"]; ja3 != "" {
		c.JA3 = ja3
	}
}

func mergeFlags(a, b string) string {
	set := map[string]bool{}
	for _, part := range splitFlags(a) {
		set[part] = true
	}
	for _, part := range splitFlags(b) {
		set[part] = true
	}
	out := ""
	for _, n := range []string{"SYN", "ACK", "PSH", "FIN", "RST", "URG", "ECE", "CWR"} {
		if set[n] {
			if out != "" {
				out += ","
			}
			out += n
		}
	}
	return out
}

func splitFlags(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func (t *Tracker) Top(n int) []*Conversation {
	t.mu.RLock()
	defer t.mu.RUnlock()
	all := make([]*Conversation, 0, len(t.flows))
	for _, c := range t.flows {
		cp := *c
		all = append(all, &cp)
	}
	// simple selection sort by bytes desc
	for i := 0; i < len(all); i++ {
		max := i
		for j := i + 1; j < len(all); j++ {
			if all[j].Bytes > all[max].Bytes {
				max = j
			}
		}
		all[i], all[max] = all[max], all[i]
	}
	if n > 0 && len(all) > n {
		all = all[:n]
	}
	return all
}

func (t *Tracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}

func (t *Tracker) Snapshot() []*Conversation {
	return t.Top(0)
}
