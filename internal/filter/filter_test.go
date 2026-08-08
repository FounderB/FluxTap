package filter_test

import (
	"testing"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
	"github.com/FounderB/FluxTap/internal/filter"
)

func TestMatchBasics(t *testing.T) {
	f := &decode.Frame{
		Protocol: "TLS",
		Src:      "192.168.1.10",
		Dst:      "1.2.3.4",
		Info:     "ClientHello",
		Length:   200,
		Meta: map[string]string{
			"sport": "49154", "dport": "443", "sni": "www.google.com", "ip_src": "192.168.1.10",
		},
		Layers: []decode.Layer{{Name: "TLS"}, {Name: "TCP"}, {Name: "IPv4"}},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"tls", true},
		{"dns", false},
		{"tcp.port == 443", true},
		{"tcp.port == 80", false},
		{`tls.sni contains google`, true},
		{`tls.sni contains yahoo`, false},
		{"tls and tcp", true},
		{"dns or tls", true},
		{"not dns", true},
		{"frame.len > 100", true},
		{"frame.len < 50", false},
		{"ip.src == 192.168.1.10", true},
	}
	for _, c := range cases {
		if got := filter.Match(f, c.expr); got != c.want {
			t.Fatalf("%q: got %v want %v", c.expr, got, c.want)
		}
	}
	_ = time.Now
}
