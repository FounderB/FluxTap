package filter

import (
	"strconv"
	"strings"

	"github.com/FounderB/FluxTap/internal/decode"
)

// Match evaluates a simple Wireshark-like display filter.
// Supports: protocol names, field comparisons, and / and / or / not.
// Examples:
//   dns
//   tcp.port == 443
//   ip.src == 1.2.3.4
//   http and tcp
//   tls.sni contains google
//   frame.len > 100
func Match(f *decode.Frame, expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	return evalOr(f, expr)
}

func evalOr(f *decode.Frame, expr string) bool {
	parts := splitTop(expr, " or ")
	if len(parts) == 1 {
		parts = splitTop(expr, " || ")
	}
	for _, p := range parts {
		if evalAnd(f, strings.TrimSpace(p)) {
			return true
		}
	}
	return false
}

func evalAnd(f *decode.Frame, expr string) bool {
	parts := splitTop(expr, " and ")
	if len(parts) == 1 {
		parts = splitTop(expr, " && ")
	}
	for _, p := range parts {
		if !evalNot(f, strings.TrimSpace(p)) {
			return false
		}
	}
	return true
}

func evalNot(f *decode.Frame, expr string) bool {
	lower := strings.ToLower(expr)
	if strings.HasPrefix(lower, "not ") {
		return !evalAtom(f, strings.TrimSpace(expr[4:]))
	}
	if strings.HasPrefix(expr, "!") {
		return !evalAtom(f, strings.TrimSpace(expr[1:]))
	}
	return evalAtom(f, expr)
}

func evalAtom(f *decode.Frame, expr string) bool {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		return evalOr(f, expr[1:len(expr)-1])
	}
	lower := strings.ToLower(expr)

	// bare protocol
	if !strings.ContainsAny(expr, "=<>") && !strings.Contains(lower, " contains ") {
		return hasProtocol(f, lower) || matchMetaKey(f, lower)
	}

	for _, op := range []string{" contains ", " == ", "!=", ">=", "<=", ">", "<", "="} {
		if i := strings.Index(strings.ToLower(expr), strings.TrimSpace(op)); i >= 0 {
			// find real index case-insensitive
			idx := indexFold(expr, strings.TrimSpace(op))
			if idx < 0 {
				continue
			}
			left := strings.TrimSpace(expr[:idx])
			right := strings.TrimSpace(expr[idx+len(strings.TrimSpace(op)):])
			right = strings.Trim(right, `"'`)
			return compare(f, left, strings.TrimSpace(op), right)
		}
	}
	return hasProtocol(f, lower)
}

func indexFold(s, sep string) int {
	return strings.Index(strings.ToLower(s), strings.ToLower(sep))
}

func hasProtocol(f *decode.Frame, name string) bool {
	name = strings.ToLower(name)
	if strings.ToLower(f.Protocol) == name {
		return true
	}
	for _, l := range f.Layers {
		if strings.ToLower(l.Name) == name || strings.ToLower(l.Name) == strings.ToUpper(name) {
			return true
		}
		if strings.EqualFold(l.Name, name) {
			return true
		}
	}
	aliases := map[string]string{"ip": "IPv4", "ipv4": "IPv4", "ipv6": "IPv6", "http2": "HTTP/2", "h2": "HTTP/2"}
	if a, ok := aliases[name]; ok {
		for _, l := range f.Layers {
			if l.Name == a {
				return true
			}
		}
	}
	return false
}

func matchMetaKey(f *decode.Frame, key string) bool {
	_, ok := f.Meta[key]
	return ok
}

func compare(f *decode.Frame, field, op, value string) bool {
	field = strings.ToLower(field)
	got := resolve(f, field)
	switch strings.ToLower(op) {
	case "contains":
		return strings.Contains(strings.ToLower(got), strings.ToLower(value))
	case "==", "=":
		if field == "tcp.port" || field == "udp.port" || field == "port" {
			for _, p := range strings.FieldsFunc(got, func(r rune) bool { return r == ',' || r == '|' }) {
				if p == value {
					return true
				}
			}
		}
		return strings.EqualFold(got, value) || got == value
	case "!=":
		if field == "tcp.port" || field == "udp.port" || field == "port" {
			for _, p := range strings.FieldsFunc(got, func(r rune) bool { return r == ',' || r == '|' }) {
				if p == value {
					return false
				}
			}
			return true
		}
		return !strings.EqualFold(got, value) && got != value
	case ">", ">=", "<", "<=":
		g, ge := toFloat(got)
		v, ve := toFloat(value)
		if !ge || !ve {
			return false
		}
		switch op {
		case ">":
			return g > v
		case ">=":
			return g >= v
		case "<":
			return g < v
		case "<=":
			return g <= v
		}
	}
	return false
}

func resolve(f *decode.Frame, field string) string {
	switch field {
	case "frame.len", "len", "length":
		return strconv.Itoa(f.Length)
	case "frame.number", "no":
		return strconv.FormatUint(f.No, 10)
	case "ip.src", "src":
		if v := f.Meta["ip_src"]; v != "" {
			return v
		}
		return f.Src
	case "ip.dst", "dst":
		if v := f.Meta["ip_dst"]; v != "" {
			return v
		}
		return f.Dst
	case "tcp.port", "udp.port", "port":
		return f.Meta["sport"] + "," + f.Meta["dport"]
	case "tcp.srcport", "udp.srcport", "sport":
		return f.Meta["sport"]
	case "tcp.dstport", "udp.dstport", "dport":
		return f.Meta["dport"]
	case "dns.qry.name", "dns.qry":
		return f.Meta["dns_qry"]
	case "http.host":
		return f.Meta["http_host"]
	case "http.request.method", "http.method":
		return f.Meta["http_method"]
	case "tls.sni", "sni":
		return f.Meta["sni"]
	case "tls.ja3", "ja3":
		return f.Meta["ja3"]
	case "protocol", "proto":
		return f.Protocol
	case "info":
		return f.Info
	}
	if v, ok := f.Meta[field]; ok {
		return v
	}
	// search layer fields
	for _, l := range f.Layers {
		for k, v := range l.Fields {
			if strings.EqualFold(k, field) || strings.EqualFold(l.Name+"."+k, field) {
				return v
			}
		}
	}
	// port equality helper: tcp.port == 443 matches either side
	if field == "tcp.port" || field == "udp.port" || field == "port" {
		return f.Meta["sport"] + "|" + f.Meta["dport"]
	}
	return ""
}

func toFloat(s string) (float64, bool) {
	// for port fields with multiple values take first
	if i := strings.IndexAny(s, ",|"); i >= 0 {
		s = s[:i]
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func splitTop(s, sep string) []string {
	lower := strings.ToLower(s)
	sep = strings.ToLower(sep)
	var parts []string
	depth := 0
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c == '(' {
			depth++
			i++
			continue
		}
		if c == ')' {
			depth--
			i++
			continue
		}
		if depth == 0 && i+len(sep) <= len(s) && lower[i:i+len(sep)] == sep {
			parts = append(parts, s[start:i])
			i += len(sep)
			start = i
			continue
		}
		i++
	}
	parts = append(parts, s[start:])
	return parts
}
