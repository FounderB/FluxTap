package decode

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

func dissectTCP(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 20 {
		return offset
	}
	sport := u16(data, offset)
	dport := u16(data, offset+2)
	seq := u32(data, offset+4)
	ack := u32(data, offset+8)
	dataOffFlags := u16(data, offset+12)
	hdrLen := int((dataOffFlags>>12)*4)
	flags := dataOffFlags & 0x1ff
	window := u16(data, offset+14)
	checksum := u16(data, offset+16)
	urgent := u16(data, offset+18)
	if hdrLen < 20 || offset+hdrLen > len(data) {
		hdrLen = 20
	}
	flagStr := tcpFlags(flags)
	summary := fmt.Sprintf("%d → %d [%s] seq=%d ack=%d win=%d", sport, dport, flagStr, seq, ack, window)
	fields := map[string]string{
		"src_port": fmt.Sprintf("%d", sport),
		"dst_port": fmt.Sprintf("%d", dport),
		"seq":      fmt.Sprintf("%d", seq),
		"ack":      fmt.Sprintf("%d", ack),
		"hdr_len":  fmt.Sprintf("%d", hdrLen),
		"flags":    flagStr,
		"window":   fmt.Sprintf("%d", window),
		"checksum": fmt.Sprintf("0x%04x", checksum),
		"urgent":   fmt.Sprintf("%d", urgent),
	}
	// Parse TCP options briefly
	if hdrLen > 20 {
		opts := parseTCPOptions(data[offset+20 : offset+hdrLen])
		if opts != "" {
			fields["options"] = opts
		}
	}
	addLayer(f, "TCP", summary, fields, offset, hdrLen, "#60a5fa")
	f.Meta["sport"] = strconv.Itoa(int(sport))
	f.Meta["dport"] = strconv.Itoa(int(dport))
	f.Meta["tcp_flags"] = flagStr
	f.Meta["tcp_seq"] = fmt.Sprintf("%d", seq)
	f.Protocol = "TCP"
	f.Info = summary

	payload := safeSlice(data, offset+hdrLen, len(data))
	if len(payload) == 0 {
		return offset + hdrLen
	}
	return dissectAppTCP(f, payload, offset+hdrLen, sport, dport)
}

func tcpFlags(flags uint16) string {
	var b strings.Builder
	names := []struct {
		bit uint16
		n   string
	}{
		{0x100, "NS"}, {0x080, "CWR"}, {0x040, "ECE"}, {0x020, "URG"},
		{0x010, "ACK"}, {0x008, "PSH"}, {0x004, "RST"}, {0x002, "SYN"}, {0x001, "FIN"},
	}
	for _, x := range names {
		if flags&x.bit != 0 {
			if b.Len() > 0 {
				b.WriteByte(',')
			}
			b.WriteString(x.n)
		}
	}
	if b.Len() == 0 {
		return "NONE"
	}
	return b.String()
}

func parseTCPOptions(opts []byte) string {
	var parts []string
	i := 0
	for i < len(opts) {
		kind := opts[i]
		if kind == 0 { // EOL
			parts = append(parts, "EOL")
			break
		}
		if kind == 1 { // NOP
			parts = append(parts, "NOP")
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if l < 2 || i+l > len(opts) {
			break
		}
		switch kind {
		case 2:
			if l == 4 {
				parts = append(parts, fmt.Sprintf("MSS=%d", u16(opts, i+2)))
			}
		case 3:
			parts = append(parts, fmt.Sprintf("WS=%d", opts[i+2]))
		case 4:
			parts = append(parts, "SACK-perm")
		case 8:
			parts = append(parts, "TS")
		default:
			parts = append(parts, fmt.Sprintf("opt-%d", kind))
		}
		i += l
	}
	return strings.Join(parts, ",")
}

func dissectAppTCP(f *Frame, payload []byte, offset int, sport, dport uint16) int {
	// TLS first (most common modern)
	if looksLikeTLS(payload) {
		return dissectTLS(f, payload, offset)
	}
	// HTTP/2 connection preface or frames
	if looksLikeHTTP2(payload) {
		return dissectHTTP2(f, payload, offset)
	}
	// HTTP/1.x
	if looksLikeHTTP(payload) {
		return dissectHTTP(f, payload, offset)
	}
	// SSH
	if bytes.HasPrefix(payload, []byte("SSH-")) {
		line := string(bytes.SplitN(payload, []byte("\n"), 2)[0])
		addLayer(f, "SSH", line, map[string]string{"banner": strings.TrimSpace(line)}, offset, len(payload), "#c084fc")
		f.Protocol = "SSH"
		f.Info = line
		f.Tags = append(f.Tags, "encrypted")
		return offset + len(payload)
	}
	// known ports heuristics
	switch {
	case sport == 443 || dport == 443 || sport == 8443 || dport == 8443:
		addLayer(f, "TLS?", fmt.Sprintf("%d bytes (likely encrypted)", len(payload)), nil, offset, len(payload), "#a78bfa")
		f.Protocol = "TLS"
		f.Tags = append(f.Tags, "encrypted")
	case sport == 80 || dport == 80 || sport == 8080 || dport == 8080:
		addLayer(f, "HTTP?", fmt.Sprintf("%d bytes", len(payload)), nil, offset, len(payload), "#38bdf8")
		f.Protocol = "HTTP"
	default:
		addLayer(f, "Data", fmt.Sprintf("%d bytes %s", len(payload), hexPreview(payload, 8)), nil, offset, len(payload), "#64748b")
	}
	return offset + len(payload)
}

func dissectUDP(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 8 {
		return offset
	}
	sport := u16(data, offset)
	dport := u16(data, offset+2)
	length := u16(data, offset+4)
	checksum := u16(data, offset+6)
	summary := fmt.Sprintf("%d → %d len=%d", sport, dport, length)
	addLayer(f, "UDP", summary, map[string]string{
		"src_port": fmt.Sprintf("%d", sport),
		"dst_port": fmt.Sprintf("%d", dport),
		"length":   fmt.Sprintf("%d", length),
		"checksum": fmt.Sprintf("0x%04x", checksum),
	}, offset, 8, "#2dd4bf")
	f.Meta["sport"] = strconv.Itoa(int(sport))
	f.Meta["dport"] = strconv.Itoa(int(dport))
	f.Protocol = "UDP"
	f.Info = summary

	payload := safeSlice(data, offset+8, len(data))
	if len(payload) == 0 {
		return offset + 8
	}
	return dissectAppUDP(f, payload, offset+8, sport, dport)
}

func dissectAppUDP(f *Frame, payload []byte, offset int, sport, dport uint16) int {
	switch {
	case sport == 53 || dport == 53 || sport == 5353 || dport == 5353:
		return dissectDNS(f, payload, offset, dport == 5353 || sport == 5353)
	case sport == 67 || dport == 67 || sport == 68 || dport == 68:
		return dissectDHCP(f, payload, offset)
	case sport == 123 || dport == 123:
		addLayer(f, "NTP", fmt.Sprintf("%d bytes", len(payload)), nil, offset, len(payload), "#fcd34d")
		f.Protocol = "NTP"
		f.Info = "Network Time Protocol"
	case looksLikeQUIC(payload):
		return dissectQUIC(f, payload, offset)
	case looksLikeDNS(payload) && (sport == 53 || dport == 53 || len(payload) > 12):
		return dissectDNS(f, payload, offset, false)
	default:
		addLayer(f, "Data", fmt.Sprintf("%d bytes", len(payload)), nil, offset, len(payload), "#64748b")
	}
	return offset + len(payload)
}

func looksLikeHTTP(b []byte) bool {
	methods := []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1."}
	s := string(b)
	if len(s) > 8 {
		s = s[:min(64, len(s))]
	}
	for _, m := range methods {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}

func looksLikeHTTP2(b []byte) bool {
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if bytes.HasPrefix(b, preface) {
		return true
	}
	// HTTP/2 frame header: length(24) type(8) flags(8) stream(31)
	if len(b) >= 9 {
		ftype := b[3]
		// common frame types 0-9
		if ftype <= 9 {
			length := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
			if length >= 0 && length < 16384 && 9+length <= len(b)+16384 {
				// weak heuristic: SETTINGS (4) or HEADERS (1) or DATA (0) on stream
				if ftype == 4 || ftype == 1 || ftype == 0 || ftype == 8 {
					return sportHintHTTP2(b)
				}
			}
		}
	}
	return false
}

func sportHintHTTP2(b []byte) bool {
	_ = b
	return true
}

func looksLikeTLS(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	// ContentType: change_cipher(20), alert(21), handshake(22), app_data(23)
	ct := b[0]
	if ct < 20 || ct > 23 {
		return false
	}
	maj, minv := b[1], b[2]
	if maj != 3 {
		return false
	}
	if minv > 4 {
		return false
	}
	length := int(u16(b, 3))
	return length > 0 && length+5 <= len(b)+2048
}

func looksLikeQUIC(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	// long header: bit 7 set, version present
	return b[0]&0x80 != 0
}

func looksLikeDNS(b []byte) bool {
	return len(b) >= 12
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
