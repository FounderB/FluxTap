package decode

import (
	"fmt"
	"strings"
)

func dissectDNS(f *Frame, data []byte, offset int, mdns bool) int {
	if len(data) < 12 {
		return offset
	}
	id := u16(data, 0)
	flags := u16(data, 2)
	qd := u16(data, 4)
	an := u16(data, 6)
	ns := u16(data, 8)
	ar := u16(data, 10)
	qr := (flags >> 15) & 1
	opcode := (flags >> 11) & 0xf
	aa := (flags >> 10) & 1
	tc := (flags >> 9) & 1
	rd := (flags >> 8) & 1
	ra := (flags >> 7) & 1
	rcode := flags & 0xf

	name := "DNS"
	if mdns {
		name = "mDNS"
	}
	pos := 12
	var queries []string
	var answers []string
	for i := 0; i < int(qd) && pos < len(data); i++ {
		qname, npos := readDNSName(data, pos)
		if npos+4 > len(data) {
			break
		}
		qtype := u16(data, npos)
		qclass := u16(data, npos+2)
		queries = append(queries, fmt.Sprintf("%s %s", dnsTypeName(qtype), qname))
		f.Meta["dns_qry"] = qname
		f.Meta["dns_qtype"] = dnsTypeName(qtype)
		_ = qclass
		pos = npos + 4
	}
	for i := 0; i < int(an) && pos < len(data); i++ {
		aname, npos := readDNSName(data, pos)
		if npos+10 > len(data) {
			break
		}
		atype := u16(data, npos)
		// aclass := u16(data, npos+2)
		ttl := u32(data, npos+4)
		rdlen := int(u16(data, npos+8))
		npos += 10
		rdata := ""
		if npos+rdlen <= len(data) {
			rdata = formatDNSRdata(data, npos, atype, rdlen)
			pos = npos + rdlen
		} else {
			break
		}
		answers = append(answers, fmt.Sprintf("%s %s %s ttl=%d", dnsTypeName(atype), aname, rdata, ttl))
		if i == 0 {
			f.Meta["dns_ans"] = rdata
		}
	}
	_ = ns
	_ = ar
	_ = opcode
	_ = aa
	_ = tc
	_ = rd
	_ = ra

	dir := "query"
	if qr == 1 {
		dir = "response"
	}
	summary := dir
	if len(queries) > 0 {
		summary = fmt.Sprintf("%s %s", dir, strings.Join(queries, ", "))
	}
	if len(answers) > 0 {
		summary = fmt.Sprintf("%s → %s", summary, strings.Join(answers, "; "))
	}
	if rcode != 0 && qr == 1 {
		summary += " [" + dnsRcode(rcode) + "]"
		f.Severity = "warn"
	}
	addLayer(f, name, summary, map[string]string{
		"id":        fmt.Sprintf("0x%04x", id),
		"qr":        dir,
		"rcode":     dnsRcode(rcode),
		"questions": fmt.Sprintf("%d", qd),
		"answers":   fmt.Sprintf("%d", an),
		"authority": fmt.Sprintf("%d", ns),
		"additional": fmt.Sprintf("%d", ar),
		"queries":   strings.Join(queries, "; "),
		"answers_detail": strings.Join(answers, "; "),
	}, offset, len(data), "#f472b6")
	f.Protocol = name
	f.Info = summary
	f.Tags = append(f.Tags, "name-resolution")
	return offset + len(data)
}

func readDNSName(data []byte, pos int) (string, int) {
	var parts []string
	visited := 0
	start := pos
	jumped := false
	for pos < len(data) && visited < 64 {
		visited++
		l := int(data[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(data) {
				break
			}
			ptr := int(u16(data, pos) & 0x3fff)
			if !jumped {
				start = pos + 2
			}
			jumped = true
			pos = ptr
			continue
		}
		pos++
		if pos+l > len(data) {
			break
		}
		parts = append(parts, string(data[pos:pos+l]))
		pos += l
	}
	if jumped {
		return strings.Join(parts, "."), start
	}
	return strings.Join(parts, "."), pos
}

func dnsTypeName(t uint16) string {
	m := map[uint16]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
		16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG",
		47: "NSEC", 48: "DNSKEY", 255: "ANY", 65: "HTTPS", 64: "SVCB",
	}
	if s, ok := m[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func dnsRcode(c uint16) string {
	m := []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}
	if int(c) < len(m) {
		return m[c]
	}
	return fmt.Sprintf("RCODE%d", c)
}

func formatDNSRdata(data []byte, pos int, atype uint16, rdlen int) string {
	switch atype {
	case 1: // A
		if rdlen == 4 {
			return ipString(data[pos : pos+4])
		}
	case 28: // AAAA
		if rdlen == 16 {
			return ipString(data[pos : pos+16])
		}
	case 5, 2, 12: // CNAME, NS, PTR
		n, _ := readDNSName(data, pos)
		return n
	case 16: // TXT
		if rdlen > 0 {
			l := int(data[pos])
			if l > rdlen-1 {
				l = rdlen - 1
			}
			return string(data[pos+1 : pos+1+l])
		}
	case 15: // MX
		if rdlen >= 3 {
			pref := u16(data, pos)
			n, _ := readDNSName(data, pos+2)
			return fmt.Sprintf("%d %s", pref, n)
		}
	}
	return hexPreview(data[pos:pos+rdlen], 16)
}

func dissectDHCP(f *Frame, data []byte, offset int) int {
	if len(data) < 240 {
		addLayer(f, "DHCP", fmt.Sprintf("%d bytes", len(data)), nil, offset, len(data), "#fbbf24")
		f.Protocol = "DHCP"
		return offset + len(data)
	}
	op := data[0]
	xid := u32(data, 4)
	ciaddr := ipString(data[12:16])
	yiaddr := ipString(data[16:20])
	chaddr := macString(data[28:34])
	msgType := "unknown"
	// options start at 240 after magic cookie
	if len(data) > 240 && u32(data, 236) == 0x63825363 {
		i := 240
		for i < len(data) {
			code := data[i]
			if code == 255 {
				break
			}
			if code == 0 {
				i++
				continue
			}
			if i+1 >= len(data) {
				break
			}
			l := int(data[i+1])
			if i+2+l > len(data) {
				break
			}
			if code == 53 && l == 1 {
				types := map[byte]string{1: "Discover", 2: "Offer", 3: "Request", 5: "ACK", 6: "NAK", 7: "Release"}
				msgType = types[data[i+2]]
				if msgType == "" {
					msgType = fmt.Sprintf("type-%d", data[i+2])
				}
			}
			i += 2 + l
		}
	}
	opName := "Boot Request"
	if op == 2 {
		opName = "Boot Reply"
	}
	summary := fmt.Sprintf("%s %s yiaddr=%s chaddr=%s", opName, msgType, yiaddr, chaddr)
	addLayer(f, "DHCP", summary, map[string]string{
		"op": opName, "xid": fmt.Sprintf("0x%08x", xid),
		"ciaddr": ciaddr, "yiaddr": yiaddr, "chaddr": chaddr, "message": msgType,
	}, offset, len(data), "#fbbf24")
	f.Protocol = "DHCP"
	f.Info = summary
	return offset + len(data)
}

func dissectQUIC(f *Frame, data []byte, offset int) int {
	flags := data[0]
	long := flags&0x80 != 0
	summary := "QUIC short header"
	fields := map[string]string{"flags": fmt.Sprintf("0x%02x", flags)}
	if long && len(data) >= 5 {
		ver := u32(data, 1)
		fields["version"] = fmt.Sprintf("0x%08x", ver)
		summary = fmt.Sprintf("QUIC long header ver=0x%08x", ver)
		if ver == 0 {
			summary = "QUIC Version Negotiation"
		}
	}
	addLayer(f, "QUIC", summary, fields, offset, len(data), "#818cf8")
	f.Protocol = "QUIC"
	f.Info = summary
	f.Tags = append(f.Tags, "encrypted", "http3")
	return offset + len(data)
}
