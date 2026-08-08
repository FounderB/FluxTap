package decode

import (
	"fmt"
	"net"
)

func dissectIPv4(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 20 {
		return offset
	}
	verIHL := data[offset]
	version := verIHL >> 4
	ihl := int(verIHL&0x0f) * 4
	if ihl < 20 || offset+ihl > len(data) {
		return offset
	}
	tos := data[offset+1]
	totalLen := int(u16(data, offset+2))
	id := u16(data, offset+4)
	flagsFrag := u16(data, offset+6)
	ttl := data[offset+8]
	proto := data[offset+9]
	checksum := u16(data, offset+10)
	src := ipString(data[offset+12 : offset+16])
	dst := ipString(data[offset+16 : offset+20])
	setEndpoints(f, src, dst)
	df := (flagsFrag >> 14) & 1
	mf := (flagsFrag >> 13) & 1
	fragOff := flagsFrag & 0x1fff
	protoName := ipProtoName(proto)
	summary := fmt.Sprintf("%s → %s proto=%s ttl=%d", src, dst, protoName, ttl)
	addLayer(f, "IPv4", summary, map[string]string{
		"version":    fmt.Sprintf("%d", version),
		"ihl":        fmt.Sprintf("%d", ihl),
		"tos":        fmt.Sprintf("0x%02x", tos),
		"total_len":  fmt.Sprintf("%d", totalLen),
		"id":         fmt.Sprintf("%d", id),
		"flags":      fmt.Sprintf("DF=%d MF=%d", df, mf),
		"frag_off":   fmt.Sprintf("%d", fragOff),
		"ttl":        fmt.Sprintf("%d", ttl),
		"protocol":   protoName,
		"checksum":   fmt.Sprintf("0x%04x", checksum),
		"src":        src,
		"dst":        dst,
	}, offset, ihl, "#34d399")
	f.Meta["ip_src"] = src
	f.Meta["ip_dst"] = dst
	f.Meta["ip_proto"] = protoName
	f.Meta["ttl"] = fmt.Sprintf("%d", ttl)
	payloadOff := offset + ihl
	return dispatchIP(f, data, payloadOff, proto)
}

func dissectIPv6(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 40 {
		return offset
	}
	vtf := u32(data, offset)
	version := vtf >> 28
	traffic := (vtf >> 20) & 0xff
	flow := vtf & 0xfffff
	payloadLen := u16(data, offset+4)
	next := data[offset+6]
	hop := data[offset+7]
	src := net.IP(data[offset+8 : offset+24]).String()
	dst := net.IP(data[offset+24 : offset+40]).String()
	setEndpoints(f, src, dst)
	protoName := ipProtoName(next)
	summary := fmt.Sprintf("%s → %s next=%s hop=%d", src, dst, protoName, hop)
	addLayer(f, "IPv6", summary, map[string]string{
		"version":     fmt.Sprintf("%d", version),
		"traffic":     fmt.Sprintf("%d", traffic),
		"flow":        fmt.Sprintf("0x%x", flow),
		"payload_len": fmt.Sprintf("%d", payloadLen),
		"next_header": protoName,
		"hop_limit":   fmt.Sprintf("%d", hop),
		"src":         src,
		"dst":         dst,
	}, offset, 40, "#4ade80")
	f.Meta["ip_src"] = src
	f.Meta["ip_dst"] = dst
	f.Meta["ip_proto"] = protoName
	return dispatchIP(f, data, offset+40, next)
}

func dispatchIP(f *Frame, data []byte, offset int, proto byte) int {
	switch proto {
	case 1:
		return dissectICMP(f, data, offset)
	case 58:
		return dissectICMPv6(f, data, offset)
	case 6:
		return dissectTCP(f, data, offset)
	case 17:
		return dissectUDP(f, data, offset)
	case 47:
		addLayer(f, "GRE", "Generic Routing Encapsulation", nil, offset, len(data)-offset, "#94a3b8")
		f.Protocol = "GRE"
	case 50:
		addLayer(f, "ESP", "IPsec ESP", nil, offset, len(data)-offset, "#f472b6")
		f.Protocol = "ESP"
	default:
		addLayer(f, ipProtoName(proto), fmt.Sprintf("%d bytes", len(data)-offset), nil, offset, len(data)-offset, "#64748b")
		f.Protocol = ipProtoName(proto)
	}
	return offset
}

func ipProtoName(p byte) string {
	switch p {
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("IPPROTO_%d", p)
	}
}

func dissectICMP(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 8 {
		return offset
	}
	typ := data[offset]
	code := data[offset+1]
	checksum := u16(data, offset+2)
	typeName := icmpTypeName(typ)
	summary := fmt.Sprintf("%s code=%d", typeName, code)
	addLayer(f, "ICMP", summary, map[string]string{
		"type":     fmt.Sprintf("%d (%s)", typ, typeName),
		"code":     fmt.Sprintf("%d", code),
		"checksum": fmt.Sprintf("0x%04x", checksum),
	}, offset, len(data)-offset, "#fb7185")
	f.Protocol = "ICMP"
	f.Info = summary
	return offset + 8
}

func dissectICMPv6(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 4 {
		return offset
	}
	typ := data[offset]
	code := data[offset+1]
	names := map[byte]string{128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation", 134: "Router Advertisement", 135: "Neighbor Solicitation", 136: "Neighbor Advertisement"}
	name := names[typ]
	if name == "" {
		name = fmt.Sprintf("type=%d", typ)
	}
	summary := fmt.Sprintf("%s code=%d", name, code)
	addLayer(f, "ICMPv6", summary, map[string]string{
		"type": fmt.Sprintf("%d", typ),
		"code": fmt.Sprintf("%d", code),
	}, offset, len(data)-offset, "#fb7185")
	f.Protocol = "ICMPv6"
	f.Info = summary
	return offset + 4
}

func icmpTypeName(t byte) string {
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		return "Destination Unreachable"
	case 5:
		return "Redirect"
	case 8:
		return "Echo Request"
	case 11:
		return "Time Exceeded"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}
