package decode

import "fmt"

func dissectEthernet(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 14 {
		return offset
	}
	dst := macString(data[offset : offset+6])
	src := macString(data[offset+6 : offset+12])
	etype := u16(data, offset+12)
	setEndpoints(f, src, dst)
	fields := map[string]string{
		"dst":      dst,
		"src":      src,
		"ethertype": fmt.Sprintf("0x%04x", etype),
	}
	summary := fmt.Sprintf("%s → %s type=0x%04x", src, dst, etype)
	addLayer(f, "Ethernet", summary, fields, offset, 14, "#22d3ee")
	offset += 14

	// VLAN (802.1Q)
	for etype == 0x8100 || etype == 0x88a8 {
		if len(data)-offset < 4 {
			return offset
		}
		tci := u16(data, offset)
		etype = u16(data, offset+2)
		vid := tci & 0x0fff
		pcp := (tci >> 13) & 0x7
		addLayer(f, "VLAN", fmt.Sprintf("id=%d pcp=%d type=0x%04x", vid, pcp, etype), map[string]string{
			"vlan_id":   fmt.Sprintf("%d", vid),
			"priority":  fmt.Sprintf("%d", pcp),
			"ethertype": fmt.Sprintf("0x%04x", etype),
		}, offset, 4, "#a78bfa")
		f.Meta["vlan"] = fmt.Sprintf("%d", vid)
		offset += 4
	}

	switch etype {
	case 0x0800:
		return dissectIPv4(f, data, offset)
	case 0x86dd:
		return dissectIPv6(f, data, offset)
	case 0x0806:
		return dissectARP(f, data, offset)
	case 0x88cc:
		addLayer(f, "LLDP", "Link Layer Discovery", nil, offset, len(data)-offset, "#94a3b8")
		f.Protocol = "LLDP"
	default:
		addLayer(f, "Payload", fmt.Sprintf("ethertype=0x%04x (%d bytes)", etype, len(data)-offset), nil, offset, len(data)-offset, "#64748b")
	}
	return offset
}

func dissectLinuxSLL(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 16 {
		return offset
	}
	pkttype := u16(data, offset)
	hatype := u16(data, offset+2)
	halen := u16(data, offset+4)
	proto := u16(data, offset+14)
	addLayer(f, "Linux SLL", fmt.Sprintf("type=%d proto=0x%04x", pkttype, proto), map[string]string{
		"packet_type": fmt.Sprintf("%d", pkttype),
		"hatype":      fmt.Sprintf("%d", hatype),
		"halen":       fmt.Sprintf("%d", halen),
		"protocol":    fmt.Sprintf("0x%04x", proto),
	}, offset, 16, "#67e8f9")
	offset += 16
	switch proto {
	case 0x0800:
		return dissectIPv4(f, data, offset)
	case 0x86dd:
		return dissectIPv6(f, data, offset)
	case 0x0806:
		return dissectARP(f, data, offset)
	}
	return offset
}

// dissectLinuxSLL2 handles DLT_LINUX_SLL2 (276) used by tcpdump -i any.
func dissectLinuxSLL2(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 20 {
		return offset
	}
	proto := u16(data, offset)
	// ifindex at 4, hatype at 8, pkttype at 10, halen at 11, addr at 12
	pkttype := data[offset+10]
	halen := data[offset+11]
	addLayer(f, "Linux SLL2", fmt.Sprintf("type=%d proto=0x%04x", pkttype, proto), map[string]string{
		"packet_type": fmt.Sprintf("%d", pkttype),
		"halen":       fmt.Sprintf("%d", halen),
		"protocol":    fmt.Sprintf("0x%04x", proto),
	}, offset, 20, "#67e8f9")
	offset += 20
	switch proto {
	case 0x0800:
		return dissectIPv4(f, data, offset)
	case 0x86dd:
		return dissectIPv6(f, data, offset)
	case 0x0806:
		return dissectARP(f, data, offset)
	}
	return offset
}

func dissectARP(f *Frame, data []byte, offset int) int {
	if len(data)-offset < 28 {
		return offset
	}
	hwType := u16(data, offset)
	proto := u16(data, offset+2)
	hwLen := data[offset+4]
	ptLen := data[offset+5]
	op := u16(data, offset+6)
	sha := macString(data[offset+8 : offset+14])
	spa := ipString(data[offset+14 : offset+18])
	tha := macString(data[offset+18 : offset+24])
	tpa := ipString(data[offset+24 : offset+28])
	opName := "unknown"
	switch op {
	case 1:
		opName = "request"
	case 2:
		opName = "reply"
	}
	summary := fmt.Sprintf("Who has %s? Tell %s", tpa, spa)
	if op == 2 {
		summary = fmt.Sprintf("%s is at %s", spa, sha)
	}
	setEndpoints(f, spa, tpa)
	f.Src = spa
	f.Dst = tpa
	addLayer(f, "ARP", summary, map[string]string{
		"hw_type":   fmt.Sprintf("%d", hwType),
		"proto":     fmt.Sprintf("0x%04x", proto),
		"hw_len":    fmt.Sprintf("%d", hwLen),
		"pt_len":    fmt.Sprintf("%d", ptLen),
		"opcode":    opName,
		"sender_mac": sha,
		"sender_ip": spa,
		"target_mac": tha,
		"target_ip": tpa,
	}, offset, 28, "#fbbf24")
	f.Protocol = "ARP"
	f.Info = summary
	f.Meta["arp_op"] = opName
	return offset + 28
}
