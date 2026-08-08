package decode

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

var tlsContentTypes = map[byte]string{
	20: "ChangeCipherSpec",
	21: "Alert",
	22: "Handshake",
	23: "ApplicationData",
	24: "Heartbeat",
}

var tlsHandshakeTypes = map[byte]string{
	1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket",
	8: "EncryptedExtensions", 11: "Certificate", 12: "ServerKeyExchange",
	13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
	16: "ClientKeyExchange", 20: "Finished",
}

var tlsVersions = map[uint16]string{
	0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
	0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}

func dissectTLS(f *Frame, data []byte, offset int) int {
	pos := 0
	var records []string
	fields := map[string]string{}
	ja3Parts := ""

	for pos+5 <= len(data) && len(records) < 12 {
		ct := data[pos]
		ver := u16(data, pos+1)
		length := int(u16(data, pos+3))
		ctName := tlsContentTypes[ct]
		if ctName == "" {
			ctName = fmt.Sprintf("type-%d", ct)
		}
		verName := tlsVersions[ver]
		if verName == "" {
			verName = fmt.Sprintf("0x%04x", ver)
		}
		rec := fmt.Sprintf("%s %s len=%d", ctName, verName, length)
		payloadOff := pos + 5
		payloadEnd := payloadOff + length
		if payloadEnd > len(data) {
			payloadEnd = len(data)
			rec += " [truncated]"
		}
		if ct == 22 && payloadOff < payloadEnd {
			hs := parseTLSHandshake(data[payloadOff:payloadEnd], fields)
			if hs != "" {
				rec = hs
			}
			if fields["handshake"] == "ClientHello" {
				ja3 := buildJA3(data[payloadOff:payloadEnd], ver)
				if ja3 != "" {
					fields["ja3"] = ja3
					fields["ja3_hash"] = md5hex(ja3)
					f.Meta["ja3"] = fields["ja3_hash"]
					f.Tags = append(f.Tags, "ja3")
					ja3Parts = ja3
				}
			}
			if fields["handshake"] == "ServerHello" {
				if cv, ok := fields["cipher_suite"]; ok {
					f.Meta["tls_cipher"] = cv
				}
				if sni, ok := fields["server_name"]; ok {
					f.Meta["sni"] = sni
				}
			}
		}
		if ct == 21 && payloadOff+1 < payloadEnd {
			rec += fmt.Sprintf(" level=%d desc=%d", data[payloadOff], data[payloadOff+1])
			f.Severity = "warn"
		}
		records = append(records, rec)
		if length <= 0 {
			break
		}
		next := pos + 5 + length
		if next <= pos {
			break
		}
		pos = next
		if pos > len(data) {
			break
		}
	}

	summary := strings.Join(records, " | ")
	if sni, ok := fields["server_name"]; ok {
		summary = "SNI=" + sni + " · " + summary
		f.Meta["sni"] = sni
	}
	if ja3Parts != "" {
		summary += " JA3=" + fields["ja3_hash"][:8]
	}
	addLayer(f, "TLS", summary, fields, offset, len(data), "#a78bfa")
	f.Protocol = "TLS"
	f.Info = summary
	f.Tags = append(f.Tags, "encrypted", "tls")
	return offset + len(data)
}

func parseTLSHandshake(data []byte, fields map[string]string) string {
	if len(data) < 4 {
		return ""
	}
	ht := data[0]
	hsLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	name := tlsHandshakeTypes[ht]
	if name == "" {
		name = fmt.Sprintf("Handshake-%d", ht)
	}
	fields["handshake"] = name
	fields["handshake_len"] = fmt.Sprintf("%d", hsLen)
	body := data[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}
	switch ht {
	case 1: // ClientHello
		return parseClientHello(body, fields)
	case 2: // ServerHello
		return parseServerHello(body, fields)
	case 11:
		return "Certificate"
	default:
		return name
	}
}

func parseClientHello(body []byte, fields map[string]string) string {
	if len(body) < 34 {
		return "ClientHello"
	}
	clientVer := u16(body, 0)
	fields["client_version"] = tlsVersions[clientVer]
	if fields["client_version"] == "" {
		fields["client_version"] = fmt.Sprintf("0x%04x", clientVer)
	}
	// random 32 bytes at 2
	pos := 34
	if pos >= len(body) {
		return "ClientHello " + fields["client_version"]
	}
	sessionLen := int(body[pos])
	pos++
	pos += sessionLen
	if pos+2 > len(body) {
		return "ClientHello"
	}
	csLen := int(u16(body, pos))
	pos += 2
	if pos+csLen > len(body) {
		return "ClientHello"
	}
	var ciphers []string
	for i := 0; i+1 < csLen; i += 2 {
		ciphers = append(ciphers, fmt.Sprintf("0x%04x", u16(body, pos+i)))
	}
	fields["cipher_suites"] = strings.Join(ciphers, ",")
	pos += csLen
	if pos >= len(body) {
		return "ClientHello"
	}
	compLen := int(body[pos])
	pos++
	pos += compLen
	sni := ""
	if pos+2 <= len(body) {
		extLen := int(u16(body, pos))
		pos += 2
		end := pos + extLen
		if end > len(body) {
			end = len(body)
		}
		var extIDs []string
		for pos+4 <= end {
			eid := u16(body, pos)
			el := int(u16(body, pos+2))
			pos += 4
			extIDs = append(extIDs, fmt.Sprintf("%d", eid))
			if pos+el > end {
				break
			}
			if eid == 0 && el >= 5 { // server_name
				// list length 2, type 1, name len 2
				npos := pos + 3
				if npos+2 <= pos+el {
					nlen := int(u16(body, npos))
					npos += 2
					if npos+nlen <= pos+el {
						sni = string(body[npos : npos+nlen])
						fields["server_name"] = sni
					}
				}
			}
			if eid == 43 && el >= 2 { // supported_versions
				// may contain TLS 1.3
				fields["supported_versions_ext"] = hex.EncodeToString(body[pos : pos+min(el, 16)])
			}
			pos += el
		}
		fields["extensions"] = strings.Join(extIDs, "-")
	}
	summary := "ClientHello " + fields["client_version"]
	if sni != "" {
		summary += " SNI=" + sni
	}
	summary += fmt.Sprintf(" ciphers=%d", len(ciphers))
	return summary
}

func parseServerHello(body []byte, fields map[string]string) string {
	if len(body) < 34 {
		return "ServerHello"
	}
	ver := u16(body, 0)
	fields["server_version"] = tlsVersions[ver]
	if fields["server_version"] == "" {
		fields["server_version"] = fmt.Sprintf("0x%04x", ver)
	}
	pos := 34
	if pos >= len(body) {
		return "ServerHello"
	}
	sessionLen := int(body[pos])
	pos++
	pos += sessionLen
	if pos+3 > len(body) {
		return "ServerHello " + fields["server_version"]
	}
	cipher := u16(body, pos)
	fields["cipher_suite"] = fmt.Sprintf("0x%04x", cipher)
	pos += 2
	_ = body[pos] // compression
	pos++
	// extensions may include supported_versions → TLS 1.3
	if pos+2 <= len(body) {
		extLen := int(u16(body, pos))
		pos += 2
		end := pos + extLen
		if end > len(body) {
			end = len(body)
		}
		for pos+4 <= end {
			eid := u16(body, pos)
			el := int(u16(body, pos+2))
			pos += 4
			if pos+el > end {
				break
			}
			if eid == 43 && el == 2 {
				sel := u16(body, pos)
				if v, ok := tlsVersions[sel]; ok {
					fields["negotiated_version"] = v
				}
			}
			pos += el
		}
	}
	verShow := fields["server_version"]
	if nv, ok := fields["negotiated_version"]; ok {
		verShow = nv
	}
	return fmt.Sprintf("ServerHello %s cipher=%s", verShow, fields["cipher_suite"])
}

// buildJA3 constructs classic JA3 fingerprint string from ClientHello body.
func buildJA3(hs []byte, recordVer uint16) string {
	if len(hs) < 4 || hs[0] != 1 {
		return ""
	}
	body := hs[4:]
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(body) > hsLen {
		body = body[:hsLen]
	}
	if len(body) < 34 {
		return ""
	}
	version := u16(body, 0)
	_ = recordVer
	pos := 34
	if pos >= len(body) {
		return ""
	}
	pos += 1 + int(body[pos]) // session
	if pos+2 > len(body) {
		return ""
	}
	csLen := int(u16(body, pos))
	pos += 2
	if pos+csLen > len(body) {
		return ""
	}
	var ciphers []string
	for i := 0; i+1 < csLen; i += 2 {
		cs := u16(body, pos+i)
		if isGREASE(cs) {
			continue
		}
		ciphers = append(ciphers, fmt.Sprintf("%d", cs))
	}
	pos += csLen
	if pos >= len(body) {
		return ""
	}
	pos += 1 + int(body[pos]) // compression
	var exts, curves, points []string
	if pos+2 <= len(body) {
		extLen := int(u16(body, pos))
		pos += 2
		end := pos + extLen
		if end > len(body) {
			end = len(body)
		}
		for pos+4 <= end {
			eid := u16(body, pos)
			el := int(u16(body, pos+2))
			pos += 4
			if pos+el > end {
				break
			}
			if !isGREASE(eid) {
				exts = append(exts, fmt.Sprintf("%d", eid))
			}
			if eid == 10 && el >= 2 { // supported_groups
				gl := int(u16(body, pos))
				for i := 2; i+1 < gl+2 && i+1 < el; i += 2 {
					g := u16(body, pos+i)
					if !isGREASE(g) {
						curves = append(curves, fmt.Sprintf("%d", g))
					}
				}
			}
			if eid == 11 && el >= 1 { // ec_point_formats
				n := int(body[pos])
				for i := 1; i <= n && i < el; i++ {
					points = append(points, fmt.Sprintf("%d", body[pos+i]))
				}
			}
			pos += el
		}
	}
	return fmt.Sprintf("%d,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
