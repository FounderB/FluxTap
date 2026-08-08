package decode

import (
	"bytes"
	"fmt"
	"strings"
)

func dissectHTTP(f *Frame, data []byte, offset int) int {
	text := string(data)
	// limit parse to headers
	headerEnd := strings.Index(text, "\r\n\r\n")
	headerPart := text
	bodyLen := 0
	if headerEnd >= 0 {
		headerPart = text[:headerEnd]
		bodyLen = len(data) - (headerEnd + 4)
	}
	lines := strings.Split(headerPart, "\r\n")
	if len(lines) == 0 {
		return offset
	}
	reqLine := lines[0]
	fields := map[string]string{"start_line": reqLine}
	isReq := true
	method, path, status := "", "", ""
	if strings.HasPrefix(reqLine, "HTTP/") {
		isReq = false
		parts := strings.SplitN(reqLine, " ", 3)
		if len(parts) >= 2 {
			status = parts[1]
			fields["status"] = status
			fields["version"] = parts[0]
			if len(parts) >= 3 {
				fields["reason"] = parts[2]
			}
		}
	} else {
		parts := strings.SplitN(reqLine, " ", 3)
		if len(parts) >= 2 {
			method, path = parts[0], parts[1]
			fields["method"] = method
			fields["path"] = path
			if len(parts) >= 3 {
				fields["version"] = parts[2]
			}
		}
	}
	host := ""
	contentType := ""
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		kv := strings.SplitN(line, ":", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			lk := strings.ToLower(k)
			fields["hdr_"+lk] = v
			switch lk {
			case "host":
				host = v
				f.Meta["http_host"] = v
			case "content-type":
				contentType = v
			case "user-agent":
				f.Meta["http_ua"] = v
			}
		}
	}
	var summary string
	if isReq {
		summary = fmt.Sprintf("%s %s", method, path)
		if host != "" {
			summary += " host=" + host
		}
		f.Meta["http_method"] = method
		f.Meta["http_path"] = path
	} else {
		summary = "HTTP " + status
		if contentType != "" {
			summary += " " + contentType
		}
		f.Meta["http_status"] = status
	}
	if bodyLen > 0 {
		fields["body_len"] = fmt.Sprintf("%d", bodyLen)
		summary += fmt.Sprintf(" (+%dB body)", bodyLen)
	}
	addLayer(f, "HTTP", summary, fields, offset, len(data), "#38bdf8")
	f.Protocol = "HTTP"
	f.Info = summary
	f.Tags = append(f.Tags, "web")
	return offset + len(data)
}

var http2FrameTypes = map[byte]string{
	0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
	4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
	8: "WINDOW_UPDATE", 9: "CONTINUATION",
}

func dissectHTTP2(f *Frame, data []byte, offset int) int {
	pos := 0
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	var frames []string
	fields := map[string]string{}

	if bytes.HasPrefix(data, preface) {
		frames = append(frames, "Magic Preface")
		fields["preface"] = "true"
		pos = len(preface)
	}

	for pos+9 <= len(data) && len(frames) < 16 {
		length := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
		ftype := data[pos+3]
		flags := data[pos+4]
		stream := u32(data, pos+5) & 0x7fffffff
		typeName := http2FrameTypes[ftype]
		if typeName == "" {
			typeName = fmt.Sprintf("TYPE_%d", ftype)
		}
		detail := fmt.Sprintf("%s stream=%d len=%d flags=0x%02x", typeName, stream, length, flags)
		if ftype == 4 && length >= 0 { // SETTINGS
			nsettings := length / 6
			detail += fmt.Sprintf(" settings=%d", nsettings)
			parseHTTP2Settings(data, pos+9, length, fields)
		}
		if ftype == 1 { // HEADERS — try HPACK-ish raw peek
			fields["headers_stream"] = fmt.Sprintf("%d", stream)
			if flags&0x4 != 0 {
				detail += " END_HEADERS"
			}
			if flags&0x1 != 0 {
				detail += " END_STREAM"
			}
		}
		if ftype == 0 {
			if flags&0x1 != 0 {
				detail += " END_STREAM"
			}
		}
		frames = append(frames, detail)
		next := pos + 9 + length
		if next <= pos || next > len(data) {
			// truncated frame — still count header
			pos = len(data)
			break
		}
		pos = next
	}

	summary := strings.Join(frames, " | ")
	if summary == "" {
		summary = fmt.Sprintf("HTTP/2 %d bytes", len(data))
	}
	fields["frames"] = strings.Join(frames, "; ")
	addLayer(f, "HTTP/2", summary, fields, offset, len(data), "#22d3ee")
	f.Protocol = "HTTP/2"
	f.Info = summary
	f.Tags = append(f.Tags, "web", "h2")
	f.Meta["http2"] = "1"
	return offset + len(data)
}

func parseHTTP2Settings(data []byte, off, length int, fields map[string]string) {
	ids := map[uint16]string{
		1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
		4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
	}
	end := off + length
	if end > len(data) {
		end = len(data)
	}
	for off+6 <= end {
		id := u16(data, off)
		val := u32(data, off+2)
		name := ids[id]
		if name == "" {
			name = fmt.Sprintf("ID_%d", id)
		}
		fields["setting_"+strings.ToLower(name)] = fmt.Sprintf("%d", val)
		off += 6
	}
}
