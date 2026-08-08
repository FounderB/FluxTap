package decode

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// Layer is one decoded protocol layer.
type Layer struct {
	Name     string            `json:"name"`
	Summary  string            `json:"summary"`
	Fields   map[string]string `json:"fields"`
	Raw      []byte            `json:"-"`
	Offset   int               `json:"offset"`
	Length   int               `json:"length"`
	Color    string            `json:"color,omitempty"`
}

// Frame is a fully dissected packet.
type Frame struct {
	No         uint64            `json:"no"`
	Timestamp  time.Time         `json:"timestamp"`
	CapLen     uint32            `json:"cap_len"`
	OrigLen    uint32            `json:"orig_len"`
	Length     int               `json:"length"`
	Src        string            `json:"src"`
	Dst        string            `json:"dst"`
	Protocol   string            `json:"protocol"`
	Info       string            `json:"info"`
	Layers     []Layer           `json:"layers"`
	HexDump    string            `json:"hex_dump,omitempty"`
	Meta       map[string]string `json:"meta"`
	FlowKey    string            `json:"flow_key,omitempty"`
	Severity   string            `json:"severity,omitempty"` // info|warn|alert
	Tags       []string          `json:"tags,omitempty"`
}

// Dissector walks the protocol stack.
type Dissector struct {
	IncludeHex bool
	MaxHex     int
}

func NewDissector() *Dissector {
	return &Dissector{IncludeHex: true, MaxHex: 512}
}

func (d *Dissector) Dissect(no uint64, ts time.Time, capLen, origLen uint32, linkType uint32, data []byte) *Frame {
	f := &Frame{
		No:        no,
		Timestamp: ts,
		CapLen:    capLen,
		OrigLen:   origLen,
		Length:    len(data),
		Meta:      map[string]string{},
		Layers:    make([]Layer, 0, 8),
	}
	if d.IncludeHex {
		n := len(data)
		if d.MaxHex > 0 && n > d.MaxHex {
			n = d.MaxHex
		}
		f.HexDump = HexDump(data[:n], 0)
	}

	offset := 0
	switch linkType {
	case 1, 0: // Ethernet
		offset = dissectEthernet(f, data, offset)
	case 113: // Linux cooked v1
		offset = dissectLinuxSLL(f, data, offset)
	case 276: // Linux cooked v2 (tcpdump -i any)
		offset = dissectLinuxSLL2(f, data, offset)
	case 101: // Raw IP
		if len(data) > 0 {
			v := data[0] >> 4
			if v == 4 {
				offset = dissectIPv4(f, data, 0)
			} else if v == 6 {
				offset = dissectIPv6(f, data, 0)
			}
		}
	default:
		f.Layers = append(f.Layers, Layer{
			Name:    "Raw",
			Summary: fmt.Sprintf("linktype=%d len=%d", linkType, len(data)),
			Fields:  map[string]string{"link_type": fmt.Sprintf("%d", linkType)},
			Offset:  0,
			Length:  len(data),
			Color:   "#64748b",
		})
	}

	if f.Protocol == "" {
		f.Protocol = topProtocol(f)
	}
	if f.Info == "" {
		f.Info = buildInfo(f)
	}
	f.FlowKey = flowKey(f)
	return f
}

func topProtocol(f *Frame) string {
	if len(f.Layers) == 0 {
		return "Unknown"
	}
	return f.Layers[len(f.Layers)-1].Name
}

func buildInfo(f *Frame) string {
	parts := make([]string, 0, len(f.Layers))
	for _, l := range f.Layers {
		if l.Summary != "" {
			parts = append(parts, l.Summary)
		}
	}
	if len(parts) == 0 {
		return f.Protocol
	}
	return parts[len(parts)-1]
}

func flowKey(f *Frame) string {
	sport := f.Meta["sport"]
	dport := f.Meta["dport"]
	proto := f.Meta["ip_proto"]
	if proto == "" {
		proto = f.Protocol
	}
	a, b := f.Src, f.Dst
	as, bs := sport, dport
	if a > b || (a == b && as > bs) {
		a, b = b, a
		as, bs = bs, as
	}
	return fmt.Sprintf("%s|%s:%s-%s:%s", proto, a, as, b, bs)
}

func macString(b []byte) string {
	if len(b) < 6 {
		return "??:??:??:??:??:??"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func ipString(b []byte) string {
	return net.IP(b).String()
}

func addLayer(f *Frame, name, summary string, fields map[string]string, off, length int, color string) {
	if fields == nil {
		fields = map[string]string{}
	}
	f.Layers = append(f.Layers, Layer{
		Name: name, Summary: summary, Fields: fields,
		Offset: off, Length: length, Color: color,
	})
}

func setEndpoints(f *Frame, src, dst string) {
	f.Src = src
	f.Dst = dst
}

// HexDump formats bytes like Wireshark hex pane.
func HexDump(data []byte, baseOffset int) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		fmt.Fprintf(&b, "%04x  ", baseOffset+i)
		for j := 0; j < 16; j++ {
			if j == 8 {
				b.WriteByte(' ')
			}
			if j < len(chunk) {
				fmt.Fprintf(&b, "%02x ", chunk[j])
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" |")
		for _, c := range chunk {
			if c >= 32 && c < 127 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	return b.String()
}

func u16(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off:])
}

func u32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint32(b[off:])
}

func safeSlice(b []byte, start, end int) []byte {
	if start < 0 || start > len(b) {
		return nil
	}
	if end > len(b) {
		end = len(b)
	}
	if end < start {
		return nil
	}
	return b[start:end]
}

func hexPreview(b []byte, n int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > n {
		return hex.EncodeToString(b[:n]) + "…"
	}
	return hex.EncodeToString(b)
}
