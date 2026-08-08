package decode_test

import (
	"testing"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
)

func TestDissectDNSAndTLS(t *testing.T) {
	d := decode.NewDissector()
	d.IncludeHex = false

	// Minimal IPv4+UDP+DNS query for example.com A
	// We'll use generator-like bytes via eth frame from a tiny handcraft
	frame := buildDNSQueryFrame()
	fr := d.Dissect(1, time.Now(), uint32(len(frame)), uint32(len(frame)), 1, frame)
	if fr.Protocol != "DNS" {
		t.Fatalf("want DNS got %s info=%s layers=%v", fr.Protocol, fr.Info, layerNames(fr))
	}
	if fr.Meta["dns_qry"] == "" {
		t.Fatalf("expected dns_qry meta, got %#v", fr.Meta)
	}

	tlsFrame := buildTLSClientHelloFrame("www.example.com")
	fr2 := d.Dissect(2, time.Now(), uint32(len(tlsFrame)), uint32(len(tlsFrame)), 1, tlsFrame)
	if fr2.Protocol != "TLS" {
		t.Fatalf("want TLS got %s info=%s", fr2.Protocol, fr2.Info)
	}
	if fr2.Meta["sni"] != "www.example.com" {
		t.Fatalf("sni=%q", fr2.Meta["sni"])
	}
	if fr2.Meta["ja3"] == "" {
		t.Fatalf("expected ja3 hash")
	}
}

func layerNames(f *decode.Frame) []string {
	var n []string
	for _, l := range f.Layers {
		n = append(n, l.Name)
	}
	return n
}

func eth(payload []byte, etype uint16) []byte {
	b := make([]byte, 14+len(payload))
	copy(b[0:], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(b[6:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	b[12] = byte(etype >> 8)
	b[13] = byte(etype)
	copy(b[14:], payload)
	return b
}

func ipv4udp(payload []byte, dport uint16) []byte {
	total := 20 + 8 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	b[2] = byte(total >> 8)
	b[3] = byte(total)
	b[8] = 64
	b[9] = 17
	copy(b[12:], []byte{192, 168, 1, 10})
	copy(b[16:], []byte{8, 8, 8, 8})
	b[20], b[21] = 0xc3, 0x50 // sport
	b[22] = byte(dport >> 8)
	b[23] = byte(dport)
	ulen := 8 + len(payload)
	b[24] = byte(ulen >> 8)
	b[25] = byte(ulen)
	copy(b[28:], payload)
	return b
}

func ipv4tcp(payload []byte, dport uint16) []byte {
	total := 20 + 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	b[2] = byte(total >> 8)
	b[3] = byte(total)
	b[8] = 64
	b[9] = 6
	copy(b[12:], []byte{192, 168, 1, 10})
	copy(b[16:], []byte{1, 2, 3, 4})
	b[20], b[21] = 0xc0, 0x00
	b[22] = byte(dport >> 8)
	b[23] = byte(dport)
	b[32] = 0x50
	b[33] = 0x18 // PSH ACK
	copy(b[40:], payload)
	return b
}

func buildDNSQueryFrame() []byte {
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, 7)
	dns = append(dns, []byte("example")...)
	dns = append(dns, 3)
	dns = append(dns, []byte("com")...)
	dns = append(dns, 0, 0, 1, 0, 1)
	return eth(ipv4udp(dns, 53), 0x0800)
}

func buildTLSClientHelloFrame(sni string) []byte {
	host := []byte(sni)
	inner := make([]byte, 5+len(host))
	inner[0] = byte((3 + len(host)) >> 8)
	inner[1] = byte(3 + len(host))
	inner[2] = 0
	inner[3] = byte(len(host) >> 8)
	inner[4] = byte(len(host))
	copy(inner[5:], host)
	ext := make([]byte, 4+len(inner))
	ext[2] = byte(len(inner) >> 8)
	ext[3] = byte(len(inner))
	copy(ext[4:], inner)
	// also add supported_groups + ec_point_formats for JA3
	ext = append(ext, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17)
	ext = append(ext, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)

	ch := []byte{0x03, 0x03}
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0)
	ch = append(ch, 0x00, 0x04, 0x13, 0x01, 0xc0, 0x2f) // 2 ciphers
	ch = append(ch, 0x01, 0x00)
	ch = append(ch, byte(len(ext)>>8), byte(len(ext)))
	ch = append(ch, ext...)

	hs := make([]byte, 4+len(ch))
	hs[0] = 1
	hs[1] = byte(len(ch) >> 16)
	hs[2] = byte(len(ch) >> 8)
	hs[3] = byte(len(ch))
	copy(hs[4:], ch)

	rec := make([]byte, 5+len(hs))
	rec[0] = 22
	rec[1], rec[2] = 0x03, 0x01
	rec[3] = byte(len(hs) >> 8)
	rec[4] = byte(len(hs))
	copy(rec[5:], hs)
	return eth(ipv4tcp(rec, 443), 0x0800)
}
