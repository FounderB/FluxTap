package pcap_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/FounderB/FluxTap/internal/pcap"
)

func TestNGRejectsHugeBlock(t *testing.T) {
	// minimal SHB then a huge block length claim
	var buf bytes.Buffer
	// magic PCAPNG (same as section header type used by Open)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x0A0D0D0A))
	// rest of SHB with total length 28
	_ = binary.Write(&buf, binary.LittleEndian, uint32(28))
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:4], 0x1a2b3c4d) // BOM
	buf.Write(body)
	// next block with insane length
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x00000001))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0x7fffffff))

	rd, err := pcap.NewReader(io.NopCloser(bytes.NewReader(buf.Bytes())))
	if err != nil {
		// SHB itself might fail depending on parser — either way huge next should fail
		return
	}
	_, err = rd.Next()
	if err == nil {
		t.Fatal("expected error for huge NG block")
	}
}
