package pcap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/FounderB/FluxTap/internal/pcap"
)

func TestOpenDemoPCAP(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "demo.pcap")
	if _, err := os.Stat(path); err != nil {
		t.Skip("demo.pcap missing — run fluxtap gen first")
	}
	rd, err := pcap.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	n := 0
	for {
		pkt, err := rd.Next()
		if err != nil {
			break
		}
		if len(pkt.Data) == 0 {
			t.Fatalf("empty packet #%d", pkt.No)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("too few packets: %d", n)
	}
}

func TestListInterfaces(t *testing.T) {
	list, err := pcap.ListInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Fatal("no interfaces")
	}
}
