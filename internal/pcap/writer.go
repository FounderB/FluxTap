package pcap

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"
)

// Writer appends classic PCAP (microsecond, little-endian) records.
type Writer struct {
	f        *os.File
	mu       sync.Mutex
	linkType uint32
	n        uint64
}

// CreateWriter writes a global header then returns a Writer for packet records.
func CreateWriter(path string, linkType uint32) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if linkType == 0 {
		linkType = LinkTypeEthernet
	}
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], linkType)
	if _, err := f.Write(hdr); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Writer{f: f, linkType: linkType}, nil
}

func (w *Writer) WritePacket(ts time.Time, data []byte) error {
	if w == nil || w.f == nil {
		return fmt.Errorf("pcap writer closed")
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(data)))
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.f.Write(rec); err != nil {
		return err
	}
	if _, err := w.f.Write(data); err != nil {
		return err
	}
	w.n++
	return nil
}

func (w *Writer) Count() uint64 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

func (w *Writer) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.f.Close()
	w.f = nil
	return err
}
