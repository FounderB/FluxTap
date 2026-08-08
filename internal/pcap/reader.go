package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

var (
	ErrUnsupported = errors.New("unsupported capture format")
	ErrTruncated   = errors.New("truncated packet record")
)

const (
	MagicPCAPLE     = 0xa1b2c3d4
	MagicPCAPBE     = 0xd4c3b2a1
	MagicPCAPNSLE   = 0xa1b23c4d
	MagicPCAPNSBE   = 0x4d3cb2a1
	MagicPCAPNG     = 0x0a0d0d0a
	LinkTypeEthernet = 1
	LinkTypeRaw     = 101
	LinkTypeLinuxSLL = 113
)

// Packet is one captured frame with metadata.
type Packet struct {
	No        uint64
	Timestamp time.Time
	CapLen    uint32
	OrigLen   uint32
	Data      []byte
	LinkType  uint32
}

// Reader streams packets from a classic PCAP or PCAPNG file.
type Reader struct {
	r          io.ReadCloser
	byteOrder  binary.ByteOrder
	nano       bool
	linkType   uint32
	snapLen    uint32
	isNG       bool
	count      uint64
	buf        []byte
	ifaceMap   map[uint32]uint32 // interface id -> linktype (pcapng)
}

func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	rd, err := NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return rd, nil
}

func NewReader(r io.ReadCloser) (*Reader, error) {
	rd := &Reader{
		r:        r,
		buf:      make([]byte, 24),
		ifaceMap: make(map[uint32]uint32),
	}
	if _, err := io.ReadFull(r, rd.buf[:4]); err != nil {
		return nil, err
	}
	magic := binary.LittleEndian.Uint32(rd.buf[:4])
	switch magic {
	case MagicPCAPLE, MagicPCAPNSLE, MagicPCAPBE, MagicPCAPNSBE:
		return rd.initClassic(magic)
	case MagicPCAPNG:
		return rd.initNG()
	default:
		// PCAPNG section header may be big-endian magic swapped
		if magic == 0x1a2b3c4d || magic == binary.BigEndian.Uint32([]byte{0x0a, 0x0d, 0x0d, 0x0a}) {
			return rd.initNG()
		}
		return nil, fmt.Errorf("%w: magic 0x%08x", ErrUnsupported, magic)
	}
}

func (rd *Reader) initClassic(magic uint32) (*Reader, error) {
	switch magic {
	case MagicPCAPLE:
		rd.byteOrder = binary.LittleEndian
	case MagicPCAPNSLE:
		rd.byteOrder = binary.LittleEndian
		rd.nano = true
	case MagicPCAPBE:
		rd.byteOrder = binary.BigEndian
	case MagicPCAPNSBE:
		rd.byteOrder = binary.BigEndian
		rd.nano = true
	}
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(rd.r, hdr); err != nil {
		return nil, err
	}
	_ = rd.byteOrder.Uint16(hdr[0:2])  // major
	_ = rd.byteOrder.Uint16(hdr[2:4])  // minor
	_ = rd.byteOrder.Uint32(hdr[4:8])  // thiszone
	_ = rd.byteOrder.Uint32(hdr[8:12]) // sigfigs
	rd.snapLen = rd.byteOrder.Uint32(hdr[12:16])
	rd.linkType = rd.byteOrder.Uint32(hdr[16:20])
	return rd, nil
}

func (rd *Reader) initNG() (*Reader, error) {
	rd.isNG = true
	// We already consumed 4 bytes of SHB block type. Read rest of first block.
	rest := make([]byte, 4)
	if _, err := io.ReadFull(rd.r, rest); err != nil {
		return nil, err
	}
	totalLen := binary.LittleEndian.Uint32(rest)
	if totalLen < 28 {
		// try big endian
		totalLen = binary.BigEndian.Uint32(rest)
		rd.byteOrder = binary.BigEndian
	} else {
		rd.byteOrder = binary.LittleEndian
	}
	body := make([]byte, int(totalLen)-8)
	if _, err := io.ReadFull(rd.r, body); err != nil {
		return nil, err
	}
	// parse byte-order magic inside SHB
	bom := binary.LittleEndian.Uint32(body[0:4])
	if bom == 0x1a2b3c4d {
		rd.byteOrder = binary.LittleEndian
	} else if bom == 0x4d3c2b1a {
		rd.byteOrder = binary.BigEndian
	}
	rd.linkType = LinkTypeEthernet
	return rd, nil
}

func (rd *Reader) LinkType() uint32 { return rd.linkType }
func (rd *Reader) SnapLen() uint32  { return rd.snapLen }
func (rd *Reader) Count() uint64    { return rd.count }

func (rd *Reader) Close() error {
	if rd.r != nil {
		return rd.r.Close()
	}
	return nil
}

// Next returns the next packet or io.EOF.
func (rd *Reader) Next() (*Packet, error) {
	if rd.isNG {
		return rd.nextNG()
	}
	return rd.nextClassic()
}

func (rd *Reader) nextClassic() (*Packet, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(rd.r, hdr); err != nil {
		return nil, err
	}
	tsSec := rd.byteOrder.Uint32(hdr[0:4])
	tsFrac := rd.byteOrder.Uint32(hdr[4:8])
	capLen := rd.byteOrder.Uint32(hdr[8:12])
	origLen := rd.byteOrder.Uint32(hdr[12:16])
	if capLen > 64*1024*1024 {
		return nil, fmt.Errorf("%w: caplen %d", ErrTruncated, capLen)
	}
	data := make([]byte, capLen)
	if _, err := io.ReadFull(rd.r, data); err != nil {
		return nil, err
	}
	var ts time.Time
	if rd.nano {
		ts = time.Unix(int64(tsSec), int64(tsFrac))
	} else {
		ts = time.Unix(int64(tsSec), int64(tsFrac)*1000)
	}
	rd.count++
	return &Packet{
		No:        rd.count,
		Timestamp: ts,
		CapLen:    capLen,
		OrigLen:   origLen,
		Data:      data,
		LinkType:  rd.linkType,
	}, nil
}

func (rd *Reader) nextNG() (*Packet, error) {
	for {
		bh := make([]byte, 8)
		if _, err := io.ReadFull(rd.r, bh); err != nil {
			return nil, err
		}
		blockType := rd.byteOrder.Uint32(bh[0:4])
		blockLen := rd.byteOrder.Uint32(bh[4:8])
		if blockLen < 12 {
			return nil, fmt.Errorf("%w: block len %d", ErrTruncated, blockLen)
		}
		bodyLen := int(blockLen) - 12 // exclude type, len, trailing len
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(rd.r, body); err != nil {
				return nil, err
			}
		}
		trail := make([]byte, 4)
		if _, err := io.ReadFull(rd.r, trail); err != nil {
			return nil, err
		}

		switch blockType {
		case 0x00000001: // Interface Description Block
			if len(body) >= 4 {
				link := uint32(rd.byteOrder.Uint16(body[0:2]))
				ifaceID := uint32(len(rd.ifaceMap))
				rd.ifaceMap[ifaceID] = link
				rd.linkType = link
			}
		case 0x00000006: // Enhanced Packet Block
			if len(body) < 20 {
				continue
			}
			ifaceID := rd.byteOrder.Uint32(body[0:4])
			tsHigh := rd.byteOrder.Uint32(body[4:8])
			tsLow := rd.byteOrder.Uint32(body[8:12])
			capLen := rd.byteOrder.Uint32(body[12:16])
			origLen := rd.byteOrder.Uint32(body[16:20])
			if int(20+capLen) > len(body) {
				return nil, fmt.Errorf("%w: epb data", ErrTruncated)
			}
			data := make([]byte, capLen)
			copy(data, body[20:20+capLen])
			ts64 := (uint64(tsHigh) << 32) | uint64(tsLow)
			// default microsecond resolution
			ts := time.Unix(0, int64(ts64)*1000)
			link := rd.linkType
			if l, ok := rd.ifaceMap[ifaceID]; ok {
				link = l
			}
			rd.count++
			return &Packet{
				No:        rd.count,
				Timestamp: ts,
				CapLen:    capLen,
				OrigLen:   origLen,
				Data:      data,
				LinkType:  link,
			}, nil
		case 0x00000002: // Simple Packet Block
			if len(body) < 4 {
				continue
			}
			origLen := rd.byteOrder.Uint32(body[0:4])
			capLen := uint32(len(body) - 4)
			// align to 4
			padded := (capLen + 3) &^ 3
			if int(4+padded) > len(body) {
				padded = capLen
			}
			data := make([]byte, capLen)
			copy(data, body[4:4+capLen])
			rd.count++
			return &Packet{
				No:        rd.count,
				Timestamp: time.Now(),
				CapLen:    capLen,
				OrigLen:   origLen,
				Data:      data,
				LinkType:  rd.linkType,
			}, nil
		default:
			// skip unknown blocks (SHB already handled, IDB, NRB, etc.)
			continue
		}
	}
}

// All reads every packet into memory (for small captures / tests).
func (rd *Reader) All() ([]*Packet, error) {
	var out []*Packet
	for {
		p, err := rd.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
}
