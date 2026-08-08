package pcap

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// KernelTap captures via AF_PACKET SOCK_RAW directly from the kernel
// (no tcpdump subprocess). Requires CAP_NET_RAW / root and a concrete iface.
type KernelTap struct {
	fd       int
	iface    string
	linkType uint32
	buf      []byte
	mu       sync.Mutex
	closed   bool
	seq      uint64
}

type KernelOpts struct {
	Iface   string
	SnapLen int
	Promisc bool
}

func OpenKernel(opts KernelOpts) (*KernelTap, error) {
	if opts.Iface == "" || opts.Iface == "any" {
		return nil, errors.New("kernel tap needs a real iface (eth0/lo); use --tcpdump for 'any'")
	}
	ifi, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("iface %s: %w", opts.Iface, err)
	}
	snap := opts.SnapLen
	if snap <= 0 {
		snap = 65535
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET: %w (need root/CAP_NET_RAW)", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	if opts.Promisc {
		_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
			Ifindex: int32(ifi.Index),
			Type:    unix.PACKET_MR_PROMISC,
		})
	}
	// short recv timeout so Pause/Stop stay responsive
	tv := unix.Timeval{Sec: 0, Usec: 200000}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	return &KernelTap{
		fd: fd, iface: opts.Iface, linkType: LinkTypeEthernet,
		buf: make([]byte, snap),
	}, nil
}

func (k *KernelTap) Iface() string    { return k.iface + " [kernel]" }
func (k *KernelTap) LinkType() uint32 { return k.linkType }

func (k *KernelTap) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	k.closed = true
	if k.fd >= 0 {
		err := unix.Close(k.fd)
		k.fd = -1
		return err
	}
	return nil
}

func (k *KernelTap) Next() (*Packet, error) {
	for {
		k.mu.Lock()
		if k.closed {
			k.mu.Unlock()
			return nil, errors.New("closed")
		}
		fd := k.fd
		buf := k.buf
		k.mu.Unlock()

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			// SO_RCVTIMEO surfaces as EAGAIN/EWOULDBLOCK or timeout errno
			if errno, ok := err.(unix.Errno); ok && (errno == unix.EAGAIN || errno == 11 || errno == unix.EINTR) {
				continue
			}
			k.mu.Lock()
			closed := k.closed
			k.mu.Unlock()
			if closed {
				return nil, errors.New("closed")
			}
			// treat timeout-like as retry
			if err.Error() == "resource temporarily unavailable" {
				continue
			}
			continue
		}
		if n <= 0 {
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		k.mu.Lock()
		k.seq++
		seq := k.seq
		k.mu.Unlock()
		return &Packet{
			No: seq, Timestamp: time.Now(),
			CapLen: uint32(n), OrigLen: uint32(n),
			Data: data, LinkType: k.linkType,
		}, nil
	}
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
