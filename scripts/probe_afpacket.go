package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func htons(v uint16) uint16 { return (v<<8)|(v>>8) }

func main() {
	iface := "lo"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}
	ifi, err := net.InterfaceByName(iface)
	must(err)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	must(err)
	defer unix.Close(fd)

	// try without ring first — blocking recv
	must(unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}))
	fmt.Println("bound", iface, "ifindex", ifi.Index, "— waiting 3s for packets via recvfrom…")
	_ = unix.SetNonblock(fd, true)
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 65535)
	nrecv := 0
	for time.Now().Before(deadline) {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		if err != nil {
			fmt.Println("recv err", err)
			break
		}
		nrecv++
		if nrecv <= 3 {
			fmt.Printf("pkt %d len=%d ethertype=%04x\n", nrecv, n, binary.BigEndian.Uint16(buf[12:14]))
		}
	}
	fmt.Println("recvfrom total", nrecv)

	// now set up V3 ring on a NEW socket
	fd2, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	must(err)
	defer unix.Close(fd2)
	var ver uint32 = 2
	must(setsockopt(fd2, unix.SOL_PACKET, unix.PACKET_VERSION, unsafe.Pointer(&ver), 4))
	page := uint32(os.Getpagesize())
	frame := uint32(2048)
	block := frame * 64
	if block%page != 0 {
		block = ((block / page) + 1) * page
	}
	blockNr := uint32(16)
	req := struct {
		blockSize, blockNr, frameSize, frameNr, retireTov, sizeofPriv, feature uint32
	}{block, blockNr, frame, (block / frame) * blockNr, 50, 0, 0}
	must(setsockopt(fd2, unix.SOL_PACKET, unix.PACKET_RX_RING, unsafe.Pointer(&req), unsafe.Sizeof(req)))
	ring, err := unix.Mmap(fd2, 0, int(block*blockNr), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	must(err)
	must(unix.Bind(fd2, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index}))
	fmt.Println("V3 ring ready — waiting 3s…")
	deadline = time.Now().Add(3 * time.Second)
	got := 0
	idx := uint32(0)
	for time.Now().Before(deadline) {
		b := ring[idx*block : (idx+1)*block]
		st := binary.LittleEndian.Uint32(b[8:12])
		if st&unix.TP_STATUS_USER == 0 {
			pfd := []unix.PollFd{{Fd: int32(fd2), Events: unix.POLLIN}}
			unix.Poll(pfd, 100)
			continue
		}
		np := binary.LittleEndian.Uint32(b[12:16])
		got += int(np)
		fmt.Println("block", idx, "status", st, "num_packets", np, "first_off", binary.LittleEndian.Uint32(b[16:20]))
		binary.LittleEndian.PutUint32(b[8:12], unix.TP_STATUS_KERNEL)
		idx = (idx + 1) % blockNr
		if got > 0 && got%10 == 0 {
			// keep going
		}
	}
	fmt.Println("ring packets seen", got)
}

func setsockopt(fd, level, name int, val unsafe.Pointer, n uintptr) error {
	_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(name), uintptr(val), n, 0)
	if e != 0 {
		return e
	}
	return nil
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
