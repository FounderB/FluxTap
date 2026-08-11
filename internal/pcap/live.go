package pcap

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Live opens a real-time capture via tcpdump writing classic PCAP to a pipe.
// Requires CAP_NET_RAW / root (or: sudo tcpdump -w - | fluxtap live --stdin).
type Live struct {
	cmd    *exec.Cmd
	rd     *Reader
	iface  string
	mu     sync.Mutex
	closed bool
}

type LiveOpts struct {
	Iface   string
	SnapLen int
	BPF     string
	Promisc bool
	Stdin   bool // read PCAP stream from os.Stdin instead of spawning tcpdump
}

func OpenLive(opts LiveOpts) (*Live, error) {
	if opts.Stdin {
		rd, err := NewReader(io.NopCloser(os.Stdin))
		if err != nil {
			return nil, fmt.Errorf("stdin pcap stream: %w (pipe: sudo tcpdump -i eth0 -U -w - | fluxtap live --stdin)", err)
		}
		return &Live{rd: rd, iface: "stdin"}, nil
	}
	if opts.Iface == "" {
		opts.Iface = "any"
	}
	if opts.SnapLen <= 0 {
		opts.SnapLen = 65535
	}
	args := []string{
		"-i", opts.Iface,
		"-w", "-",
		"-U",
		"--immediate-mode",
		"-n",
		"-s", strconv.Itoa(opts.SnapLen),
	}
	if !opts.Promisc {
		args = append(args, "-p")
	}
	// Terminate option parsing so BPF cannot inject extra tcpdump flags.
	args = append(args, "--")
	if opts.BPF != "" {
		args = append(args, opts.BPF)
	}
	cmd := exec.Command("tcpdump", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start tcpdump: %w", err)
	}

	errBuf := &strings.Builder{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, e := stderr.Read(buf)
			if n > 0 {
				msg := string(buf[:n])
				errBuf.WriteString(msg)
				for _, line := range strings.Split(msg, "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						fmt.Fprintf(os.Stderr, "tcpdump: %s\n", line)
					}
				}
			}
			if e != nil {
				return
			}
		}
	}()

	type result struct {
		rd  *Reader
		err error
	}
	ch := make(chan result, 1)
	go func() {
		rd, err := NewReader(io.NopCloser(stdout))
		ch <- result{rd, err}
	}()

	var rd *Reader
	select {
	case res := <-ch:
		if res.err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			hint := strings.TrimSpace(errBuf.String())
			if hint == "" {
				hint = "permission denied? try: sudo fluxtap live -i " + opts.Iface + "  OR  sudo tcpdump -i " + opts.Iface + " -U -w - | fluxtap live --stdin"
			}
			return nil, fmt.Errorf("pcap stream: %v (%s)", res.err, hint)
		}
		rd = res.rd
	case <-time.After(4 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		hint := strings.TrimSpace(errBuf.String())
		if hint == "" {
			hint = "timeout waiting for tcpdump pcap header — need root/CAP_NET_RAW"
		}
		return nil, fmt.Errorf("live capture failed: %s", hint)
	}

	live := &Live{cmd: cmd, rd: rd, iface: opts.Iface}
	go func() {
		_ = cmd.Wait()
		live.mu.Lock()
		live.closed = true
		live.mu.Unlock()
	}()
	return live, nil
}

func (l *Live) Next() (*Packet, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, io.EOF
	}
	return l.rd.Next()
}

func (l *Live) LinkType() uint32 {
	return l.rd.LinkType()
}

func (l *Live) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.cmd != nil && l.cmd.Process != nil {
		_ = l.cmd.Process.Signal(os.Interrupt)
		time.Sleep(50 * time.Millisecond)
		_ = l.cmd.Process.Kill()
	}
	return nil
}

func (l *Live) Iface() string { return l.iface }

// ListInterfaces returns network interface names suitable for -i.
func ListInterfaces() ([]string, error) {
	out, err := exec.Command("tcpdump", "-D").Output()
	if err == nil {
		var names []string
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			rest := line
			if dot := strings.IndexByte(line, '.'); dot >= 0 {
				rest = line[dot+1:]
			}
			name := strings.Fields(rest)[0]
			names = append(names, name)
		}
		if len(names) > 0 {
			return names, nil
		}
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return []string{"any", "lo"}, nil
	}
	names := []string{"any"}
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}
