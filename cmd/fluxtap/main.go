package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/FounderB/FluxTap/internal/decode"
	"github.com/FounderB/FluxTap/internal/engine"
	"github.com/FounderB/FluxTap/internal/pcap"
	"github.com/FounderB/FluxTap/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "parse", "p":
		cmdParse(os.Args[2:])
	case "serve", "ui", "dashboard":
		cmdServe(os.Args[2:])
	case "live", "capture", "tap":
		cmdLive(os.Args[2:])
	case "ifaces", "interfaces":
		cmdIfaces()
	case "gen", "generate":
		cmdGen(os.Args[2:])
	case "bench":
		cmdBench(os.Args[2:])
	case "help", "-h", "--help":
		printHelp()
	default:
		if strings.HasSuffix(os.Args[1], ".pcap") || strings.HasSuffix(os.Args[1], ".pcapng") {
			cmdParse(os.Args[1:])
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Print(`
FluxTap — live network protocol dissector (kernel · sessions · Telegram · webhooks · story)

Usage:
  fluxtap live   -i IFACE [--kernel|--tcpdump] [--addr :8090]
                 [--tg-token TOKEN] [--tg-chat ID] [--tg-dry]
                 [--webhook-url URL] [--webhook-dry]
                 [--token TOKEN | --no-auth]
  fluxtap live   --stdin [--addr :8090]
  fluxtap serve  <file.pcap> [--addr :8090] [--replay] [--tg-dry] [--webhook-url URL]
  fluxtap parse  <file.pcap> [--filter EXPR] [--json out.json]
  fluxtap ifaces | gen | bench

Examples:
  sudo fluxtap live -i eth0 --kernel --addr :8090
  sudo fluxtap live -i lo --tg-token $FLUXTAP_TG_TOKEN --tg-chat $FLUXTAP_TG_CHAT
  sudo fluxtap live -i eth0 --webhook-url https://hooks.example/fluxtap --webhook-dry
  sudo fluxtap live -i eth0 --tcpdump --bpf "port 443"
  fluxtap serve testdata/demo.pcap --replay --tg-dry --no-auth

Env: FLUXTAP_TG_TOKEN, FLUXTAP_TG_CHAT, FLUXTAP_WEBHOOK_URL, FLUXTAP_TOKEN

`)
}

func cmdLive(args []string) {
	fs := flag.NewFlagSet("live", flag.ExitOnError)
	iface := fs.String("i", "eth0", "interface (eth0, lo, …; kernel needs concrete iface)")
	addr := fs.String("addr", ":8090", "dashboard listen address")
	bpf := fs.String("bpf", "", "capture BPF filter (tcpdump path only)")
	filter := fs.String("filter", "", "display filter")
	promisc := fs.Bool("promisc", false, "enable promiscuous mode")
	stdin := fs.Bool("stdin", false, "read PCAP stream from stdin")
	kernel := fs.Bool("kernel", true, "AF_PACKET kernel tap (no tcpdump)")
	tcpdumpForce := fs.Bool("tcpdump", false, "force tcpdump capture path")
	tgToken := fs.String("tg-token", os.Getenv("FLUXTAP_TG_TOKEN"), "Telegram bot token")
	tgChat := fs.String("tg-chat", os.Getenv("FLUXTAP_TG_CHAT"), "Telegram chat id")
	tgDry := fs.Bool("tg-dry", false, "log Telegram alerts instead of sending")
	webhookURL := fs.String("webhook-url", os.Getenv("FLUXTAP_WEBHOOK_URL"), "POST findings JSON to this URL")
	webhookDry := fs.Bool("webhook-dry", false, "log webhook payloads instead of POSTing")
	dashToken := fs.String("token", os.Getenv("FLUXTAP_TOKEN"), "dashboard auth token (auto if empty)")
	noAuth := fs.Bool("no-auth", false, "disable dashboard auth (insecure)")
	_ = fs.Parse(args)
	useKernel := *kernel && !*tcpdumpForce && !*stdin
	cfg := engine.Config{
		Iface: *iface, BPF: *bpf, Filter: *filter,
		IncludeHex: true, Promisc: *promisc, Stdin: *stdin, Kernel: useKernel,
		TelegramTok: *tgToken, TelegramChat: *tgChat, TelegramDry: *tgDry,
		WebhookURL: *webhookURL, WebhookDry: *webhookDry,
	}
	if *stdin {
		cfg = engine.Config{
			Filter: *filter, IncludeHex: true, Stdin: true,
			TelegramTok: *tgToken, TelegramChat: *tgChat, TelegramDry: *tgDry,
			WebhookURL: *webhookURL, WebhookDry: *webhookDry,
		}
	}
	eng := engine.New(cfg)
	runDashboard(eng, *addr, *dashToken, *noAuth, func() {
		if *stdin {
			fmt.Println("📡 live capture from stdin PCAP pipe …")
		} else if useKernel {
			fmt.Printf("📡 KERNEL tap (AF_PACKET) on %s …\n", *iface)
		} else {
			fmt.Printf("📡 tcpdump capture on %s …\n", *iface)
			if *bpf != "" {
				fmt.Printf("   bpf: %s\n", *bpf)
			}
		}
		if *tgToken != "" && *tgChat != "" {
			mode := ""
			if *tgDry {
				mode = " (dry-run)"
			}
			fmt.Println("📬 Telegram alerts: enabled" + mode)
		}
		if *webhookURL != "" {
			mode := ""
			if *webhookDry {
				mode = " (dry-run)"
			}
			fmt.Println("🪝 Webhook alerts: enabled" + mode)
		}
	})
}

func printBanner() {
	fmt.Print(`
  _____ _           _____           
 |  ___| |_   ___ _|_   _|_ _ _ __  
 | |_  | | | | \ \/ / | |/ _' | '_ \ 
 |  _| | | |_| |>  <  | | (_| | |_) |
 |_|   |_|\__,_/_/\_\ |_|\__,_| .__/ 
                              |_|    
         live protocol dissector
`)
}

func cmdParse(args []string) {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	filter := fs.String("filter", "", "display filter")
	limit := fs.Int("limit", 0, "max packets")
	jsonOut := fs.String("json", "", "export JSON path")
	csvOut := fs.String("csv", "", "export CSV path")
	quiet := fs.Bool("q", false, "quiet summary only")
	path, rest := splitPathArgs(args)
	_ = fs.Parse(rest)
	if path == "" {
		path = fs.Arg(0)
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "parse requires a pcap file")
		os.Exit(1)
	}
	eng := engine.New(engine.Config{Path: path, Filter: *filter, MaxPackets: *limit, IncludeHex: true})
	start := time.Now()
	if err := eng.Run(); err != nil {
		fatal(err)
	}
	elapsed := time.Since(start)

	if !*quiet {
		printBanner()
		frames := eng.Frames()
		show := frames
		if len(show) > 40 {
			show = show[:40]
		}
		for _, f := range show {
			printFrameBrief(f)
		}
		if len(frames) > 40 {
			fmt.Printf("  … %d more packets (use serve UI or --json)\n", len(frames)-40)
		}
		fmt.Println()
		s := eng.Stats.Snapshot()
		pps := float64(s.Packets) / elapsed.Seconds()
		if elapsed < time.Microsecond {
			pps = float64(s.Packets)
		}
		fmt.Printf("⚡ %d packets · %s · %.0f pps · %d flows · %d findings · %s\n",
			s.Packets, humanBytes(s.Bytes), pps,
			eng.Flows.Count(), len(eng.Security.Findings()), elapsed)
		if len(eng.Security.Findings()) > 0 {
			fmt.Println("\n🔐 Security radar:")
			for i, f := range eng.Security.Findings() {
				if i >= 8 {
					break
				}
				fmt.Printf("  [%s] %s — %s\n", f.Severity, f.Rule, f.Message)
			}
		}
	} else {
		fmt.Println(eng.Summary())
	}

	if *jsonOut != "" {
		f, err := os.Create(*jsonOut)
		if err != nil {
			fatal(err)
		}
		if err := eng.ExportJSON(f); err != nil {
			fatal(err)
		}
		f.Close()
		fmt.Println("wrote", *jsonOut)
	}
	if *csvOut != "" {
		if err := eng.ExportCSV(*csvOut); err != nil {
			fatal(err)
		}
		fmt.Println("wrote", *csvOut)
	}
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8090", "listen address")
	filter := fs.String("filter", "", "display filter")
	replay := fs.Bool("replay", false, "slow replay for live UI feel")
	tgToken := fs.String("tg-token", os.Getenv("FLUXTAP_TG_TOKEN"), "Telegram bot token")
	tgChat := fs.String("tg-chat", os.Getenv("FLUXTAP_TG_CHAT"), "Telegram chat id")
	tgDry := fs.Bool("tg-dry", false, "log Telegram alerts instead of sending")
	webhookURL := fs.String("webhook-url", os.Getenv("FLUXTAP_WEBHOOK_URL"), "POST findings JSON to this URL")
	webhookDry := fs.Bool("webhook-dry", false, "log webhook payloads instead of POSTing")
	dashToken := fs.String("token", os.Getenv("FLUXTAP_TOKEN"), "dashboard auth token (auto if empty)")
	noAuth := fs.Bool("no-auth", false, "disable dashboard auth (insecure)")
	path, rest := splitPathArgs(args)
	_ = fs.Parse(rest)
	if path == "" {
		path = fs.Arg(0)
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "serve requires a pcap file (or use: fluxtap live -i eth0)")
		os.Exit(1)
	}
	speed := time.Duration(0)
	if *replay {
		speed = 2 * time.Millisecond
	}
	eng := engine.New(engine.Config{
		Path: path, Filter: *filter, IncludeHex: true, Speed: speed,
		TelegramTok: *tgToken, TelegramChat: *tgChat, TelegramDry: *tgDry,
		WebhookURL: *webhookURL, WebhookDry: *webhookDry,
	})
	runDashboard(eng, *addr, *dashToken, *noAuth, func() {
		fmt.Printf("📂 loading %s …\n", path)
	})
}

func runDashboard(eng *engine.Engine, addr, token string, noAuth bool, announce func()) {
	srv := web.New(eng, web.Options{Addr: normalizeAddr(addr), Token: token, NoAuth: noAuth})
	errCh := make(chan error, 1)
	go func() {
		time.Sleep(250 * time.Millisecond)
		printBanner()
		announce()
		if err := eng.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "engine:", err)
			errCh <- err
			return
		}
		fmt.Println("✅", eng.Summary())
		if eng.IsLive() {
			// live stream ended (stdin EOF / interface down)
			errCh <- nil
		}
	}()
	go func() {
		if err := <-errCh; err != nil {
			time.Sleep(100 * time.Millisecond)
			os.Exit(1)
		}
	}()
	if err := srv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

func cmdIfaces() {
	list, err := listIfaces()
	if err != nil {
		fatal(err)
	}
	fmt.Println("Capture interfaces:")
	for _, n := range list {
		fmt.Println(" ", n)
	}
}

func cmdBench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	path, rest := splitPathArgs(args)
	_ = fs.Parse(rest)
	if path == "" {
		path = fs.Arg(0)
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "bench requires a pcap file")
		os.Exit(1)
	}
	const rounds = 5
	var best time.Duration
	var pkts uint64
	for i := 0; i < rounds; i++ {
		eng := engine.New(engine.Config{Path: path, IncludeHex: false})
		start := time.Now()
		if err := eng.Run(); err != nil {
			fatal(err)
		}
		d := time.Since(start)
		pkts = eng.Stats.Snapshot().Packets
		if best == 0 || d < best {
			best = d
		}
	}
	pps := float64(pkts) / best.Seconds()
	fmt.Printf("bench: %d packets best=%s → %.0f pps (%.2f µs/pkt)\n",
		pkts, best, pps, best.Seconds()*1e6/float64(pkts))
}

func cmdGen(args []string) {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	count := fs.Int("count", 120, "approximate packet count")
	path, rest := splitPathArgs(args)
	_ = fs.Parse(rest)
	out := path
	if out == "" {
		out = fs.Arg(0)
	}
	if out == "" {
		out = "demo.pcap"
	}
	if err := writeDemoPCAP(out, *count); err != nil {
		fatal(err)
	}
	fmt.Println("✨ wrote", out)
}

// splitPathArgs pulls the first non-flag token (usually the pcap path) so flags can appear before or after it.
func splitPathArgs(args []string) (path string, flags []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			flags = append(flags, args[i:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// copy value for flags that take an argument
			name := strings.TrimLeft(a, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				continue
			}
			switch name {
			case "filter", "limit", "json", "csv", "addr", "count", "i", "bpf",
				"tg-token", "tg-chat", "webhook-url", "token":
				if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		if path == "" {
			path = a
			continue
		}
		flags = append(flags, a)
	}
	return path, flags
}

func listIfaces() ([]string, error) {
	return pcap.ListInterfaces()
}

func printFrameBrief(f *decode.Frame) {
	sev := " "
	if f.Severity == "warn" {
		sev = "!"
	} else if f.Severity == "alert" {
		sev = "‼"
	}
	fmt.Printf("%s %5d  %-16s → %-16s  %-7s  %s\n", sev, f.No, trunc(f.Src, 16), trunc(f.Dst, 16), f.Protocol, trunc(f.Info, 70))
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func normalizeAddr(a string) string {
	if strings.HasPrefix(a, ":") {
		return "127.0.0.1" + a
	}
	return a
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// --- demo PCAP generator (Ethernet frames) ---

func writeDemoPCAP(path string, count int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// global header LE micro
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], 1) // ethernet
	if _, err := f.Write(hdr); err != nil {
		return err
	}
	ts := time.Now().Add(-time.Minute)
	n := 0
	write := func(frame []byte) {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
		binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(frame)))
		_, _ = f.Write(rec)
		_, _ = f.Write(frame)
		ts = ts.Add(time.Millisecond * time.Duration(5+n%17))
		n++
	}

	// ARP
	write(ethFrame(0x0806, arpRequest()))
	write(ethFrame(0x0806, arpReply()))

	// DNS query + response
	write(ethFrame(0x0800, ipv4udp(clientIP(), dnsIP(), 53000, 53, dnsQuery("example.com", 1))))
	write(ethFrame(0x0800, ipv4udp(dnsIP(), clientIP(), 53, 53000, dnsResponse("example.com", "93.184.216.34"))))
	write(ethFrame(0x0800, ipv4udp(clientIP(), dnsIP(), 53001, 53, dnsQuery("api.github.com", 28))))
	write(ethFrame(0x0800, ipv4udp(clientIP(), dnsIP(), 53002, 53, dnsQuery(strings.Repeat("longlabel", 8)+".evil.test", 1))))

	// DHCP discover
	write(ethFrame(0x0800, ipv4udp([4]byte{0, 0, 0, 0}, [4]byte{255, 255, 255, 255}, 68, 67, dhcpDiscover())))

	// HTTP GET
	httpReq := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: FluxTap/1.0\r\nAuthorization: Basic dXNlcjpwYXNz\r\nAccept: */*\r\n\r\n")
	write(ethFrame(0x0800, ipv4tcp(clientIP(), serverIP(), 49152, 80, 0x18, httpReq)))
	httpResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, PCAP!\n")
	write(ethFrame(0x0800, ipv4tcp(serverIP(), clientIP(), 80, 49152, 0x18, httpResp)))

	// HTTP/2 preface + SETTINGS
	h2 := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), http2Settings()...)
	write(ethFrame(0x0800, ipv4tcp(clientIP(), serverIP(), 49153, 8080, 0x18, h2)))

	// TLS ClientHello with SNI
	write(ethFrame(0x0800, ipv4tcp(clientIP(), serverIP(), 49154, 443, 0x18, tlsClientHello("www.google.com"))))
	write(ethFrame(0x0800, ipv4tcp(serverIP(), clientIP(), 443, 49154, 0x18, tlsServerHello())))

	// QUIC long header
	quic := make([]byte, 40)
	quic[0] = 0xc0
	binary.BigEndian.PutUint32(quic[1:], 0x00000001)
	write(ethFrame(0x0800, ipv4udp(clientIP(), serverIP(), 49155, 443, quic)))

	// ICMP echo
	write(ethFrame(0x0800, ipv4icmp(clientIP(), serverIP())))

	// SYN scan-ish
	for i := 0; i < 35; i++ {
		write(ethFrame(0x0800, ipv4tcp(clientIP(), serverIP(), uint16(40000+i), uint16(20+i), 0x02, nil)))
	}

	// pad with mixed traffic until count
	for n < count {
		switch n % 5 {
		case 0:
			write(ethFrame(0x0800, ipv4udp(clientIP(), dnsIP(), uint16(40000+n), 53, dnsQuery(fmt.Sprintf("host%d.local", n), 1))))
		case 1:
			write(ethFrame(0x0800, ipv4tcp(clientIP(), serverIP(), uint16(50000+n%1000), 443, 0x18, tlsAppData(64))))
		case 2:
			write(ethFrame(0x0800, ipv4tcp(clientIP(), serverIP(), uint16(51000+n%1000), 80, 0x18, []byte("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n"))))
		case 3:
			write(ethFrame(0x0800, ipv4icmp(clientIP(), [4]byte{1, 1, 1, 1})))
		default:
			write(ethFrame(0x0800, ipv4udp(clientIP(), serverIP(), uint16(52000+n%1000), 443, quic)))
		}
	}
	return nil
}

func clientIP() [4]byte { return [4]byte{192, 168, 1, 10} }
func serverIP() [4]byte { return [4]byte{93, 184, 216, 34} }
func dnsIP() [4]byte    { return [4]byte{8, 8, 8, 8} }

func ethFrame(etherType uint16, payload []byte) []byte {
	b := make([]byte, 14+len(payload))
	copy(b[0:], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(b[6:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint16(b[12:], etherType)
	copy(b[14:], payload)
	return b
}

func arpRequest() []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint16(b[0:], 1)
	binary.BigEndian.PutUint16(b[2:], 0x0800)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:], 1)
	copy(b[8:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	cip := clientIP()
	sip := serverIP()
	copy(b[14:], cip[:])
	copy(b[24:], sip[:])
	return b
}

func arpReply() []byte {
	b := arpRequest()
	binary.BigEndian.PutUint16(b[6:], 2)
	copy(b[8:], []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	sip := serverIP()
	cip := clientIP()
	copy(b[14:], sip[:])
	copy(b[18:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	copy(b[24:], cip[:])
	return b
}

func ipv4udp(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	total := 20 + udpLen
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	b[8] = 64
	b[9] = 17
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint16(b[24:], uint16(udpLen))
	copy(b[28:], payload)
	return b
}

func ipv4tcp(src, dst [4]byte, sport, dport uint16, flags byte, payload []byte) []byte {
	total := 20 + 20 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	b[8] = 64
	b[9] = 6
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	binary.BigEndian.PutUint16(b[20:], sport)
	binary.BigEndian.PutUint16(b[22:], dport)
	binary.BigEndian.PutUint32(b[24:], 1000)
	binary.BigEndian.PutUint32(b[28:], 2000)
	b[32] = 0x50 // hdr len 20
	b[33] = flags
	binary.BigEndian.PutUint16(b[34:], 65535)
	copy(b[40:], payload)
	return b
}

func ipv4icmp(src, dst [4]byte) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 28)
	b[8] = 64
	b[9] = 1
	copy(b[12:], src[:])
	copy(b[16:], dst[:])
	b[20] = 8 // echo request
	return b
}

func dnsQuery(name string, qtype uint16) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	b = append(b, encodeDNSName(name)...)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[0:], qtype)
	binary.BigEndian.PutUint16(tmp[2:], 1)
	return append(b, tmp...)
}

func dnsResponse(name, ip string) []byte {
	q := dnsQuery(name, 1)
	q[2] = 0x81
	q[3] = 0x80
	binary.BigEndian.PutUint16(q[6:], 1) // ancount
	ans := encodeDNSName(name)
	rr := make([]byte, 10+4)
	binary.BigEndian.PutUint16(rr[0:], 1)
	binary.BigEndian.PutUint16(rr[2:], 1)
	binary.BigEndian.PutUint32(rr[4:], 60)
	binary.BigEndian.PutUint16(rr[8:], 4)
	parts := strings.Split(ip, ".")
	for i := 0; i < 4; i++ {
		var v int
		fmt.Sscanf(parts[i], "%d", &v)
		rr[10+i] = byte(v)
	}
	out := append(q, ans...)
	return append(out, rr...)
}

func encodeDNSName(name string) []byte {
	var b []byte
	for _, p := range strings.Split(name, ".") {
		b = append(b, byte(len(p)))
		b = append(b, []byte(p)...)
	}
	b = append(b, 0)
	return b
}

func dhcpDiscover() []byte {
	b := make([]byte, 240)
	b[0] = 1 // boot request
	b[1] = 1
	b[2] = 6
	binary.BigEndian.PutUint32(b[4:], 0xdeadbeef)
	copy(b[28:], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	binary.BigEndian.PutUint32(b[236:], 0x63825363)
	// options: 53=1 discover, end
	opts := []byte{53, 1, 1, 255}
	b = append(b, opts...)
	return b
}

func http2Settings() []byte {
	// length=6, type=SETTINGS, flags=0, stream=0, one setting
	b := make([]byte, 15)
	b[2] = 6
	b[3] = 4
	binary.BigEndian.PutUint16(b[9:], 3) // MAX_CONCURRENT_STREAMS
	binary.BigEndian.PutUint32(b[11:], 100)
	return b
}

func tlsClientHello(sni string) []byte {
	// Build minimal ClientHello inside Handshake + Record
	extSNI := buildSNIExtension(sni)
	extGroups := []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17} // supported_groups secp256r1
	extEC := []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}
	exts := append(append(extSNI, extGroups...), extEC...)

	ch := make([]byte, 0, 256)
	ch = append(ch, 0x03, 0x03) // client version TLS1.2
	ch = append(ch, make([]byte, 32)...) // random
	ch = append(ch, 0)                   // session id len
	// cipher suites
	ciphers := []uint16{0x1301, 0x1302, 0xc02f, 0xc030, 0x009c}
	cs := make([]byte, 2+2*len(ciphers))
	binary.BigEndian.PutUint16(cs[0:], uint16(2*len(ciphers)))
	for i, c := range ciphers {
		binary.BigEndian.PutUint16(cs[2+2*i:], c)
	}
	ch = append(ch, cs...)
	ch = append(ch, 1, 0) // compression
	el := make([]byte, 2)
	binary.BigEndian.PutUint16(el, uint16(len(exts)))
	ch = append(ch, el...)
	ch = append(ch, exts...)

	hs := make([]byte, 4+len(ch))
	hs[0] = 1 // ClientHello
	hs[1] = byte(len(ch) >> 16)
	hs[2] = byte(len(ch) >> 8)
	hs[3] = byte(len(ch))
	copy(hs[4:], ch)

	rec := make([]byte, 5+len(hs))
	rec[0] = 22 // handshake
	rec[1], rec[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func buildSNIExtension(host string) []byte {
	hostBytes := []byte(host)
	// extension type 0, then extension data
	inner := make([]byte, 5+len(hostBytes))
	binary.BigEndian.PutUint16(inner[0:], uint16(3+len(hostBytes))) // server name list len
	inner[2] = 0                                                    // host_name
	binary.BigEndian.PutUint16(inner[3:], uint16(len(hostBytes)))
	copy(inner[5:], hostBytes)
	ext := make([]byte, 4+len(inner))
	binary.BigEndian.PutUint16(ext[0:], 0) // server_name
	binary.BigEndian.PutUint16(ext[2:], uint16(len(inner)))
	copy(ext[4:], inner)
	return ext
}

func tlsServerHello() []byte {
	sh := make([]byte, 0, 64)
	sh = append(sh, 0x03, 0x03)
	sh = append(sh, make([]byte, 32)...)
	sh = append(sh, 0)
	sh = append(sh, 0xc0, 0x2f) // cipher
	sh = append(sh, 0)         // compression
	hs := make([]byte, 4+len(sh))
	hs[0] = 2
	hs[1] = byte(len(sh) >> 16)
	hs[2] = byte(len(sh) >> 8)
	hs[3] = byte(len(sh))
	copy(hs[4:], sh)
	rec := make([]byte, 5+len(hs))
	rec[0] = 22
	rec[1], rec[2] = 0x03, 0x03
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func tlsAppData(n int) []byte {
	b := make([]byte, 5+n)
	b[0] = 23
	b[1], b[2] = 0x03, 0x03
	binary.BigEndian.PutUint16(b[3:], uint16(n))
	for i := 0; i < n; i++ {
		b[5+i] = byte(i)
	}
	return b
}
