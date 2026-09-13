# FluxTap

<p align="center">
  <img src="assets/fluxtap-icon.png" alt="FluxTap" width="128" height="128"/>
</p>

<p align="center">
  <strong>Live network protocol dissector</strong> — tap the wire, decode the flux.
</p>

<p align="center">
  <a href="https://github.com/FounderB/FluxTap"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-FounderB%2FFluxTap-2ee6a6?style=for-the-badge&logo=github"/></a>
  <img alt="Go" src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white"/>
  <img alt="License" src="https://img.shields.io/badge/License-MIT-2ee6a6?style=for-the-badge"/>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Linux-0c1a24?style=for-the-badge"/>
</p>

FluxTap captures packets in real time, dissects them into protocol layers
(DNS · HTTP/1 · HTTP/2 · TLS/JA3 · QUIC · DHCP · ARP · …), and streams the
result to a WebSocket dashboard built for speed-reading traffic.

---

## Why FluxTap?

| | |
|---|---|
| **Live capture** | Kernel AF_PACKET tap (or tcpdump / stdin) |
| **Deep dissector** | Custom protocol stack with SNI + JA3 |
| **Realtime UI** | WebSocket feed, pause/resume, Follow/Freeze, stream collapse |
| **Operator UX** | Filter presets · click IO peaks · right-click filters · Attack Story |
| **Security radar** | SYN-scan, cleartext Basic auth, DNS-tunnel hints, weak TLS |
| **SOC notify** | Telegram + SSRF-hardened webhooks · dashboard token auth |
| **Record** | `--write out.pcap` while you watch live |

---

## Quick start

```bash
git clone https://github.com/FounderB/FluxTap.git
cd FluxTap
go build -o fluxtap ./cmd/fluxtap

# list interfaces
./fluxtap ifaces

# LIVE capture (needs root or CAP_NET_RAW)
# prints http://127.0.0.1:8090/?token=…  — open that URL
sudo ./fluxtap live -i eth0 --addr :8090

# record while dissecting
sudo ./fluxtap live -i eth0 --write capture.pcap --addr :8090

# Pipe mode — capture as root, dissect as user
sudo tcpdump -i eth0 -U -w - | ./fluxtap live --stdin --addr :8090

# BPF at capture time
sudo ./fluxtap live -i any --bpf "port 53 or port 443"

# offline / demo
./fluxtap gen testdata/demo.pcap --count 500
./fluxtap serve testdata/demo.pcap --replay --addr :8090
./fluxtap parse testdata/demo.pcap --filter "dns or tls"
```

> **Permissions:** live mode shells out to `tcpdump -w -` unless `--kernel`. Prefer:
> ```bash
> sudo tcpdump -i eth0 -U -w - | ./fluxtap live --stdin --addr :8090
> ```
> or `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`

---

## SOC extras (v0.3.3)

| Feature | How |
|---------|-----|
| **Kernel tap** | `sudo fluxtap live -i eth0 --kernel` — AF_PACKET, no tcpdump |
| **Live record** | `--write capture.pcap` — classic PCAP while dissecting |
| **Filter presets** | UI dropdown (DNS / TLS / HTTP / :443 / …) |
| **Session Player** | UI → pick a flow → Play / seek TLS·HTTP·DNS beats |
| **Attack Story** | `/api/story` + UI — findings → cinematic chapters |
| **Telegram alerts** | `--tg-token` + `--tg-chat` (or `FLUXTAP_TG_*`); `--tg-dry` |
| **Webhooks** | `--webhook-url` / `FLUXTAP_WEBHOOK_URL` — HTTPS only; private/metadata blocked |
| **Dashboard auth** | auto token (or `--token` / `FLUXTAP_TOKEN`); `--no-auth` opt-out |

```bash
sudo fluxtap live -i eth0 --kernel --addr :8090 --write capture.pcap \
  --tg-token "$FLUXTAP_TG_TOKEN" --tg-chat "$FLUXTAP_TG_CHAT" \
  --webhook-url "$FLUXTAP_WEBHOOK_URL"
```

Pair with [Tracefuse](https://github.com/FounderB/Tracefuse) for repo/CI supply-chain scans ·
[SignShield](https://github.com/FounderB/SignShield) for what you sign.

## Dashboard features

- **Protocol color coding** — TLS green, HTTP blue, ICMP red, DNS pink…
- **TCP stream collapse** — repeated packets in one flow fold into a single row
- **Interactive IO graph** — click a peak; the packet table jumps to that second
- **Context filters** — right-click IP / port / protocol → *Apply as filter*
- **Pause / Resume** — large button above the table freezes ingestion
- **Follow live / Freeze view** — stop auto-scroll or freeze the table under load
- **Attack Story** — chapters from security findings with jump-to-frame
- **LIVE pill** — top-right status for live vs paused vs file replay
- **Dissection pane** — layer tree + hex dump
- **Security radar** — heuristic alerts as traffic flows

### Display filter examples

```
dns
http and tcp
tls.sni contains google
tcp.port == 443
ip.src == 192.168.1.10
not arp
```

---

## Architecture

```
 Interface / PCAP file / stdin pipe
         │
         ▼
   ┌─────────────┐     WebSocket      ┌────────────────┐
   │  Capture     │ ─────────────────▶│  FluxTap UI     │
   │  (kernel /   │                   │  presets · pause│
   │   tcpdump /  │                   │  streams · IO   │
   │   file / -)  │                   └────────────────┘
   └──────┬──────┘
          ▼
   ┌─────────────┐
   │  Dissector   │  Eth → IP → TCP/UDP → DNS/HTTP/TLS/…
   └──────┬──────┘
          ▼
   Stats · Flows · Security · --write PCAP · Display filter
```

---

## CLI

```
fluxtap live   [-i IFACE] [--bpf EXPR] [--addr :8090] [--write out.pcap] [--promisc]
fluxtap live   --stdin [--addr :8090] [--write out.pcap]
fluxtap serve  <file.pcap> [--addr :8090] [--filter EXPR] [--replay]
fluxtap parse  <file.pcap> [--filter EXPR] [--json out.json] [--csv out.csv]
fluxtap ifaces
fluxtap gen    <out.pcap> [--count N]
fluxtap bench  <file.pcap>
```

```bash
make build && make test
make serve   # demo replay
make live    # sudo live on any
```

---

## License

MIT © FluxTap contributors — see [LICENSE](LICENSE).

<p align="center"><b>Tap the flux. Read the wire.</b></p>
