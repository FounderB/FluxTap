# Changelog

## 0.3.3 — CI harden + CGNAT + WS drop

- CI: `go vet` + `go test -race`
- Webhook SSRF: block CGNAT `100.64.0.0/10` (not covered by `net.IP.IsPrivate`)
- Drop dead WebSocket clients on broadcast write error

## 0.3.2 — Deadlock + webhook pin

- **Live.Close/Next** — no longer hold the mutex across the blocking tcpdump pipe read (Close can kill without deadlock)
- Warn when `--bpf` is set with default kernel capture (BPF is tcpdump-path only)
- HTTP server `ReadHeaderTimeout` / `ReadTimeout` / `IdleTimeout`
- Webhook dial pins the IP validated by `ValidateWebhookURL` (mitigate DNS rebind)

## 0.3.1 — Record + harden

- **`--write out.pcap`** — record classic PCAP while live dissecting
- **Filter presets** in the dashboard toolbar
- Webhook SSRF guard (HTTPS; block private / metadata / redirects to same)
- UI packet detail fetch uses auth token (`apiURL`)
- Brand mark `assets/fluxtap-icon.png` + favicon

## 0.3.0 — Hardening + Attack Story

- **Dashboard auth** — auto token (or `--token` / `FLUXTAP_TOKEN`); `--no-auth` opt-out
- **Webhook alerts** — `--webhook-url` / `FLUXTAP_WEBHOOK_URL` (+ dry-run)
- **Attack Story** — `/api/story` + UI chapters from security findings ↔ sessions
- WS write mutex + origin checks; security headers; async Telegram/webhook notify
- PCAPNG / caplen size caps; safer tcpdump BPF (`--` terminator)
- Telegram token redaction in status/errors; map growth caps on security analyzer
- UI: Follow/Freeze stay; alert merge fix; export respects token

## 0.2.0 — SOC mode

- **Kernel live tap** via `AF_PACKET` (`--kernel`, default) — no tcpdump subprocess
- **Session Player** — TCP/UDP conversation timelines with Play/Seek in the UI
- **Telegram alerts** — security findings → bot (`--tg-token` / `--tg-chat` / `--tg-dry`)
- APIs: `/api/sessions`, `/api/session`, `/api/telegram/test`, WS `sessions` + `alert`

## 0.1.0 — FluxTap

- Live capture via `tcpdump` pipe (`fluxtap live -i …` / `--stdin`)
- Protocol dissectors: Ethernet, VLAN, ARP, IPv4/IPv6, ICMP, TCP/UDP, DNS, DHCP, HTTP, HTTP/2, TLS (SNI + JA3), QUIC
- Realtime WebSocket dashboard with pause/resume
- Protocol row colors, TCP stream collapse, clickable IO graph, context “Apply as filter”
- Display filters, flow tracker, security radar, JSON/CSV export
- MIT license, contributing + security docs
