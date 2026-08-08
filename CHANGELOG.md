# Changelog

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
