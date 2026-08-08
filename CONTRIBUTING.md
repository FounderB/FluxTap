# Contributing to FluxTap

Thanks for helping make the dissector sharper.

## Ground rules

1. Keep dissectors **allocation-conscious** — live capture burns CPU for breakfast.
2. Prefer small, reviewable PRs (one protocol or one UX slice).
3. Never commit captures that contain credentials or private traffic.

## Setup

```bash
git clone https://github.com/FounderB/FluxTap.git
cd fluxtap
go test ./...
go build -o fluxtap ./cmd/fluxtap
```

Live capture needs `tcpdump` and privileges (`sudo` or capabilities).

## Adding a protocol

1. Add `dissectXYZ` under `internal/decode/`.
2. Hook it from TCP/UDP app dispatch (`tcpudp.go`) or EtherType switch.
3. Set `f.Protocol`, `f.Info`, and useful `f.Meta` keys for filters.
4. Extend `testdata` via `fluxtap gen` or a tiny crafted frame in tests.
5. Document filter fields in the README if they are user-facing.

## UI changes

The dashboard lives in `internal/web/static/index.html` (embedded via `go:embed`).
Keep the first viewport focused: capture controls, table, dissection — no dashboard soup.

## Commit style

Short imperative subject, why in the body when needed:

```
decode: add MQTT CONNECT/PUBLISH dissector

Enables filtering mqtt.topic in live MQTT lab captures.
```

## Code of conduct

Be respectful. Disagreements about TLV parsers are fine; personal attacks are not.
