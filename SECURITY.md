# Security Policy

## Supported versions

The `main` branch is the only supported line for security fixes.

## Reporting a vulnerability

If you find a bug that can crash FluxTap on malicious PCAP input, leak memory
unbounded, or escalate privileges via crafted packets:

1. **Do not** open a public issue with a weaponized PoC.
2. Email maintainers privately or open a draft security advisory on GitHub.
3. Include: FluxTap version / commit, OS, capture source (file vs live), and a
   minimal PCAP or hex dump that triggers the issue.

We aim to acknowledge reports within a few days.

## Hardening notes for operators

- **Dashboard auth is on by default.** FluxTap prints a URL with `?token=…`.
  Pass `--token` / `FLUXTAP_TOKEN` to set it, or `--no-auth` only on trusted hosts.
- API + WebSocket require `Authorization: Bearer <token>` or `?token=`.
- WebSocket `Origin` is restricted to the dashboard host / localhost.
- Run live capture with the **least privilege** that still works (`CAP_NET_RAW`
  / `setcap` is preferable to an all-root shell forever). Prefer
  `sudo tcpdump … | fluxtap live --stdin` so the UI stays unprivileged.
- The dashboard binds to `127.0.0.1` when you pass `:port`. Binding `0.0.0.0`
  prints a warning — do not expose it to untrusted networks.
- Telegram / webhook errors are redacted so bot tokens never appear in `/api/status`.
- PCAPNG block sizes and classic `caplen` are capped (16 MiB) to resist OOM.
- BPF filters are passed as a single argument after `--` to tcpdump (no argv injection).
- Display filters and BPF filters are different: BPF drops at capture time; display
  filters only hide rows in the UI/engine store.

## Pairing with Tracefuse

For repo/CI supply-chain checks (secrets, Dockerfile smells, Actions misuse),
use [Tracefuse](https://github.com/FounderB/Tracefuse) alongside FluxTap:
FluxTap watches the wire; Tracefuse watches what you ship.
