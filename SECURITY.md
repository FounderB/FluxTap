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

- Run live capture with the **least privilege** that still works (`setcap` on
  `tcpdump` is preferable to an all-root shell forever).
- The dashboard binds to `127.0.0.1` by default when you pass `:port` — do not
  expose it to untrusted networks without auth in front.
- Display filters and BPF filters are different: BPF drops at capture time; display
  filters only hide rows in the UI/engine store.
