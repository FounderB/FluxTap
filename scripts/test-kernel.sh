#!/bin/bash
# Kernel-tap smoke test. Run with: sudo -E ./scripts/test-kernel.sh
set -e
cd "$(dirname "$0")/.."
go build -o fluxtap ./cmd/fluxtap
echo BUILT
pkill -9 -f '[.]/fluxtap|fluxtap live' 2>/dev/null || true
sleep 1
./fluxtap live -i lo --kernel --addr :8093 --tg-dry --tg-token x --tg-chat 1 > /tmp/ft-kern-test.log 2>&1 &
sleep 3
echo '---LOG---'
head -20 /tmp/ft-kern-test.log
echo '---STATUS---'
curl -s http://127.0.0.1:8093/api/status
echo
ping -c 10 -i 0.1 127.0.0.1 >/dev/null 2>&1 || true
sleep 1
echo '---AFTER---'
curl -s http://127.0.0.1:8093/api/status
echo
curl -s http://127.0.0.1:8093/api/stats
echo
