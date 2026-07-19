# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-19

### Added
- **`pe26` — Modern Implant Loader**: purpose-built technique that composes
  the full evasion stack (decrypt-at-rest → module-stomp staging → callback
  execution).
- **`aes` evasion layer**: AES-256-CBC (PKCS7) encrypt-at-rest. Verified
  against pycryptodome (FIPS-197 vector + randomized round-trips). Embedded
  C decrypt is byte-identical to the Python encrypt.
- **`stomp` evasion layer**: module stomping — stages the payload inside a
  legitimate module's `.text` so it is file-backed and RX (defeats
  unbacked-memory checks). `--stomp-dll` selects the host DLL.
- **`callbacks` evasion layer**: executes the payload via
  `CreateTimerQueueTimer` instead of `CreateThread` (no thread-creation event).
- **`unhook-kd` evasion layer**: overwrites ntdll `.text` from
  `\KnownDlls\ntdll.dll` — no disk read, stealthier than `unhook`.
- **`--hash`**: switch the dynamic-API hash between `fnv` (FNV-1a, default —
  less signatured) and `ror13` (legacy).
- `dynamic-api` now remaps **all** known Win32 signatures, not just a
  technique's own calls.
- AMSI/ETW patching is hash-resolved when dynamic-api is on (no plaintext
  `AmsiScanBuffer` / `EtwEventWrite` strings).
- Encrypting `sleep` layer: flips the region to RW and XOR-scrambles it while idle.
- `--aes-key` CLI option.

### Changed
- `evasion.assemble()` splits generated C into `code_pre` / `macros` /
  `code_post` so every remapped-name reference resolves through the resolved
  pointer (fixes IAT leaks of helper APIs).

### Verified
- A `pe26 -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd` build has the
  full injection-indicator triad (`OpenProcess`, `VirtualAllocEx`,
  `WriteProcessMemory`, `CreateRemoteThread`, `CreateThread`, `LoadLibraryA`,
  `GetProcAddress`, `CreateTimerQueueTimer`) **absent from the IAT**, no
  plaintext AMSI/ETW strings, and an AES-encrypted payload (0 msfvenom-prologue
  matches).

## [0.1.0] - 2026-07-18

### Added
- Initial release.
- Catalog of all 25 Offensive-Panda Process Injection techniques; 8 fully
  code-generated (`pe01`, `pe02`, `pe04`, `pe05`, `pe08`, `pe23`, `pe24`,
  `pe25`), the remainder emit documented scaffolds.
- Composable evasion layers: `dynamic-api` (PEB walk + hash), `xor`, `rc4`,
  `amsi`, `etw`, `unhook`, `sleep`.
- Direct (`pe24`) and indirect (`pe25`) syscalls with Hell's Gate SSN resolution.
- mingw-w64 cross-compile pipeline producing real Windows PE/DLL output.
- Authorization gate (`./shroud authorize`), `list` / `show` / `generate` /
  `build` commands.
