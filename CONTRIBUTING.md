# Contributing to shroud

Thanks for your interest in improving shroud. Contributions that extend
**coverage** (more techniques implemented, more evasion layers) or **quality**
(cleaner C, better opsec, tests) are very welcome.

## Before you contribute

- **Authorized use only.** PRs must not introduce features whose primary purpose
  is to harm systems the operator does not control. This is a research /
  authorized-pentest tool.
- Open an issue first for non-trivial changes, so we can align on design.

## Project layout

```
shroud            CLI (argparse) — entrypoint
lib/
  registry.py     all techniques (metadata: id, name, category, MITRE, flow)
  cstubs.py       embedded C source for every evasion primitive
  evasion.py      composable evasion layers + dynamic-API remap + shroud_exec/stage
  techniques.py   per-technique C bodies (pe01..pe26) + scaffolder
  shellcode.py    shellcode ingest + AES/RC4/XOR + C-array formatting
  payload.py      assembles a technique + evasion stack into a buildable project
  builder.py      x86_64-w64-mingw32-gcc pipeline
```

## Adding a technique

1. Add an entry to `lib/registry.py` (use an existing one as a template) with
   `implemented=True`.
2. Write a generator in `lib/techniques.py` returning a dict:
   ```python
   def peNN(params):
       return dict(
           api_names=[...],          # Win32 names you call (for dynamic-api)
           needs_target=False,        # remote inject -> True (needs --process)
           needs_host=False,          # hollowing/ghosting -> True (needs --host)
           needs_dll=False,           # pe05-style -> True (needs --dll)
           needs_syscalls=False,      # uses the syscall stubs
           globals="",                # extra top-level C declarations
           main=r""" ... C statements ... """,
           note="opsec note for the README",
       )
   ```
   and register it in `IMPLEMENTED`.
3. List any new Win32 API in `evasion.SIGNATURES` so `-e dynamic-api` can remap it.
4. If you call Win32 APIs in helper code, remember the **ordering rule**: code
   that uses a remapped name must live in the *post-macro* half (see
   `evasion.assemble`).

## Adding an evasion layer

1. Add the C to `lib/cstubs.py` as a new string constant.
2. Wire it in `evasion.assemble()` (and add it to `evasion.OPTIONS` so the CLI
   lists it).
3. If the C uses Win32 names, place it in the `post` half (after the dynamic-api
   `#define`s).

## Code quality

- The generated C must compile cleanly under `x86_64-w64-mingw32-gcc` with
  `-Wall -O2 -std=gnu11`. Test with `./shroud generate <id> -o /tmp/x` and check
  the build succeeds.
- Keep the C correct and readable — it is what readers will study.
- Match the existing Python style (no type annotations on trivial helpers,
  short focused functions, docstrings on modules).

## Testing

There is no formal test suite yet. Before a PR:

```bash
./shroud authorize < /dev/null
# build every implemented technique + a representative evasion matrix:
for t in pe01 pe02 pe04 pe05 pe08 pe23 pe24 pe25 pe26; do
  ./shroud generate $t -o /tmp/q_$t 2>&1 | grep -q "built ->" \
    && echo "$t OK" || echo "$t FAIL"
done
./shroud generate pe26 -e aes,stomp,callbacks,dynamic-api,etw,amsi,unhook-kd -o /tmp/q_full
```

All of the above should report `OK` / a successful build.

## Commit messages

Short imperative summary, optional body. Example:

```
add module-stomping evasion layer (backed-memory staging)
```

## Licensing

By contributing you agree your contributions are licensed under the project's
[MIT License](LICENSE).
