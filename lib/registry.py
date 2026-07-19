"""
registry.py — Technique catalog for the shroud payload generator.

All 25 techniques are drawn from the Offensive-Panda "Process Injection
Series" laboratory (https://offensive-panda.github.io/ProcessInjectionTechniques/).

Each entry carries enough metadata to drive `list`, `show`, and the generator.
`implemented=True` means shroud can emit a working C payload for it today;
otherwise `generate` produces a documented scaffold so the technique can be
completed later without changing the CLI.
"""

from collections import OrderedDict

# Canonical MITRE ATT&CK ID for the family
MITRE_FAMILY = "T1055"

# category -> short label shown in the catalog
CATEGORIES = OrderedDict([
    ("classic",    "Classic code injection"),
    ("dll",        "DLL injection"),
    ("hollowing",  "Process hollowing / replacement"),
    ("pe",         "Whole-PE injection"),
    ("apc",        "APC-based injection"),
    ("memory",     "Memory-region abuse"),
    ("ghosting",   "Fileless / section-based spawning"),
    ("hijack",     "Thread / context hijacking"),
    ("stomp",      "Module stomping"),
    ("peb",        "PEB walk / dynamic resolution"),
    ("ntapi",      "NT (undocumented) API"),
    ("abuse",      "Vulnerable-DLL / fork abuse"),
    ("fibers",     "Cooperative threading"),
    ("syscalls",   "Direct / indirect syscalls"),
])

# id -> metadata
TECHNIQUES = OrderedDict([
    ("pe01", dict(
        id="pe01", name="Local Process Shellcode",
        category="classic", subtech="T1055",
        tags=["local", "VirtualAlloc", "CreateThread"],
        implemented=True,
        summary="Allocate RWX (or RW->RX) memory in the current process, copy shellcode, execute via a local thread.",
        flow=[
            "VirtualAlloc executable memory in self",
            "memcpy shellcode into the region",
            "CreateThread on the region (or cast to function pointer)",
        ],
        notes="Simplest possible primitive. Pair with dynamic-api + encryption to defeat static and IAT checks.",
    )),
    ("pe02", dict(
        id="pe02", name="Remote Thread Injection",
        category="classic", subtech="T1055.003",
        tags=["remote", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        implemented=True,
        summary="Open a remote process, allocate+write shellcode, kick it off with CreateRemoteThread.",
        flow=[
            "OpenProcess(target pid) -> PROCESS_ALL_ACCESS",
            "VirtualAllocEx(RWX) in target",
            "WriteProcessMemory(shellcode)",
            "CreateRemoteThread(entry = shellcode base)",
        ],
        notes="Noisy: CreateRemoteThread + cross-process WPM are heavily telemetry'd. Reserve for lab/legacy targets.",
    )),
    ("pe03", dict(
        id="pe03", name="Classic Injection + API Obfuscation",
        category="classic", subtech="T1055.001",
        tags=["remote", "dynamic-api", "iat-bypass"],
        implemented=True,
        summary="PE02 flow but every Win32 API is resolved at runtime via PEB walk + hashing, leaving a clean IAT.",
        flow=[
            "Resolve OpenProcess/VirtualAllocEx/WPM/CreateRemoteThread by hash",
            "Execute the PE02 flow through resolved pointers",
            "Resulting binary imports nothing suspicious",
        ],
        notes="This is PE02 with -e dynamic-api. Generate pe02 and enable the dynamic-api evasion layer.",
    )),
    ("pe04", dict(
        id="pe04", name="VirtualProtect RW->RX Bypass",
        category="classic", subtech="T1055",
        tags=["local", "VirtualProtect", "rwx-avoid"],
        implemented=True,
        summary="Allocate RW, write shellcode, then flip to RX with VirtualProtect only before execution — never RWX.",
        flow=[
            "VirtualAlloc(PAGE_READWRITE)",
            "memcpy shellcode",
            "VirtualProtect(PAGE_EXECUTE_READ)",
            "execute",
        ],
        notes="Avoids the standalone-RWX allocation heuristic that most EDRs flag.",
    )),
    ("pe05", dict(
        id="pe05", name="Classic DLL Injection (LoadLibrary)",
        category="dll", subtech="T1055.001",
        tags=["remote", "LoadLibrary", "dll"],
        implemented=True,
        summary="Force a remote process to LoadLibrary a path you choose by injecting the path and calling LoadLibrary via CreateRemoteThread.",
        flow=[
            "OpenProcess(target)",
            "VirtualAllocEx room for DLL path string",
            "WriteProcessMemory the ASCII path",
            "CreateRemoteThread(LoadLibraryA, arg = path)",
        ],
        notes="Path is written to the target's memory and the DLL hits disk — detectable. Use reflective (pe06) or memory-only techniques for evasion.",
    )),
    ("pe06", dict(
        id="pe06", name="Reflective DLL Injection",
        category="dll", subtech="T1055.001",
        tags=["fileless", "reflective", "manual-map"],
        implemented=False,
        summary="Load a DLL straight from a memory buffer in the target process — a bootstrap stub resolves imports/relocs itself; nothing touches disk.",
        flow=[
            "Map DLL bytes into target process",
            "Bootstrap stub resolves kernel32!LoadLibrary/GetProcAddress",
            "Stub processes import table + relocations",
            "Call DllMain(DLL_PROCESS_ATTACH)",
        ],
        notes="Template scaffold. Pair with pe24/pe25 syscalls and an encrypted payload for EDR evasion.",
    )),
    ("pe07", dict(
        id="pe07", name="Lagos Island — Manual NTDLL Map (unhook)",
        category="ntapi", subtech="T1055.001",
        tags=["unhook", "ntdll", "manual-map"],
        implemented=False,
        summary="Manually map a fresh copy of ntdll.dll from disk without adding it to the PEB module list — used to overwrite EDR hooks with clean .text.",
        flow=[
            "Open \\KnownDlls\\ntdll.dll (or read from disk)",
            "Map section privately",
            "Copy clean .text over the hooked ntdll .text",
        ],
        notes="Equivalent to the unhook evasion layer applied standalone. See -e unhook.",
    )),
    ("pe08", dict(
        id="pe08", name="Process Hollowing",
        category="hollowing", subtech="T1055.012",
        tags=["suspended", "unmap", "hollow"],
        implemented=True,
        summary="Start a legit process suspended, unmap its image, write your PE/shellcode in its place, fix contexts, resume — runs under a trusted identity.",
        flow=[
            "CreateProcess(suspended) a signed binary (e.g. notepad)",
            "Read PEB.ImageBaseAddress of the suspended process",
            "NtUnmapViewOfSection(old image)",
            "Write payload (raw shellcode into hollowed base, or map a full PE)",
            "Update PEB.ImageBaseAddress + thread context Rip/Rcx",
            "ResumeThread",
        ],
        notes="Image path on disk is legitimate; memory is the lie. Strong default for stealthy execution.",
    )),
    ("pe09", dict(
        id="pe09", name="PE Injection (whole image)",
        category="pe", subtech="T1055",
        tags=["remote", "manual-map", "pe"],
        implemented=False,
        summary="Copy an entire portable executable into another process, apply relocations, and execute its entrypoint in the remote context.",
        flow=[
            "VirtualAllocEx in target",
            "Write PE image (headers + sections)",
            "Apply base relocations",
            "Redirect remote thread to AddressOfEntryPoint",
        ],
        notes="Template scaffold. Combine with module stomping (pe16) to land inside an existing legit module.",
    )),
    ("pe10", dict(
        id="pe10", name="AddressOfEntryPoint Injection (WPM magic)",
        category="classic", subtech="T1055",
        tags=["remote", "wpm", "rx-region"],
        implemented=False,
        summary="Reuse the already-RX AddressOfEntryPoint region of the target via WriteProcessMemory — no VirtualAlloc(Ex) or VirtualProtect at all.",
        flow=[
            "OpenProcess(target)",
            "ReadProcessMemory PEB -> ImageBase -> OptionalHeader.AddressOfEntryPoint",
            "WriteProcessMemory(shellcode) directly into the RX entry region",
            "Trigger (or wait for) execution at the entrypoint",
        ],
        notes="Avoids both alloc and protect calls. Detectable via WPM into RX cross-process. Template scaffold.",
    )),
    ("pe11", dict(
        id="pe11", name="APC Injection",
        category="apc", subtech="T1055.004",
        tags=["apc", "queue", "thread"],
        implemented=False,
        summary="Queue a shellcode address as an Asynchronous Procedure Call onto a target thread's APC queue; it runs when the thread enters an alertable wait.",
        flow=[
            "Find a thread in an alertable state (or force one)",
            "VirtualAllocEx + WriteProcessMemory shellcode",
            "QueueUserAPC(shellcode, thread)",
        ],
        notes="Needs an alertable thread. See pe12 (Early Bird) for the lifecycle-start variant. Template scaffold.",
    )),
    ("pe12", dict(
        id="pe12", name="Early Bird APC Injection",
        category="apc", subtech="T1055.004",
        tags=["apc", "suspended", "lifecycle"],
        implemented=False,
        summary="Queue the APC before the process initialises: create suspended, QueueUserAPC on its main thread, resume — payload runs before main runs.",
        flow=[
            "CreateProcess(suspended)",
            "QueueUserAPC(shellcode, main thread)",
            "ResumeThread -> APC fires before the image entry",
        ],
        notes="Runs earlier than hollowing, often before EDR hooks initialise in-process. Template scaffold.",
    )),
    ("pe13", dict(
        id="pe13", name="RWX Hunting + Injection",
        category="memory", subtech="T1055.011",
        tags=["rwx-hunt", "reuse"],
        implemented=False,
        summary="Scan the target's address space for an already-RWX region and write shellcode there — no fresh RWX allocation is ever requested.",
        flow=[
            "VirtualQueryEx walk target VA space",
            "Locate a committed RWX region",
            "WriteProcessMemory shellcode into it",
            "Redirect execution (thread context / APC)",
        ],
        notes="Defeats the 'new RWX allocation' heuristic. Template scaffold.",
    )),
    ("pe14", dict(
        id="pe14", name="Process Ghosting",
        category="ghosting", subtech="T1055",
        tags=["fileless", "pending-delete", "section"],
        implemented=False,
        summary="Create a file, mark it for deletion, map it as a section, close the handle (file vanishes from disk), then spawn a process from the now-fileless image section.",
        flow=[
            "NtCreateFile(payload) + NtSetInformationFile(FileDispositionInfo=DeletePending)",
            "NtCreateSection(SectionHandle, payload file)",
            "Close file handle -> file deleted",
            "NtCreateProcessEx from section",
            "Set up PEB / arguments / thread",
        ],
        notes="Image never exists on disk in a scannable state. Template scaffold.",
    )),
    ("pe15", dict(
        id="pe15", name="Remote Thread Hijacking",
        category="hijack", subtech="T1055",
        tags=["hijack", "context", "suspend"],
        implemented=False,
        summary="Suspend an existing remote thread, rewrite its context (Rip) to point at shellcode, resume — no new thread is ever created.",
        flow=[
            "OpenThread on a running target thread",
            "SuspendThread",
            "GetThreadContext / set Rip = shellcode / SetThreadContext",
            "ResumeThread",
        ],
        notes="No CreateRemoteThread telemetry. Template scaffold.",
    )),
    ("pe16", dict(
        id="pe16", name="Module Stomping",
        category="stomp", subtech="T1055.002",
        tags=["module", "stomp", "legit"],
        implemented=False,
        summary="Load a legitimate DLL into the target, then overwrite its .text with shellcode — execution appears to come from a trusted, signed module.",
        flow=[
            "Force-load a legit DLL (LoadLibrary via remote thread / manual map)",
            "Find its base + .text bounds",
            "VirtualProtect(.text -> RW) and overwrite with shellcode",
            "VirtualProtect back to RX, redirect execution",
        ],
        notes="Defeats 'unbacked/anonymous executable memory' checks. Template scaffold.",
    )),
    ("pe17", dict(
        id="pe17", name="PEB Walk Injection",
        category="peb", subtech="T1055",
        tags=["peb", "dynamic-resolve"],
        implemented=False,
        summary="Walk the PEB to find kernel32 and resolve VirtualAllocEx/WPM/CreateRemoteThread at runtime — no static imports to the suspicious APIs.",
        flow=[
            "PEB -> Ldr -> InLoadOrderModuleList -> find kernel32 base",
            "Walk export table, resolve each API by name",
            "Run the PE02 flow through the resolved pointers",
        ],
        notes="This is the dynamic-api evasion layer applied to a remote inject. Generate pe02 with -e dynamic-api.",
    )),
    ("pe18", dict(
        id="pe18", name="PEB Walk + API Obfuscation",
        category="peb", subtech="T1055",
        tags=["peb", "dynamic-api", "layered"],
        implemented=False,
        summary="PE17 plus full call-site obfuscation — defeats both static import analysis and naive dynamic monitoring in one go.",
        flow=[
            "PEB walk to resolve APIs (pe17)",
            "Layer call-site obfuscation / indirect invocation",
            "Execute remote inject",
        ],
        notes="pe02 with -e dynamic-api plus additional indirection. Template scaffold.",
    )),
    ("pe19", dict(
        id="pe19", name="NtCreateSection + NtMapViewOfSection",
        category="ntapi", subtech="T1055",
        tags=["section", "ntapi", "shared-memory"],
        implemented=False,
        summary="Create a shared section, map it RWX into both processes, write shellcode locally, execute it remotely — no WriteProcessMemory cross-process write.",
        flow=[
            "NtCreateSection(RWX, size) in self",
            "NtMapViewOfSection(self, RW)",
            "NtMapViewOfSection(target, RX) via duplicate handle",
            "memcpy shellcode into local view",
            "NtCreateThreadEx on the remote view",
        ],
        notes="No WPM call at all — a classic telemetry gap. Template scaffold.",
    )),
    ("pe20", dict(
        id="pe20", name="Mokingjay",
        category="abuse", subtech="T1055",
        tags=["rwx-abuse", "vulnerable-dll"],
        implemented=False,
        summary="Abuse an already-RWX region shipped inside a vulnerable DLL (e.g. msys-2.0.dll) to host shellcode — no suspicious allocation by your code.",
        flow=[
            "Load the vulnerable DLL (locally or remotely)",
            "Locate its shipped RWX section",
            "Write shellcode into the existing RWX region",
            "Execute (self-inject or remote-inject variant)",
        ],
        notes="Exploits third-party RWX slack. Template scaffold.",
    )),
    ("pe21", dict(
        id="pe21", name="Fork API Injection (Dirty Vanity)",
        category="abuse", subtech="T1055",
        tags=["fork", "rtlcreateprocessreflection"],
        implemented=False,
        summary="Write shellcode into your own process, then fork it with the undocumented RtlCreateProcessReflection — the forked copy runs your shellcode under a fresh PID.",
        flow=[
            "Stage shellcode in self",
            "RtlCreateProcessReflection -> child is a copy with shellcode already resident",
            "Child executes the staged code",
        ],
        notes="Evades injection-focused hooks because nothing is written cross-process. Template scaffold.",
    )),
    ("pe22", dict(
        id="pe22", name="Injection via Fibers",
        category="fibers", subtech="T1055",
        tags=["fibers", "cooperative"],
        implemented=False,
        summary="Convert the thread to a fiber, create a fiber whose entry is shellcode, and switch to it — no new OS thread is ever created.",
        flow=[
            "ConvertThreadToFiber",
            "CreateFiber(entry = shellcode)",
            "SwitchToFiber -> runs shellcode in user-mode cooperative context",
        ],
        notes="No thread-creation event. Template scaffold.",
    )),
    ("pe23", dict(
        id="pe23", name="NT API Injection",
        category="ntapi", subtech="T1055.001",
        tags=["ntapi", "undocumented", "ntcreateprocessex"],
        implemented=True,
        summary="Remote injection done entirely with undocumented ntdll APIs (NtOpenProcess / NtAllocateVirtualMemory / NtWriteVirtualMemory / NtCreateThreadEx) — under the Win32 layer where many hooks sit.",
        flow=[
            "NtOpenProcess(target)",
            "NtAllocateVirtualMemory(RW or RWX) in target",
            "NtWriteVirtualMemory(shellcode)",
            "NtProtectVirtualMemory(->RX) if needed",
            "NtCreateThreadEx(shellcode)",
            "NtWaitForSingleObject(thread)",
        ],
        notes="Skips kernel32 entirely. Use -e syscalls=direct/indirect to go one layer deeper than even ntdll.",
    )),
    ("pe24", dict(
        id="pe24", name="Direct Syscalls",
        category="syscalls", subtech="T1055.004",
        tags=["direct-syscall", "hook-bypass", "kernel"],
        implemented=True,
        summary="Invoke the syscall instruction directly from a stub in your own module — execution transitions to the kernel without ever entering ntdll's hooked stubs.",
        flow=[
            "Resolve syscall SSN + syscall numbers for the Nt* routines you need",
            "Emit a stub: mov r10,rcx; mov eax,<ssn>; syscall; ret",
            "Drive the PE23 flow through the stubs",
        ],
        notes="Bypasses all userland hooks but the 'syscall from non-ntdll memory' return address is itself a detection — see pe25.",
    )),
    ("pe25", dict(
        id="pe25", name="Indirect Syscalls",
        category="syscalls", subtech="T1055.004",
        tags=["indirect-syscall", "ntdll-origin", "hook-bypass"],
        implemented=True,
        summary="Like pe24, but jump to the literal `syscall` instruction located inside ntdll.dll — the return address and stack originate from ntdll, so it looks like a legitimate kernel32->ntdll transition.",
        flow=[
            "Resolve SSNs (as pe24)",
            "Locate a `syscall; ret` gadget inside ntdll .text",
            "Stub: mov r10,rcx; mov eax,<ssn>; jmp <ntdll syscall gadget>",
            "Drive the PE23 flow; every transition originates in ntdll memory",
        ],
        notes="Strongest userland evasion in the series. Still visible to kernel callbacks (ETW-TI, minifilters) — pair with sleep + encryption for memory scanners.",
    )),
    ("pe26", dict(
        id="pe26", name="Modern Implant Loader",
        category="classic", subtech="T1055",
        tags=["implant", "aes", "stomp", "callbacks", "layered"],
        implemented=True,
        summary="shroud's purpose-built modern loader: decrypt-at-rest (AES-256-CBC), stage into backed memory via module stomping, and execute through a callback API — on top of dynamic-API/FNV resolution, AMSI/ETW patching and KnownDlls unhooking. Composes the full evasion stack rather than a single primitive.",
        flow=[
            "evasion.init: resolve APIs via PEB/FNV, patch AMSI/ETW, unhook ntdll (KnownDlls)",
            "AES-256-CBC decrypt the staged payload in place",
            "Stage: module-stomp into a legit DLL's .text (backed memory) [if -e stomp]",
            "Execute via CreateTimerQueueTimer (no CreateThread) [if -e callbacks]",
        ],
        notes="The loader to test against a modern EDR. It is NOT a single injection trick — "
              "it is the composed stack. Add/remove layers with -e to fit the target's sensors.",
    )),
])


def get(tid):
    return TECHNIQUES.get(tid.lower())


def all_techniques():
    return list(TECHNIQUES.values())


def implemented():
    return [t for t in TECHNIQUES.values() if t["implemented"]]


def by_category():
    groups = OrderedDict((c, []) for c in CATEGORIES)
    for t in TECHNIQUES.values():
        groups[t["category"]].append(t)
    return groups


def resolve(query):
    """Accept 'pe08', 'PE 08', '8', '08', or a slug/name substring."""
    q = query.strip().lower().replace(" ", "").replace("-", "")
    if q in TECHNIQUES:
        return TECHNIQUES[q]
    if q.isdigit():
        n = int(q)
        if 1 <= n <= 25:
            return TECHNIQUES["pe%02d" % n]
    for t in TECHNIQUES.values():
        slug = t["name"].lower().replace(" ", "-")
        if q in slug or q in t["id"]:
            return t
    return None
