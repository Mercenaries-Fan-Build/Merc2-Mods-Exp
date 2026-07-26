/* lua_bridge.c — exposes Mercenaries 2's statically-linked Lua 5.1.2
 * runtime via a localhost TCP REPL, allowing arbitrary Lua chunks to
 * be executed against the live engine state.
 *
 * Ported from Merc2Reborn's Merc2Fix (https://github.com/loganw234/Mercenaries2)
 * to the mercs2-qol-mods SDK
 * (https://github.com/Mercenaries-Fan-Build/mercs2-qol-mods).
 *
 * Pairs with the companion `multiplayer-restore/` mod in this same
 * repo, but is independent: enable one or both via the modkit.
 *
 * What it does:
 *   * Detects which Mercenaries2.exe build is running (canonical retail
 *     vs the mercs2-securom-bypass-patched form) via an FNV-1a
 *     fingerprint, and selects the matching per-binary RVA table.
 *   * MinHook-detours: the shared no-op stub, luaB_type, and
 *     CreateTextWidget. These together capture the live lua_State on
 *     any Lua dispatch and serve as pump sources for queued chunks.
 *   * Hijacks `_G.print` / `_G.next` / `_G.tostring` at registration
 *     time by patching the engine's luaL_Reg table BEFORE the real
 *     luaL_register sees it. The hijacked functions drain the chunk
 *     queue whenever scripts call them — gives high-frequency pump
 *     sources without needing more MinHook detours.
 *   * Phase 3 executor: pushes a hand-crafted TString onto the engine's
 *     Lua stack, calls luaB_loadstring + luaB_pcall directly to
 *     compile + run a chunk, formats the return values, ships them
 *     back over the REPL socket.
 *
 * Listens on 127.0.0.1:27050 by default. Configurable via lua_bridge.ini.
 * Use tools/lua_repl.py or tools/lua_console.py from the parent project
 * for a client.
 *
 * Reverse-engineering notes — verified gotchas baked into this code:
 *   * TValue is 8 bytes here (Pandemic built with lua_Number = float),
 *     not the stock 16. Layout: Value at +0, int tt at +4.
 *   * lua_State packs CommonHeader tightly: L->top at +0x08, L->base
 *     at +0x0C (vs stock +0x0C and +0x10).
 *   * Lua's debug library is stripped; no lua_sethook. Pump from the
 *     captured dispatch sites instead.
 *   * luaB_pcall is non-stock: returns stack-shaped junk at slot 0
 *     instead of a clean bool status. Display-layer handles this.
 *   * The "noop stub" is shared across ~60 names (print, SendEvent_*,
 *     music stubs, _SummonEd, ...). Hooking it captures L from any of
 *     them. C++ engine code also routes through here with `this` in
 *     arg0 — LooksLikeLuaState filters those out.
 *
 * Full background, design rationale, and incident history:
 *   https://github.com/loganw234/Mercenaries2/blob/main/Merc2Fix/dllmain.cpp
 *   https://github.com/loganw234/Mercenaries2/blob/main/tools/lua_api_findings.md
 *   https://github.com/loganw234/Mercenaries2/blob/main/tools/engine_api.md
 */

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <bcrypt.h>       /* SHA-1 for the WebSocket handshake */
#include <wincrypt.h>     /* CryptBinaryToStringA — base64 for the same */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "m2.h"

/* Compatibility shim: the upstream Merc2Fix uses MSVC's safe-string
 * extensions (_snprintf_s with _TRUNCATE, strncpy_s, strcpy_s).
 * MinGW doesn't ship those; map them to POSIX snprintf / strncpy
 * with manual NUL-termination so the same source compiles under both
 * toolchains. Link with -lws2_32 (see Makefile). */
#ifdef _MSC_VER
  /* MSVC: native safe-string, SEH, and TLS extensions. */
  #define SEH_TRY            __try {
  #define SEH_CATCH_AV(rv)   } __except (EXCEPTION_EXECUTE_HANDLER) { return (rv); }
  #define MOD_THREAD         __declspec(thread)
#else
  /* MinGW: substitute POSIX where possible, skip SEH (no support on
   * GCC x86 — if SafeCallLuaCFunction's target AVs, the game crashes
   * instead of being caught here). _TRUNCATE is already defined by
   * MinGW's _mingw.h as ((size_t)-1); reuse it. */
  #define _snprintf_s(buf, sz, _trunc, ...) snprintf((buf), (sz), __VA_ARGS__)
  #define strncpy_s(dst, dst_sz, src, count) \
      (strncpy((dst), (src), (count)), (dst)[(dst_sz) - 1] = 0, 0)
  #define strcpy_s(dst, dst_sz, src) \
      (strncpy((dst), (src), (dst_sz) - 1), (dst)[(dst_sz) - 1] = 0, 0)
  #define SEH_TRY            do {
  #define SEH_CATCH_AV(rv)   } while (0)
  #define MOD_THREAD         __thread
#endif

/* ======================================================================== *
 * Status: PROOF OF CONCEPT — this port has NOT been built or test-run
 * against the mercs2-qol-mods framework. Drafted without the SDK build
 * environment set up locally. See README.md for what is and isn't
 * validated.
 *
 * The architecture is proven: the upstream Merc2Fix.asi runs cleanly
 * against a mercs2-securom-bypass-patched binary loaded by pmc_bb.dll,
 * with the bridge fully operational. So the surface area below is
 * known-correct; what's untested is the per-SDK-helper mapping
 * (m2_logf vs Log, m2_hook_attach vs MH_CreateHook, m2_ini_parse vs
 * a custom parser) — likely needs adjustments to match this SDK's
 * exact signatures.
 *
 * ONE KNOWN COMPLICATION: the luaL_register hijack requires a "naked"
 * detour to preserve a non-standard register-arg ABI (ECX=L, EAX=libname,
 * stack=table). On MSVC this is a one-paragraph __declspec(naked)
 * function. On the GCC/MinGW toolchain the SDK uses, x86 doesn't
 * support __attribute__((naked)), so this needs to live in a separate
 * .S file with global assembly. The DetourLuaLRegister section below
 * has the MSVC source as a comment block plus the GCC translation
 * sketch. Without this hook the bridge still works — we lose the
 * print/next/tostring hijack and the registration-table dump, but
 * the executor + the other detours keep functioning. Easier to ship
 * v1 without it and add later.
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * Per-binary RVA tables and fingerprint-based selection.
 *
 * The Mercenaries 2 binary ships in multiple flavors. The Lua bridge
 * needs per-binary addresses for the C functions it hooks. We compute
 * an FNV-1a fingerprint over a 4 KB region of .text at startup and
 * select the matching table.
 *
 * To add a new binary: run the static analyzers from the upstream repo
 * (tools/find_lua_print.py, tools/resolve_lua_api.py) against the new
 * exe to derive RVAs; compute the FNV-1a hash of 4 KB at RVA 0x11000
 * to get the fingerprint; add another LuaRvaSet and switch case below.
 * ------------------------------------------------------------------------ */

typedef struct LuaRvaSet {
    const char* label;
    DWORD noop_stub;         /* shared no-op stub: print, SendEvent_*, music, etc. */
    DWORD luaB_type;
    DWORD luaB_loadstring;
    DWORD luaB_pcall;
    DWORD CreateTextWidget;
    DWORD luaL_register;
} LuaRvaSet;

static const LuaRvaSet kRvas_v1_1 = {
    "v1.1 (archive.org English retail)",
    0x002AEF90, /* noop_stub        VA 0x006AEF90 */
    0x00460E90, /* luaB_type        VA 0x00860E90 */
    0x004611E0, /* luaB_loadstring  VA 0x008611E0 (real __cdecl) */
    0x00461810, /* luaB_pcall       VA 0x00861810 (real __cdecl) */
    0x001B7D30, /* CreateTextWidget VA 0x005B7D30 (__fastcall engine binding) */
    0x0045F720, /* luaL_register    VA 0x0085F720 (custom register ABI) */
};

static const LuaRvaSet kRvas_v1_1_bypass = {
    "v1.1 + mercs2-securom-bypass (cracked retail)",
    0x002D5640, /* noop_stub        (moved +0x266B0 vs v1.1) */
    0x00460C70, /* luaB_type        (shifted -0x220) */
    0x00460FC0, /* luaB_loadstring  (shifted -0x220) */
    0x004615F0, /* luaB_pcall       (shifted -0x220) */
    0x001B7D40, /* CreateTextWidget (shifted +0x10) */
    0x0045F500, /* luaL_register    (shifted -0x220) */
};

static const LuaRvaSet* g_rvas = &kRvas_v1_1;

/* FNV-1a 64-bit. Hashes are stable, deterministic, no crypto deps. */
static uint64_t Fnv1a64(const void* data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ULL;
    const uint8_t* b = (const uint8_t*)data;
    for (size_t i = 0; i < len; ++i) {
        h ^= b[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

/* ------------------------------------------------------------------------ *
 * Memory-safety helpers
 * ------------------------------------------------------------------------ */
static BOOL SafeProbe(const void* p, size_t bytes) {
    const char* addr;
    const char* end;
    const DWORD readable =
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const DWORD unreadable = PAGE_NOACCESS | PAGE_GUARD;
    MEMORY_BASIC_INFORMATION mbi;

    if (!p || (uintptr_t)p < 0x10000) return FALSE;
    addr = (const char*)p;
    end  = addr + bytes;
    while (addr < end) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return FALSE;
        if (mbi.State != MEM_COMMIT) return FALSE;
        if (mbi.Protect & unreadable) return FALSE;
        if (!(mbi.Protect & readable)) return FALSE;
        addr = (const char*)mbi.BaseAddress + mbi.RegionSize;
    }
    return TRUE;
}

/* ------------------------------------------------------------------------ *
 * Layout constants — verified against the engine
 * ------------------------------------------------------------------------ */
#define LUA_OFF_TOP       0x08
#define LUA_OFF_BASE      0x0C
#define TVALUE_SIZE       0x08
#define TVALUE_TT_OFFSET  0x04

#define LUA_TNIL          0
#define LUA_TBOOLEAN      1
#define LUA_TNUMBER       3
#define LUA_TSTRING       4
#define LUA_TTABLE        5
#define LUA_TFUNCTION     6
#define LUA_TTHREAD       8

/* Identifies a lua_State by tt-byte at +4 (LUA_TTHREAD = 8) plus
 * structural checks. Filters out C++ this-pointers that the shared
 * noop stub gets called with from engine code. */
static BOOL LooksLikeLuaState(void* L) {
    uint8_t L_tt;
    void *top, *base, *l_G;
    uintptr_t t, b;

    if (!SafeProbe(L, 0x18)) return FALSE;
    L_tt = *(uint8_t*)((char*)L + 4);
    if (L_tt != LUA_TTHREAD) return FALSE;

    top  = *(void**)((char*)L + LUA_OFF_TOP);
    base = *(void**)((char*)L + LUA_OFF_BASE);
    l_G  = *(void**)((char*)L + 0x10);

    if (!SafeProbe(base, 16) || !SafeProbe(top, 4) || !SafeProbe(l_G, 4)) return FALSE;
    t = (uintptr_t)top;
    b = (uintptr_t)base;
    if ((t | b) & 0x3) return FALSE;
    if (t < b) return FALSE;
    if (t - b > 0x10000) return FALSE;
    return TRUE;
}

/* ------------------------------------------------------------------------ *
 * Fingerprint + RVA selection
 * ------------------------------------------------------------------------ */
static const LuaRvaSet* SelectRvas(HMODULE mod) {
    BYTE* base = (BYTE*)mod;
    uint64_t fp;

    if (!SafeProbe(base + 0x11000, 0x1000)) {
        m2_logf("[!] lua_bridge: SelectRvas: 4KB at RVA 0x11000 unreadable; default v1.1");
        return &kRvas_v1_1;
    }
    fp = Fnv1a64(base + 0x11000, 0x1000);
    /* Split into two 32-bit halves: m2_logf goes through wvsprintfA, which
     * supports neither %ll nor a width specifier and silently emitted the
     * literal text "0xlX" instead of the hash. That mattered — the header
     * comment above tells you to read this value off the log to add support
     * for a new binary, and it never once printed. */
    m2_logf("[*] lua_bridge: binary fingerprint = 0x%08lX%08lX",
            (unsigned long)(fp >> 32), (unsigned long)(fp & 0xFFFFFFFFu));

    switch (fp) {
        case 0xB79E4DD22A4BFCB3ULL:
            m2_logf("[*] lua_bridge: matched %s", kRvas_v1_1.label);
            return &kRvas_v1_1;
        case 0x1942B494FF9F4DB3ULL:
            m2_logf("[*] lua_bridge: matched %s", kRvas_v1_1_bypass.label);
            return &kRvas_v1_1_bypass;
        default:
            m2_logf("[!] lua_bridge: unknown binary (fp=0x%016llX); defaulting to v1.1 + relying on prologue validator", fp);
            return &kRvas_v1_1;
    }
}

/* ------------------------------------------------------------------------ *
 * Hook-target validator — refuses to install a hook if the bytes at the
 * target don't look right for the kind of code we expect. Prevents CTDs
 * when our RVA table doesn't match this binary.
 * ------------------------------------------------------------------------ */
typedef enum HookKind { HOOK_NOOP_STUB, HOOK_NORMAL_FUNC } HookKind;

static BOOL ValidateHookTarget(const void* p, HookKind kind) {
    const uint8_t* b;
    if (!SafeProbe(p, 8)) return FALSE;
    b = (const uint8_t*)p;
    if (kind == HOOK_NOOP_STUB) {
        return b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0xC3;  /* xor eax,eax; ret */
    }
    /* HOOK_NORMAL_FUNC: any common x86 prologue */
    if (b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) return TRUE;
    if (b[0] == 0x53) return TRUE;
    if (b[0] == 0x56) return TRUE;
    if (b[0] == 0x57) return TRUE;
    if (b[0] == 0x83 && b[1] == 0xEC) return TRUE;
    if (b[0] == 0x81 && b[1] == 0xEC) return TRUE;
    if (b[0] == 0x6A) return TRUE;
    if (b[0] == 0x68) return TRUE;
    if (b[0] == 0x8B && b[1] == 0xFF) return TRUE;
    if (b[0] == 0x8B && (b[1] & 0xC0) == 0xC0) return TRUE;
    return FALSE;
}

/* ------------------------------------------------------------------------ *
 * Calling-convention typedefs
 * ------------------------------------------------------------------------ */
typedef int  (__cdecl*   lua_CFunction_t)(void* L);
typedef int  (__fastcall* pandemic_CFunction_t)(void* L, void* edx);

/* ------------------------------------------------------------------------ *
 * Crafted TString for pushing arbitrary source onto the Lua stack.
 *
 * Layout matches stock Lua 5.1.2 TString (verified — Pandemic packed
 * TValue but NOT TString). FIXEDBIT in `marked` tells the GC to leave
 * us alone.
 * ------------------------------------------------------------------------ */
#pragma pack(push, 4)
typedef struct FixedTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[1048576];  /* 1 MB — sized to absorb any realistic chunk */
} FixedTString;
#pragma pack(pop)
static FixedTString g_chunkSource;

/* Second source buffer, used only by Loader.LoadFile. LoadFile runs a chunk
 * from inside a C function that is itself executing out of g_chunkSource, so
 * sharing one buffer would clobber the caller's source mid-flight. */
static FixedTString g_loadFileChunkSource;
static int          g_loadFileDepth = 0;

static void InitChunkSource(void) {
    memset(&g_chunkSource, 0, sizeof(g_chunkSource));
    g_chunkSource.tt     = (uint8_t)LUA_TSTRING;
    g_chunkSource.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_chunkSource.hash   = 0xDEADBEEF;

    memset(&g_loadFileChunkSource, 0, sizeof(g_loadFileChunkSource));
    g_loadFileChunkSource.tt     = (uint8_t)LUA_TSTRING;
    g_loadFileChunkSource.marked = 0x20 | 0x01;
    g_loadFileChunkSource.hash   = 0x10ADF11E;  /* "loadfile"-ish, arbitrary */
}

/* Fixed-size TString for Loader.GetKeyboardState()'s return value.
 * 256 bytes, one per VK code; high bit set = currently pressed.
 *
 * Two documented caveats:
 *   1. Static buffer, reused per call. `local a = Loader.GetKeyboardState();
 *      Loader.GetKeyboardState()` — `a` now reflects the second call's
 *      contents because both references point at this same struct.
 *      Copy bytes out if you need to compare two snapshots.
 *   2. Not interned with the engine's string table. `s == "..."` will
 *      always be false regardless of content. Decode byte-wise with
 *      string.byte(s, vk+1). */
#pragma pack(push, 4)
typedef struct KeyboardStateTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[256];
} KeyboardStateTString;
#pragma pack(pop)
static KeyboardStateTString g_kbStateTString;

static void InitKeyboardStateTString(void) {
    memset(&g_kbStateTString, 0, sizeof(g_kbStateTString));
    g_kbStateTString.tt     = (uint8_t)LUA_TSTRING;
    g_kbStateTString.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_kbStateTString.hash   = 0x4B425953;    /* "KBYS" — arbitrary, unused unless interned */
    g_kbStateTString.len    = 256;
}

/* Companion TString for Loader.PopKeyEvents(). Same buffer-reuse
 * semantics as g_kbStateTString — the returned string is a private,
 * per-call view; consume immediately, don't hold across another pop. */
#define KEYEVENT_BUFFER_SIZE 128
#pragma pack(push, 4)
typedef struct KeyEventsTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[KEYEVENT_BUFFER_SIZE];
} KeyEventsTString;
#pragma pack(pop)
static KeyEventsTString g_keyEventsTString;

static void InitKeyEventsTString(void) {
    memset(&g_keyEventsTString, 0, sizeof(g_keyEventsTString));
    g_keyEventsTString.tt     = (uint8_t)LUA_TSTRING;
    g_keyEventsTString.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_keyEventsTString.hash   = 0x45564553;   /* "EVES" */
    g_keyEventsTString.len    = 0;
}

/* Companion TString for the name half of Loader.GetLoadPhase(). Same
 * reuse semantics as the two above: valid until the next call. */
#pragma pack(push, 4)
typedef struct PhaseNameTString {
    void*    next;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[64];
} PhaseNameTString;
#pragma pack(pop)
static PhaseNameTString g_phaseNameTString;

static void InitPhaseNameTString(void) {
    memset(&g_phaseNameTString, 0, sizeof(g_phaseNameTString));
    g_phaseNameTString.tt     = (uint8_t)LUA_TSTRING;
    g_phaseNameTString.marked = 0x20 | 0x01;  /* FIXEDBIT | WHITE0BIT */
    g_phaseNameTString.hash   = 0x50485345;   /* "PHSE" */
    g_phaseNameTString.len    = 0;
}

/* ------------------------------------------------------------------------ *
 * Globals
 * ------------------------------------------------------------------------ */
static HMODULE g_hModule = NULL;

/* Resolved RVAs (set in WorkerThread): */
static lua_CFunction_t      fpOriginal_NoopStub          = NULL;
static lua_CFunction_t      fpOriginal_luaB_type         = NULL;
static pandemic_CFunction_t fpOriginal_CreateTextWidget  = NULL;
static lua_CFunction_t      p_luaB_loadstring            = NULL;
static lua_CFunction_t      p_luaB_pcall                 = NULL;

/* Captured engine lua_State, set by the detours: */
static void* volatile g_LuaState = NULL;

/* Output buffer — accumulates execution results before the next TCP flush. */
static CRITICAL_SECTION g_outMtx;
static char*  g_outBuf       = NULL;
static size_t g_outBuf_len   = 0;
static size_t g_outBuf_cap   = 0;

/* Input queue — pending chunks waiting for a pump source to fire.
 * `from_ws` = 1 means the chunk was queued by a WebSocket client, which
 * receives its results via Loader.WsSend on the {type:"ws"} broadcast
 * channel (result routing lives in Lua-space via the client-side tag).
 * The pump skips the g_outBuf writes for these — g_outBuf is the raw-TCP
 * result channel, and a WS-queued chunk's result flooding it would be
 * seen as unsolicited output by any concurrently-connected raw-TCP
 * client. from_ws=0 covers raw-TCP submissions and loader-initiated
 * OnKey/OnBoot/OnLoad scripts (both still write results to g_outBuf,
 * matching the prior v0.4.0 behavior). */
typedef struct ChunkNode {
    char*  code;
    size_t len;
    int    from_ws;
    struct ChunkNode* next;
} ChunkNode;
static CRITICAL_SECTION g_inMtx;
static ChunkNode* g_inQueue_head = NULL;
static ChunkNode* g_inQueue_tail = NULL;
static volatile LONG g_PendingScripts = 0;

/* Loader lifecycle flags — moved up so RecomputeHotWork can see them. */
static volatile LONG g_OnLoadTriggered = 0;
static volatile LONG g_OnLoadExecuted  = 0;

/* Hot-path gate. When 0, GatedPump fast-returns after a single volatile
 * load. Set to 1 whenever there might be pump work (script queued, or
 * OnLoad transition pending); recomputed from ground-truth after any
 * event that could clear it. Idempotent — occasional stale-1 just costs
 * one extra slow-path traversal, no correctness impact. */
static volatile LONG g_hotWork = 0;

static __inline void RecomputeHotWork(void) {
    LONG onload_pending = (g_OnLoadTriggered && !g_OnLoadExecuted) ? 1 : 0;
    LONG scripts_pending = (g_PendingScripts > 0) ? 1 : 0;
    g_hotWork = onload_pending | scripts_pending;
}

/* Per-thread re-entry guard — prevents the executor from recursing
 * into itself if a capture detour fires mid-LuaDoString. */
static MOD_THREAD BOOL t_inBridgeExec = FALSE;

/* ------------------------------------------------------------------------ *
 * Watchdog — self-healing safety net for silent pump stalls.
 *
 * The bridge has several state variables that in principle can end up in
 * a stuck configuration where PendingScripts > 0 but the pump never
 * drains: hotWork stuck at 0 despite pending work, t_inBridgeExec stuck
 * TRUE on the game thread, g_LuaState pointing at a destroyed VM, or a
 * seen[] set full of stale pointers. Every one of these is a real bug we
 * should eventually diagnose — but until we can reproduce them, users
 * hit "chunks stopped executing, only a reboot fixes it."
 *
 * The watchdog runs on a background thread, wakes every ~2 seconds, and
 * if it observes (a) chunks pending, (b) game running (detour fired
 * recently), (c) no pump progress for `watchdog_stuck_ms`, then it does
 * a full-hammer reset: hotWork=1, signal PumpQueue to force-clear its
 * TLS flag next entry, null out g_LuaState + seen[] so the next detour
 * re-captures cleanly. Log everything for post-mortem diagnosis.
 *
 * All three reset actions are individually safe. Not escalating to
 * medium/hard tiers keeps the code simple — the cost of over-resetting
 * a transient blip is one extra re-capture log line, no user harm.
 * ------------------------------------------------------------------------ */
static volatile DWORD g_lastDetourFireTick    = 0;
static volatile DWORD g_lastPumpAttemptTick   = 0;
static volatile DWORD g_lastPumpProgressTick  = 0;
/* 0 = not currently executing; else the tick when we entered LuaDoString.
 * Read by the watchdog to detect "hung inside a native call from Lua" — the
 * case where the game thread is blocked so no more detours can fire and the
 * since_detour heuristic would incorrectly bail. */
static volatile DWORD g_bridgeExecStartTick   = 0;
static volatile LONG  g_watchdogForceClearTLS = 0;

/* Configuration (loaded from lua_bridge.ini). */
static char  g_repl_host[64] = "127.0.0.1";
static int   g_repl_port     = 27050;
static int   g_loader_enabled  = 1;
static int   g_loader_onboot   = 1;
static int   g_loader_onload   = 1;
static int   g_loader_delay_ms = 50;
static int   g_loader_onkey_cooldown_ms = 250;  /* per-script re-fire lockout */
static int   g_watchdog_stuck_ms = 8000;         /* 0 disables the watchdog */
static int   g_ws_enabled        = 1;            /* 0 disables the WebSocket transport (raw-TCP only) */

/* --- Added in v0.5.0. Every one of these defaults to the value that either
 * preserves pre-0.5.0 behavior or fixes an outright bug, so an existing
 * install keeps working untouched. See the ini for per-key rationale. --- */

/* Drop OnKey hotkey fires while the game is not the foreground window.
 * Pre-0.5.0 behavior was to fire regardless of focus, which meant a
 * browser F5 / F11 would trigger game scripts in the background. Set to 0
 * to restore that if some workflow depends on it. */
static int   g_loader_onkey_require_focus = 1;

/* Require the held modifier set to match a binding EXACTLY, so `F5` and
 * `ctrl+F5` can go to different scripts. 0 = pre-0.5.0 matching, where
 * modifiers are ignored entirely and a plain `F5` binding fires even while
 * ctrl is held. */
static int   g_loader_onkey_exact_modifiers = 1;

/* Re-run OnBoot/OnLoad after a main-menu round-trip. The engine wipes _G
 * on menu entry and hands out fresh lua_States on the next load, so
 * without this every OnLoad-installed framework stays dead until the game
 * process restarts. 0 = pre-0.5.0 behavior (once per process). */
static int   g_loader_rearm_on_menu = 1;

/* Track the world-load phase ladder so Loader.GetLoadPhase() works and the
 * menu re-arm can see a load restart. Costs a substring scan per captured
 * game log line on the detour path; set to 0 to remove that cost entirely
 * (GetLoadPhase then reports -1 and the menu re-arm stops working). */
static int   g_loader_track_phase = 1;

/* Source-encoding normalization for .lua files and WS-submitted chunks:
 * 1 = auto (strip BOMs; transcode valid-UTF-8-with-high-bytes to CP1252),
 * 0 = off (raw bytes through, pre-0.5.0 behavior; BOMs still stripped
 * because a BOM is an unconditional Lua 5.1 syntax error). */
static int   g_loader_source_encoding_auto = 1;

/* One-shot stack-layout dump on the first chunk execution. Exists to
 * locate this build's pcall status slot; see the STACKDIAG block in
 * LuaDoString. Cheap (one burst of log lines per process). */
static int   g_stack_diag     = 1;
/* Dump the first few executions rather than just one, so a deliberately
 * failing chunk can be compared against a succeeding one in the same run. */
#define STACK_DIAG_MAX 8
static int   g_stackDiagCount = 0;

/* ------------------------------------------------------------------------ *
 * WebSocket client tracking. Multiple concurrent WS clients: each gets
 * its own worker thread running ws_serve_client, and adds/removes itself
 * from g_wsClients[] under g_wsClientMtx. Broadcasters (Loader.Printf
 * and Loader.WsSend fanouts on the game thread) iterate the list and
 * fan out; a send failure prunes the dead client in place. Send calls
 * to a given socket are serialized by the same mutex — briefly held
 * for the duration of one frame's byte stream so two writers can't
 * interleave. Cap chosen high enough for realistic use (a browser tab
 * or two + a REPL + a debug page + slack) with negligible cost.
 * ------------------------------------------------------------------------ */
#define WS_MAX_CLIENTS 16
static CRITICAL_SECTION g_wsClientMtx;
static int              g_wsClientMtxInit = 0;
static SOCKET           g_wsClients[WS_MAX_CLIENTS];
static int              g_wsClientCount = 0;

/* Forward declarations — the loader_lib[] table and LuaLoaderPrintf
 * reference these; their definitions live in the WebSocket section
 * further down. */
static void ws_broadcast_typed_line(const char* type, const char* line, size_t line_len);
static int  LuaLoaderWsSend(void* L);

/* ------------------------------------------------------------------------ *
 * Output-buffer helpers
 * ------------------------------------------------------------------------ */
static void OutAppend(const char* s, size_t s_len) {
    EnterCriticalSection(&g_outMtx);
    {
        size_t needed = g_outBuf_len + s_len + 2;
        if (needed > g_outBuf_cap) {
            size_t newcap = g_outBuf_cap ? g_outBuf_cap * 2 : 4096;
            char*  newbuf;
            while (newcap < needed) newcap *= 2;
            newbuf = (char*)realloc(g_outBuf, newcap);
            if (newbuf) { g_outBuf = newbuf; g_outBuf_cap = newcap; }
            else { LeaveCriticalSection(&g_outMtx); return; }
        }
        memcpy(g_outBuf + g_outBuf_len, s, s_len);
        g_outBuf_len += s_len;
        g_outBuf[g_outBuf_len++] = '\n';
        g_outBuf[g_outBuf_len]   = '\0';
    }
    LeaveCriticalSection(&g_outMtx);
}

/* ------------------------------------------------------------------------ *
 * Input-queue helpers
 * ------------------------------------------------------------------------ */
static void InQueuePush(const char* code, size_t len, int from_ws) {
    ChunkNode* node = (ChunkNode*)malloc(sizeof(ChunkNode));
    if (!node) return;
    node->code = (char*)malloc(len + 1);
    if (!node->code) { free(node); return; }
    memcpy(node->code, code, len);
    node->code[len] = '\0';
    node->len     = len;
    node->from_ws = from_ws;
    node->next    = NULL;

    EnterCriticalSection(&g_inMtx);
    if (g_inQueue_tail) g_inQueue_tail->next = node;
    else                g_inQueue_head       = node;
    g_inQueue_tail = node;
    LeaveCriticalSection(&g_inMtx);

    InterlockedIncrement(&g_PendingScripts);
    g_hotWork = 1;
}

static ChunkNode* InQueuePop(void) {
    ChunkNode* node;
    EnterCriticalSection(&g_inMtx);
    node = g_inQueue_head;
    if (node) {
        g_inQueue_head = node->next;
        if (!g_inQueue_head) g_inQueue_tail = NULL;
        InterlockedDecrement(&g_PendingScripts);
    }
    LeaveCriticalSection(&g_inMtx);
    return node;
}

static void ChunkNodeFree(ChunkNode* n) {
    if (!n) return;
    free(n->code);
    free(n);
}

/* ------------------------------------------------------------------------ *
 * Result-formatting + executor
 * ------------------------------------------------------------------------ */
static int SafeCallLuaCFunction(lua_CFunction_t fn, void* L) {
#ifdef _MSC_VER
    __try {
        return fn(L);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return -1;
    }
#else
    /* MinGW x86 doesn't support MSVC SEH; call unguarded. If the
     * target AVs, the game crashes. Documented trade-off. */
    return fn(L);
#endif
}

/* Append "<value>" (or "nil" / "true" / a number) representing one
 * TValue slot to `out`. `out_cap` is the buffer's total capacity,
 * `*out_len` is updated. Caller ensures room. */
static void FormatTValue(const char* slot, char* out, size_t out_cap, size_t* out_len) {
    int tt = *(const int*)(slot + TVALUE_TT_OFFSET);
    char tmp[128];
    int n = 0;
    switch (tt) {
        case LUA_TNIL:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "nil");
            break;
        case LUA_TBOOLEAN:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                            *(const int*)slot ? "true" : "false");
            break;
        case LUA_TNUMBER: {
            float f = *(const float*)slot;  /* lua_Number = float in this build */
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "%g", (double)f);
            break;
        }
        case LUA_TSTRING: {
            void* gc = *(void* const*)slot;
            uint32_t slen;
            const char* sdata;
            if (!SafeProbe(gc, 0x14)) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<string: gc unreadable>");
                break;
            }
            slen = *(uint32_t*)((char*)gc + 0x0C);
            if (slen > 16u * 1024u * 1024u) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                                "<string: implausible len=%u>", slen);
                break;
            }
            sdata = (const char*)gc + 0x10;
            if (!SafeProbe(sdata, slen + 1)) {
                n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<string: data unreadable>");
                break;
            }
            /* Bypass the tmp buffer for string content — copy straight to out. */
            if (*out_len + slen + 3 < out_cap) {
                out[(*out_len)++] = '"';
                memcpy(out + *out_len, sdata, slen);
                *out_len += slen;
                out[(*out_len)++] = '"';
                out[*out_len] = '\0';
            }
            return;
        }
        case LUA_TTABLE:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<table>");
            break;
        case LUA_TFUNCTION:
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "<function>");
            break;
        default: {
            void* v = *(void* const*)slot;
            n = _snprintf_s(tmp, sizeof(tmp), _TRUNCATE,
                            "<tt=%d val=%p>", tt, v);
            break;
        }
    }
    if (n > 0 && (size_t)n + *out_len + 1 < out_cap) {
        memcpy(out + *out_len, tmp, n);
        *out_len += n;
        out[*out_len] = '\0';
    }
}

/* Phase 3 executor. Builds a NEW Lua frame on top of the engine's
 * active frame (does NOT clobber base) and runs the chunk via
 * luaB_loadstring + luaB_pcall. Result formatted into `out`.
 *
 * Must be called from inside a real lua_CFunction detour with a
 * verified-valid L (i.e. after LooksLikeLuaState). */
/* Executor core. `src` is the FixedTString used to hand the source text to
 * the engine's loadstring; it is a parameter rather than always g_chunkSource
 * so Loader.LoadFile can execute a nested chunk without overwriting the
 * source buffer of the chunk that called it. */
static void LuaDoStringEx(void* L, const char* code, size_t code_len,
                          char* out, size_t out_cap, FixedTString* src) {
    char *Lc, *new_base, *top_slot;
    void **top_ptr, **base_ptr;
    void *saved_top, *saved_base;
    int load_n, pcall_n, compiled_tt;
    size_t out_len = 0;
    ptrdiff_t after_exec;
    int result_slots, i;
    int succeeded = 0;
    int have_status = 0;
    int skip_artifact = 0;
    int first_result;
    /* STACKDIAG: value of saved_base[0] BEFORE we run anything, so the dump
     * can prove whether the engine's own frame slot gets written. */
    int   pre_tt   = 0;
    void* pre_val  = NULL;
    int   have_pre = 0;
    /* Engine-frame preservation — see the big comment before the pcall. */
    char   frame_save[16 * TVALUE_SIZE];
    size_t frame_bytes     = 0;
    int    have_frame_save = 0;
    int    diag_this_call  = 0;
    int    status_tt_after = -1;
    int    status_val_after = 0;

    if (!L) { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] no L"); return; }
    if (!LooksLikeLuaState(L)) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] L failed validation");
        return;
    }
    if (!p_luaB_loadstring || !p_luaB_pcall) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] executor fn pointers not resolved");
        return;
    }
    if (code_len == 0)                          { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] empty chunk"); return; }
    if (!src)                              { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] no chunk source buffer"); return; }
    if (code_len >= sizeof(src->data))     { _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] chunk too large"); return; }

    Lc       = (char*)L;
    top_ptr  = (void**)(Lc + LUA_OFF_TOP);
    base_ptr = (void**)(Lc + LUA_OFF_BASE);
    saved_top  = *top_ptr;
    saved_base = *base_ptr;
    new_base   = (char*)saved_top;

    if (!SafeProbe(new_base, 3 * TVALUE_SIZE)) {
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] L->top + scratch unwritable");
        return;
    }

    /* Snapshot the engine's own frame slot 0 before we touch anything. If the
     * post-run dump shows this changed into a boolean matching the chunk's
     * success, then this build's luaB_pcall resolved lua_insert(L,1) against
     * saved_base instead of the new_base we install — meaning every chunk
     * execution overwrites the first argument of the hooked function we are
     * standing in, which the detour then calls. That is a correctness bug for
     * the engine, not just for our result formatting. */
    if (g_stack_diag && g_stackDiagCount < STACK_DIAG_MAX &&
        SafeProbe(saved_base, TVALUE_SIZE)) {
        pre_tt   = *(int*)((char*)saved_base + TVALUE_TT_OFFSET);
        pre_val  = *(void**)saved_base;
        have_pre = 1;
    }

    /* --- Engine-frame preservation ---------------------------------------
     * PROVEN by STACKDIAG over 8 samples on v1.1+bypass: this build's
     * luaB_pcall writes its boolean status to saved_base[0] — the base of the
     * frame belonging to the hooked C function we are executing inside —
     * rather than the new_base we install above. Because each detour calls
     * the original function AFTER GatedPump, that original then reads a
     * clobbered argument 1: a `type(x)` routed through luaB_type answers
     * "boolean" no matter what x is. Every chunk this bridge has ever run
     * did that to whatever frame it happened to land in.
     *
     * Snapshot the frame slots below new_base and restore them once the call
     * is done. Exact, and costs a couple of TValues each way. The 16-slot cap
     * is a bound on a value we do not control; measured base_delta is 4. */
    frame_bytes = (size_t)((char*)new_base - (char*)saved_base);
    if (frame_bytes > sizeof(frame_save)) frame_bytes = sizeof(frame_save);
    if (frame_bytes > 0 && SafeProbe(saved_base, frame_bytes)) {
        memcpy(frame_save, saved_base, frame_bytes);
        have_frame_save = 1;
    }

    memcpy(src->data, code, code_len);
    src->data[code_len] = '\0';
    src->len = (uint32_t)code_len;

    *(void**)new_base                            = src;
    *(int*)(new_base + TVALUE_TT_OFFSET)         = LUA_TSTRING;
    *base_ptr = new_base;
    *top_ptr  = new_base + TVALUE_SIZE;

    load_n = SafeCallLuaCFunction(p_luaB_loadstring, L);
    if (load_n < 0) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] luaB_loadstring crashed");
        return;
    }
    if (load_n == 2) {
        char* err_slot = new_base + 2 * TVALUE_SIZE;
        out_len = 0;
        out_len += _snprintf_s(out, out_cap, _TRUNCATE, "[compile] ");
        FormatTValue(err_slot, out, out_cap, &out_len);
        *top_ptr = saved_top; *base_ptr = saved_base;
        return;
    }
    if (load_n != 1) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] loadstring returned %d", load_n);
        return;
    }

    /* Success: stack is [chunk, fn] at new_base. Slide fn down to new_base[0]
     * so pcall reads it at index 1. */
    top_slot = (char*)*top_ptr - TVALUE_SIZE;
    compiled_tt = *(int*)(top_slot + TVALUE_TT_OFFSET);
    if (compiled_tt != LUA_TFUNCTION) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE,
                    "[bridge] loadstring result not a function (tt=%d)", compiled_tt);
        return;
    }
    if (top_slot != new_base) memcpy(new_base, top_slot, TVALUE_SIZE);
    *top_ptr = new_base + TVALUE_SIZE;

    pcall_n = SafeCallLuaCFunction(p_luaB_pcall, L);

    /* Read the status from where this build actually leaves it, BEFORE the
     * frame is put back. Recorded but not yet trusted for the [ok]/[runtime]
     * label — every sample so far came back `true`, including for a chunk
     * that failed, so it may be a fixed marker rather than a real status.
     * Logged next to the formatted result below so the two can be correlated
     * over a set of known-good and known-bad chunks. */
    if (have_frame_save && frame_bytes >= TVALUE_SIZE) {
        status_tt_after  = *(int*)((char*)saved_base + TVALUE_TT_OFFSET);
        status_val_after = *(int*)saved_base;
    }

    /* Put the engine's frame back exactly as we found it. Results live at
     * new_base and above, so this cannot disturb them. */
    if (have_frame_save) {
        memcpy(saved_base, frame_save, frame_bytes);
    }

    if (pcall_n < 0) {
        *top_ptr = saved_top; *base_ptr = saved_base;
        _snprintf_s(out, out_cap, _TRUNCATE, "[bridge] luaB_pcall crashed");
        return;
    }

    after_exec = (char*)*top_ptr - new_base;
    result_slots = (int)(after_exec / TVALUE_SIZE);
    if (result_slots > 16) result_slots = 16;

    /* ---- One-shot stack-layout diagnostic (v0.5.0) ----------------------
     * Live testing on v1.1+bypass showed this build's luaB_pcall leaves a
     * TABLE in slot 0 with the chunk's real results from slot 1 up — the
     * boolean status stock luaB_pcall lua_insert()s at index 1 is NOT
     * anywhere in [new_base, top). Verified across 12 probes: `return` with
     * 0/1/3 values, and nil/boolean/number/table/function returns, all
     * landed at slot 1+.
     *
     * That leaves one thing worth ruling out: if this build's lua_insert
     * resolved index 1 against saved_base rather than the new_base we
     * install above, the status boolean is being written into the engine's
     * OWN live frame on every execution — which would be stack corruption
     * and a candidate root cause for the intermittent pump stalls the
     * watchdog exists to paper over. Dump the window around new_base once
     * per process so that question can be settled from a log. */
    if (g_stack_diag && g_stackDiagCount < STACK_DIAG_MAX) {
        int d;
        g_stackDiagCount++;
        diag_this_call = 1;
        m2_logf("[*] lua_bridge: STACKDIAG #%d new_base=%p saved_base=%p "
                "saved_top=%p top_now=%p slots=%d (base_delta=%d slots)",
                g_stackDiagCount, new_base, saved_base, saved_top,
                *top_ptr, result_slots,
                (int)(((char*)new_base - (char*)saved_base) / TVALUE_SIZE));
        /* The decisive line: did the engine's own frame slot 0 change? */
        if (have_pre) {
            int  post_tt  = SafeProbe(saved_base, TVALUE_SIZE)
                            ? *(int*)((char*)saved_base + TVALUE_TT_OFFSET) : -1;
            void* post_val = SafeProbe(saved_base, TVALUE_SIZE)
                            ? *(void**)saved_base : NULL;
            m2_logf("[*] lua_bridge: STACKDIAG   saved_base[0] BEFORE tt=%d val=%p "
                    "-> AFTER tt=%d val=%p %s",
                    pre_tt, pre_val, post_tt, post_val,
                    (pre_tt == post_tt && pre_val == post_val)
                        ? "(UNCHANGED - engine frame is intact)"
                        : "(CHANGED - pcall wrote the engine's frame!)");
        }
        for (d = -2; d <= 3; ++d) {
            char* slot = new_base + d * TVALUE_SIZE;
            if (!SafeProbe(slot, TVALUE_SIZE)) {
                m2_logf("[*] lua_bridge: STACKDIAG   slot%d unreadable", d);
                continue;
            }
            m2_logf("[*] lua_bridge: STACKDIAG   slot%d tt=%d val=%p",
                    d, *(int*)(slot + TVALUE_TT_OFFSET), *(void**)slot);
        }
        if (SafeProbe(saved_base, TVALUE_SIZE)) {
            m2_logf("[*] lua_bridge: STACKDIAG   saved_base[0] tt=%d val=%p",
                    *(int*)((char*)saved_base + TVALUE_TT_OFFSET),
                    *(void**)saved_base);
        }
    }

    /* --- Status recovery --------------------------------------------------
     * VERIFIED LIVE on v1.1+bypass: this build's luaB_pcall leaves its boolean
     * status at saved_base[0] — captured above, just before the executor
     * restores the engine's frame. Established by correlation across 8
     * samples: val=0 for exactly the chunk that failed, val=1 for every chunk
     * that succeeded.
     *
     * This is what finally makes [ok] reachable. Pre-0.5.0 the status was
     * looked for at new_base[0], which on this build always holds a table, so
     * `succeeded` was pinned at 0 and every result — successes included — was
     * labelled [runtime]. */
    if (status_tt_after == LUA_TBOOLEAN) {
        have_status = 1;
        succeeded   = (status_val_after != 0);
    }

    /* Independently, decide whether slot 0 is a real result or an artifact.
     * On this build it is always the mystery table. The boolean/number
     * branches are the stock layout, kept so that adding an RVA table for a
     * different binary doesn't require rediscovering any of this. */
    if (result_slots >= 1) {
        int tt0 = *(int*)(new_base + TVALUE_TT_OFFSET);
        if (tt0 == LUA_TTABLE || tt0 == LUA_TFUNCTION) {
            /* Neither can be a pcall status, so it is the slot-0 artifact —
             * skip it rather than formatting it. That junk "<table>" prefix
             * was on every result this bridge ever returned. */
            skip_artifact = 1;
        } else if (!have_status && tt0 == LUA_TBOOLEAN) {
            have_status   = 1;
            succeeded     = (*(int*)new_base != 0);
            skip_artifact = 1;
        } else if (!have_status && tt0 == LUA_TNUMBER) {
            have_status   = 1;
            succeeded     = (*(const float*)new_base != 0.0f);
            skip_artifact = 1;
        }
    }
    first_result = skip_artifact ? 1 : 0;

    out_len = 0;
    out_len += _snprintf_s(out, out_cap, _TRUNCATE, "%s", succeeded ? "[ok]" : "[runtime]");
    for (i = first_result; i < result_slots; ++i) {
        char* rslot = new_base + i * TVALUE_SIZE;
        if (out_len + 2 < out_cap) {
            out[out_len++] = succeeded ? '\t' : ' ';
            out[out_len]   = '\0';
        }
        FormatTValue(rslot, out, out_cap, &out_len);
    }

    *top_ptr = saved_top;
    *base_ptr = saved_base;

    /* Correlate the recovered status against the actual outcome. If
     * status_tt_after is consistently LUA_TBOOLEAN and its value tracks
     * success vs failure across these samples, the [ok]/[runtime] label can
     * finally be driven from it. */
    if (diag_this_call) {
        m2_logf("[*] lua_bridge: STACKDIAG   status_slot_after tt=%d val=%d | result=%s",
                status_tt_after, status_val_after, out);
    }
}

/* Back-compat wrapper — every pre-existing caller runs out of the primary
 * chunk buffer, unchanged. */
static void LuaDoString(void* L, const char* code, size_t code_len,
                        char* out, size_t out_cap) {
    LuaDoStringEx(L, code, code_len, out, out_cap, &g_chunkSource);
}

static void RegisterTcpLib(void* L);
static void RegisterLoaderLib(void* L);
static void RegisterMathLib(void* L);
static void RunPolyfill(void* L);
static void ExecuteLuaFolder(void* L, const char* folder_name);
static void InitializeKeyScripts(void);
static void LoaderLogLine(const char* line);
static void RearmLoaderForNewLoadCycle(const char* why);

/* ------------------------------------------------------------------------ *
 * Pump — drain the input queue against a verified-valid L
 * ------------------------------------------------------------------------ */
static void PumpQueue(void* L_for_exec) {
    char result_buf[16384];
    int L_ok;

    if (g_PendingScripts <= 0) return;
    if (t_inBridgeExec) {
        /* Watchdog escape hatch: if the watchdog decided this thread's
         * TLS is stuck TRUE (leaked from an earlier abnormal exit), it
         * sets g_watchdogForceClearTLS. Consume the flag and clear our
         * TLS so this call proceeds. Uses InterlockedCompareExchange so
         * only one thread claims the reset even in the rare case that
         * multiple threads race into this branch. */
        if (InterlockedCompareExchange(&g_watchdogForceClearTLS, 0, 1) == 1) {
            t_inBridgeExec = FALSE;
            m2_logf("[!] lua_bridge: watchdog force-cleared t_inBridgeExec on this thread");
        } else {
            return;
        }
    }

    /* Re-register our libs ONCE at batch start, not per chunk. Defends
     * against engine _G resets between batches (menu → mission,
     * cutscene entry, etc.); a wipe mid-batch is essentially impossible
     * since chunks drain back-to-back. luaL_register is idempotent, so
     * this is also cheap. */
    L_ok = (L_for_exec && LooksLikeLuaState(L_for_exec));
    if (L_ok) {
        RegisterTcpLib(L_for_exec);
        RegisterLoaderLib(L_for_exec);
        RegisterMathLib(L_for_exec);
        RunPolyfill(L_for_exec);
    }

    for (;;) {
        ChunkNode* node = InQueuePop();
        if (!node) return;

        g_bridgeExecStartTick = GetTickCount();
        t_inBridgeExec = TRUE;
        if (L_ok) {
            LuaDoString(L_for_exec, node->code, node->len, result_buf, sizeof(result_buf));
        } else {
            _snprintf_s(result_buf, sizeof(result_buf), _TRUNCATE,
                        "[bridge] pump fired without a valid L — chunk dropped");
        }
        t_inBridgeExec = FALSE;
        g_bridgeExecStartTick = 0;

        m2_logf("[+] lua_bridge: Script executed. Result: %s", result_buf);
        /* Only fan out to the raw-TCP result channel (g_outBuf) for
         * chunks that came from raw TCP or the loader. WS-queued
         * chunks return their results via Loader.WsSend from the Lua
         * wrapper; writing to g_outBuf here would spray them at any
         * concurrently-connected raw-TCP client as unsolicited noise. */
        if (!node->from_ws) {
            OutAppend(result_buf, strlen(result_buf));
            OutAppend("<<<END>>>", 9);
        }
        ChunkNodeFree(node);

        /* Watchdog telemetry: successful drain proves the pump path is
         * alive. Updated per-chunk (not per-batch) so long batches don't
         * look stuck to the watchdog if they take longer than the
         * stuck-timeout. */
        g_lastPumpProgressTick = GetTickCount();
    }
}

static __inline void GatedPump(void* L_arg0) {
    /* Fast path: single volatile load. Fires thousands of times per
     * second from detours; anything else here is measurable. */
    if (!g_hotWork) return;

    /* Slow path: something wants doing. Watchdog uses this timestamp
     * to distinguish "hotWork stuck at 0" (this never updates) from
     * "hotWork trying, PumpQueue not draining" (this updates but
     * g_lastPumpProgressTick doesn't). */
    g_lastPumpAttemptTick = GetTickCount();

    /* !t_inBridgeExec added in v0.5.0: without it, a script already running
     * under LuaDoString (an OnBoot chunk, or any queued chunk) could trigger
     * a detour that lands here and starts OnLoad nested inside it. */
    if (g_loader_enabled && g_loader_onload && g_OnLoadTriggered &&
        !g_OnLoadExecuted && !t_inBridgeExec) {
        if (LooksLikeLuaState(L_arg0)) {
            g_OnLoadExecuted = 1;
            ExecuteLuaFolder(L_arg0, "OnLoad");
        }
    }

    if (g_PendingScripts > 0 && !t_inBridgeExec && LooksLikeLuaState(L_arg0)) {
        PumpQueue(L_arg0);
    }

    RecomputeHotWork();
}

/* Seen-L set, file-scope so the watchdog can memset it during a hard reset.
 * All access from the game thread's CaptureL; the watchdog only writes
 * (never reads for logic), so no atomicity needed beyond aligned-store. */
#define SEEN_L_SLOTS 16
static void* g_seenL[SEEN_L_SLOTS] = {0};
static int   g_seenLNext = 0;   /* ring cursor — where the next eviction writes */

/* Loader once-per-load-cycle guards. File-scope rather than function-local
 * statics so RearmLoaderForNewLoadCycle() can clear them on a menu return. */
static volatile LONG g_keyLoaderInitialized = 0;
static volatile LONG g_onbootExecuted       = 0;

static void CaptureL(void* L, const char* via) {
    int i;

    /* Fast path #1: same L as last capture. This is the common case
     * (every detour fire on the same VM). Single pointer compare. */
    if (!L || L == g_LuaState) return;

    /* Fast path #2: L is in g_seenL[]. We've already validated + registered
     * on this VM before; the engine just flipped back to it. Scanning a
     * small pointer array is pure L1 (~5 cycles) versus LooksLikeLuaState
     * which does 4 VirtualQuery syscalls (~2µs). This is the biggest
     * hot-path win — the engine flips between frontend / gameplay VMs
     * many times per second.
     *
     * Scans every slot. The pre-0.5.0 loop broke out at the first NULL,
     * which was only safe while the table filled strictly front-to-back
     * and never evicted; with the ring below, entries are no longer
     * guaranteed contiguous. */
    for (i = 0; i < SEEN_L_SLOTS; ++i) {
        if (g_seenL[i] == L) { g_LuaState = L; return; }
    }

    /* Slow path: L we've never seen. Validate, register, log, remember. */
    if (!LooksLikeLuaState(L)) return;
    g_LuaState = L;

    /* Ring-evict the oldest entry when the table is full instead of giving
     * up. A main-menu round-trip burns TWO slots — measured: the engine
     * builds a fresh shell VM and a fresh game VM per load — so a
     * fill-and-stop table is exhausted after a handful of menu visits.
     * Pre-0.5.0, reaching that ceiling returned early and silently killed
     * two things at once: the fast-path match above (so every subsequent
     * detour fire on a new VM paid the full 4-syscall validation) and the
     * lib registration below (so Loader/Tcp/math were missing on fresh VMs
     * until the next pump batch happened to re-register them). */
    g_seenL[g_seenLNext] = L;
    g_seenLNext = (g_seenLNext + 1) % SEEN_L_SLOTS;

    m2_logf("[+] lua_bridge: Lua VM captured via %s: L=%p", via, L);
    RegisterTcpLib(L);
    RegisterLoaderLib(L);
    RegisterMathLib(L);
    RunPolyfill(L);

    /* New-load-cycle detection, and the reason it lives here rather than in
     * the log-line detour: verified live, a main-menu round-trip wipes _G and
     * the next load builds FRESH lua_States. So a brand-new L arriving after a
     * load cycle has already completed IS the "we started over" signal — and
     * it is essentially free, because this slow path only runs for VMs we have
     * never seen. Watching every log line for a marker string cost ~2 FPS.
     *
     * Boot is not a false positive: the initial boot's second VM appears
     * BEFORE OnLoad has executed (confirmed in the logs), so the
     * g_OnLoadExecuted guard excludes it. Must run before the two blocks
     * below, since it clears the guards they test. */
    if (g_loader_enabled && g_loader_rearm_on_menu && g_OnLoadExecuted) {
        RearmLoaderForNewLoadCycle("fresh Lua VM after a completed load");
    }

    if (g_loader_enabled && !g_keyLoaderInitialized) {
        g_keyLoaderInitialized = 1;
        InitializeKeyScripts();
    }

    if (g_loader_enabled && g_loader_onboot && !g_onbootExecuted) {
        g_onbootExecuted = 1;
        ExecuteLuaFolder(L, "OnBoot");
    }
}

/* ------------------------------------------------------------------------ *
 * World-load phase tracking + main-menu re-arm
 *
 * Feeds loadprobe's phase ladder (sdk/m2/load_ladder.gen.h) from the log
 * lines the noop-stub detour already sees.
 *
 * Deliberately NOT wired through m2_loadtrigger_install(): that MinHooks
 * M2_LOG_STUB_VA, which is the SAME address as this mod's own noop_stub
 * detour (both 0x006D5640 on v1.1+bypass), so installing it would
 * double-hook a target we already own. We reuse the ladder DATA and
 * m2_loadtrigger_phase_name() only — neither installs anything.
 *
 * Sole consumer is Loader.GetLoadPhase(), which lets a script ask how far the
 * load has progressed before it touches world entities.
 *
 * Scanning is deliberately confined to the duration of a load: the detour
 * joins + matches only while g_loadPhase is below the fully-loaded phase, and
 * RearmLoaderForNewLoadCycle drops it back to -1 for the next load. That puts
 * the cost inside a loading screen, where nobody is counting frames, and
 * keeps it out of the steady-state frame loop this stub actually lives in.
 *
 * The new-load-cycle detection driving the OnBoot/OnLoad re-arm does NOT live
 * here — it hangs off CaptureL seeing a fresh lua_State, which is free. The
 * first 0.5.0 cut watched every log line for a load-start marker instead, and
 * that cost ~2 FPS. See the comment in CaptureL.
 * ------------------------------------------------------------------------ */
static volatile LONG g_loadPhase = -1;   /* highest ladder phase this cycle */

/* Highest ladder phase whose marker appears in msg, else -1. Mirrors
 * m2_loadtrigger's MatchPhase (which is file-static over there). Scans high
 * to low so the first hit is already the highest and we can return early. */
static int MatchLoadPhase(const char* msg) {
    int i, j;
    for (i = M2_LADDER_COUNT - 1; i >= 0; --i) {
        const M2LoadPhase* ph = &k_m2_ladder[i];
        for (j = 0; j < ph->match_count; ++j) {
            if (strstr(msg, ph->matches[j])) return ph->idx;
        }
    }
    return -1;
}

static void RearmLoaderForNewLoadCycle(const char* why) {
    m2_logf("[*] lua_bridge: new load cycle detected (%s) — re-arming loader "
            "(was at phase %d)", why, (int)g_loadPhase);

    /* Back to -1 so phase tracking re-activates for the incoming load; the
     * detour's scan is gated on being below the fully-loaded phase. */
    g_loadPhase = -1;

    InterlockedExchange(&g_OnLoadTriggered, 0);
    InterlockedExchange(&g_OnLoadExecuted, 0);
    if (g_loader_onboot) InterlockedExchange(&g_onbootExecuted, 0);

    /* Re-scan key bindings too — a fresh load cycle is the natural point to
     * pick up .lua files added since boot. InitializeKeyScripts() is safe to
     * call repeatedly as of v0.5.0 (it spawns its polling thread once and
     * swaps the table under a lock). */
    InterlockedExchange(&g_keyLoaderInitialized, 0);

    g_hotWork = 1;
}

/* ------------------------------------------------------------------------ *
 * Detours
 * ------------------------------------------------------------------------ */
static int __cdecl DetourNoopStub(void* L) {
    g_lastDetourFireTick = GetTickCount();

    /* HOT PATH — Debug.Printf and ~700 other stripped log functions funnel
     * through this stub thousands of times per frame from stock scripts, so
     * anything unconditional here costs real framerate. Both consumers of the
     * joined log line therefore go dormant on their own:
     *
     *   - the OnLoad trigger stops once its milestone is seen (as it always
     *     did pre-0.5.0)
     *   - phase tracking stops once the world is fully loaded, and is
     *     re-armed by RearmLoaderForNewLoadCycle — so it is live during a
     *     load and idle during gameplay, which is exactly when each is
     *     wanted.
     *
     * Both gates are plain volatile loads. The first 0.5.0 cut ran the join
     * unconditionally for phase tracking and cost ~2 FPS; measured, not
     * theorized. Do not make this unconditional again. */
    {
        int want_phase  = (g_loader_track_phase &&
                           g_loadPhase < M2_PHASE_REACHED_WORLD_IDX);
        int want_onload = (g_loader_enabled && g_loader_onload &&
                           !g_OnLoadTriggered);

        if (want_phase || want_onload) {
            char msg[512];
            if (m2_lua_join_strings(L, msg, sizeof(msg)) >= 1) {
                if (want_phase) {
                    int ph = MatchLoadPhase(msg);
                    if (ph > g_loadPhase) g_loadPhase = ph;
                }
                if (want_onload && strstr(msg, "GlobalExit - Complete")) {
                    m2_logf("[*] lua_bridge: OnLoad milestone reached (GlobalExit - Complete). Queuing OnLoad scripts.");
                    InterlockedExchange(&g_OnLoadTriggered, 1);
                    g_hotWork = 1;
                }
            }
        }
    }
    GatedPump(L);
    return fpOriginal_NoopStub ? fpOriginal_NoopStub(L) : 0;
}

static int __cdecl DetourLuaType(void* L) {
    g_lastDetourFireTick = GetTickCount();
    CaptureL(L, "type");
    GatedPump(L);
    return fpOriginal_luaB_type ? fpOriginal_luaB_type(L) : 0;
}

static int __fastcall DetourCreateTextWidget(void* L, void* edx) {
    g_lastDetourFireTick = GetTickCount();
    GatedPump(L);
    return fpOriginal_CreateTextWidget ? fpOriginal_CreateTextWidget(L, edx) : 0;
}

/* ------------------------------------------------------------------------ *
 * Print/Next/ToString hijack — see commented-out luaL_register section
 * below. Without that hook these hijacks never get installed, so the
 * functions below are unused in this draft. Left in place so they're
 * ready when the naked-detour question is resolved.
 * ------------------------------------------------------------------------ */
static lua_CFunction_t fpOriginalPrint    = NULL;
static lua_CFunction_t fpOriginalNext     = NULL;
static lua_CFunction_t fpOriginalToString = NULL;

static int __cdecl HijackedPrint(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalPrint ? fpOriginalPrint(L) : 0;
}
static int __cdecl HijackedNext(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalNext ? fpOriginalNext(L) : 0;
}
static int __cdecl HijackedToString(void* L) {
    if (g_PendingScripts > 0 && !t_inBridgeExec) PumpQueue(L);
    return fpOriginalToString ? fpOriginalToString(L) : 0;
}

/* ======================================================================== *
 * luaL_register hijack — DEFERRED
 *
 * Mercenaries 2's luaL_register uses a custom register-arg ABI:
 *   ECX = lua_State* L
 *   EAX = const char* libname
 *   [esp+4] = const luaL_Reg* table
 * Caller cleans the 4-byte stack arg.
 *
 * On MSVC, hooking this needs a __declspec(naked) detour that
 * preserves the registers and forwards. The MSVC source is below as
 * a comment, since GCC/MinGW on x86 doesn't support
 * __attribute__((naked)) and this SDK's Makefiles use MinGW.
 *
 * Three reasonable resolutions:
 *
 *   1) Translate to a global assembly file (lua_bridge_asm.S). The
 *      contents are essentially the same instructions GCC's inline
 *      asm would emit. Add to the Makefile as an additional source.
 *
 *   2) Compile with MSVC instead. The SDK's helpers should work fine
 *      either way; only the build glue would need to change.
 *
 *   3) Skip this hook. The bridge degrades gracefully without it: the
 *      noop_stub / luaB_type / CreateTextWidget detours still capture
 *      L, the executor still runs chunks. We lose the print/next/
 *      tostring hijack (a high-frequency pump source) and the
 *      registration-table dump (a discovery convenience), but core
 *      functionality is intact. This is what the draft below opts for.
 *
 * MSVC reference implementation:
 *
 *   __declspec(naked) static void DetourLuaLRegister(void) {
 *       __asm {
 *           push edx
 *           push eax
 *           push ecx
 *           push dword ptr [esp + 0x10]   ; table
 *           push dword ptr [esp + 0x08]   ; libname
 *           push dword ptr [esp + 0x08]   ; L
 *           call OnLuaRegisterCalled
 *           add esp, 12
 *           pop ecx
 *           pop eax
 *           pop edx
 *           jmp dword ptr [fpOriginal_luaL_register]
 *       }
 *   }
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * Expose Tcp.Send to Lua
 * ------------------------------------------------------------------------ */
typedef struct luaL_Reg {
    const char *name;
    int (__cdecl *func)(void* L);
} luaL_Reg;

static int LuaTcpSend(void* L) {
    char host[128];
    char msg[2048];
    int port;

    if (m2_lua_nargs(L) < 3) return 0;
    if (m2_lua_arg_string(L, 0, host, sizeof(host)) == 0) return 0;
    
    // Port is standard Lua float, extract from stack base:
    char* base = *(char**)((char*)L + 0x0C); // L->base
    if (!base) return 0;
    float port_val = *(float*)(base + 8);    // First stack slot (8 bytes per TValue)
    port = (int)port_val;

    if (m2_lua_arg_string(L, 2, msg, sizeof(msg)) == 0) return 0;

    unsigned long ip = inet_addr(host);
    if (ip == INADDR_NONE) return 0;

    /*
     * SECURITY RESTRICTION:
     * Only allow connections to loopback/localhost (127.0.0.0/8).
     * This decision was made for player security, preventing malicious or
     * untrusted Lua scripts from performing port scans on the player's
     * local network or exfiltrating data to external servers on the internet.
     *
     * NOTE: If this restriction is removed, it could potentially allow
     * secondary out-of-band communication between coop players to sync
     * mod status over the network without needing to integrate directly
     * with the game's built-in P2P networking core.
     */
    unsigned long ip_host = ntohl(ip);
    if ((ip_host & 0xFF000000) != 0x7F000000) {
        return 0; // Block non-localhost destinations
    }

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s != INVALID_SOCKET) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = ip;

        DWORD timeout = 500;
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
        
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            send(s, msg, (int)strlen(msg), 0);
        }
        closesocket(s);
    }
    return 0;
}

static const luaL_Reg tcp_lib[] = {
    {"Send", LuaTcpSend},
    {NULL, NULL}
};

/* ------------------------------------------------------------------------ *
 * Native Lua Script Loader
 * ------------------------------------------------------------------------ */
#define MAX_SCRIPTS 128

typedef struct {
    char path[MAX_PATH];
    char rel_path[MAX_PATH];
    int load_order;
    int disabled;      /* set when lua_loader.ini gives off/no/disabled */
} LuaScriptFile;

static int CompareAlphabetical(const void* a, const void* b) {
    return _stricmp(((const LuaScriptFile*)a)->rel_path, ((const LuaScriptFile*)b)->rel_path);
}

static int CompareLoadOrder(const void* a, const void* b) {
    int diff = ((const LuaScriptFile*)a)->load_order - ((const LuaScriptFile*)b)->load_order;
    if (diff != 0) return diff;
    return _stricmp(((const LuaScriptFile*)a)->rel_path, ((const LuaScriptFile*)b)->rel_path);
}

static void EnsureLoaderDirectories(void) {
    char exe_dir[MAX_PATH];
    char path[MAX_PATH];
    char* slash;

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(path, sizeof(path), "%sscripts", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnBoot", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnLoad", exe_dir);
    CreateDirectoryA(path, NULL);

    snprintf(path, sizeof(path), "%sscripts\\OnKey", exe_dir);
    CreateDirectoryA(path, NULL);
}

/* Deepest subdirectory nesting the scanner will descend. Belt-and-braces
 * behind the reparse-point skip below: unbounded recursion here means a
 * stack overflow on the game thread, since each level costs ~600 bytes. */
#define LOADER_MAX_DEPTH 8

/* Number of .lua files the last scan had to drop because the caller's array
 * was full. Callers reset this before scanning and report it afterwards, so
 * hitting MAX_SCRIPTS is no longer silent. */
static int g_scanDropped = 0;

static void CollectScriptsRecursive(const char* base_path, const char* sub_path, LuaScriptFile* list, int* count, int max_count, int depth) {
    char search_path[MAX_PATH];
    WIN32_FIND_DATAA ffd;
    HANDLE hFind;

    if (depth > LOADER_MAX_DEPTH) {
        m2_logf("[!] lua_bridge: script scan hit the %d-level depth cap at %s%s "
                "— not descending further", LOADER_MAX_DEPTH, base_path, sub_path);
        return;
    }

    snprintf(search_path, sizeof(search_path), "%s%s*", base_path, sub_path);
    hFind = FindFirstFileA(search_path, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0) {
            continue;
        }

        /* Never follow junctions or symlinks. A directory junction pointing at
         * one of its own ancestors is an infinite descent, and the depth cap
         * alone would still burn a lot of game-thread stack getting there. */
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            m2_logf("[*] lua_bridge: skipping reparse point in script scan: %s%s%s",
                    base_path, sub_path, ffd.cFileName);
            continue;
        }

        char relative_path[MAX_PATH];
        if (sub_path[0] == '\0') {
            snprintf(relative_path, sizeof(relative_path), "%s", ffd.cFileName);
        } else {
            snprintf(relative_path, sizeof(relative_path), "%s%s", sub_path, ffd.cFileName);
        }

        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* '_'-prefixed directories are never auto-run, so shared library
             * code can live at e.g. scripts/OnLoad/_lib/ and be pulled in via
             * Loader.LoadFile instead of executing on its own. Before this,
             * the recursive scan picked up everything, so there was no way to
             * keep a non-auto-run .lua anywhere under the folders. */
            if (ffd.cFileName[0] == '_') continue;
            char next_sub[MAX_PATH];
            snprintf(next_sub, sizeof(next_sub), "%s\\", relative_path);
            CollectScriptsRecursive(base_path, next_sub, list, count, max_count, depth + 1);
        } else {
            size_t len = strlen(ffd.cFileName);
            if (len > 4 && _stricmp(ffd.cFileName + len - 4, ".lua") == 0) {
                if (*count < max_count) {
                    snprintf(list[*count].path, sizeof(list[*count].path), "%s%s", base_path, relative_path);

                    strncpy(list[*count].rel_path, relative_path, sizeof(list[*count].rel_path) - 1);
                    list[*count].rel_path[sizeof(list[*count].rel_path) - 1] = '\0';

                    list[*count].load_order = -1;
                    list[*count].disabled   = 0;
                    (*count)++;
                } else {
                    g_scanDropped++;
                }
            }
        }
    } while (FindNextFileA(hFind, &ffd) != 0);

    FindClose(hFind);
}

static void EnsureLoaderIniHeader(const char* path) {
    FILE* f = fopen(path, "r");
    if (f) {
        fclose(f);
        return; // File already exists
    }
    
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "; lua_loader.ini — Lua Script Loader Configuration\n");
        fprintf(f, "; Define execution order for [OnBoot] and [OnLoad] (lowest numbers load first)\n");
        fprintf(f, "; Define hotkey triggers under [OnKey] (e.g. script.lua = F1 or script.lua = insert)\n");
        fprintf(f, ";\n");
        fprintf(f, "; Virtual Key codes reference: https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes\n");
        fprintf(f, "; Common keys: insert, delete, home, end, pageup, pagedown, space, enter, escape, F1..F12, A..Z, 0..9\n\n");
        fclose(f);
    }
}

static void ExtractDefaultKey(const char* file_path, char* out_key, size_t out_max) {
    strncpy(out_key, "unassigned", out_max);
    FILE* f = fopen(file_path, "r");
    if (!f) return;
    
    char line[256];
    int i;
    for (i = 0; i < 10; ++i) {
        if (!fgets(line, sizeof(line), f)) break;
        char* p = strstr(line, "KEYVAL");
        if (p) {
            char* eq = strchr(p, '=');
            if (eq) {
                char* q1 = strchr(eq, '"');
                if (!q1) q1 = strchr(eq, '\'');
                if (q1) {
                    q1++;
                    char* q2 = strchr(q1, '"');
                    if (!q2) q2 = strchr(q1, '\'');
                    if (q2 && (size_t)(q2 - q1) < out_max) {
                        size_t len = q2 - q1;
                        memcpy(out_key, q1, len);
                        out_key[len] = '\0';
                        break;
                    }
                }
            }
        }
    }
    fclose(f);
}

/* Modifier bits for a binding spec. */
#define KEYMOD_CTRL  0x01
#define KEYMOD_SHIFT 0x02
#define KEYMOD_ALT   0x04

/* Resolve a bare key name to a VK. Every mapping that existed pre-0.5.0 is
 * preserved byte-for-byte; the rest is purely additive, so no existing
 * lua_loader.ini changes meaning. */
static int ResolveKeyName(const char* name) {
    if (!name) return 0;
    if (_stricmp(name, "unassigned") == 0) return 0;

    if (name[0] != '\0' && name[1] == '\0') {
        char c = name[0];
        if (c >= 'a' && c <= 'z') return 0x41 + (c - 'a');
        if (c >= 'A' && c <= 'Z') return 0x41 + (c - 'A');
        if (c >= '0' && c <= '9') return 0x30 + (c - '0');
    }

    /* Numpad before the F-key test: "numpad1" must not be mistaken for
     * anything else, and the digit suffix parse is the same shape. */
    if (_strnicmp(name, "numpad", 6) == 0) {
        const char* s = name + 6;
        if (s[0] >= '0' && s[0] <= '9' && s[1] == '\0') return VK_NUMPAD0 + (s[0] - '0');
        if (_stricmp(s, "plus")     == 0 || _stricmp(s, "add")      == 0) return VK_ADD;
        if (_stricmp(s, "minus")    == 0 || _stricmp(s, "subtract") == 0) return VK_SUBTRACT;
        if (_stricmp(s, "multiply") == 0 || _stricmp(s, "star")     == 0) return VK_MULTIPLY;
        if (_stricmp(s, "divide")   == 0 || _stricmp(s, "slash")    == 0) return VK_DIVIDE;
        if (_stricmp(s, "decimal")  == 0 || _stricmp(s, "dot")      == 0) return VK_DECIMAL;
        return 0;
    }

    if ((name[0] == 'f' || name[0] == 'F') && name[1] >= '1' && name[1] <= '9') {
        int num = atoi(name + 1);
        if (num >= 1 && num <= 24) return 0x70 + (num - 1);
    }

    if (_stricmp(name, "insert") == 0) return VK_INSERT;
    if (_stricmp(name, "delete") == 0) return VK_DELETE;
    if (_stricmp(name, "home") == 0) return VK_HOME;
    if (_stricmp(name, "end") == 0) return VK_END;
    if (_stricmp(name, "pageup") == 0) return VK_PRIOR;
    if (_stricmp(name, "pagedown") == 0) return VK_NEXT;
    if (_stricmp(name, "space") == 0) return VK_SPACE;
    if (_stricmp(name, "enter") == 0 || _stricmp(name, "return") == 0) return VK_RETURN;
    if (_stricmp(name, "escape") == 0 || _stricmp(name, "esc") == 0) return VK_ESCAPE;
    if (_stricmp(name, "backspace") == 0) return VK_BACK;
    if (_stricmp(name, "tab") == 0) return VK_TAB;
    if (_stricmp(name, "shift") == 0) return VK_SHIFT;
    if (_stricmp(name, "ctrl") == 0 || _stricmp(name, "control") == 0) return VK_CONTROL;
    if (_stricmp(name, "alt") == 0) return VK_MENU;
    if (_stricmp(name, "left") == 0) return VK_LEFT;
    if (_stricmp(name, "up") == 0) return VK_UP;
    if (_stricmp(name, "right") == 0) return VK_RIGHT;
    if (_stricmp(name, "down") == 0) return VK_DOWN;

    /* --- added in v0.5.0 --- */
    /* Left/right-specific modifiers, for when "either shift" is too broad. */
    if (_stricmp(name, "lshift") == 0) return VK_LSHIFT;
    if (_stricmp(name, "rshift") == 0) return VK_RSHIFT;
    if (_stricmp(name, "lctrl")  == 0) return VK_LCONTROL;
    if (_stricmp(name, "rctrl")  == 0) return VK_RCONTROL;
    if (_stricmp(name, "lalt")   == 0) return VK_LMENU;
    if (_stricmp(name, "ralt")   == 0) return VK_RMENU;

    /* Lock / system keys. */
    if (_stricmp(name, "capslock")    == 0) return VK_CAPITAL;
    if (_stricmp(name, "numlock")     == 0) return VK_NUMLOCK;
    if (_stricmp(name, "scrolllock")  == 0) return VK_SCROLL;
    if (_stricmp(name, "pause")       == 0 || _stricmp(name, "break") == 0) return VK_PAUSE;
    if (_stricmp(name, "printscreen") == 0 || _stricmp(name, "prtsc") == 0) return VK_SNAPSHOT;

    /* Punctuation / OEM. "tilde" is the traditional console key and was
     * previously unbindable, which pushed people onto F-keys the browser
     * also claims. */
    if (_stricmp(name, "tilde") == 0 || _stricmp(name, "grave") == 0 ||
        _stricmp(name, "`")     == 0) return VK_OEM_3;
    if (_stricmp(name, "minus")     == 0 || _stricmp(name, "-") == 0) return VK_OEM_MINUS;
    if (_stricmp(name, "plus")      == 0 || _stricmp(name, "=") == 0 ||
        _stricmp(name, "equals")    == 0) return VK_OEM_PLUS;
    if (_stricmp(name, "lbracket")  == 0 || _stricmp(name, "[") == 0) return VK_OEM_4;
    if (_stricmp(name, "rbracket")  == 0 || _stricmp(name, "]") == 0) return VK_OEM_6;
    if (_stricmp(name, "backslash") == 0 || _stricmp(name, "\\") == 0) return VK_OEM_5;
    if (_stricmp(name, "semicolon") == 0 || _stricmp(name, ";") == 0) return VK_OEM_1;
    if (_stricmp(name, "quote")     == 0 || _stricmp(name, "'") == 0) return VK_OEM_7;
    if (_stricmp(name, "comma")     == 0 || _stricmp(name, ",") == 0) return VK_OEM_COMMA;
    if (_stricmp(name, "period")    == 0 || _stricmp(name, ".") == 0) return VK_OEM_PERIOD;
    if (_stricmp(name, "slash")     == 0 || _stricmp(name, "/") == 0) return VK_OEM_2;

    /* Extra mouse buttons — thumb buttons make good mod keys since the game
     * doesn't bind them. Note these are NOT focus-gated any differently
     * from keys; the same IsGameFocused() check applies. */
    if (_stricmp(name, "mouse4") == 0) return VK_XBUTTON1;
    if (_stricmp(name, "mouse5") == 0) return VK_XBUTTON2;

    return 0;
}

/* Parse a full binding spec: "F5", "ctrl+F5", "shift+alt+k", "numpad3".
 * Modifier prefixes are order-independent and case-insensitive. Returns the
 * base VK (0 if unrecognized) and writes the modifier mask to *out_mods.
 *
 * A bare modifier name still resolves as a base key ("shift" -> VK_SHIFT),
 * preserving pre-0.5.0 behavior for anyone who bound one directly. */
static int ResolveKeySpec(const char* spec, int* out_mods) {
    char   buf[64];
    char   tok[64];
    char*  p;
    char*  plus;
    size_t n;
    int    mods = 0;

    if (out_mods) *out_mods = 0;
    if (!spec) return 0;

    strncpy(buf, spec, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    p = buf;
    while (*p == ' ' || *p == '\t') ++p;
    n = strlen(p);
    while (n > 0 && (p[n - 1] == ' '  || p[n - 1] == '\t' ||
                     p[n - 1] == '\r' || p[n - 1] == '\n')) {
        p[--n] = '\0';
    }

    for (;;) {
        plus = strchr(p, '+');
        if (!plus) break;
        n = (size_t)(plus - p);
        if (n == 0 || n >= sizeof(tok)) break;   /* e.g. the "+" key itself */
        memcpy(tok, p, n);
        tok[n] = '\0';
        if      (_stricmp(tok, "ctrl")  == 0 || _stricmp(tok, "control") == 0) mods |= KEYMOD_CTRL;
        else if (_stricmp(tok, "shift") == 0) mods |= KEYMOD_SHIFT;
        else if (_stricmp(tok, "alt")   == 0) mods |= KEYMOD_ALT;
        else break;                              /* not a modifier token */
        p = plus + 1;
        while (*p == ' ') ++p;
    }

    if (out_mods) *out_mods = mods;
    return ResolveKeyName(p);
}

/* ------------------------------------------------------------------------ *
 * Script byte loading + source-encoding normalization
 *
 * ONE chokepoint for turning a .lua file on disk into bytes for the
 * executor, replacing the two near-identical fopen/fseek/malloc/fread
 * blocks that used to live in ExecuteLuaFolder and LoaderKeyThread.
 *
 * Why normalize: the engine's text renderers consume strings as single-byte
 * CP1252 — verified live against BOTH the native MrxGui.TextWidget font path
 * and the Scaleform .gfx path. A .lua saved as UTF-8 puts two bytes (C3 B6)
 * where the renderer wants one (F6), so "Möbius" renders as "MÃ¶bius". The
 * bridge is byte-transparent and always was; the mismatch is purely
 * authoring encoding vs what the renderer expects, so this is the right
 * layer to fix it.
 *
 * Two transformations, in order:
 *
 *   1. BOM strip — unconditional, even with normalization off. A UTF-8 BOM
 *      is a hard Lua 5.1 syntax error ("unexpected symbol"), and editors add
 *      one silently, so nothing can depend on it surviving. UTF-16 BOMs get
 *      an explicit log line instead of being fed to the parser as garbage.
 *
 *   2. UTF-8 -> CP1252 — only when the bytes are VALID UTF-8 (probed with
 *      MB_ERR_INVALID_CHARS) *and* contain a byte >= 0x80. Pure ASCII is
 *      bit-identical in both encodings so it is never touched, and an
 *      already-CP1252 file with high bytes almost never forms valid UTF-8,
 *      so it fails the probe and passes through untouched. That makes the
 *      auto-detect safe in both directions rather than a guess.
 *
 * Characters with no CP1252 representation (CJK, Cyrillic, checkmarks)
 * cannot survive the trip; those are logged per file so the author finds
 * out rather than silently shipping '?' glyphs.
 *
 * Known corner: a CP1252 file containing literal mojibake ("Ã©" = C3 A9) is
 * itself valid UTF-8 and will be folded to "é". That is almost certainly
 * repairing an earlier double-encode, and is vanishingly rare in real Lua
 * source. Set loader_source_encoding = 0 to opt out entirely.
 * ------------------------------------------------------------------------ */
static void NormalizeSourceEncoding(char** pbuf, size_t* plen,
                                    const char* what, const char* path) {
    char*  buf = *pbuf;
    size_t len = *plen;
    size_t i;
    int    has_high = 0;
    int    wlen, clen;
    wchar_t* wide;
    char*  conv;
    BOOL   used_default = FALSE;

    /* --- 1. BOM handling (runs even when normalization is switched off) --- */
    if (len >= 3 && (unsigned char)buf[0] == 0xEF &&
                    (unsigned char)buf[1] == 0xBB &&
                    (unsigned char)buf[2] == 0xBF) {
        memmove(buf, buf + 3, len - 3 + 1);
        len -= 3;
        m2_logf("[*] lua_bridge: %s: stripped UTF-8 BOM from %s "
                "(a BOM is a Lua 5.1 syntax error)", what, path);
    } else if (len >= 2 &&
               (((unsigned char)buf[0] == 0xFF && (unsigned char)buf[1] == 0xFE) ||
                ((unsigned char)buf[0] == 0xFE && (unsigned char)buf[1] == 0xFF))) {
        m2_logf("[!] lua_bridge: %s: %s looks UTF-16 encoded (BOM %02X %02X). "
                "Lua cannot parse that — re-save it as ANSI or UTF-8.",
                what, path, (unsigned char)buf[0], (unsigned char)buf[1]);
        *plen = len;
        return;
    }
    *plen = len;

    if (!g_loader_source_encoding_auto || len == 0) return;

    for (i = 0; i < len; ++i) {
        if ((unsigned char)buf[i] >= 0x80) { has_high = 1; break; }
    }
    if (!has_high) return;   /* pure ASCII — identical in both encodings */

    /* MB_ERR_INVALID_CHARS makes this fail on CP1252 input, which is exactly
     * the discriminator we want: success => it really is UTF-8. */
    wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buf, (int)len, NULL, 0);
    if (wlen <= 0) return;   /* not valid UTF-8 — assume CP1252 already */

    wide = (wchar_t*)malloc((size_t)wlen * sizeof(wchar_t));
    if (!wide) return;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, buf, (int)len,
                            wide, wlen) != wlen) {
        free(wide);
        return;
    }

    clen = WideCharToMultiByte(1252, 0, wide, wlen, NULL, 0, NULL, NULL);
    if (clen <= 0) { free(wide); return; }
    conv = (char*)malloc((size_t)clen + 1);
    if (!conv) { free(wide); return; }
    if (WideCharToMultiByte(1252, 0, wide, wlen, conv, clen,
                            "?", &used_default) != clen) {
        free(conv);
        free(wide);
        return;
    }
    conv[clen] = '\0';
    free(wide);

    /* Count the substitutions rather than just reporting that some happened —
     * "13 characters became '?'" is actionable, "some characters" is not.
     * Two linear scans on an already-linear operation; negligible. */
    if (used_default) {
        size_t qi, before_q = 0, after_q = 0;
        for (qi = 0; qi < len; ++qi)            if (buf[qi]  == '?') before_q++;
        for (qi = 0; qi < (size_t)clen; ++qi)   if (conv[qi] == '?') after_q++;
        m2_logf("[*] lua_bridge: %s: %s was UTF-8 — transcoded to CP1252 "
                "(%lu -> %lu bytes). %lu character(s) have no CP1252 equivalent "
                "and became '?'. Harmless if they are in comments; check any "
                "that are in displayed strings (the engine cannot render them "
                "either way).",
                what, path, (unsigned long)len, (unsigned long)clen,
                (unsigned long)(after_q > before_q ? after_q - before_q : 0));
    } else {
        m2_logf("[*] lua_bridge: %s: %s was UTF-8 — transcoded to CP1252 "
                "(%lu -> %lu bytes)", what, path,
                (unsigned long)len, (unsigned long)clen);
    }

    free(*pbuf);
    *pbuf = conv;
    *plen = (size_t)clen;
}

/* Read a .lua into a fresh NUL-terminated buffer, encoding-normalized.
 * Returns NULL on any failure (already logged). Caller frees. */
static char* LoadScriptBytes(const char* path, const char* what, size_t* out_len) {
    FILE*  f;
    long   sz;
    char*  buf;
    size_t n;

    *out_len = 0;
    f = fopen(path, "rb");
    if (!f) {
        m2_logf("[!] lua_bridge: %s: failed to open %s", what, path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Cap against the executor's own limit rather than a separate constant,
     * so "the loader accepted it" and "the executor will run it" can't
     * disagree. Oversize is now logged instead of silently skipped. */
    if (sz <= 0 || sz >= (long)sizeof(g_chunkSource.data)) {
        if (sz > 0) {
            m2_logf("[!] lua_bridge: %s: %s is %ld bytes, at/over the %lu-byte "
                    "chunk cap — skipped", what, path, sz,
                    (unsigned long)sizeof(g_chunkSource.data));
        }
        fclose(f);
        return NULL;
    }

    buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    n = fread(buf, 1, (size_t)sz, f);
    buf[n] = '\0';
    fclose(f);

    NormalizeSourceEncoding(&buf, &n, what, path);
    *out_len = n;
    return buf;
}

static void ExecuteLuaFolder(void* L, const char* folder_name) {
    char exe_dir[MAX_PATH];
    char folder_path[MAX_PATH];
    char loader_ini_path[MAX_PATH];
    char* slash;
    /* static rather than stack: 128 * sizeof(LuaScriptFile) is ~67 KB and
     * this runs on the game thread inside a detour frame, where the
     * remaining stack budget is not ours to assume. result_buf is also
     * bumped to PumpQueue's 16 KB — at 4 KB it silently truncated the
     * results and error messages of any script that returned much. Safe as
     * statics because of the nesting guard directly below. */
    static LuaScriptFile scripts[MAX_SCRIPTS];
    static char result_buf[16384];
    static int  in_folder = 0;
    int script_count = 0;
    int i;

    /* Re-entrancy guard. A script run from here can trigger a detour, and
     * GatedPump's OnLoad branch does not consult t_inBridgeExec — so OnLoad
     * could begin while OnBoot was still on the stack. That was always
     * fragile; with static buffers it would be outright corruption, so
     * refuse to nest. (GatedPump now also checks t_inBridgeExec, making this
     * belt-and-braces rather than the only defense.) */
    if (in_folder) {
        m2_logf("[!] lua_bridge: ExecuteLuaFolder(%s) re-entered while another "
                "folder was still running — skipped", folder_name);
        return;
    }
    in_folder = 1;

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(folder_path, sizeof(folder_path), "%sscripts\\%s\\", exe_dir, folder_name);
    m2_module_path(g_hModule, "lua_loader.ini", loader_ini_path, sizeof(loader_ini_path));
    EnsureLoaderIniHeader(loader_ini_path);

    g_scanDropped = 0;
    CollectScriptsRecursive(folder_path, "", scripts, &script_count, MAX_SCRIPTS, 0);
    if (g_scanDropped > 0) {
        m2_logf("[!] lua_bridge: scripts/%s/ holds more than %d .lua files — %d were "
                "silently ignored. Raise MAX_SCRIPTS or split the folder.",
                folder_name, MAX_SCRIPTS, g_scanDropped);
    }

    if (script_count == 0) {
        m2_logf("[*] lua_bridge: No scripts found in scripts/%s/", folder_name);
        in_folder = 0;
        return;
    }

    qsort(scripts, script_count, sizeof(LuaScriptFile), CompareAlphabetical);

    for (i = 0; i < script_count; ++i) {
        char order_val[64];
        int  order;

        /* Read as a string first so an explicit disable sentinel can be told
         * apart from a number. Deliberately NOT repurposing "0" for disable:
         * an existing ini could legitimately contain 0 and it currently runs
         * the script, so changing that meaning would break installs. */
        GetPrivateProfileStringA(folder_name, scripts[i].rel_path, "",
                                 order_val, sizeof(order_val), loader_ini_path);
        if (order_val[0] != '\0' &&
            (_stricmp(order_val, "off")      == 0 ||
             _stricmp(order_val, "no")       == 0 ||
             _stricmp(order_val, "disabled") == 0)) {
            m2_logf("[*] lua_bridge: %s script disabled by ini: %s",
                    folder_name, scripts[i].rel_path);
            scripts[i].disabled = 1;
            continue;
        }

        order = GetPrivateProfileIntA(folder_name, scripts[i].rel_path, -1, loader_ini_path);
        if (order == -1) {
            order = (i + 1) * 10;
            char order_str[32];
            snprintf(order_str, sizeof(order_str), "%d", order);
            WritePrivateProfileStringA(folder_name, scripts[i].rel_path, order_str, loader_ini_path);
        }
        scripts[i].load_order = order;
    }

    qsort(scripts, script_count, sizeof(LuaScriptFile), CompareLoadOrder);

    /* Re-register libs before running the batch — same reasoning as
     * PumpQueue: engine may have wiped _G between capture and now. */
    RegisterTcpLib(L);
    RegisterLoaderLib(L);
    RegisterMathLib(L);
    RunPolyfill(L);

    for (i = 0; i < script_count; ++i) {
        size_t code_len = 0;
        char*  code;

        if (scripts[i].disabled) continue;

        code = LoadScriptBytes(scripts[i].path, folder_name, &code_len);
        if (!code) continue;   /* already logged with a reason */

        m2_logf("[*] lua_bridge: Loading script (%s): %s (%lu bytes)",
                folder_name, scripts[i].rel_path, (unsigned long)code_len);

        /* Watchdog telemetry. Pre-0.5.0 this set t_inBridgeExec but NOT
         * g_bridgeExecStartTick, so the watchdog's hung-inside-exec path
         * (the whole point of v0.3.1) was blind to a hang in an OnBoot or
         * OnLoad script — precisely the case it was written to catch, since
         * a blocked game thread also stops the detours Path B relies on. */
        g_bridgeExecStartTick = GetTickCount();
        t_inBridgeExec = TRUE;
        LuaDoString(L, code, code_len, result_buf, sizeof(result_buf));
        t_inBridgeExec = FALSE;
        g_bridgeExecStartTick = 0;

        m2_logf("[+] lua_bridge: Script result: %s", result_buf);

        /* Mirror to the live channels. Pre-0.5.0 loader results went to the
         * .log only, so a connected REPL or browser client never saw an
         * OnBoot/OnLoad failure — you had to know to go read the file. */
        {
            char line[1024];
            _snprintf_s(line, sizeof(line), _TRUNCATE, "[%s] %s -> %s",
                        folder_name, scripts[i].rel_path, result_buf);
            LoaderLogLine(line);
        }

        free(code);

        /* NOTE: loader_delay_ms deliberately no longer sleeps here.
         * ExecuteLuaFolder runs ON the game thread (via CaptureL for OnBoot
         * and GatedPump for OnLoad), so Sleep()ing between scripts could
         * never "let the engine settle" the way the option's name suggests —
         * the engine IS the thread being slept. All it bought was a
         * loader_delay_ms * (scripts-1) freeze on top of the load. The key
         * is still parsed so existing inis stay valid; see the ini comment. */
    }

    in_folder = 0;
}

typedef struct {
    char  path[MAX_PATH];
    char  rel_path[MAX_PATH];
    char  key_name[64];
    int   vk_code;
    int   mods;              /* KEYMOD_* mask required alongside vk_code */
    int   was_down;
    DWORD last_fired_tick;   /* GetTickCount() at last successful queue-push */
    int   throttle_logged;   /* First cooldown throttle for this script logged? */
} LuaKeyScript;

static LuaKeyScript g_KeyScripts[MAX_SCRIPTS];
static int g_KeyScriptCount = 0;

/* Guards g_KeyScripts / g_KeyScriptCount. The polling thread reads the table
 * while InitializeKeyScripts may be rebuilding it — pre-0.5.0 that was only
 * safe because the scan ran exactly once, before the thread was spawned.
 * Now that a load-cycle re-arm can rescan, the table needs a lock. */
static CRITICAL_SECTION g_keyScriptMtx;
static int              g_keyScriptMtxInit = 0;
static int              g_keyThreadStarted = 0;

/* ------------------------------------------------------------------------ *
 * Key-event ring buffer — feeds Loader.PopKeyEvents().
 *
 * LoaderKeyEventThread samples GetAsyncKeyState across all 256 VK codes at
 * ~60 Hz, tracks per-key previous state, and appends the VK code to this
 * ring on each up→down edge. LuaLoaderPopKeyEvents drains the ring into
 * g_keyEventsTString and returns it to Lua as a string of raw VK bytes.
 *
 * Presses only (no release events). If a caller needs release edges,
 * we'd extend the encoding (pair of bytes or a companion buffer) — held
 * off for a first cut since chat / rebind / debug-console use cases only
 * need presses.
 *
 * Ring overflow policy: drop oldest. 128 events between polls covers
 * ~10 seconds of continuous 100 WPM typing; realistic clients poll much
 * faster than that.
 * ------------------------------------------------------------------------ */
static CRITICAL_SECTION g_keyEventMtx;
static int              g_keyEventMtxInit = 0;
static uint8_t          g_keyEventRing[KEYEVENT_BUFFER_SIZE];
static int              g_keyEventHead    = 0;   /* next write slot */
static int              g_keyEventTail    = 0;   /* next read slot */
static int              g_keyEventCount   = 0;   /* live events in ring */

static void KeyEventsPush(uint8_t vk) {
    if (!g_keyEventMtxInit) return;
    EnterCriticalSection(&g_keyEventMtx);
    g_keyEventRing[g_keyEventHead] = vk;
    g_keyEventHead = (g_keyEventHead + 1) % KEYEVENT_BUFFER_SIZE;
    if (g_keyEventCount < KEYEVENT_BUFFER_SIZE) {
        g_keyEventCount++;
    } else {
        /* Full — advance tail to drop oldest. Head has already lapped it. */
        g_keyEventTail = (g_keyEventTail + 1) % KEYEVENT_BUFFER_SIZE;
    }
    LeaveCriticalSection(&g_keyEventMtx);
}

static int KeyEventsPopAll(uint8_t* out, int max_out) {
    int n = 0;
    if (!g_keyEventMtxInit) return 0;
    EnterCriticalSection(&g_keyEventMtx);
    while (g_keyEventCount > 0 && n < max_out) {
        out[n++] = g_keyEventRing[g_keyEventTail];
        g_keyEventTail = (g_keyEventTail + 1) % KEYEVENT_BUFFER_SIZE;
        g_keyEventCount--;
    }
    LeaveCriticalSection(&g_keyEventMtx);
    return n;
}

/* Is the foreground window owned by our process? Uses process-ID match
 * rather than window-class matching, so it works across any game version
 * or multi-window layout without hardcoded strings. */
static BOOL IsGameFocused(void) {
    HWND fg;
    DWORD fg_pid = 0;
    fg = GetForegroundWindow();
    if (!fg) return FALSE;
    GetWindowThreadProcessId(fg, &fg_pid);
    return fg_pid == GetCurrentProcessId();
}

/* ------------------------------------------------------------------------ *
 * WatchdogThread — silent-stall self-healer. See the big design comment
 * above g_lastDetourFireTick for the full rationale.
 *
 * Wakes every ~2 seconds, decides based on three timestamps whether the
 * bridge is stuck, and if so does a comprehensive state reset. Cheap to
 * run: two InterlockedCompare-ish reads and a Sleep(2000) between checks
 * — measured under a microsecond per iteration, ~0.00005% of one core.
 * ------------------------------------------------------------------------ */
static DWORD WINAPI WatchdogThread(LPVOID param) {
    DWORD last_reset_tick = 0;
    (void)param;
    for (;;) {
        Sleep(2000);

        int stuck_ms = g_watchdog_stuck_ms;
        if (stuck_ms <= 0) continue;            /* watchdog disabled by ini */

        /* v0.5.0: no early-out on g_PendingScripts here any more. Path A
         * (hung inside exec) has to be able to fire for OnBoot/OnLoad
         * scripts, which run straight through ExecuteLuaFolder and never
         * enter the queue — so PendingScripts is 0 during exactly the hang
         * we most want to catch. Path B keeps the guard, since a queue stall
         * is meaningless with nothing queued. */

        DWORD now             = GetTickCount();
        DWORD since_detour    = now - g_lastDetourFireTick;
        DWORD since_attempt   = now - g_lastPumpAttemptTick;
        DWORD since_progress  = now - g_lastPumpProgressTick;
        DWORD since_last_reset = now - last_reset_tick;
        DWORD exec_start      = g_bridgeExecStartTick;
        int   fired           = 0;
        const char* diag      = NULL;

        /* Path A — hung-inside-exec: the game thread is blocked inside
         * LuaDoString (typically a native call from Lua that never returned
         * — SetSwfFile on a wedged D3D device, an infinite Lua loop, etc.).
         * When this happens, the same thread that runs our hooked detours
         * is stuck, so no more detours can fire and the since_detour guard
         * in Path B would incorrectly bail. Check this first, independent
         * of detour activity. */
        if (exec_start != 0 && (now - exec_start) > (DWORD)stuck_ms) {
            if (last_reset_tick == 0 || since_last_reset >= (DWORD)(stuck_ms / 2)) {
                diag  = "in-bridge-exec-not-returning (native call from Lua hung)";
                fired = 1;
                m2_logf("[!] lua_bridge:   exec_elapsed=%lums",
                        (unsigned long)(now - exec_start));
            }
        }

        /* Path B — detour-visible stuck states: hotWork stuck at 0 or the
         * pump entering but not draining. Requires detours to have fired
         * recently to distinguish real stalls from legitimate pauses. */
        if (!fired) {
            if (g_PendingScripts <= 0) continue;  /* nothing queued to stall on */
            if (since_detour > 2000) continue;
            if (since_progress < (DWORD)stuck_ms) continue;
            if (last_reset_tick != 0 && since_last_reset < (DWORD)(stuck_ms / 2)) continue;

            if (since_attempt > (DWORD)stuck_ms) {
                diag = "hotWork-stuck-at-0 (GatedPump not entering slow path)";
            } else {
                diag = "PumpQueue-not-draining (t_inBridgeExec stuck or L invalid)";
            }
            fired = 1;
        }

        m2_logf("[!] lua_bridge: WATCHDOG stuck-state detected — pattern: %s", diag);
        m2_logf("[!] lua_bridge:   hotWork=%d PendingScripts=%d "
                "since_detour=%lums since_attempt=%lums since_progress=%lums",
                (int)g_hotWork, (int)g_PendingScripts,
                (unsigned long)since_detour,
                (unsigned long)since_attempt,
                (unsigned long)since_progress);
        m2_logf("[!] lua_bridge:   g_LuaState=%p", g_LuaState);

        /* Full-hammer reset. All three actions are individually safe.
         * Non-escalating: cost of over-resetting is one extra re-capture
         * cycle on the next detour, no user-visible harm. */
        g_hotWork = 1;
        InterlockedExchange(&g_watchdogForceClearTLS, 1);
        g_LuaState = NULL;
        memset(g_seenL, 0, sizeof(g_seenL));
        last_reset_tick = now;

        m2_logf("[*] lua_bridge: WATCHDOG reset applied "
                "(hotWork=1, force-clear TLS, clear g_LuaState + g_seenL)");
    }
    return 0;
}

static DWORD WINAPI LoaderKeyEventThread(LPVOID param) {
    static uint8_t prev_down[256];
    int vk;
    (void)param;
    memset(prev_down, 0, sizeof(prev_down));
    for (;;) {
        /* Sample state every tick regardless of focus so prev_down stays
         * accurate. Only the push is focus-gated — this avoids ghost
         * events when the user Alt+Tabs while holding a key: the sampler
         * observes the eventual up→down while unfocused (no push), then
         * the follow-on down→up on refocus is a real edge with fresh
         * state. */
        BOOL focused = IsGameFocused();
        for (vk = 0; vk < 256; ++vk) {
            SHORT s = GetAsyncKeyState(vk);
            uint8_t is_down = (s & 0x8000) ? 1 : 0;
            if (is_down && !prev_down[vk] && focused) {
                KeyEventsPush((uint8_t)vk);
            }
            prev_down[vk] = is_down;
        }
        Sleep(16); /* ~60 Hz — 3–4× the highest realistic typing rate */
    }
    return 0;
}

/* Do the currently-held modifiers exactly match `mods`?
 *
 * Exact match (not "at least"), so `F5` and `ctrl+F5` can be bound to
 * different scripts without both firing. The one behavior difference for
 * pre-0.5.0 bindings: a plain `F5` binding no longer fires while ctrl/shift/
 * alt is held. That is almost never intended, and
 * loader_onkey_exact_modifiers = 0 restores the old "ignore modifiers"
 * matching for anyone who relied on it. */
static BOOL ModifiersMatch(int mods) {
    int held = 0;
    if (GetAsyncKeyState(VK_CONTROL) & 0x8000) held |= KEYMOD_CTRL;
    if (GetAsyncKeyState(VK_SHIFT)   & 0x8000) held |= KEYMOD_SHIFT;
    if (GetAsyncKeyState(VK_MENU)    & 0x8000) held |= KEYMOD_ALT;
    if (!g_loader_onkey_exact_modifiers) return (held & mods) == mods;
    return held == mods;
}

static DWORD WINAPI LoaderKeyThread(LPVOID param) {
    (void)param;
    for (;;) {
        int i;

        /* Focus gate. LoaderKeyEventThread (which feeds Loader.PopKeyEvents)
         * has always dropped keystrokes while the game is in the background;
         * this thread did not, so a browser F5/F11 or anything typed into
         * another app fired game scripts behind your back. Same predicate,
         * same reasoning — just applied to the path that runs whole .lua
         * files. Sampled once per tick rather than per script. */
        if (g_loader_onkey_require_focus && !IsGameFocused()) {
            /* Clear edge state so refocusing with a key already held does
             * not immediately fire on a stale up->down transition. */
            for (i = 0; i < g_KeyScriptCount; ++i) g_KeyScripts[i].was_down = 0;
            Sleep(33);
            continue;
        }

        if (g_keyScriptMtxInit) EnterCriticalSection(&g_keyScriptMtx);
        for (i = 0; i < g_KeyScriptCount; ++i) {
            int vk = g_KeyScripts[i].vk_code;
            if (vk > 0 && vk < 256) {
                int is_down = (GetAsyncKeyState(vk) & 0x8000) != 0;
                if (is_down && !ModifiersMatch(g_KeyScripts[i].mods)) {
                    /* Right key, wrong modifier set. Treat as not-pressed so
                     * releasing the modifier and pressing again re-triggers. */
                    g_KeyScripts[i].was_down = 0;
                    continue;
                }
                if (is_down) {
                    if (!g_KeyScripts[i].was_down) {
                        g_KeyScripts[i].was_down = 1;

                        /* Per-script cooldown gate. If the same script fires
                         * again inside `loader_onkey_cooldown_ms` of its last
                         * queue-push, skip. Purpose: keep non-reentrant
                         * gameplay scripts (menus, cheats that mutate engine
                         * state) safe from human hammer-tapping the hotkey.
                         * DWORD subtraction handles GetTickCount wrap
                         * correctly (~49.7-day cycle). Log the first throttle
                         * per script per session so users learn about it,
                         * then stay silent to avoid log spam. */
                        if (g_loader_onkey_cooldown_ms > 0 &&
                            g_KeyScripts[i].last_fired_tick != 0) {
                            DWORD now     = GetTickCount();
                            DWORD elapsed = now - g_KeyScripts[i].last_fired_tick;
                            if (elapsed < (DWORD)g_loader_onkey_cooldown_ms) {
                                if (!g_KeyScripts[i].throttle_logged) {
                                    g_KeyScripts[i].throttle_logged = 1;
                                    m2_logf("[!] lua_bridge: OnKey '%s' throttled (%s "
                                            "re-fired %lu ms after last press; cooldown = %d ms). "
                                            "Further throttles on this script this session will be silent.",
                                            g_KeyScripts[i].key_name,
                                            g_KeyScripts[i].rel_path,
                                            (unsigned long)elapsed,
                                            g_loader_onkey_cooldown_ms);
                                }
                                continue;
                            }
                        }

                        /* Explicit existence check before fopen. If the .lua
                         * file was deleted after boot (or the ini has a stale
                         * mapping to something that never existed), skip
                         * cleanly rather than proceeding down the read+queue
                         * path — reports have shown that path can destabilize
                         * the game when the file is gone. */
                        DWORD attrs = GetFileAttributesA(g_KeyScripts[i].path);
                        if (attrs == INVALID_FILE_ATTRIBUTES ||
                            (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                            m2_logf("[!] lua_bridge: OnKey '%s' bound to missing file: %s (skipped)",
                                    g_KeyScripts[i].key_name, g_KeyScripts[i].rel_path);
                            continue;
                        }

                        g_KeyScripts[i].last_fired_tick = GetTickCount();

                        /* Read + queue. Goes through the shared chokepoint so
                         * an OnKey script gets the same BOM strip and
                         * UTF-8->CP1252 normalization as OnBoot/OnLoad. Still
                         * re-read from disk on every press, which is what
                         * makes editing a bound script hot-reload. */
                        {
                            size_t code_len = 0;
                            char*  code = LoadScriptBytes(g_KeyScripts[i].path,
                                                          "OnKey", &code_len);
                            if (code) {
                                m2_logf("[*] lua_bridge: OnKey hotkey '%s' pressed. Queuing script %s",
                                        g_KeyScripts[i].key_name, g_KeyScripts[i].rel_path);
                                InQueuePush(code, code_len, 0);
                                free(code);
                            }
                        }
                    }
                } else {
                    g_KeyScripts[i].was_down = 0;
                }
            }
        }
        if (g_keyScriptMtxInit) LeaveCriticalSection(&g_keyScriptMtx);
        Sleep(33); // 30Hz polling rate
    }
    return 0;
}

/* Scan scripts/OnKey/, resolve bindings, and swap the table in.
 *
 * Safe to call repeatedly as of v0.5.0 (the load-cycle re-arm does exactly
 * that, so a .lua added mid-session gets picked up without a restart):
 *   - builds into a scratch table and swaps under g_keyScriptMtx, so the
 *     polling thread never sees a half-built table;
 *   - spawns the polling thread only once, however many times it is called.
 *     Pre-0.5.0 the CreateThread was unconditional, so a second call would
 *     have left two pollers running and fired every hotkey twice. */
static void InitializeKeyScripts(void) {
    char exe_dir[MAX_PATH];
    char folder_path[MAX_PATH];
    char loader_ini_path[MAX_PATH];
    char* slash;
    int i, j;
    /* static: ~67 KB + ~78 KB is far too much stack for a detour frame.
     * Serialized by construction — only ever called from CaptureL on the
     * game thread. */
    static LuaScriptFile temp_files[MAX_SCRIPTS];
    static LuaKeyScript  rebuilt[MAX_SCRIPTS];
    int file_count = 0;
    int built = 0;

    GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
    slash = strrchr(exe_dir, '\\');
    if (slash) *(slash + 1) = '\0';

    snprintf(folder_path, sizeof(folder_path), "%sscripts\\OnKey\\", exe_dir);
    m2_module_path(g_hModule, "lua_loader.ini", loader_ini_path, sizeof(loader_ini_path));
    EnsureLoaderIniHeader(loader_ini_path);

    g_scanDropped = 0;
    CollectScriptsRecursive(folder_path, "", temp_files, &file_count, MAX_SCRIPTS, 0);
    if (g_scanDropped > 0) {
        m2_logf("[!] lua_bridge: scripts/OnKey/ holds more than %d .lua files — %d "
                "were silently ignored.", MAX_SCRIPTS, g_scanDropped);
    }

    if (file_count == 0) {
        m2_logf("[*] lua_bridge: No scripts found in scripts/OnKey/");
        if (g_keyScriptMtxInit) EnterCriticalSection(&g_keyScriptMtx);
        g_KeyScriptCount = 0;
        if (g_keyScriptMtxInit) LeaveCriticalSection(&g_keyScriptMtx);
        return;
    }

    qsort(temp_files, file_count, sizeof(LuaScriptFile), CompareAlphabetical);

    for (i = 0; i < file_count && built < MAX_SCRIPTS; ++i) {
        char key_name[64];
        int  mods = 0;
        int  vk;

        GetPrivateProfileStringA("OnKey", temp_files[i].rel_path, "", key_name,
                                 sizeof(key_name), loader_ini_path);

        if (key_name[0] == '\0') {
            ExtractDefaultKey(temp_files[i].path, key_name, sizeof(key_name));
            WritePrivateProfileStringA("OnKey", temp_files[i].rel_path, key_name,
                                       loader_ini_path);
        }

        if (_stricmp(key_name, "off")      == 0 ||
            _stricmp(key_name, "no")       == 0 ||
            _stricmp(key_name, "disabled") == 0) {
            m2_logf("[*] lua_bridge: OnKey script disabled by ini: %s",
                    temp_files[i].rel_path);
            continue;
        }

        vk = ResolveKeySpec(key_name, &mods);

        /* Unrecognized names used to resolve silently to VK 0 and simply
         * never fire, which is a miserable thing to debug — a typo like
         * "pgup" or "F13" looked identical to a working binding in the log. */
        if (vk == 0 && _stricmp(key_name, "unassigned") != 0) {
            m2_logf("[!] lua_bridge: OnKey '%s' for %s is not a recognized key name "
                    "— this script will NEVER fire. Try a letter/digit, F1..F24, "
                    "numpad0..9, insert/delete/home/end/pageup/pagedown, tilde, "
                    "or a ctrl+/shift+/alt+ combination.",
                    key_name, temp_files[i].rel_path);
        }

        strncpy(rebuilt[built].path, temp_files[i].path, sizeof(rebuilt[built].path) - 1);
        rebuilt[built].path[sizeof(rebuilt[built].path) - 1] = '\0';

        strncpy(rebuilt[built].rel_path, temp_files[i].rel_path, sizeof(rebuilt[built].rel_path) - 1);
        rebuilt[built].rel_path[sizeof(rebuilt[built].rel_path) - 1] = '\0';

        strncpy(rebuilt[built].key_name, key_name, sizeof(rebuilt[built].key_name) - 1);
        rebuilt[built].key_name[sizeof(rebuilt[built].key_name) - 1] = '\0';

        rebuilt[built].vk_code         = vk;
        rebuilt[built].mods            = mods;
        rebuilt[built].was_down        = 0;
        rebuilt[built].last_fired_tick = 0;
        rebuilt[built].throttle_logged = 0;

        m2_logf("[*] lua_bridge: Registered OnKey script: scripts/OnKey/%s bound to '%s' (VK 0x%X mods 0x%X)",
                temp_files[i].rel_path, key_name, vk, mods);

        built++;
    }

    if (i < file_count) {
        m2_logf("[!] lua_bridge: scripts/OnKey/ has more than %d scripts — %d were "
                "not registered", MAX_SCRIPTS, file_count - i);
    }

    /* Warn about shared bindings. Multiple scripts on one key is a supported
     * feature, but it is also what an accidental KEYVAL collision looks like,
     * and nothing used to say so. */
    for (i = 0; i < built; ++i) {
        for (j = i + 1; j < built; ++j) {
            if (rebuilt[i].vk_code != 0 &&
                rebuilt[i].vk_code == rebuilt[j].vk_code &&
                rebuilt[i].mods    == rebuilt[j].mods) {
                m2_logf("[!] lua_bridge: OnKey '%s' is bound to BOTH %s and %s — "
                        "both will run on every press. Intentional? If not, "
                        "change one binding in lua_loader.ini.",
                        rebuilt[i].key_name, rebuilt[i].rel_path, rebuilt[j].rel_path);
            }
        }
    }

    if (g_keyScriptMtxInit) EnterCriticalSection(&g_keyScriptMtx);
    memcpy(g_KeyScripts, rebuilt, (size_t)built * sizeof(LuaKeyScript));
    g_KeyScriptCount = built;
    if (g_keyScriptMtxInit) LeaveCriticalSection(&g_keyScriptMtx);

    if (!g_keyThreadStarted) {
        g_keyThreadStarted = 1;
        CreateThread(NULL, 0, LoaderKeyThread, NULL, 0, NULL);
        m2_logf("[*] lua_bridge: Spawning background hotkey polling thread");
    } else {
        m2_logf("[*] lua_bridge: OnKey table rescanned (%d scripts); polling thread "
                "already running", built);
    }
}

static void RegisterTcpLib(void* L) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD func_addr = (DWORD)base + g_rvas->luaL_register;
    const char* libname = "Tcp";
    const luaL_Reg* table = tcp_lib;

    __asm__ volatile (
        "push %2\n\t"        // Push table pointer (stack arg)
        "call *%3\n\t"       // Call luaL_register
        "add $4, %%esp\n\t"  // Clean stack (4 bytes)
        :
        : "c"(L), "a"(libname), "r"(table), "r"(func_addr)
        : "edx", "memory"
    );
    static int logged = 0;
    if (!logged) { logged = 1; m2_logf("[*] lua_bridge: Registered Tcp.Send globally"); }
}

/* ------------------------------------------------------------------------ *
 * Expose Loader.Printf to Lua — a lightweight replacement for the engine's
 * Debug.Printf, aimed at custom scripts that want their own uncluttered log.
 * Debug.Printf is called thousands of times per frame from stock scripts, so
 * routing script debug output there gets drowned out. Loader.Printf writes
 * to a dedicated <module dir>\lua_loader_printf.log instead.
 *
 * Usage from Lua:
 *   Loader.Printf("[give_cash] +10000 cash")
 *   Loader.Printf("tag", "value")   -- multiple string args join tab-separated
 * ------------------------------------------------------------------------ */
static HANDLE            g_LoaderPrintfLog = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION  g_LoaderPrintfMtx;
static int               g_LoaderPrintfMtxInit = 0;

static void InitLoaderPrintfLog(void) {
    char path[MAX_PATH];
    if (!g_LoaderPrintfMtxInit) {
        InitializeCriticalSection(&g_LoaderPrintfMtx);
        g_LoaderPrintfMtxInit = 1;
    }
    m2_module_path(g_hModule, "lua_loader_printf.log", path, sizeof(path));
    g_LoaderPrintfLog = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ,
                                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_LoaderPrintfLog == INVALID_HANDLE_VALUE) {
        m2_logf("[!] lua_bridge: failed to open %s GLE=%lu",
                path, (unsigned long)GetLastError());
    } else {
        m2_logf("[*] lua_bridge: Loader.Printf log opened at %s", path);
    }
}

static int LuaLoaderPrintf(void* L) {
    char msg[2048];
    int  joined;
    DWORD written;
    size_t len;

    if (g_LoaderPrintfLog == INVALID_HANDLE_VALUE) return 0;

    /* Join every string arg tab-separated (mirrors Lua's print()). Non-string
     * args are silently skipped — matches m2_lua_join_strings semantics.
     * On extraction failure, still emit a marker line so the log tells us
     * the C fn was reached rather than staying silent. */
    joined = m2_lua_join_strings(L, msg, (int)sizeof(msg) - 32);
    if (joined <= 0) {
        len = (size_t)_snprintf_s(msg, sizeof(msg), _TRUNCATE,
                                  "[Loader.Printf: no string args (joined=%d)]", joined);
    } else {
        len = strlen(msg);
    }
    if (len > sizeof(msg) - 2) len = sizeof(msg) - 2;
    msg[len++] = '\r';
    msg[len++] = '\n';

    /* NB: no FlushFileBuffers here — it forces a synchronous disk sync
     * that can stall the game's Lua thread for seconds (AV, HDD, cloud
     * sync). WriteFile alone commits to the OS write cache, which is
     * enough for a live debug log; entries survive normal shutdown. */
    EnterCriticalSection(&g_LoaderPrintfMtx);
    WriteFile(g_LoaderPrintfLog, msg, (DWORD)len, &written, NULL);
    LeaveCriticalSection(&g_LoaderPrintfMtx);

    /* Also mirror this line to the connected WS client as
     * {type:"log",line:"…"} — the live console feed. Strip the trailing
     * \r\n we appended for the log file; the WS side is line-oriented
     * on the receiver so we ship the line contents only. No-op if no
     * WS client is connected. */
    {
        size_t body_len = len;
        if (body_len >= 2 && msg[body_len - 2] == '\r') body_len -= 2;
        else if (body_len >= 1 && msg[body_len - 1] == '\n') body_len -= 1;
        ws_broadcast_typed_line("log", msg, body_len);
    }
    return 0;
}

/* Emit one line on the same two live channels Loader.Printf uses — the
 * lua_loader_printf.log file and the WS {type:"log"} feed. Lets the loader
 * surface OnBoot/OnLoad script results to whatever is connected instead of
 * burying them in lua_bridge_DEV.log. */
static void LoaderLogLine(const char* line) {
    char   msg[2048];
    DWORD  written;
    size_t len;

    if (!line) return;
    len = strlen(line);
    if (len > sizeof(msg) - 3) len = sizeof(msg) - 3;
    memcpy(msg, line, len);

    if (g_LoaderPrintfLog != INVALID_HANDLE_VALUE && g_LoaderPrintfMtxInit) {
        msg[len]     = '\r';
        msg[len + 1] = '\n';
        EnterCriticalSection(&g_LoaderPrintfMtx);
        WriteFile(g_LoaderPrintfLog, msg, (DWORD)(len + 2), &written, NULL);
        LeaveCriticalSection(&g_LoaderPrintfMtx);
    }
    /* WS side is length-delimited, so ship the body without the CRLF. */
    ws_broadcast_typed_line("log", msg, len);
}

/* ------------------------------------------------------------------------ *
 * Loader.GetKeyboardState() — return a 256-byte string where byte[vk] has
 * its high bit set iff virtual-key `vk` is currently pressed. Lua-side:
 *   local s = Loader.GetKeyboardState()
 *   if string.byte(s, VK_SHIFT + 1) >= 128 then ... end
 *
 * Uses GetAsyncKeyState (physical, system-wide) NOT Win32 GetKeyboardState
 * (per-thread message-queue snapshot — would return stale/zero from the
 * game thread). Same call LoaderKeyThread already trusts.
 *
 * Pushes the hand-crafted g_kbStateTString directly onto L->top and
 * advances top by one TValue slot. Safe because the engine reserves at
 * least LUA_MINSTACK slots for every C function frame. See the
 * KeyboardStateTString definition for the buffer-reuse caveats.
 * ------------------------------------------------------------------------ */
static int LuaLoaderGetKeyboardState(void* L) {
    /* Fast path — see the note on LuaLoaderIsKeyDown below. */
    char* Lc  = (char*)L;
    char* top = *(char**)(Lc + LUA_OFF_TOP);
    int i;

    for (i = 0; i < 256; ++i) {
        SHORT s = GetAsyncKeyState(i);
        g_kbStateTString.data[i] = (s & 0x8000) ? (char)0x80 : (char)0x00;
    }

    *(void**)top                             = &g_kbStateTString;
    *(int*)(top + TVALUE_TT_OFFSET)          = LUA_TSTRING;
    *(char**)(Lc + LUA_OFF_TOP)              = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Loader.IsKeyDown(vk) — beginner-friendly single-key predicate.
 * Lua-side:
 *   if Loader.IsKeyDown(0x10) then ... end   -- Shift held?
 *
 * Same GetAsyncKeyState-based state as Loader.GetKeyboardState, just
 * scoped to one VK code and returning a plain boolean. Cheaper if the
 * caller only needs one key; also easier to teach.
 * ------------------------------------------------------------------------ */
static int LuaLoaderIsKeyDown(void* L) {
    /* Fast path — no SafeProbe / LooksLikeLuaState. When Lua's own
     * dispatch calls a registered C function, L / base / top are
     * engine-guaranteed valid; reserved LUA_MINSTACK slots at top mean
     * we can push one return value without checking. Dropping the checks
     * saves 6+ VirtualQuery syscalls per call (~15µs → ~1µs). Safe
     * because this function is only reachable via luaL_register-
     * installed dispatch, never called with a caller-supplied L. Same
     * treatment applied below to GetKeyboardState / IsGameFocused /
     * PopKeyEvents / ClearKeyEvents / math.*. */
    char* Lc   = (char*)L;
    char* base = *(char**)(Lc + LUA_OFF_BASE);
    char* top  = *(char**)(Lc + LUA_OFF_TOP);
    int   vk;
    SHORT ks;

    if (!base || (top - base) < TVALUE_SIZE) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;

    vk = (int)*(float*)base;  /* lua_Number = float in this build */
    if (vk < 0 || vk > 255) return 0;

    ks = GetAsyncKeyState(vk);

    *(int*)top                       = (ks & 0x8000) ? 1 : 0;
    *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TBOOLEAN;
    *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Loader.PopKeyEvents() — drain the C-side event ring into a string of
 * raw VK codes (one byte per event), in press order. Empty string if
 * nothing new since last call.
 *
 *   local events = Loader.PopKeyEvents()
 *   for i=1,#events do
 *       local vk = string.byte(events, i)
 *       -- ...dispatch...
 *   end
 *
 * The ring is filled by LoaderKeyEventThread at ~60 Hz across all 256
 * VKs, so a poll-once-per-frame client never misses a keypress the way
 * client-side edge detection on GetKeyboardState does.
 * ------------------------------------------------------------------------ */
static int LuaLoaderPopKeyEvents(void* L) {
    /* Fast path — see the note on LuaLoaderIsKeyDown below. */
    char* Lc  = (char*)L;
    char* top = *(char**)(Lc + LUA_OFF_TOP);
    int   n;

    n = KeyEventsPopAll((uint8_t*)g_keyEventsTString.data, KEYEVENT_BUFFER_SIZE);
    g_keyEventsTString.len = (uint32_t)n;

    *(void**)top                     = &g_keyEventsTString;
    *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TSTRING;
    *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Loader.ClearKeyEvents() — drop every buffered event without returning
 * them. Useful right when a chat input opens: call this once, then wait
 * for the user to type, then PopKeyEvents(). Same effect as calling
 * PopKeyEvents() and discarding the result — this just reads more
 * clearly at the call site.
 * ------------------------------------------------------------------------ */
static int LuaLoaderClearKeyEvents(void* L) {
    (void)L;
    if (!g_keyEventMtxInit) return 0;
    EnterCriticalSection(&g_keyEventMtx);
    g_keyEventCount = 0;
    g_keyEventHead  = 0;
    g_keyEventTail  = 0;
    LeaveCriticalSection(&g_keyEventMtx);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * Loader.IsGameFocused() — is the foreground window owned by our
 * process? True for any window belonging to the game (main or dialog);
 * false when Alt+Tabbed to another app.
 *
 * PopKeyEvents already gates its captures on this internally. Exposed
 * here so callers can gate their own logic (e.g. skip heavy work while
 * backgrounded, or wrap raw IsKeyDown queries with focus-awareness).
 * ------------------------------------------------------------------------ */
static int LuaLoaderIsGameFocused(void* L) {
    /* Fast path — see the note on LuaLoaderIsKeyDown below. */
    char* Lc  = (char*)L;
    char* top = *(char**)(Lc + LUA_OFF_TOP);

    *(int*)top                       = IsGameFocused() ? 1 : 0;
    *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TBOOLEAN;
    *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Persistence — Loader.SaveVar(key, value) / Loader.LoadVar(key)
 *
 * Simple key-value store that survives game restarts. Values are numbers,
 * strings, or booleans. Stored on disk as `lua_loader_data.ini` next to
 * the .asi, in a human-readable format that users can hand-edit if they
 * want to reset a value:
 *
 *   ; auto-managed by lua-bridge
 *   ; Format: key=type:value  (n=number, s=string, b=boolean 0/1)
 *   MasterCheatMenu_Progress=n:18
 *   MyMod_Setting=s:hardcore
 *   MyMod_TutorialSeen=b:1
 *
 * Namespacing: single flat namespace shared by every script. Wiki docs
 * tell script authors to prefix keys with their script name.
 *
 * Type preservation: SaveVar accepts number/string/boolean, LoadVar
 * returns the same Lua type it was saved as (or nil if the key isn't
 * set). Numbers and booleans are stored inline; strings are heap-
 * allocated FixedTStrings with FIXEDBIT set (GC-ignored, same trick as
 * g_kbStateTString). New string values allocate fresh — old strings are
 * intentionally leaked so any Lua variable still holding a reference to
 * a previous LoadVar result stays valid. Bounded by SaveVar call rate
 * (thousands of calls per session is still ~100 KB, tolerable).
 *
 * Crash safety: SaveVar writes to `lua_loader_data.ini.tmp` and then
 * MoveFileExA(MOVEFILE_REPLACE_EXISTING) — a crash mid-write leaves the
 * old file intact rather than truncating.
 * ------------------------------------------------------------------------ */
#define DATA_KEY_MAX      128
#define DATA_STR_MAX      2048
#define DATA_TYPE_NUMBER  'n'
#define DATA_TYPE_STRING  's'
#define DATA_TYPE_BOOL    'b'

typedef struct DataEntry {
    char    key[DATA_KEY_MAX];
    char    type;      /* 'n' / 's' / 'b' */
    float   num_val;
    int     bool_val;
    void*   str_tstring;   /* FixedTString ptr for type='s', NULL otherwise */
    struct DataEntry* next;
} DataEntry;

static DataEntry*        g_dataDict     = NULL;
static CRITICAL_SECTION  g_dataMtx;
static int               g_dataMtxInit  = 0;
static int               g_dataLoaded   = 0;

/* Allocate a fresh Lua-visible TString for a value. Uses the same layout
 * trick as g_kbStateTString / g_chunkSource — matches Pandemic's packed
 * TValue, marked FIXEDBIT so the engine's GC leaves it alone.
 *
 * Deliberately leaked (never freed). Each SaveVar overwriting an existing
 * key allocates a NEW TString rather than mutating the existing one, so
 * any Lua variable holding a reference to a previous LoadVar result
 * remains valid with the old value. Bounded by write frequency — 1000
 * SaveVar calls with 100-char strings = 100 KB, fine for a game session. */
#pragma pack(push, 4)
typedef struct DataTString {
    void*    next_gc;
    uint8_t  tt;
    uint8_t  marked;
    uint8_t  reserved;
    uint8_t  _pad;
    uint32_t hash;
    uint32_t len;
    char     data[1];   /* flexible; actual allocation is sizeof(struct) + len */
} DataTString;
#pragma pack(pop)

static DataTString* AllocDataTString(const char* value, size_t len) {
    DataTString* ts = (DataTString*)malloc(sizeof(DataTString) + len);
    if (!ts) return NULL;
    ts->next_gc = NULL;
    ts->tt      = (uint8_t)LUA_TSTRING;
    ts->marked  = 0x20 | 0x01;   /* FIXEDBIT | WHITE0BIT */
    ts->reserved= 0;
    ts->_pad    = 0;
    ts->hash    = 0xDA7A0000u | (uint32_t)(len & 0xFFFF);
    ts->len     = (uint32_t)len;
    memcpy(ts->data, value, len);
    return ts;
}

/* Value escaping for the on-disk format. Only backslash, CR, LF need
 * quoting since we use `=` and `:` as delimiters but strip them on
 * parse; user string values containing `=` or `:` round-trip fine. */
static void EscapeValue(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    while (*in && o + 3 < out_size) {
        char c = *in++;
        if (c == '\\')      { out[o++] = '\\'; out[o++] = '\\'; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n';  }
        else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r';  }
        else                { out[o++] = c; }
    }
    out[o] = '\0';
}

static void UnescapeValue(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    while (*in && o + 1 < out_size) {
        char c = *in++;
        if (c == '\\' && *in) {
            char n = *in++;
            if      (n == 'n')  out[o++] = '\n';
            else if (n == 'r')  out[o++] = '\r';
            else if (n == '\\') out[o++] = '\\';
            else                out[o++] = n;      /* unknown escape — pass through */
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
}

/* Look up an entry by key. Caller must hold g_dataMtx. Returns NULL if not present. */
static DataEntry* DataDictFind(const char* key) {
    DataEntry* e = g_dataDict;
    while (e) {
        if (strcmp(e->key, key) == 0) return e;
        e = e->next;
    }
    return NULL;
}

/* Insert or update. Caller must hold g_dataMtx. `type` is 'n'/'s'/'b'. */
static DataEntry* DataDictUpsert(const char* key, char type) {
    DataEntry* e = DataDictFind(key);
    if (!e) {
        e = (DataEntry*)malloc(sizeof(DataEntry));
        if (!e) return NULL;
        memset(e, 0, sizeof(*e));
        strncpy(e->key, key, DATA_KEY_MAX - 1);
        e->key[DATA_KEY_MAX - 1] = '\0';
        e->next = g_dataDict;
        g_dataDict = e;
    }
    e->type = type;
    /* Don't null out fields other than the one being written — old
     * str_tstring stays valid for any Lua vars still referencing it. */
    return e;
}

static void PersistDataFileLocked(void) {
    char ini_path[MAX_PATH];
    char tmp_path[MAX_PATH];
    FILE* f;
    DataEntry* e;

    m2_module_path(g_hModule, "lua_loader_data.ini", ini_path, sizeof(ini_path));
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", ini_path);

    f = fopen(tmp_path, "w");
    if (!f) return;

    fputs("; lua_loader_data.ini — auto-managed by lua-bridge Loader.SaveVar/LoadVar\n"
          "; Format: key=type:value   (n=number, s=string, b=boolean 0/1)\n"
          "; Safe to hand-edit while the game is not running; edits made while\n"
          "; the game is running will be overwritten on the next SaveVar.\n\n", f);

    for (e = g_dataDict; e; e = e->next) {
        if (e->type == DATA_TYPE_NUMBER) {
            fprintf(f, "%s=n:%g\n", e->key, (double)e->num_val);
        } else if (e->type == DATA_TYPE_BOOL) {
            fprintf(f, "%s=b:%d\n", e->key, e->bool_val ? 1 : 0);
        } else if (e->type == DATA_TYPE_STRING && e->str_tstring) {
            DataTString* ts = (DataTString*)e->str_tstring;
            char escaped[DATA_STR_MAX * 2 + 4];
            /* Build a null-terminated copy of the TString bytes for EscapeValue. */
            char raw[DATA_STR_MAX + 1];
            size_t n = ts->len < DATA_STR_MAX ? ts->len : DATA_STR_MAX;
            memcpy(raw, ts->data, n);
            raw[n] = '\0';
            EscapeValue(raw, escaped, sizeof(escaped));
            fprintf(f, "%s=s:%s\n", e->key, escaped);
        }
    }
    fclose(f);

    /* Atomic replace so a crash mid-write leaves the old file intact. */
    if (!MoveFileExA(tmp_path, ini_path, MOVEFILE_REPLACE_EXISTING)) {
        m2_logf("[!] lua_bridge: SaveVar persist rename failed (GLE=%lu)",
                (unsigned long)GetLastError());
    }
}

static void LoadDataFileLocked(void) {
    char ini_path[MAX_PATH];
    FILE* f;
    char line[DATA_STR_MAX * 2 + 32];

    m2_module_path(g_hModule, "lua_loader_data.ini", ini_path, sizeof(ini_path));
    f = fopen(ini_path, "r");
    if (!f) return;    /* file doesn't exist yet — first run, empty dict is fine */

    int loaded_count = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Skip blank lines + comments. */
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ';' || *p == '#' || *p == '\n' || *p == '\r' || *p == '\0') continue;

        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char* type_val = eq + 1;

        /* Strip trailing whitespace from key. */
        size_t klen = strlen(p);
        while (klen > 0 && (p[klen - 1] == ' ' || p[klen - 1] == '\t')) p[--klen] = '\0';

        /* type_val looks like `n:18` — first char is type, then colon, then value. */
        if (type_val[0] == '\0' || type_val[1] != ':') continue;
        char type = type_val[0];
        char* raw_val = type_val + 2;

        /* Strip trailing newline from value. */
        size_t vlen = strlen(raw_val);
        while (vlen > 0 && (raw_val[vlen - 1] == '\n' || raw_val[vlen - 1] == '\r')) {
            raw_val[--vlen] = '\0';
        }

        DataEntry* e = DataDictUpsert(p, type);
        if (!e) continue;
        if (type == DATA_TYPE_NUMBER) {
            e->num_val = (float)atof(raw_val);
        } else if (type == DATA_TYPE_BOOL) {
            e->bool_val = (atoi(raw_val) != 0) ? 1 : 0;
        } else if (type == DATA_TYPE_STRING) {
            char unescaped[DATA_STR_MAX + 1];
            UnescapeValue(raw_val, unescaped, sizeof(unescaped));
            size_t ulen = strlen(unescaped);
            e->str_tstring = AllocDataTString(unescaped, ulen);
        }
        loaded_count++;
    }
    fclose(f);
    if (loaded_count > 0) {
        m2_logf("[*] lua_bridge: Loaded %d persisted variable(s) from lua_loader_data.ini",
                loaded_count);
    }
}

static void InitDataDict(void) {
    if (!g_dataMtxInit) {
        InitializeCriticalSection(&g_dataMtx);
        g_dataMtxInit = 1;
    }
    EnterCriticalSection(&g_dataMtx);
    if (!g_dataLoaded) {
        g_dataLoaded = 1;
        LoadDataFileLocked();
    }
    LeaveCriticalSection(&g_dataMtx);
}

/* Loader.SaveVar(sKey, xValue) — accepts number, string, boolean.
 * Persists to disk immediately. Returns nothing. */
static int LuaLoaderSaveVar(void* L) {
    char* Lc; char* base;
    char key[DATA_KEY_MAX];
    int tt_val;
    if (!L) return 0;
    if (m2_lua_nargs(L) < 2) return 0;
    if (m2_lua_arg_string(L, 0, key, sizeof(key)) <= 0) return 0;
    if (!g_dataMtxInit) InitDataDict();

    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base) return 0;
    tt_val = *(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET);

    EnterCriticalSection(&g_dataMtx);
    if (tt_val == LUA_TNUMBER) {
        DataEntry* e = DataDictUpsert(key, DATA_TYPE_NUMBER);
        if (e) e->num_val = *(float*)(base + TVALUE_SIZE);
    } else if (tt_val == LUA_TBOOLEAN) {
        DataEntry* e = DataDictUpsert(key, DATA_TYPE_BOOL);
        if (e) e->bool_val = (*(int*)(base + TVALUE_SIZE) != 0) ? 1 : 0;
    } else if (tt_val == LUA_TSTRING) {
        char sval[DATA_STR_MAX];
        int slen = m2_lua_arg_string(L, 1, sval, sizeof(sval));
        if (slen > 0) {
            DataEntry* e = DataDictUpsert(key, DATA_TYPE_STRING);
            if (e) {
                /* Fresh TString; old one stays alive for any Lua vars still
                 * referencing a prior LoadVar result. Intentional leak. */
                e->str_tstring = AllocDataTString(sval, (size_t)slen);
            }
        }
    } else {
        LeaveCriticalSection(&g_dataMtx);
        return 0;  /* unsupported value type */
    }
    PersistDataFileLocked();
    LeaveCriticalSection(&g_dataMtx);
    return 0;
}

/* Loader.LoadVar(sKey) — returns number/string/boolean (with original
 * type) or nil if the key isn't set. */
static int LuaLoaderLoadVar(void* L) {
    char* Lc; char* top;
    char key[DATA_KEY_MAX];
    DataEntry* e;
    if (!L) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    if (m2_lua_arg_string(L, 0, key, sizeof(key)) <= 0) return 0;
    if (!g_dataMtxInit) InitDataDict();

    Lc  = (char*)L;
    top = *(char**)(Lc + LUA_OFF_TOP);

    EnterCriticalSection(&g_dataMtx);
    e = DataDictFind(key);
    if (!e) {
        LeaveCriticalSection(&g_dataMtx);
        /* Push nil — tt = LUA_TNIL, value doesn't matter. */
        *(int*)top                       = 0;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TNIL;
        *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
        return 1;
    }

    if (e->type == DATA_TYPE_NUMBER) {
        *(float*)top                     = e->num_val;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TNUMBER;
    } else if (e->type == DATA_TYPE_BOOL) {
        *(int*)top                       = e->bool_val ? 1 : 0;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TBOOLEAN;
    } else if (e->type == DATA_TYPE_STRING && e->str_tstring) {
        *(void**)top                     = e->str_tstring;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TSTRING;
    } else {
        LeaveCriticalSection(&g_dataMtx);
        *(int*)top                       = 0;
        *(int*)(top + TVALUE_TT_OFFSET)  = LUA_TNIL;
        *(char**)(Lc + LUA_OFF_TOP)      = top + TVALUE_SIZE;
        return 1;
    }
    LeaveCriticalSection(&g_dataMtx);
    *(char**)(Lc + LUA_OFF_TOP) = top + TVALUE_SIZE;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Loader.GetLoadPhase() -> nIndex, sName
 *
 * How far the world load has progressed, on loadprobe's 0..20 ladder.
 * Returns -1, "none" before anything has been observed. The two values a
 * script usually cares about:
 *     11 "Player spawn"                     -- the local player exists
 *     20 "World fully loaded (GlobalExit)"   -- control is with the player
 *
 * Lets a script check it is actually in a world before touching entities,
 * instead of inferring it from whether an OnLoad hook has run yet. Reset
 * when a new load cycle is detected, so it tracks the CURRENT load rather
 * than sticking at the high-water mark for the process.
 *
 * Requires loader_track_phase = 1 (the default); reports -1 when off.
 * ------------------------------------------------------------------------ */
static int LuaLoaderGetLoadPhase(void* L) {
    char* Lc  = (char*)L;
    char* top = *(char**)(Lc + LUA_OFF_TOP);
    int   ph  = (int)g_loadPhase;
    const char* name = (ph >= 0) ? m2_loadtrigger_phase_name(ph) : "none";
    size_t n = strlen(name);

    if (n > sizeof(g_phaseNameTString.data) - 1) n = sizeof(g_phaseNameTString.data) - 1;
    memcpy(g_phaseNameTString.data, name, n);
    g_phaseNameTString.data[n] = '\0';
    g_phaseNameTString.len     = (uint32_t)n;

    /* lua_Number is float in this build — see FormatTValue. */
    *(float*)top                    = (float)ph;
    *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;
    top += TVALUE_SIZE;
    *(void**)top                    = &g_phaseNameTString;
    *(int*)(top + TVALUE_TT_OFFSET) = LUA_TSTRING;
    top += TVALUE_SIZE;
    *(char**)(Lc + LUA_OFF_TOP)     = top;
    return 2;
}

/* ------------------------------------------------------------------------ *
 * Loader.LoadFile(sRelPath) -> bLoaded
 *
 * Execute another .lua, resolved relative to <game>/scripts/, on the current
 * VM. The point is shared library code: before this, the only way for two
 * scripts to share anything was to leave it in _G from an OnBoot script,
 * which the engine wipes on a menu return. Pair it with the '_'-prefixed
 * directory convention — files under e.g. scripts/OnLoad/_lib/ are skipped
 * by the folder scanner, so they only run when something asks for them:
 *
 *     Loader.LoadFile("OnLoad/_lib/util.lua")
 *
 * Returns true if the file was found and executed (its own runtime errors
 * are logged, and reported on the Loader.Printf / WS channels, rather than
 * failing the call). Constraints:
 *   - relative paths under scripts/ only; absolute paths and '..' rejected
 *   - one level deep — a LoadFile from inside a LoadFile is refused, which
 *     also stops a file that loads itself from running away
 *
 * Runs synchronously on the calling VM, using its own source buffer so the
 * caller's chunk text stays intact. LuaDoStringEx saves and restores both
 * L->base and L->top, so the C-function frame we were called in is
 * undisturbed.
 * ------------------------------------------------------------------------ */
static int LuaLoaderLoadFile(void* L) {
    char  rel[MAX_PATH];
    char* Lc;
    char* top;
    int   ok = 0;

    if (!L) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    if (m2_lua_arg_string(L, 0, rel, sizeof(rel)) <= 0) return 0;

    if (g_loadFileDepth > 0) {
        m2_logf("[!] lua_bridge: Loader.LoadFile('%s') refused — a LoadFile is "
                "already in progress (nesting is not supported)", rel);
    } else if (rel[0] == '\0' || rel[1] == ':' || rel[0] == '\\' ||
               rel[0] == '/'  || strstr(rel, "..")) {
        m2_logf("[!] lua_bridge: Loader.LoadFile('%s') refused — must be a path "
                "relative to scripts/ with no '..' segments", rel);
    } else {
        char   exe_dir[MAX_PATH];
        char   full[MAX_PATH];
        char*  slash;
        char*  code;
        size_t code_len = 0;
        static char result_buf[4096];

        GetModuleFileNameA(NULL, exe_dir, MAX_PATH);
        slash = strrchr(exe_dir, '\\');
        if (slash) *(slash + 1) = '\0';
        snprintf(full, sizeof(full), "%sscripts\\%s", exe_dir, rel);

        code = LoadScriptBytes(full, "LoadFile", &code_len);
        if (code) {
            g_loadFileDepth++;
            LuaDoStringEx(L, code, code_len, result_buf, sizeof(result_buf),
                          &g_loadFileChunkSource);
            g_loadFileDepth--;
            free(code);

            m2_logf("[*] lua_bridge: Loader.LoadFile('%s') -> %s", rel, result_buf);
            {
                char line[1024];
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                            "[LoadFile] %s -> %s", rel, result_buf);
                LoaderLogLine(line);
            }
            ok = 1;
        }
    }

    Lc  = (char*)L;
    top = *(char**)(Lc + LUA_OFF_TOP);
    *(int*)top                      = ok ? 1 : 0;
    *(int*)(top + TVALUE_TT_OFFSET) = LUA_TBOOLEAN;
    *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;
    return 1;
}

static const luaL_Reg loader_lib[] = {
    {"Printf",           LuaLoaderPrintf},
    {"WsSend",           LuaLoaderWsSend},
    {"GetKeyboardState", LuaLoaderGetKeyboardState},
    {"IsKeyDown",        LuaLoaderIsKeyDown},
    {"PopKeyEvents",     LuaLoaderPopKeyEvents},
    {"ClearKeyEvents",   LuaLoaderClearKeyEvents},
    {"IsGameFocused",    LuaLoaderIsGameFocused},
    {"SaveVar",          LuaLoaderSaveVar},
    {"LoadVar",          LuaLoaderLoadVar},
    {"GetLoadPhase",     LuaLoaderGetLoadPhase},
    {"LoadFile",         LuaLoaderLoadFile},
    {NULL, NULL}
};

static void RegisterLoaderLib(void* L) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD func_addr = (DWORD)base + g_rvas->luaL_register;
    const char* libname = "Loader";
    const luaL_Reg* table = loader_lib;

    __asm__ volatile (
        "push %2\n\t"        // Push table pointer (stack arg)
        "call *%3\n\t"       // Call luaL_register
        "add $4, %%esp\n\t"  // Clean stack (4 bytes)
        :
        : "c"(L), "a"(libname), "r"(table), "r"(func_addr)
        : "edx", "memory"
    );
    static int logged = 0;
    if (!logged) { logged = 1; m2_logf("[*] lua_bridge: Registered Loader.Printf globally"); }
}

/* ------------------------------------------------------------------------ *
 * math.* — Pandemic's stripped Lua build is missing most of the trig,
 * log, and random helpers a modern script (or an AI-assisted one) will
 * reach for. This section registers real single-precision math functions
 * so scripts can call math.sin, math.sqrt, math.random, etc. natively
 * instead of re-implementing them via Taylor series.
 *
 * The engine's luaL_register reuses the existing `math` global table
 * (Pandemic kept the table — just without most entries), so what's here
 * is additive: math.floor / math.abs / math.max / math.min / etc. that
 * the engine already ships stay untouched. See stdlib_report.txt in the
 * stress harness scratchpad for the full present/missing enumeration
 * that motivated each entry.
 * ------------------------------------------------------------------------ */

/* One-arg → one-return single-precision math wrapper. Fast path: no
 * SafeProbe / LooksLikeLuaState — same reasoning as LuaLoaderIsKeyDown
 * (engine guarantees L/base/top valid when Lua dispatches to a
 * registered C function). Just checks arg count via top-base pointer
 * arithmetic and the arg's type tag. */
#define MATH_ONEARG(fn_name, cfunc)                                          \
    static int LuaMath##fn_name(void* L) {                                    \
        char* Lc   = (char*)L;                                                \
        char* base = *(char**)(Lc + LUA_OFF_BASE);                            \
        char* top  = *(char**)(Lc + LUA_OFF_TOP);                             \
        float x;                                                              \
        if (!base || (top - base) < TVALUE_SIZE) return 0;                    \
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;        \
        x = *(float*)base;                                                    \
        *(float*)top                    = (float)cfunc(x);                    \
        *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;                        \
        *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;                  \
        return 1;                                                             \
    }

/* Two-arg → one-return single-precision math wrapper. */
#define MATH_TWOARG(fn_name, cfunc)                                          \
    static int LuaMath##fn_name(void* L) {                                    \
        char* Lc   = (char*)L;                                                \
        char* base = *(char**)(Lc + LUA_OFF_BASE);                            \
        char* top  = *(char**)(Lc + LUA_OFF_TOP);                             \
        float x, y;                                                           \
        if (!base || (top - base) < TVALUE_SIZE * 2) return 0;                \
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;        \
        if (*(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET) != LUA_TNUMBER)    \
            return 0;                                                         \
        x = *(float*)base;                                                    \
        y = *(float*)(base + TVALUE_SIZE);                                    \
        *(float*)top                    = (float)cfunc(x, y);                 \
        *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;                        \
        *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;                  \
        return 1;                                                             \
    }

MATH_ONEARG(Sin,   sinf)
MATH_ONEARG(Cos,   cosf)
MATH_ONEARG(Tan,   tanf)
MATH_ONEARG(Asin,  asinf)
MATH_ONEARG(Acos,  acosf)
MATH_ONEARG(Atan,  atanf)
MATH_ONEARG(Sinh,  sinhf)
MATH_ONEARG(Cosh,  coshf)
MATH_ONEARG(Tanh,  tanhf)
MATH_ONEARG(Sqrt,  sqrtf)
MATH_ONEARG(Log,   logf)
MATH_ONEARG(Log10, log10f)

MATH_TWOARG(Atan2, atan2f)
MATH_TWOARG(Fmod,  fmodf)

/* ldexp(x, e) — e is naturally an int; Lua passes a number, cast internally. */
static int LuaMathLdexp(void* L) {
    char* Lc; char* base; char* top; float x; int e;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 2) return 0;
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE * 2)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    if (*(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    x = *(float*)base;
    e = (int)*(float*)(base + TVALUE_SIZE);
    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE)) return 0;
    *(float*)top                    = ldexpf(x, e);
    *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;
    return 1;
}

/* modf(x) → integer_part, fractional_part. Two-return. */
static int LuaMathModf(void* L) {
    char* Lc; char* base; char* top; float x, ipart, fpart;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    x = *(float*)base;
    fpart = modff(x, &ipart);
    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE * 2)) return 0;
    *(float*)top                                     = ipart;
    *(int*)(top + TVALUE_TT_OFFSET)                  = LUA_TNUMBER;
    *(float*)(top + TVALUE_SIZE)                     = fpart;
    *(int*)(top + TVALUE_SIZE + TVALUE_TT_OFFSET)    = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)                      = top + TVALUE_SIZE * 2;
    return 2;
}

/* frexp(x) → mantissa, exponent. Two-return. */
static int LuaMathFrexp(void* L) {
    char* Lc; char* base; char* top; float x, mant; int expo;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    x = *(float*)base;
    mant = frexpf(x, &expo);
    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE * 2)) return 0;
    *(float*)top                                     = mant;
    *(int*)(top + TVALUE_TT_OFFSET)                  = LUA_TNUMBER;
    *(float*)(top + TVALUE_SIZE)                     = (float)expo;
    *(int*)(top + TVALUE_SIZE + TVALUE_TT_OFFSET)    = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)                      = top + TVALUE_SIZE * 2;
    return 2;
}

/* random() → float 0..1
 * random(n) → int 1..n
 * random(m, n) → int m..n
 * Matches stock Lua 5.1 semantics, backed by CRT rand(). */
static int LuaMathRandom(void* L) {
    char* Lc; char* base; char* top;
    int nargs;
    float result;

    if (!L || !LooksLikeLuaState(L)) return 0;
    nargs = m2_lua_nargs(L);
    Lc   = (char*)L;
    base = *(char**)(Lc + LUA_OFF_BASE);

    if (nargs == 0) {
        result = (float)rand() / (float)RAND_MAX;
    } else if (nargs == 1) {
        int upper;
        if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
        upper = (int)*(float*)base;
        if (upper < 1) return 0;
        result = (float)(1 + rand() % upper);
    } else {
        int lo, hi;
        if (!base || !SafeProbe(base, TVALUE_SIZE * 2)) return 0;
        if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
        if (*(int*)(base + TVALUE_SIZE + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
        lo = (int)*(float*)base;
        hi = (int)*(float*)(base + TVALUE_SIZE);
        if (hi < lo) return 0;
        result = (float)(lo + rand() % (hi - lo + 1));
    }

    top = *(char**)(Lc + LUA_OFF_TOP);
    if (!SafeProbe(top, TVALUE_SIZE)) return 0;
    *(float*)top                    = result;
    *(int*)(top + TVALUE_TT_OFFSET) = LUA_TNUMBER;
    *(char**)(Lc + LUA_OFF_TOP)     = top + TVALUE_SIZE;
    return 1;
}

/* randomseed(x) → seed the CRT rand() from a number. No return. */
static int LuaMathRandomseed(void* L) {
    char* base;
    if (!L || !LooksLikeLuaState(L)) return 0;
    if (m2_lua_nargs(L) < 1) return 0;
    base = *(char**)((char*)L + LUA_OFF_BASE);
    if (!base || !SafeProbe(base, TVALUE_SIZE)) return 0;
    if (*(int*)(base + TVALUE_TT_OFFSET) != LUA_TNUMBER) return 0;
    srand((unsigned int)*(float*)base);
    return 0;
}

static const luaL_Reg math_lib[] = {
    {"sin",        LuaMathSin},
    {"cos",        LuaMathCos},
    {"tan",        LuaMathTan},
    {"asin",       LuaMathAsin},
    {"acos",       LuaMathAcos},
    {"atan",       LuaMathAtan},
    {"atan2",      LuaMathAtan2},
    {"sinh",       LuaMathSinh},
    {"cosh",       LuaMathCosh},
    {"tanh",       LuaMathTanh},
    {"sqrt",       LuaMathSqrt},
    {"log",        LuaMathLog},
    {"log10",      LuaMathLog10},
    {"fmod",       LuaMathFmod},
    {"ldexp",      LuaMathLdexp},
    {"modf",       LuaMathModf},
    {"frexp",      LuaMathFrexp},
    {"random",     LuaMathRandom},
    {"randomseed", LuaMathRandomseed},
    {NULL, NULL}
};

static void RegisterMathLib(void* L) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;
    DWORD func_addr = (DWORD)base + g_rvas->luaL_register;
    const char* libname = "math";
    const luaL_Reg* table = math_lib;

    __asm__ volatile (
        "push %2\n\t"
        "call *%3\n\t"
        "add $4, %%esp\n\t"
        :
        : "c"(L), "a"(libname), "r"(table), "r"(func_addr)
        : "edx", "memory"
    );
    static int logged = 0;
    if (!logged) { logged = 1; m2_logf("[*] lua_bridge: Registered 19 math.* functions globally"); }
}

/* ------------------------------------------------------------------------ *
 * Polyfill — Lua-side patch for the two things luaL_register can't give
 * us: constants (math.pi, math.huge) and the missing base function
 * assert. Runs as a small Lua chunk right after RegisterMathLib in every
 * place the register calls happen, so a _G wipe recovers both the
 * functions AND these polyfills on the next pump batch.
 *
 * Idempotent (each define is `if not ... then ... end`), so the cost of
 * running it twice is a compile+pcall of a tiny chunk (~150 µs); at the
 * measured 113 pumps/sec stress ceiling that's ~2% CPU. At realistic
 * REPL rates (<10 pumps/sec) it's negligible.
 * ------------------------------------------------------------------------ */
static const char kPolyfillChunk[] =
    "if math then "
    "  if not math.pi   then math.pi   = 3.14159265358979323846 end "
    "  if not math.huge then math.huge = 1e308 end "
    "end "
    "if not _G.assert then "
    "  _G.assert = function(v, msg) "
    /* level=2 skips the assert function frame so the error message
     * points at the caller of assert (matching stock Lua semantics),
     * not at this polyfill chunk. Critical for debuggable script code. */
    "    if not v then error(msg or 'assertion failed!', 2) end "
    "    return v "
    "  end "
    "end";

static void RunPolyfill(void* L) {
    char buf[512];
    if (!L || !LooksLikeLuaState(L)) return;
    /* No t_inBridgeExec guard here — callers that need re-entry safety
     * (PumpQueue) sit around this, but the polyfill itself is a leaf
     * LuaDoString that saves/restores top+base cleanly. Nesting a leaf
     * inside PumpQueue's LuaDoString would be a problem, but we run it
     * BEFORE the user-chunk LuaDoString, so no nesting. */
    buf[0] = '\0';
    LuaDoString(L, kPolyfillChunk, sizeof(kPolyfillChunk) - 1, buf, sizeof(buf));

    /* Log honestly on first run: LuaDoString writes "[compile] ..." for
     * compile errors and "[bridge] ..." for internal LuaDoString bail-outs
     * (empty chunk, bad L, etc). Either at buf[0] means the polyfill
     * silently didn't apply, and shipping a broken chunk with a "polyfill
     * applied" log line is exactly the kind of silent failure that hides
     * bugs from the next contributor. Note: "[runtime]" on success is
     * expected (Pandemic's pcall leaves stack junk in slot 0), so we do
     * NOT treat it as failure — genuine runtime errors would show up in
     * dev testing when the buggy chunk is first written. */
    int failed = (strncmp(buf, "[compile]", 9) == 0)
              || (strncmp(buf, "[bridge]",  8) == 0);
    static int logged_ok = 0;
    static int logged_fail = 0;
    if (failed) {
        if (!logged_fail) {
            logged_fail = 1;
            m2_logf("[!] lua_bridge: polyfill FAILED to apply: %s", buf);
        }
    } else if (!logged_ok) {
        logged_ok = 1;
        m2_logf("[*] lua_bridge: polyfill applied (math.pi, math.huge, assert)");
    }
}

/* ------------------------------------------------------------------------ *
 * WebSocket transport
 *
 * A browser can't open raw TCP, but it can open a WebSocket, which is
 * just an HTTP upgrade + a framed byte stream. The queue/pump/executor
 * is transport-agnostic, so WS only touches the accept branch and the
 * output fanout. Raw-TCP clients are unaffected.
 *
 * Wire contract (JSON text frames — one message = one request):
 *   client -> bridge   {"id":"q17abc","code":"<lua source>"}
 *   bridge -> client   {"type":"ack","id":"q17abc","status":"queued"}
 *   bridge -> client   {"type":"log","line":"…a Loader.Printf line…"}
 *   bridge -> client   {"type":"ws","line":"…a Loader.WsSend line…"}
 *
 * Results come back via a Lua-side wrapper: the client wraps user code
 * so that after execution it emits a nonce-tagged line via
 * Loader.WsSend (the hidden channel — WS-only, never logged). The
 * client matches its tag on the {type:"ws"} feed. No result-routing
 * plumbing in C; the id lives in Lua space. Same tag trick tools/
 * lua_repl.py uses, just off a WS feed instead of the log file.
 *
 * Only one WS client (or one raw-TCP client) is served at a time. That
 * matches the existing listener's design and keeps the fanout trivial:
 * Loader.Printf / Loader.WsSend check g_wsClient under a mutex and
 * write to that one socket. Multi-client fanout is a future upgrade.
 * ------------------------------------------------------------------------ */

/* GUID from RFC 6455 §1.3 — concatenated with the client's key to
 * derive the Sec-WebSocket-Accept header. */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/* Frame opcodes we care about. */
#define WS_OP_CONT   0x0
#define WS_OP_TEXT   0x1
#define WS_OP_BINARY 0x2
#define WS_OP_CLOSE  0x8
#define WS_OP_PING   0x9
#define WS_OP_PONG   0xA

/* Cap for a single incoming WS message. Matches the raw-TCP chunk_buf
 * (1 MB) so users can send equivalently large chunks. */
#define WS_MAX_MSG   (1024 * 1024)

/* ------------------------------------------------------------------------ *
 * SHA-1 via BCrypt (Windows Vista+). The one-shot BCryptHash isn't in
 * older MinGW bcrypt.h, so use the three-call sequence
 * (CreateHash → HashData → FinishHash → DestroyHash) which is present
 * on every bcrypt version.
 * ------------------------------------------------------------------------ */
static int ws_sha1(const void* in, size_t in_len, unsigned char out[20]) {
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;
    int ok = 0;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, 0);
    if (st < 0 || !hAlg) return 0;
    st = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (st < 0 || !hHash) goto out;
    st = BCryptHashData(hHash, (PUCHAR)in, (ULONG)in_len, 0);
    if (st < 0) goto out;
    st = BCryptFinishHash(hHash, out, 20, 0);
    if (st < 0) goto out;
    ok = 1;
out:
    if (hHash) BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* ------------------------------------------------------------------------ *
 * Base64 via CryptBinaryToStringA. For our fixed 20-byte SHA-1 input,
 * output is exactly 28 chars + NUL — but we pass a big enough buffer
 * anyway and let the API report the length. NOCRLF because we're
 * emitting into an HTTP header, not a MIME body.
 * ------------------------------------------------------------------------ */
static int ws_base64(const void* in, size_t in_len, char* out, size_t out_cap) {
    DWORD cchOut = (DWORD)out_cap;
    if (!CryptBinaryToStringA((const BYTE*)in, (DWORD)in_len,
                              CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                              out, &cchOut)) return 0;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Blocking send-all wrapper — WS frames are contiguous byte streams;
 * a short send from the OS means we loop until the whole frame is out
 * or the socket dies. Returns 1 on full send, 0 on error/disconnect.
 * ------------------------------------------------------------------------ */
static int ws_send_all(SOCKET c, const void* buf, size_t len) {
    const char* p = (const char*)buf;
    size_t off = 0;
    while (off < len) {
        int n = send(c, p + off, (int)(len - off), 0);
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

/* Blocking recv-exact wrapper. Returns 1 on full read, 0 on
 * error/disconnect. */
static int ws_recv_all(SOCKET c, void* buf, size_t len) {
    char* p = (char*)buf;
    size_t off = 0;
    while (off < len) {
        int n = recv(c, p + off, (int)(len - off), 0);
        if (n <= 0) return 0;
        off += (size_t)n;
    }
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Send a server frame (unmasked). opcode = WS_OP_TEXT / WS_OP_PONG /
 * WS_OP_CLOSE. Payload len chooses 7 / 16 / 64-bit length encoding per
 * RFC 6455 §5.2. Returns 1 on success, 0 on socket error.
 *
 * Not thread-safe on its own — WS output paths (server thread, game
 * thread fanouts) synchronize on g_wsClientMtx before calling this so
 * two writers can't interleave frame bytes.
 * ------------------------------------------------------------------------ */
static int ws_send_frame(SOCKET c, int opcode, const void* payload, size_t len) {
    unsigned char hdr[14];
    size_t hdr_len;

    hdr[0] = (unsigned char)(0x80 | (opcode & 0x0F));       /* FIN | opcode */

    if (len < 126) {
        hdr[1] = (unsigned char)len;
        hdr_len = 2;
    } else if (len < 65536) {
        hdr[1] = 126;
        hdr[2] = (unsigned char)((len >> 8) & 0xFF);
        hdr[3] = (unsigned char)(len & 0xFF);
        hdr_len = 4;
    } else {
        uint64_t L = (uint64_t)len;
        hdr[1] = 127;
        hdr[2] = (unsigned char)((L >> 56) & 0xFF);
        hdr[3] = (unsigned char)((L >> 48) & 0xFF);
        hdr[4] = (unsigned char)((L >> 40) & 0xFF);
        hdr[5] = (unsigned char)((L >> 32) & 0xFF);
        hdr[6] = (unsigned char)((L >> 24) & 0xFF);
        hdr[7] = (unsigned char)((L >> 16) & 0xFF);
        hdr[8] = (unsigned char)((L >> 8) & 0xFF);
        hdr[9] = (unsigned char)(L & 0xFF);
        hdr_len = 10;
    }

    if (!ws_send_all(c, hdr, hdr_len)) return 0;
    if (len > 0 && !ws_send_all(c, payload, len)) return 0;
    return 1;
}

/* Send a WS text frame. Convenience wrapper. */
static int ws_send_text(SOCKET c, const void* payload, size_t len) {
    return ws_send_frame(c, WS_OP_TEXT, payload, len);
}

/* ------------------------------------------------------------------------ *
 * Receive one full text message. Assembles continuation frames if any,
 * auto-handles ping (replies with pong) and close (sends close back
 * and returns 0). Returns:
 *   >0 = payload length in bytes (written to out, NUL-terminated)
 *   0  = connection closed cleanly (client sent close or hit socket EOF)
 *   -1 = protocol error / malformed frame / oversize
 * ------------------------------------------------------------------------ */
static int ws_recv_message(SOCKET c, char* out, size_t out_cap) {
    size_t total = 0;
    int    first_opcode = -1;

    for (;;) {
        unsigned char hdr[2];
        int    fin;
        int    opcode;
        int    masked;
        size_t plen;
        unsigned char mask[4];

        if (!ws_recv_all(c, hdr, 2)) return 0;
        fin    = (hdr[0] & 0x80) != 0;
        opcode =  hdr[0] & 0x0F;
        masked = (hdr[1] & 0x80) != 0;
        plen   =  hdr[1] & 0x7F;

        if (plen == 126) {
            unsigned char ext[2];
            if (!ws_recv_all(c, ext, 2)) return 0;
            plen = ((size_t)ext[0] << 8) | (size_t)ext[1];
        } else if (plen == 127) {
            unsigned char ext[8];
            uint64_t L = 0;
            int i;
            if (!ws_recv_all(c, ext, 8)) return 0;
            for (i = 0; i < 8; ++i) L = (L << 8) | ext[i];
            if (L > (uint64_t)WS_MAX_MSG) return -1;
            plen = (size_t)L;
        }

        /* Per RFC 6455 §5.1, clients MUST mask. Reject unmasked
         * client frames — the alternative is silent corruption. */
        if (!masked) return -1;
        if (!ws_recv_all(c, mask, 4)) return 0;

        /* Control frames (opcode >= 0x8) can be interleaved with a
         * fragmented data message and have their own payload. Handle
         * them fully here (auto-pong / close), then continue the loop
         * to collect the outer data message. */
        if (opcode >= 0x8) {
            unsigned char cpl[125];        /* control frames are <= 125 bytes */
            size_t i;
            if (plen > sizeof(cpl)) return -1;
            if (plen > 0 && !ws_recv_all(c, cpl, plen)) return 0;
            for (i = 0; i < plen; ++i) cpl[i] ^= mask[i & 3];

            if (opcode == WS_OP_PING) {
                EnterCriticalSection(&g_wsClientMtx);
                ws_send_frame(c, WS_OP_PONG, cpl, plen);
                LeaveCriticalSection(&g_wsClientMtx);
                continue;
            }
            if (opcode == WS_OP_CLOSE) {
                EnterCriticalSection(&g_wsClientMtx);
                ws_send_frame(c, WS_OP_CLOSE, cpl, plen);  /* echo back per §5.5.1 */
                LeaveCriticalSection(&g_wsClientMtx);
                return 0;
            }
            /* WS_OP_PONG: nothing to do — we never originate pings. */
            continue;
        }

        /* Data frame. First fragment sets the opcode; continuations
         * must use WS_OP_CONT. */
        if (first_opcode == -1) {
            first_opcode = opcode;
            if (opcode != WS_OP_TEXT && opcode != WS_OP_BINARY) return -1;
        } else {
            if (opcode != WS_OP_CONT) return -1;
        }

        if (plen > 0) {
            size_t i;
            if (total + plen >= out_cap) return -1;
            if (!ws_recv_all(c, out + total, plen)) return 0;
            for (i = 0; i < plen; ++i) out[total + i] ^= mask[i & 3];
            total += plen;
        }

        if (fin) {
            out[total] = '\0';
            return (int)total;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * Handshake: parse an HTTP GET, extract Sec-WebSocket-Key, respond
 * with 101 Switching Protocols. `peek` holds bytes already read from
 * the socket (up to peek_len); everything up through the terminating
 * "\r\n\r\n" must be present or we bail. Returns 1 on 101 sent, 0 on
 * malformed / not a WS upgrade / socket error.
 * ------------------------------------------------------------------------ */
static int ws_do_handshake(SOCKET c, const char* peek, size_t peek_len) {
    char req[8192];
    size_t rlen = 0;
    const char* key_hdr;
    const char* key_start;
    const char* key_end;
    char key[128];
    size_t key_len;
    unsigned char sha[20];
    char accept[64];
    char concat[256];
    size_t concat_len;
    char resp[512];
    int resp_len;

    /* Seed the request buffer with what's already been peeked, then
     * read the rest up to \r\n\r\n. */
    if (peek_len >= sizeof(req)) return 0;
    memcpy(req, peek, peek_len);
    rlen = peek_len;

    while (rlen + 1 < sizeof(req)) {
        int n;
        req[rlen] = '\0';
        if (rlen >= 4 && strstr(req, "\r\n\r\n")) break;
        n = recv(c, req + rlen, (int)(sizeof(req) - rlen - 1), 0);
        if (n <= 0) return 0;
        rlen += (size_t)n;
    }
    req[rlen] = '\0';

    /* Locate the Sec-WebSocket-Key header (case-insensitive per RFC
     * 2616; we use _strnicmp for a simple substring pass). */
    {
        const char* p = req;
        const char* needle = "Sec-WebSocket-Key:";
        size_t nlen = strlen(needle);
        key_hdr = NULL;
        while (*p) {
            if (_strnicmp(p, needle, nlen) == 0) { key_hdr = p + nlen; break; }
            while (*p && *p != '\n') p++;
            if (*p == '\n') p++;
        }
        if (!key_hdr) return 0;
    }
    while (*key_hdr == ' ' || *key_hdr == '\t') key_hdr++;
    key_start = key_hdr;
    key_end = key_start;
    while (*key_end && *key_end != '\r' && *key_end != '\n') key_end++;
    key_len = (size_t)(key_end - key_start);
    if (key_len == 0 || key_len >= sizeof(key)) return 0;
    memcpy(key, key_start, key_len);
    key[key_len] = '\0';

    /* Sec-WebSocket-Accept = base64(sha1(key + WS_GUID)) */
    concat_len = key_len + strlen(WS_GUID);
    if (concat_len >= sizeof(concat)) return 0;
    memcpy(concat, key, key_len);
    memcpy(concat + key_len, WS_GUID, strlen(WS_GUID));
    if (!ws_sha1(concat, concat_len, sha)) return 0;
    if (!ws_base64(sha, 20, accept, sizeof(accept))) return 0;

    resp_len = _snprintf_s(resp, sizeof(resp), _TRUNCATE,
                           "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n"
                           "\r\n",
                           accept);
    if (resp_len <= 0) return 0;
    return ws_send_all(c, resp, (size_t)resp_len);
}

/* ------------------------------------------------------------------------ *
 * JSON — minimal helpers, scoped to exactly what the wire contract
 * needs. Not a full parser: we look up two known string keys ("id",
 * "code") and unescape their values; nothing else is exercised.
 * ------------------------------------------------------------------------ */

/* Skip JSON whitespace at *p (advances the pointer in-place). */
static void js_skip_ws(const char** p, const char* end) {
    while (*p < end) {
        char ch = **p;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') (*p)++;
        else return;
    }
}

/* Parse a JSON string starting at **p (must be pointing at '"').
 * Writes unescaped bytes to out (up to out_cap-1), NUL-terminates, and
 * advances *p to just past the closing quote. Returns bytes written,
 * or -1 on malformed / overflow. Handles \" \\ \/ \n \r \t \b \f and
 * \uXXXX for basic Latin (>0xFF is transcoded to '?' — the bridge
 * doesn't need Unicode fidelity for our two fields). */
static int js_parse_string(const char** p, const char* end, char* out, size_t out_cap) {
    size_t o = 0;
    if (*p >= end || **p != '"') return -1;
    (*p)++;
    while (*p < end) {
        char ch = **p;
        if (ch == '"') { (*p)++; if (o < out_cap) out[o] = '\0'; return (int)o; }
        if (ch == '\\') {
            (*p)++;
            if (*p >= end) return -1;
            {
                char esc = **p;
                (*p)++;
                if (o + 1 >= out_cap) return -1;
                switch (esc) {
                    case '"':  out[o++] = '"';  break;
                    case '\\': out[o++] = '\\'; break;
                    case '/':  out[o++] = '/';  break;
                    case 'n':  out[o++] = '\n'; break;
                    case 'r':  out[o++] = '\r'; break;
                    case 't':  out[o++] = '\t'; break;
                    case 'b':  out[o++] = '\b'; break;
                    case 'f':  out[o++] = '\f'; break;
                    case 'u': {
                        unsigned int v = 0;
                        int i;
                        if (*p + 4 > end) return -1;
                        for (i = 0; i < 4; ++i) {
                            char h = (*p)[i];
                            v <<= 4;
                            if (h >= '0' && h <= '9') v |= (h - '0');
                            else if (h >= 'a' && h <= 'f') v |= (h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') v |= (h - 'A' + 10);
                            else return -1;
                        }
                        (*p) += 4;
                        out[o++] = (v <= 0xFF) ? (char)v : '?';
                        break;
                    }
                    default: return -1;
                }
            }
        } else {
            if (o + 1 >= out_cap) return -1;
            out[o++] = ch;
            (*p)++;
        }
    }
    return -1;
}

/* Extract id and code from {"id":"…","code":"…"}. Whitespace-tolerant.
 * Non-string fields and other keys are silently skipped. Returns 1 on
 * success (both fields found), 0 otherwise. */
static int ws_parse_request(const char* body, size_t body_len,
                            char* id_out, size_t id_cap,
                            char* code_out, size_t code_cap) {
    const char* p   = body;
    const char* end = body + body_len;
    int have_id = 0, have_code = 0;

    js_skip_ws(&p, end);
    if (p >= end || *p != '{') return 0;
    p++;

    for (;;) {
        char key[32];
        int kl;

        js_skip_ws(&p, end);
        if (p >= end) return 0;
        if (*p == '}') { p++; break; }

        kl = js_parse_string(&p, end, key, sizeof(key));
        if (kl < 0) return 0;
        js_skip_ws(&p, end);
        if (p >= end || *p != ':') return 0;
        p++;
        js_skip_ws(&p, end);

        if (strcmp(key, "id") == 0) {
            int r = js_parse_string(&p, end, id_out, id_cap);
            if (r < 0) return 0;
            have_id = 1;
        } else if (strcmp(key, "code") == 0) {
            int r = js_parse_string(&p, end, code_out, code_cap);
            if (r < 0) return 0;
            have_code = 1;
        } else {
            /* Skip an unknown value. We only need strings in practice,
             * but handle numbers / booleans / null defensively. */
            if (*p == '"') {
                char sink[256];
                if (js_parse_string(&p, end, sink, sizeof(sink)) < 0) return 0;
            } else {
                while (p < end && *p != ',' && *p != '}') p++;
            }
        }

        js_skip_ws(&p, end);
        if (p >= end) return 0;
        if (*p == ',') { p++; continue; }
        if (*p == '}') { p++; break; }
        return 0;
    }

    return have_id && have_code;
}

/* Escape a string into JSON: outputs to *dst (advanced in-place) up to
 * dst_end. Backslash / quote / control chars are escaped per RFC 8259.
 * Non-ASCII bytes are passed through raw (the wire is UTF-8; the
 * upstream data is already valid UTF-8 in practice — Loader.Printf
 * output is ASCII/Latin plus whatever mods pass through). Returns 1
 * on success, 0 on buffer overflow. */
static int js_escape_into(const char* src, size_t src_len, char** dst, char* dst_end) {
    size_t i;
    char* d = *dst;
    for (i = 0; i < src_len; ++i) {
        unsigned char ch = (unsigned char)src[i];
        if (ch == '\\' || ch == '"') {
            if (d + 2 > dst_end) return 0;
            *d++ = '\\'; *d++ = (char)ch;
        } else if (ch == '\n') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'n'; }
          else if (ch == '\r') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'r'; }
          else if (ch == '\t') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 't'; }
          else if (ch == '\b') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'b'; }
          else if (ch == '\f') { if (d + 2 > dst_end) return 0; *d++ = '\\'; *d++ = 'f'; }
          else if (ch < 0x20) {
            if (d + 6 > dst_end) return 0;
            _snprintf_s(d, 7, _TRUNCATE, "\\u%04x", ch);
            d += 6;
        } else {
            if (d + 1 > dst_end) return 0;
            *d++ = (char)ch;
        }
    }
    *dst = d;
    return 1;
}

/* ------------------------------------------------------------------------ *
 * Client-list helpers. Add/remove under g_wsClientMtx; the broadcaster
 * iterates the same list and prunes on send failure. Called from the
 * per-client worker thread on entry/exit.
 * ------------------------------------------------------------------------ */
static int ws_add_client(SOCKET c) {
    int ok = 0;
    EnterCriticalSection(&g_wsClientMtx);
    if (g_wsClientCount < WS_MAX_CLIENTS) {
        g_wsClients[g_wsClientCount++] = c;
        ok = 1;
    }
    LeaveCriticalSection(&g_wsClientMtx);
    return ok;
}

static void ws_remove_client(SOCKET c) {
    int i;
    EnterCriticalSection(&g_wsClientMtx);
    for (i = 0; i < g_wsClientCount; ++i) {
        if (g_wsClients[i] == c) {
            g_wsClients[i] = g_wsClients[--g_wsClientCount];   /* swap-remove */
            break;
        }
    }
    LeaveCriticalSection(&g_wsClientMtx);
}

/* ------------------------------------------------------------------------ *
 * Broadcast — called from the game thread inside Loader.Printf and
 * Loader.WsSend. Build the JSON envelope once (outside the lock), then
 * fan out to every connected client. Send failure means the client is
 * gone; close the socket and swap-remove it from the list so the next
 * broadcast doesn't hit it. The per-client worker thread's recv will
 * see the close on its next iteration and exit cleanly.
 *
 * Iterating in reverse means a swap-remove doesn't skip an entry —
 * we visit each index at most once regardless of what gets pruned.
 * ------------------------------------------------------------------------ */
static void ws_broadcast_typed_line(const char* type, const char* line, size_t line_len) {
    char buf[2560];              /* enough for a full 2 KB Loader.Printf line + envelope */
    char* d = buf;
    char* de = buf + sizeof(buf);
    size_t prefix_len;
    size_t suffix_len;
    const char* prefix_a = "{\"type\":\"";
    const char* prefix_b = "\",\"line\":\"";
    const char* suffix   = "\"}";
    size_t buf_len;
    int i;

    if (!g_wsClientMtxInit) return;

    /* Build once, unlocked. */
    prefix_len = strlen(prefix_a);
    if (d + prefix_len > de) return;
    memcpy(d, prefix_a, prefix_len); d += prefix_len;

    {
        size_t tlen = strlen(type);
        if (d + tlen > de) return;
        memcpy(d, type, tlen); d += tlen;
    }

    prefix_len = strlen(prefix_b);
    if (d + prefix_len > de) return;
    memcpy(d, prefix_b, prefix_len); d += prefix_len;

    if (!js_escape_into(line, line_len, &d, de)) return;

    suffix_len = strlen(suffix);
    if (d + suffix_len > de) return;
    memcpy(d, suffix, suffix_len); d += suffix_len;

    buf_len = (size_t)(d - buf);

    /* Fan out. */
    EnterCriticalSection(&g_wsClientMtx);
    for (i = g_wsClientCount - 1; i >= 0; --i) {
        SOCKET s = g_wsClients[i];
        if (!ws_send_text(s, buf, buf_len)) {
            closesocket(s);
            g_wsClients[i] = g_wsClients[--g_wsClientCount];   /* swap-remove */
        }
    }
    LeaveCriticalSection(&g_wsClientMtx);
}

/* ------------------------------------------------------------------------ *
 * Loader.WsSend(str, ...) — the HIDDEN channel. Same join semantics as
 * Loader.Printf (tab-separated string args), but NEVER writes the log
 * file. Broadcasts each call as {type:"ws",line:"…"} to the connected
 * WS client if any; no-op otherwise. This is what tagged results ride
 * on: the client wraps user code so the tagged reply lands here,
 * invisible to lua_loader_printf.log.
 * ------------------------------------------------------------------------ */
static int LuaLoaderWsSend(void* L) {
    char msg[2048];
    int  joined = m2_lua_join_strings(L, msg, (int)sizeof(msg) - 2);
    if (joined <= 0) return 0;
    ws_broadcast_typed_line("ws", msg, strlen(msg));
    return 0;
}

/* ------------------------------------------------------------------------ *
 * Per-client session loop. Receives JSON messages, parses {id, code},
 * queues the code as a WS-provenance chunk, sends the immediate ack
 * directly on this socket, then loops. Log/ws-send fanout happens on
 * the game thread via ws_broadcast_typed_line — this thread only
 * handles input + acks. On disconnect / bad frame / send error, the
 * wrapper (WsClientThread) does the cleanup.
 *
 * The pump doesn't OutAppend for WS-queued chunks (see the from_ws
 * gate in PumpQueue), so we don't need to drain g_outBuf on this
 * thread — g_outBuf is exclusively the raw-TCP path's problem now.
 * ------------------------------------------------------------------------ */
static void ws_serve_client(SOCKET c) {
    char msg[WS_MAX_MSG];
    char id[128];
    char* code = NULL;
    const size_t code_cap = WS_MAX_MSG;

    code = (char*)malloc(code_cap);
    if (!code) { m2_logf("[!] lua_bridge: ws: OOM allocating code buffer"); return; }

    for (;;) {
        int r;
        char ack[192];
        int  ack_len;

        r = ws_recv_message(c, msg, sizeof(msg));
        if (r <= 0) break;                        /* clean close or error */

        id[0] = '\0';
        code[0] = '\0';
        if (!ws_parse_request(msg, (size_t)r, id, sizeof(id), code, code_cap)) {
            m2_logf("[!] lua_bridge: ws: rejected malformed request (%d bytes)", r);
            continue;
        }

        InQueuePush(code, strlen(code), 1);       /* from_ws=1 — skip g_outBuf fanout */
        /* %lu not %zu — wvsprintfA drops %z and printed the literal "zu". */
        m2_logf("[+] lua_bridge: ws: queued chunk (id=%s, %lu bytes)",
                id, (unsigned long)strlen(code));

        ack_len = _snprintf_s(ack, sizeof(ack), _TRUNCATE,
                              "{\"type\":\"ack\",\"id\":\"%s\",\"status\":\"queued\"}", id);
        if (ack_len > 0) {
            EnterCriticalSection(&g_wsClientMtx);
            if (!ws_send_text(c, ack, (size_t)ack_len)) {
                LeaveCriticalSection(&g_wsClientMtx);
                break;
            }
            LeaveCriticalSection(&g_wsClientMtx);
        }
    }

    free(code);
}

/* ------------------------------------------------------------------------ *
 * Per-client worker thread. Adds this socket to the broadcast list on
 * entry, runs the session loop, removes on exit. If the list is full
 * (WS_MAX_CLIENTS already connected), refuses the new connection
 * cleanly — log a line so users can see they hit the cap.
 * ------------------------------------------------------------------------ */
static DWORD WINAPI WsClientThread(LPVOID param) {
    SOCKET c = (SOCKET)(uintptr_t)param;

    if (!ws_add_client(c)) {
        m2_logf("[!] lua_bridge: ws: refused client — %d clients already connected (WS_MAX_CLIENTS)",
                WS_MAX_CLIENTS);
        closesocket(c);
        return 0;
    }
    m2_logf("[*] lua_bridge: ws: client connected (%d/%d)", g_wsClientCount, WS_MAX_CLIENTS);

    ws_serve_client(c);

    ws_remove_client(c);
    closesocket(c);
    m2_logf("[*] lua_bridge: ws: client disconnected (%d/%d)", g_wsClientCount, WS_MAX_CLIENTS);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * TCP REPL server
 *
 * Protocol (matches tools/lua_repl.py and tools/lua_console.py in the
 * upstream Merc2Reborn project):
 *   - Client connects to g_repl_host:g_repl_port.
 *   - Client sends one or more lines, terminated by a line containing
 *     literal "<<<RUN>>>". The lines preceding the marker form the
 *     chunk to execute.
 *   - Server queues the chunk and replies "[queued]" immediately.
 *   - Whenever a pump source fires, the queued chunk runs against the
 *     captured L. The result is written back as one or more lines,
 *     followed by a line containing "<<<END>>>".
 *
 * When g_ws_enabled=1 (the default), the first bytes of each accepted
 * connection are peeked. If they start with "GET ", the connection is
 * upgraded to WebSocket via ws_do_handshake + ws_serve_client. Anything
 * else falls through to the raw-TCP loop below, unchanged.
 * ------------------------------------------------------------------------ */
#define BRIDGE_SENTINEL   "<<<RUN>>>"
#define BRIDGE_END_MARKER "<<<END>>>"

static DWORD WINAPI BridgeServerThread(LPVOID arg) {
    WSADATA w;
    SOCKET srv, c;
    struct sockaddr_in addr;
    BOOL reuse = TRUE;
    (void)arg;

    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) {
        m2_logf("[!] lua_bridge: WSAStartup failed");
        return 1;
    }
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) {
        m2_logf("[!] lua_bridge: socket() failed GLE=%lu", (unsigned long)WSAGetLastError());
        return 1;
    }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((u_short)g_repl_port);
    inet_pton(AF_INET, g_repl_host, &addr.sin_addr);
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0 || listen(srv, 8) != 0) {
        m2_logf("[!] lua_bridge: bind/listen on %s:%d failed GLE=%lu",
                g_repl_host, g_repl_port, (unsigned long)WSAGetLastError());
        closesocket(srv);
        return 1;
    }
    m2_logf("[*] lua_bridge: listening on %s:%d", g_repl_host, g_repl_port);

    for (;;) {
        char rx[65536];  /* per-line receive buffer; a single line longer
                          * than this wedges the recv loop (recv asks for
                          * 0 more bytes and breaks). 64 KB comfortably
                          * covers realistic Lua chunk lines. */
        char chunk_buf[1048576];  /* 1 MB — matches FixedTString.data */
        size_t chunk_len = 0;
        fd_set fds;
        struct timeval tv;
        int r;
        const char* nl;
        const char* p;
        size_t rx_len = 0;

        c = accept(srv, NULL, NULL);
        if (c == INVALID_SOCKET) continue;

        /* Discard any pending raw-TCP output that leaked in from a
         * previous session. The bridge is single-client, so anything
         * in g_outBuf at accept-time is stale — most commonly the
         * result_buf of a chunk a WS client queued then disconnected
         * before its pump run. Cross-session leakage would confuse a
         * fresh raw-TCP client that expects its first byte to be its
         * own [queued] ack. */
        EnterCriticalSection(&g_outMtx);
        if (g_outBuf_len > 0) {
            g_outBuf_len = 0;
            if (g_outBuf) g_outBuf[0] = '\0';
        }
        LeaveCriticalSection(&g_outMtx);

        /* WebSocket peek-and-branch. MSG_PEEK doesn't consume the bytes,
         * so on a match ws_do_handshake starts fresh recv()s that see
         * the full request. Non-match falls through to the raw-TCP
         * loop below with an untouched socket buffer.
         *
         * Handshake runs inline on the server thread (fast, bounded —
         * a full HTTP header + one Sec-WebSocket-Accept computation),
         * then the socket is handed to a dedicated worker thread so
         * this server thread can immediately loop back to accept the
         * next connection. Multiple concurrent WS clients share the
         * broadcast list; each worker runs independently. */
        if (g_ws_enabled) {
            char wsPeek[16];
            int  pn = recv(c, wsPeek, (int)sizeof(wsPeek), MSG_PEEK);
            if (pn >= 4 && memcmp(wsPeek, "GET ", 4) == 0) {
                if (!ws_do_handshake(c, NULL, 0)) {
                    m2_logf("[!] lua_bridge: ws: handshake failed");
                    closesocket(c);
                    continue;
                }
                {
                    HANDLE h = CreateThread(NULL, 0, WsClientThread,
                                            (LPVOID)(uintptr_t)c, 0, NULL);
                    if (!h) {
                        m2_logf("[!] lua_bridge: ws: CreateThread failed GLE=%lu",
                                (unsigned long)GetLastError());
                        closesocket(c);
                    } else {
                        CloseHandle(h);      /* fire-and-forget worker */
                    }
                }
                continue;
            }
        }

        for (;;) {
            /* Flush pending output */
            EnterCriticalSection(&g_outMtx);
            if (g_outBuf_len > 0) {
                size_t off = 0;
                int send_failed = 0;
                while (off < g_outBuf_len) {
                    int sent = send(c, g_outBuf + off, (int)(g_outBuf_len - off), 0);
                    if (sent <= 0) { send_failed = 1; break; }
                    off += (size_t)sent;
                }
                g_outBuf_len = 0;
                if (g_outBuf) g_outBuf[0] = '\0';
                if (send_failed) { LeaveCriticalSection(&g_outMtx); break; }
            }
            LeaveCriticalSection(&g_outMtx);

            FD_ZERO(&fds);
            FD_SET(c, &fds);
            tv.tv_sec = 0; tv.tv_usec = 50000;
            r = select(0, &fds, NULL, NULL, &tv);
            if (r < 0) break;
            if (r == 0) continue;

            {
                int n = recv(c, rx + rx_len, (int)(sizeof(rx) - rx_len - 1), 0);
                if (n <= 0) break;
                rx_len += (size_t)n;
                rx[rx_len] = '\0';
            }

            /* Process complete lines */
            p = rx;
            while ((nl = (const char*)memchr(p, '\n', rx + rx_len - p)) != NULL) {
                size_t line_len = (size_t)(nl - p);
                /* Strip trailing \r if present */
                if (line_len > 0 && p[line_len - 1] == '\r') line_len--;
                if (line_len == sizeof(BRIDGE_SENTINEL) - 1 &&
                    memcmp(p, BRIDGE_SENTINEL, line_len) == 0) {
                    /* Submit accumulated chunk */
                    if (chunk_len > 0) {
                        m2_logf("[+] lua_bridge: queued chunk (%lu bytes)",
                                (unsigned long)chunk_len);
                        InQueuePush(chunk_buf, chunk_len, 0);
                        OutAppend("[queued]", 8);
                    }
                    chunk_len = 0;
                } else {
                    /* Append line + newline to chunk */
                    if (chunk_len + line_len + 1 < sizeof(chunk_buf)) {
                        memcpy(chunk_buf + chunk_len, p, line_len);
                        chunk_len += line_len;
                        chunk_buf[chunk_len++] = '\n';
                    }
                }
                p = nl + 1;
            }
            /* Shift unconsumed bytes to front */
            {
                size_t consumed = (size_t)(p - rx);
                if (consumed > 0 && consumed < rx_len) {
                    memmove(rx, rx + consumed, rx_len - consumed);
                }
                rx_len -= consumed;
                rx[rx_len] = '\0';
            }
        }

        closesocket(c);
    }
}

/* ------------------------------------------------------------------------ *
 * INI config
 * ------------------------------------------------------------------------ */
/* m2_ini_parse's callback signature is (ud, key, value) — the parser
 * strips section headers internally and never surfaces them, so we
 * dispatch on the key name alone. Our two keys (`host` and `port`)
 * are unique across the INI's sections so this is fine. */
static void OnIniKV(void* ud, const char* key, const char* value) {
    (void)ud;
    if (!key || !value) return;
    if (_stricmp(key, "host") == 0) {
        strncpy(g_repl_host, value, sizeof(g_repl_host) - 1);
        g_repl_host[sizeof(g_repl_host) - 1] = 0;
    } else if (_stricmp(key, "port") == 0) {
        g_repl_port = atoi(value);
        if (g_repl_port <= 0 || g_repl_port > 65535) g_repl_port = 27050;
    } else if (_stricmp(key, "loader_enabled") == 0) {
        g_loader_enabled = atoi(value);
    } else if (_stricmp(key, "loader_onboot") == 0) {
        g_loader_onboot = atoi(value);
    } else if (_stricmp(key, "loader_onload") == 0) {
        g_loader_onload = atoi(value);
    } else if (_stricmp(key, "loader_delay_ms") == 0) {
        g_loader_delay_ms = atoi(value);
        if (g_loader_delay_ms < 0) g_loader_delay_ms = 0;
    } else if (_stricmp(key, "loader_onkey_cooldown_ms") == 0) {
        g_loader_onkey_cooldown_ms = atoi(value);
        if (g_loader_onkey_cooldown_ms < 0) g_loader_onkey_cooldown_ms = 0;
    } else if (_stricmp(key, "watchdog_stuck_ms") == 0) {
        g_watchdog_stuck_ms = atoi(value);
        if (g_watchdog_stuck_ms < 0) g_watchdog_stuck_ms = 0;
    } else if (_stricmp(key, "websocket_enabled") == 0) {
        g_ws_enabled = atoi(value);
    } else if (_stricmp(key, "loader_onkey_require_focus") == 0) {
        g_loader_onkey_require_focus = atoi(value);
    } else if (_stricmp(key, "loader_onkey_exact_modifiers") == 0) {
        g_loader_onkey_exact_modifiers = atoi(value);
    } else if (_stricmp(key, "loader_rearm_on_menu") == 0) {
        g_loader_rearm_on_menu = atoi(value);
    } else if (_stricmp(key, "loader_track_phase") == 0) {
        g_loader_track_phase = atoi(value);
    } else if (_stricmp(key, "loader_source_encoding") == 0) {
        /* Accept the words as well as 0/1 — "auto" and "off" read better in
         * an ini than a bare digit for something that isn't a toggle. */
        if (_stricmp(value, "auto") == 0)      g_loader_source_encoding_auto = 1;
        else if (_stricmp(value, "off") == 0 ||
                 _stricmp(value, "raw") == 0)  g_loader_source_encoding_auto = 0;
        else                                   g_loader_source_encoding_auto = atoi(value);
    } else if (_stricmp(key, "stack_diag") == 0) {
        g_stack_diag = atoi(value);
    }
}

/* Baked-in defaults, written to disk if the .ini is missing. Keeps the
 * .asi self-sufficient — users can drop the .asi alone and get a
 * commented, editable config on first launch. */
static const char kDefaultIni[] =
    "; lua-bridge configuration.\n"
    "; Drop this next to lua_bridge.asi in your game folder.\n"
    "\n"
    "[repl]\n"
    "; Host to bind the REPL listener on. 127.0.0.1 = localhost-only,\n"
    "; which is what you want unless you're routing through a tunnel.\n"
    "host = 127.0.0.1\n"
    "\n"
    "; Port for the REPL listener. Matches the default the upstream\n"
    "; tools/lua_repl.py and tools/lua_console.py expect.\n"
    "port = 27050\n"
    "\n"
    "[loader]\n"
    "; Enable or disable the native Lua Loader (1 = enabled, 0 = disabled)\n"
    "loader_enabled = 1\n"
    "\n"
    "; Load scripts in scripts/OnBoot/ once captured (1 = enabled, 0 = disabled)\n"
    "loader_onboot = 1\n"
    "\n"
    "; Load scripts in scripts/OnLoad/ once game enters world (1 = enabled, 0 = disabled)\n"
    "loader_onload = 1\n"
    "\n"
    "; DEPRECATED in v0.5.0 and now a no-op. ExecuteLuaFolder runs ON the game\n"
    "; thread, so sleeping between scripts could never let the engine settle\n"
    "; the way this name suggests -- the engine IS the thread being slept. All\n"
    "; it bought was a delay * (scripts-1) freeze on top of every load. Still\n"
    "; parsed so existing .ini files stay valid.\n"
    "loader_delay_ms = 50\n"
    "\n"
    "; Minimum time (in milliseconds) between the SAME OnKey script re-firing.\n"
    "; Prevents human hammer-tapping the hotkey from queueing multiple back-to-back\n"
    "; runs of the same script, which can crash non-reentrant scripts (menus,\n"
    "; state-mutating cheats, etc). First throttle per script is logged so users\n"
    "; can see it kick in; subsequent throttles are silent to avoid log spam.\n"
    "; Set to 0 to disable the cooldown entirely.\n"
    "loader_onkey_cooldown_ms = 250\n"
    "\n"
    "; Watchdog: if the queue has pending chunks and no pump progress happens\n"
    "; for this many milliseconds (while the game is actively running detours),\n"
    "; a background thread force-resets the bridge's stuck-state candidates\n"
    "; (hotWork, t_inBridgeExec, g_LuaState, seen-set) and logs a comprehensive\n"
    "; diagnostic line. Set to 0 to disable the watchdog entirely.\n"
    "watchdog_stuck_ms = 8000\n"
    "\n"
    "; WebSocket transport (1 = enabled, 0 = disabled). When enabled, the same\n"
    "; listener speaks either raw TCP (existing lua_repl.py / lua_console.py\n"
    "; protocol) or WebSocket — auto-detected from the first bytes. Browser\n"
    "; clients (tools/ess-bridge.js) connect via WS and receive structured\n"
    "; JSON messages: {type:\"ack\"}, {type:\"log\"} (mirrors Loader.Printf),\n"
    "; and {type:\"ws\"} (the hidden Loader.WsSend channel). Disable this if\n"
    "; you want the bridge locked to raw-TCP only.\n"
    "websocket_enabled = 1\n"
    "\n"
    "; --- added in v0.5.0 ---\n"
    "\n"
    "; Drop OnKey hotkey fires while the game is NOT the foreground window.\n"
    "; Before 0.5.0 hotkeys fired regardless of focus, so pressing F5 in a\n"
    "; browser (refresh) or F11 (fullscreen) silently ran your game scripts in\n"
    "; the background. Loader.PopKeyEvents has always been focus-gated; this\n"
    "; makes the .lua-firing path agree with it. 0 = old behavior.\n"
    "loader_onkey_require_focus = 1\n"
    "\n"
    "; Require the held modifier set to match a binding EXACTLY, so you can\n"
    "; bind `F5` and `ctrl+F5` to two different scripts. Side effect: a plain\n"
    "; `F5` binding no longer fires while ctrl/shift/alt is held. 0 = ignore\n"
    "; modifiers entirely (pre-0.5.0 matching).\n"
    "loader_onkey_exact_modifiers = 1\n"
    "\n"
    "; Re-run OnBoot/OnLoad after a main-menu round-trip. The engine wipes _G\n"
    "; when you exit to the menu and builds fresh Lua VMs on the next load, so\n"
    "; without this every OnLoad-installed framework stays dead until you\n"
    "; restart the game. Detected by watching for a world-load-start marker\n"
    "; after the world had already finished loading. 0 = once per process.\n"
    "loader_rearm_on_menu = 1\n"
    "\n"
    "; Track the world-load phase ladder (0..20) so Loader.GetLoadPhase()\n"
    "; works and the re-arm above can see a load restart. Costs a substring\n"
    "; scan per captured game log line on the detour path. 0 removes that cost\n"
    "; but disables GetLoadPhase and the menu re-arm.\n"
    "loader_track_phase = 1\n"
    "\n"
    "; Source-encoding normalization for .lua files and WS-submitted chunks.\n"
    "; The engine's text renderers consume single-byte CP1252, so a UTF-8\n"
    "; source file renders \"Mobius\" (o-umlaut) as \"MA-bius\". auto strips BOMs\n"
    "; and transcodes UTF-8 -> CP1252 only when the bytes are valid UTF-8 AND\n"
    "; contain a byte >= 0x80, so pure-ASCII and already-ANSI files are never\n"
    "; touched. off = raw bytes through (BOMs are still stripped, because a\n"
    "; BOM is an unconditional Lua syntax error).\n"
    "loader_source_encoding = auto\n"
    "\n"
    "; One-shot Lua stack-layout dump on the first chunk execution. This build\n"
    "; of Lua leaves a table where stock pcall leaves its boolean status, and\n"
    "; the status is not in the window the bridge reads — this dump exists to\n"
    "; find where it went, and to confirm it is NOT being written into the\n"
    "; engine's own stack frame. Costs one burst of log lines per process.\n"
    "stack_diag = 1\n";

static void EnsureIniDefault(const char* path) {
    FILE* f = fopen(path, "r");
    if (f) { fclose(f); return; }        /* user's file wins */
    f = fopen(path, "w");
    if (!f) return;
    fputs(kDefaultIni, f);
    fclose(f);
    m2_logf("[*] lua_bridge: wrote default %s", path);
}

static void LoadConfig(void) {
    char ini_path[MAX_PATH];
    m2_module_path(g_hModule, "lua_bridge_DEV.ini", ini_path, sizeof(ini_path));
    EnsureIniDefault(ini_path);
    m2_ini_parse(ini_path, OnIniKV, NULL);
}

/* ------------------------------------------------------------------------ *
 * Init
 * ------------------------------------------------------------------------ */
static DWORD WINAPI WorkerThread(LPVOID arg) {
    HMODULE mod;
    BYTE* base;
    int hooks_armed = 0;
    int t;

    typedef struct HookSpec {
        DWORD     rva;
        LPVOID    detour;
        LPVOID*   orig;
        const char* name;
        HookKind  kind;
    } HookSpec;
    HookSpec specs[3];

    (void)arg;

    LoadConfig();
    if (g_loader_enabled) {
        EnsureLoaderDirectories();
    }
    InitializeCriticalSection(&g_inMtx);
    InitializeCriticalSection(&g_outMtx);
    InitializeCriticalSection(&g_keyEventMtx);
    g_keyEventMtxInit = 1;
    InitializeCriticalSection(&g_keyScriptMtx);
    g_keyScriptMtxInit = 1;
    InitChunkSource();
    InitKeyboardStateTString();
    InitKeyEventsTString();
    InitPhaseNameTString();
    InitLoaderPrintfLog();
    InitDataDict();

    mod = GetModuleHandleA(NULL);
    if (!mod) {
        m2_logf("[!] lua_bridge: GetModuleHandle(NULL) returned NULL");
        return 1;
    }
    base = (BYTE*)mod;

    g_rvas = SelectRvas(mod);

    /* Same SecuROM-unpack-wait pattern Merc2Fix uses on the noop stub. */
    {
        BYTE* probe = base + g_rvas->noop_stub;
        for (t = 0; t < 400; t++) {
            int nz = 0, i;
            for (i = 0; i < 8; i++) if (probe[i]) { nz = 1; break; }
            if (nz) break;
            Sleep(25);
        }
    }

    p_luaB_loadstring = (lua_CFunction_t)(base + g_rvas->luaB_loadstring);
    p_luaB_pcall      = (lua_CFunction_t)(base + g_rvas->luaB_pcall);
    m2_logf("[*] lua_bridge: executor armed (loadstring=%p, pcall=%p)",
            p_luaB_loadstring, p_luaB_pcall);

    specs[0].rva = g_rvas->noop_stub;
    specs[0].detour = (LPVOID)&DetourNoopStub;
    specs[0].orig = (LPVOID*)&fpOriginal_NoopStub;
    specs[0].name = "noop-stub (print/SendEvent_*/...)";
    specs[0].kind = HOOK_NOOP_STUB;

    specs[1].rva = g_rvas->luaB_type;
    specs[1].detour = (LPVOID)&DetourLuaType;
    specs[1].orig = (LPVOID*)&fpOriginal_luaB_type;
    specs[1].name = "luaB_type";
    specs[1].kind = HOOK_NORMAL_FUNC;

    specs[2].rva = g_rvas->CreateTextWidget;
    specs[2].detour = (LPVOID)&DetourCreateTextWidget;
    specs[2].orig = (LPVOID*)&fpOriginal_CreateTextWidget;
    specs[2].name = "CreateTextWidget";
    specs[2].kind = HOOK_NORMAL_FUNC;

    /* NOTE: luaL_register hook intentionally omitted — see commented
     * block above. Bridge works without it; we just lose the
     * print/next/tostring hijack and the registration-table dump. */

    for (t = 0; t < (int)(sizeof(specs)/sizeof(specs[0])); ++t) {
        LPVOID target = (LPVOID)(base + specs[t].rva);
        if (!ValidateHookTarget(target, specs[t].kind)) {
            m2_logf("[!] lua_bridge: RVA 0x%X (%s) failed prologue validation — skipping",
                    specs[t].rva, specs[t].name);
            continue;
        }
        if (!m2_hook_attach(target, specs[t].detour, specs[t].orig)) {
            m2_logf("[!] lua_bridge: m2_hook_attach(%s) failed", specs[t].name);
            continue;
        }
        m2_logf("[*] lua_bridge: hook armed on %s (RVA 0x%X -> %p)",
                specs[t].name, specs[t].rva, target);
        hooks_armed++;
    }

    if (hooks_armed == 0) {
        m2_logf("[!] lua_bridge: 0 hooks armed — bridge disabled for this binary. "
                "REPL will NOT be started.");
        return 0;
    }

    /* Initialize the WS-client mutex before spawning any thread that
     * might touch g_wsClient (the server thread updates it on
     * connect/disconnect; game-thread Loader.Printf/WsSend read it
     * for fanout). Safe to always init even when g_ws_enabled=0 — the
     * mutex is cheap and the fanout still checks g_wsClient itself. */
    if (!g_wsClientMtxInit) {
        InitializeCriticalSection(&g_wsClientMtx);
        g_wsClientMtxInit = 1;
    }
    CreateThread(NULL, 0, BridgeServerThread, NULL, 0, NULL);
    CreateThread(NULL, 0, LoaderKeyEventThread, NULL, 0, NULL);
    m2_logf("[*] lua_bridge: key-event sampler armed (~60 Hz, %d-slot ring)",
            KEYEVENT_BUFFER_SIZE);
    if (g_watchdog_stuck_ms > 0) {
        /* Seed timestamps to "now" so the very first watchdog wake sees
         * coherent since_X deltas instead of "now - 0" (a huge number that
         * makes since_progress look like a stall the moment PendingScripts
         * first goes nonzero). g_bridgeExecStartTick stays 0 = not executing. */
        DWORD boot_tick = GetTickCount();
        g_lastDetourFireTick    = boot_tick;
        g_lastPumpAttemptTick   = boot_tick;
        g_lastPumpProgressTick  = boot_tick;
        CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
        m2_logf("[*] lua_bridge: watchdog armed (stuck threshold %d ms)",
                g_watchdog_stuck_ms);
    } else {
        m2_logf("[*] lua_bridge: watchdog disabled (watchdog_stuck_ms = 0)");
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = (HMODULE)h;
        DisableThreadLibraryCalls(h);
        m2_log_init(g_hModule);
        m2_logf("==========================================");
        m2_logf("[*] lua_bridge loading");
        m2_logf("==========================================");
        CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    }
    return TRUE;
}
