# Changelog

All notable changes to the Mercenaries 2 Experimental Mods project will be documented in this file.

## [v0.5.1] - 2026-07-26

Only `lua-bridge-DEV` bumped (0.5.0 → 0.5.1). Two transport-layer correctness fixes, both found by reading the consumers rather than the bridge. No API changes, no config changes.

### Fixed

- **The raw-TCP result channel was one execution behind.** Long-standing enough that `mercs2-lua-essentials`' `tools/lua_repl.py` was rewritten around it — that tool abandoned the socket as a result channel entirely, treating it as "advisory, possibly stale" and reading results back out of the log instead. Root cause: `g_outBuf` carried no association between a result and the connection that asked for it, and the executor's results are produced asynchronously on the game thread. The v0.4.0 accept-time buffer clear could not fix it, because the race isn't stale-data-at-accept — it's a result arriving *after* the next client has already connected:

  ```
  conn A submits chunk N, reads [queued], disconnects
  conn B is accepted        -> g_outBuf cleared (nothing pending yet)
  the pump finally runs N   -> result_N appended to g_outBuf
  conn B's flush            -> B receives A's result, then its own
  ```

  B reads to the first `<<<END>>>`, gets the previous chunk's answer, and stays exactly one execution behind for every subsequent request on that connection. Fixed by tagging each queued chunk with the raw-TCP session id that submitted it (incremented per `accept`) and delivering a result only when that session is still connected. A result whose requester has gone is dropped and logged rather than misdelivered.
  - Verified live by reproduction: four chunks submitted with the `lua_repl.py` close-early pattern produced two `dropped result for session N (client gone; current session N+1)` lines — the exact condition that used to cause the misdelivery — with zero cross-request leakage.
  - **Behavior change:** OnKey/OnBoot/OnLoad results no longer reach the raw-TCP channel. Pressing a hotkey while a REPL was connected used to inject an unsolicited result into that client's stream, which is the same desync by another route. Loader results still go to `lua_bridge_DEV.log` and to the WebSocket `{type:"log"}` feed.

- **WebSocket text frames could carry invalid UTF-8.** `js_escape_into` escaped control characters but passed bytes `0x80`–`0xFF` through untouched. The strings the bridge broadcasts are single-byte CP1252 (the engine's text encoding), so any accented character produced a malformed TEXT frame — and RFC 6455 §5.6 requires TEXT payloads to be valid UTF-8, so a conforming browser is entitled to fail the connection with protocol error 1007 rather than display the line. High bytes are now emitted as `\uXXXX`, which keeps the frame pure ASCII and therefore always valid.
  - The mapping is the real CP1252 one, not a naive `\u00XX`: byte `0x92` is a right single quote (U+2019), not U+0092, so the naive form would have turned every apostrophe the engine emits into an invisible control character. `0xA0`–`0xFF` is genuine Latin-1 and maps to the same codepoint.
  - Also resized the broadcast buffer. At the old 2560 bytes — sized for 1:1 passthrough — a 2 KB line of accented text would have exceeded the destination, and `js_escape_into` returning 0 causes the broadcaster to drop the **entire line**. That would have been a worse failure than the malformed frame it replaced.
  - Raw TCP is unaffected either way; it's a byte stream with no encoding contract.
  - Verified live over a real WebSocket handshake: `0xF6 → ö`, `0x92 → ’`, frames decode as valid UTF-8 and parse as valid JSON.

### Known gap (not shipping-blocking)

`mercs2-lua-essentials`' `tools/test_bridge_client.js` contains a deliberate line-for-line port of `js_escape_into`, so the two failing to agree makes the test fail. That port still says "everything else passes through" and no test input uses a high byte, so it no longer mirrors the C and would not catch a future regression in high-byte escaping. The C is correct and verified; the stale mirror lives in another repo and is tracked there.

### Verification

- Reproduction harness for the off-by-one: 4 close-early submissions + 1 normal request, zero leakage, drop path confirmed firing.
- Minimal stdlib WebSocket client for the framing fix: handshake, frame decode, UTF-8 and JSON validation, CP1252 mapping spot-checks.
- Ess framework smoke suite re-run against the rebuilt bridge: **49/49**.

## [v0.5.0] - 2026-07-25

Only `lua-bridge-DEV` bumped (0.4.1 → 0.5.0). Version-family boundary: `v0.5` is a **reliability pass on the loader half** of the mod, which had not had the same scrutiny as the bridge half. Most of what follows was found by driving a live session over the REPL rather than by reading the source, and several are long-standing bugs rather than new features. Every behavior change ships with an ini lever that restores the pre-0.5.0 behavior.

### Fixed

- **`OnBoot`/`OnLoad` never re-ran after a main-menu round-trip.** Exiting to the main menu wipes `_G`, and the next load builds fresh `lua_State`s — measured: two new VMs per load, distinct from the boot pair. Both hooks were guarded by once-per-process statics, so everything a startup script installed was silently gone and stayed gone until the game process restarted. Confirmed live: a planted `_G` sentinel and a 616 KB framework loaded from `OnLoad` were both `nil` after a menu trip, with only one `OnLoad milestone` line in the log across four VM captures.
  - Detection hangs off **`CaptureL` seeing a fresh `lua_State`** — since a menu round-trip demonstrably builds new VMs, a previously-unseen `L` arriving after a load cycle has already completed *is* the "we started over" signal, and it costs nothing because that slow path only runs for genuinely new VMs. Boot is not a false positive: the initial boot's second VM appears before OnLoad has executed, so the guard excludes it. (The first cut of this release detected it by watching every game log line for a load-start marker instead. That cost ~2 FPS and was replaced — see the perf note below.)
  - Level-to-level transitions do **not** wipe `_G` and correctly do **not** re-trigger.
  - `scripts/OnKey/` is re-scanned at the same time, so a `.lua` added mid-session is picked up without a restart. `InitializeKeyScripts` is now safe to call repeatedly — it spawns its polling thread once (the pre-0.5.0 `CreateThread` was unconditional, so a second call would have left two pollers running and fired every hotkey twice) and swaps the table under a new lock.
  - Lever: `loader_rearm_on_menu = 0`.

- **`OnKey` hotkeys fired while the game was in the background.** `LoaderKeyEventThread` (which feeds `Loader.PopKeyEvents`) had always been focus-gated and the README advertised that; `LoaderKeyThread`, which runs whole `.lua` files, was not. Pressing `F5` in a browser to refresh a page, or `F11` to go fullscreen, silently ran game scripts. Now gated on the same `IsGameFocused()` predicate, with edge state cleared on focus loss so refocusing with a key held doesn't fire on a stale transition. Lever: `loader_onkey_require_focus = 0`.

- **Every chunk result carried a junk `<table>` prefix, and `[ok]` was unreachable.** This build's `luaB_pcall` leaves a **table** in slot 0 with the chunk's real results from slot 1 up — the boolean status stock `luaB_pcall` `lua_insert`s at index 1 is not anywhere in the window the executor reads. Since `tt0` matched neither the boolean nor the number branch, `have_status` stayed 0, `first_result` stayed 0, and the label stayed `[runtime]` on *every execution since this code shipped* — including successful ones. Verified across 12 probes (`return` with 0/1/3 values; nil/boolean/number/table/function returns all landed at slot 1+, and `return print` correctly rendered `<function>`, ruling out a misreported residual).
  - Slot 0 is now recognized as an artifact and skipped when it holds a table or function — neither can be a pcall status.
  - **`[ok]` now works.** The status turned out to live at `saved_base[0]`, and it is a real status, not a fixed marker: correlated over 8 live samples, `val=0` for exactly the chunk that failed and `val=1` for every chunk that succeeded. The executor reads it there (just before restoring the engine's frame — see the next entry) and the label is finally accurate. The stock-layout `new_base[0]` boolean/number branches are retained so adding an RVA table for another binary doesn't require rediscovering any of this.
  - **Output-shape note:** the formatter separates values with `succeeded ? '\t' : ' '`. With `succeeded` permanently 0, every result until now used a space; successful results now use a tab, as the code always intended. Consumers splitting on generic whitespace are unaffected; anything splitting on tab specifically will see different fields.

- **Every chunk execution corrupted the hooked function's stack frame.** The hunt for the missing pcall status found something worse. `STACKDIAG` proved, across 8 samples, that this build's `luaB_pcall` writes its boolean status to **`saved_base[0]`** — the base of the frame belonging to the hooked C function the bridge is executing inside — rather than the `new_base` the executor installs. The slot went in as a string (`tt=4`), a table (`tt=5`), or lightuserdata (`tt=2`) and came out boolean `true` every single time; the three samples that logged "unchanged" were the ones already clobbered by an earlier execution.
  - Because each detour calls the original function *after* `GatedPump`, that original then read a replaced argument 1. A `type(x)` dispatched through the hooked `luaB_type` would answer `"boolean"` regardless of `x`, for any stock game script unlucky enough to share a detour call with a chunk execution. This has been happening on every chunk since the executor shipped, and is a plausible contributor to the intermittent misbehavior the watchdog was built to survive.
  - Fixed by snapshotting the frame slots below `new_base` before the call and restoring them after — exact, and a couple of TValues of copying each way. Results live at `new_base` and above, so the restore cannot disturb them. Measured `base_delta` is 4 slots; the snapshot is capped at 16 as a bound on a value we don't control.

- **The watchdog was blind to hangs in loader scripts.** `ExecuteLuaFolder` set `t_inBridgeExec` but never `g_bridgeExecStartTick`, so the hung-inside-exec path added in v0.3.1 could not see a hung `OnBoot`/`OnLoad` script — exactly the failure it was written to catch, since a blocked game thread also stops the detours Path B depends on. Additionally the watchdog bailed early on `g_PendingScripts <= 0`, which is *always* true for loader scripts (they bypass the queue entirely). Path A no longer consults `g_PendingScripts`; Path B keeps the guard, where it's meaningful.

- **`g_seenL` exhausted after a handful of menu visits, silently.** Two new VMs per load against 8 fill-and-stop slots. Once full, `CaptureL` returned *before* the four `Register*` calls — the comment claimed it only dropped a log line, but it dropped lib registration too, and the fast-path `g_seenL[i] == L` match could never hit again, so every subsequent detour fire on a new VM paid the full 4-syscall `LooksLikeLuaState`. That silently discards the single biggest hot-path win the v0.3.0 notes describe. Now a 16-slot ring with oldest-eviction, registration hoisted above the bookkeeping, and the scan no longer breaks at the first `NULL` (only safe while the table filled strictly front-to-back).

- **`loader_delay_ms` froze the game for no benefit.** `ExecuteLuaFolder` runs on the game thread, so `Sleep()`ing between scripts could not let the engine settle — the engine is the thread being slept. All it bought was a `delay × (scripts−1)` stall on top of every load. Now a no-op; still parsed so existing `.ini` files stay valid, and documented as deprecated.

- **`m2_logf` silently corrupted C99 format specifiers.** It goes through `wvsprintfA`, which supports neither `%zu` nor `%ll` nor width specifiers, and emits the literal text instead. Three call sites were affected. The worst was the binary fingerprint, which printed `0xlX` — and the header comment tells you to read that value off the log in order to add support for a new executable, so the documented procedure for supporting a new binary had never worked. Now split into two `%08lX` halves; the two `%zu` sizes are cast to `unsigned long`.

- **Nested `ExecuteLuaFolder` was possible.** `GatedPump`'s OnLoad branch didn't consult `t_inBridgeExec`, so `OnLoad` could begin while an `OnBoot` script was still on the stack. Now guarded in both places.

### Added

- **Source-encoding normalization.** The engine's text renderers consume strings as single-byte **CP1252** — verified live against both the native `MrxGui.TextWidget` font path and the Scaleform `.gfx` path — so a `.lua` saved as UTF-8 puts two bytes (`C3 B6`) where the renderer wants one (`F6`) and `Möbius` renders as `MÃ¶bius`. The bridge itself was never corrupting anything; it is byte-transparent end to end, which is why this is fixed at load time rather than in the render path.
  - One `LoadScriptBytes()` chokepoint replaces the two near-identical `fopen`/`fread` blocks in `ExecuteLuaFolder` and `LoaderKeyThread`.
  - BOMs are stripped **unconditionally**, even with normalization off: a UTF-8 BOM is a hard Lua 5.1 syntax error and editors add one silently. UTF-16 BOMs get an explicit "re-save as ANSI or UTF-8" line instead of being fed to the parser as garbage.
  - UTF-8 → CP1252 runs only when the bytes are valid UTF-8 (probed with `MB_ERR_INVALID_CHARS`, which fails on CP1252 input — exactly the discriminator needed) **and** contain a byte ≥ 0x80. Pure-ASCII files are bit-identical in both encodings and never touched; already-CP1252 files fail the probe and pass through. Characters with no CP1252 equivalent are logged rather than silently becoming `?`.
  - `lua_console.py` sent UTF-8 too, and now uses CP1252 in both directions.
  - Lever: `loader_source_encoding = off`.
- **`Loader.GetLoadPhase()` → `nIndex, sName`** — position on loadprobe's 0..20 world-load ladder, so a script can confirm it is in a world before touching entities. Fed from the existing noop-stub detour, **not** `m2_loadtrigger_install()`: that MinHooks `M2_LOG_STUB_VA`, which is the same address this mod already detours (`0x006D5640` on v1.1+bypass), so installing it would double-hook a target we own. Only the ladder data and `m2_loadtrigger_phase_name()` are reused. Scanning is confined to the duration of a load — it stops at phase 20 and re-arms for the next load — so the cost sits inside a loading screen rather than the steady-state frame loop. Lever: `loader_track_phase = 0`.
- **`Loader.LoadFile(sRelPath)`** — execute another `.lua` relative to `<game>/scripts/` on the current VM, synchronously. Gives scripts a way to share library code, which previously only existed via `_G` pollution from `OnBoot` — and that gets wiped. Uses its own chunk-source buffer so it can't clobber the source text of the chunk that called it; rejects absolute paths and `..`, and refuses to nest (which also stops a file that loads itself).
- **Modifier combinations in hotkey bindings** — `ctrl+`, `shift+`, `alt+` in any order (`KEYVAL = "ctrl+F5"`). Modifiers must match exactly so `F5` and `ctrl+F5` can drive different scripts; `loader_onkey_exact_modifiers = 0` restores modifier-insensitive matching.
- **Many more bindable keys** — `numpad0`–`numpad9` and the numpad operators, `F13`–`F24`, `capslock`/`numlock`/`scrolllock`/`pause`/`printscreen`, left/right-specific modifiers, the full punctuation/OEM set including `tilde` (the traditional console key, previously unbindable — which is what pushed people onto the F-keys browsers also claim), and `mouse4`/`mouse5`. Purely additive: every pre-0.5.0 name resolves identically.
- **`_`-prefixed directories are not scanned**, so shared library code can live at e.g. `scripts/OnLoad/_lib/` and be pulled in with `Loader.LoadFile` instead of auto-running. Previously the recursive scan picked up everything, so there was nowhere to put a non-auto-run `.lua`.
- **Per-script disable** — `off`, `no`, or `disabled` as a script's value in `lua_loader.ini` skips it without deleting the file. Deliberately *not* repurposing `0`, which existing configs may contain and which currently means "run first".
- **Loader script results reach live clients.** `OnBoot`/`OnLoad`/`LoadFile` results now go to the `Loader.Printf` log and the WS `{type:"log"}` feed, not just `lua_bridge_DEV.log` — a connected REPL or browser never saw a startup-script failure before. `result_buf` also raised from 4 KB to `PumpQueue`'s 16 KB, since it was silently truncating longer results and error messages.

### Performance

- **The noop-stub detour stays off the per-frame budget.** `Debug.Printf` and ~700 other stripped log functions funnel through that stub thousands of times per frame from stock scripts, so anything unconditional in it is measurable. Pre-0.5.0 the `m2_lua_join_strings` call there stopped entirely once the OnLoad milestone was seen; the first cut of this release reintroduced it permanently to feed phase tracking, which showed up in testing as a drop from a locked 60 FPS to ~58. Both consumers now gate themselves off: the OnLoad trigger stops at its milestone as before, and phase tracking stops at the fully-loaded phase and is re-armed per load cycle. Steady-state gameplay is back to two volatile loads and a `GetTickCount()`, matching pre-0.5.0. The re-arm detection moved to the free `CaptureL` signal in the same pass.

### Changed / hardened

- Script scanning: junctions and symlinks are skipped outright (a junction pointing at an ancestor was an unbounded recursion, and each level costs ~600 bytes of *game-thread* stack), with an 8-level depth cap behind it. The two `LuaScriptFile[128]` arrays (~67 KB each) and `LuaKeyScript[128]` (~78 KB) moved off the stack to statics, protected by the new nesting guard. Hitting `MAX_SCRIPTS` is now reported instead of silently dropping files.
- Unrecognized `OnKey` key names log a loud warning naming the valid forms. Previously a typo like `pgup` or `F13` resolved to VK 0 and simply never fired, looking identical to a working binding in the log.
- Two scripts sharing one binding is logged at registration. It's a supported feature, but it's also what an accidental `KEYVAL` collision looks like, and nothing said so.
- The oversize-script cap is now `sizeof(g_chunkSource.data)` rather than a separate 1 MB constant, so "the loader accepted it" and "the executor will run it" can't disagree — and going over is logged rather than silently skipped.
- `lua_loader.ini` dropped from the shipped `assets[]`. Shipping it defeated `EnsureLoaderIniHeader`, which early-returns when the file exists — so users got a stripped copy referencing three sample scripts that aren't in the zip, and never saw the commented VK-code reference the code takes care to write. Existing installs keep their file untouched.

### Notes for script authors

- **String escapes in this build are OCTAL, not decimal.** Stock Lua 5.1 reads `"\ddd"` as decimal; this build reads base 8 and does not reject the digits 8 or 9. `ö` is `"\366"`, not `"\246"` (which yields `0xA6`). `"\9"` is a tab; `"\195"` is `0x8D`. Live-verified with `"\101"` → `"A"` (65), where decimal would have given `e`. `"M\366bius"` in an ASCII-only file is the dependency-free way to write an accented string.

### Verification

- Built clean with `i686-w64-mingw32-gcc` 16.1.0; no new warning *classes* versus baseline (the original source was compiled for comparison — same two, `-Wstringop-truncation` and `-Wformat-truncation`, with higher counts only from more code of the same safe `strncpy(dst, src, sizeof-1)` + explicit-NUL shape).
- Live-tested throughout against v1.1 + mercs2-securom-bypass:
  - 12 stack-layout probes establishing that results start at slot 1.
  - 4 escape-encoding probes establishing the octal behavior (`"\101"` → `"A"`).
  - A two-variant on-screen render comparison through `MrxGui.TextWidget` confirming the single-byte CP1252 target, agreeing with the `.gfx` path.
  - 8 `STACKDIAG` samples proving the engine-frame corruption, then 8 more confirming the restore holds (`UNCHANGED` on every sample, original types preserved).
  - Status correlation over a known-good/known-bad chunk set.
  - Full main-menu round-trip: `_G` confirmed wiped, re-arm fired off the fresh-VM signal, `OnKey` table rescanned without a duplicate polling thread, OnLoad re-ran, and the `Ess` framework came back as a live table where it was `nil` before.
  - Framerate confirmed back to a locked 60 after the hot-path regression was fixed.

## [v0.4.1] - 2026-07-17

Only `lua-bridge-DEV` bumped (0.4.0 → 0.4.1). Adds concurrent WebSocket clients — same wire contract, no user-facing API changes, no config change.

### Added

- **Concurrent WebSocket clients (up to 16 at once).** Each accepted WS connection is served on its own worker thread, and all connected clients receive every `{type:"log"}` and `{type:"ws"}` broadcast. Result routing is unchanged — the tagged-nonce mechanism in the reference client-side wrapper works exactly as it did on v0.4.0 because it lives in Lua-space (the client filters the shared `{type:"ws"}` stream for its own tag). This enables the natural use cases the design was already set up for: a browser console + a Python REPL + a mod's admin dashboard, all watching the same live game session simultaneously. Raw TCP is still single-client (its `<<<RUN>>>` / `<<<END>>>` line protocol is inherently 1:1); the mix of "one raw TCP + N WS" is now supported.
  - `WS_MAX_CLIENTS = 16`. The 17th client's accept is refused cleanly (`ws_add_client` returns 0, the socket is closed, a log line records the refusal). Existing clients are unaffected.
  - Listen backlog raised from 1 to 8 so a burst of connection attempts doesn't RST any of them.

### Fixed

- **Cross-transport chunk output leakage.** With multi-client comes the possibility of a WS client submitting a chunk while a raw-TCP client is connected. Previously the pump wrote every chunk's `result_buf` to `g_outBuf` (the raw-TCP output channel), which would have caused a raw-TCP client to see mystery output for chunks it didn't submit. Fixed by adding a `from_ws` provenance bit to `ChunkNode` — WS-queued chunks return their results via `Loader.WsSend` in the Lua wrapper and skip the `g_outBuf` fanout entirely. Raw-TCP and loader-queued chunks (OnKey / OnLoad / OnBoot) still use `g_outBuf` exactly as before.

## [v0.4.0] - 2026-07-17

Only `lua-bridge-DEV` bumped (0.3.1 → 0.4.0). Version-family boundary: `v0.4` adds a **WebSocket transport** alongside the existing raw-TCP one, which unlocks a whole new class of client — a browser can now connect directly to the live game and drive Lua without a Python/PowerShell relay in the middle. Also adds a new Lua function for pushing values back out on a hidden channel.

### Added

- **WebSocket transport.** The same listener (`127.0.0.1:27050` by default) now speaks either raw TCP (the existing `lua_repl.py` / `lua_console.py` protocol) or WebSocket, auto-detected from the first bytes of each connection. Peek for `GET ` → WebSocket handshake (RFC 6455, SHA-1 via BCrypt + base64 via `CryptBinaryToStringA` — no vendored crypto); anything else falls through to the raw-TCP path unchanged. Wire contract is JSON text frames:
  ```
  client -> bridge   {"id":"q17abc","code":"<lua source>"}
  bridge -> client   {"type":"ack","id":"q17abc","status":"queued"}
  bridge -> client   {"type":"log","line":"…a Loader.Printf line…"}
  bridge -> client   {"type":"ws","line":"…a Loader.WsSend line…"}
  ```
  One WS message = one request. Ack is immediate (socket thread, deterministic). Log and WsSend feeds mirror in real time. Ping/pong and close frames are handled per spec. Frame sizes up to 1 MB per message, matching the raw-TCP chunk cap. Reference browser client lives in [`mercs2-lua-essentials/tools/ess-bridge.js`](https://github.com/loganw234/mercs2-lua-essentials).
- **`Loader.WsSend(str, …)`** — a new Lua global that broadcasts each call as `{"type":"ws","line":"…"}` to the connected WebSocket client **and never writes the log file**. Same join semantics as `Loader.Printf` (tab-separated string args). This is the "hidden channel" — REPL result plumbing (tagged nonces from the client-side wrapper) rides it without polluting `lua_loader_printf.log`, and mods can stream telemetry to a browser page without dumping it into the log too. No-op when no WS client is connected, so scripts that call it under raw-TCP or offline are harmless.
- **INI toggle** `websocket_enabled = 1` (default on). Rollback lever — set to 0 to disable the WS transport entirely and lock the listener to raw-TCP only.

### Changed

- `Loader.Printf` still writes to `lua_loader_printf.log` exactly as before, but now also mirrors each line to the connected WS client as `{"type":"log","line":"…"}`. This is the browser's "live console feed." Raw-TCP behavior is unaffected — Printf never wrote to that path in the first place, and doesn't now.

### Fixed

- **Cross-session `g_outBuf` leakage.** The single-client output buffer used by the raw-TCP path could carry stale content from a previous session — most commonly the executor's `result_buf` for a chunk a WS client queued and then disconnected before its pump run. A fresh raw-TCP client's first read would then contain that stale result before its own `[queued]` ack. Now cleared at accept-time on every new raw-TCP session and drained continuously during WS sessions, so no output can survive across session boundaries.

## [v0.3.1] - 2026-07-15

Only `lua-bridge-DEV` bumped (0.3.0 → 0.3.1). Watchdog reliability patch — no user-facing API changes.

### Fixed

- **Watchdog now detects "hung inside a native call from Lua."** Previously the watchdog's `since_detour > 2000` guard — meant to distinguish a genuine stall from a legitimate pause — silently misfired in the very case it existed to catch. When a queued script called into native code that never returned (e.g. `SetSwfFile()` on a wedged D3D device, an infinite `while true do end`), the game thread was blocked, so no more of our hooked detours could fire. After 2 seconds the watchdog treated the hang as "game paused" and bailed. This is the specific pattern users reported as "bridge queue stops draining, only PC restart fixes it."
- **New detection path.** A separate `g_bridgeExecStartTick` tracks when the pump entered `LuaDoString`. If it stays set for longer than the stuck threshold, the watchdog fires regardless of detour activity — because being inside exec proves the pump was active. Logged as `pattern: in-bridge-exec-not-returning (native call from Lua hung)` with `exec_elapsed=Xms` for post-mortem.
- **Boot-time timestamp seeding.** `g_lastDetourFireTick`, `g_lastPumpAttemptTick`, and `g_lastPumpProgressTick` are now initialized to `GetTickCount()` before the watchdog thread starts, instead of BSS-zero. Prevents `since_progress = GetTickCount()` (a huge number) on the first wake, which could produce incoherent diagnostics in edge cases.
- **What this fixes and doesn't fix.** When the game thread eventually recovers (driver unblocks, native call completes late), the reset means the next pump entry finds a clean bridge state — fresh `g_LuaState`, cleared `g_seenL`, `t_inBridgeExec` force-cleared — instead of a permanently jammed queue. The bridge cannot forcibly unstick a hung native call from a different thread; if the game process is genuinely dead, only a restart helps. But the failure mode is now recoverable rather than fatal, and the diagnostic log clearly identifies which of three stuck patterns fired.

## [v0.3.0] - 2026-07-09

Only `lua-bridge-DEV` bumped (0.2.2 → 0.3.0). Version-family boundary: `v0.1` had no math library, `v0.2` reached stock Lua math parity, `v0.3` adds **persistence** — the first user-facing capability that lets script authors do things previously impossible on this platform (survive a game restart with saved state). Also bundles a meaningful hot-path perf improvement to the input functions.

### Added

- **`Loader.SaveVar(sKey, xValue)` / `Loader.LoadVar(sKey)`** — simple key-value persistence for numbers, strings, and booleans. Values survive game restarts. Stored on disk as `lua_loader_data.ini` next to the `.asi` in a human-readable format that users can hand-edit while the game is offline:
  ```
  ; Format: key=type:value  (n=number, s=string, b=boolean 0/1)
  MasterCheatMenu_Progress=n:18
  MyMod_TutorialSeen=b:1
  MyMod_Setting=s:hardcore
  ```
  - **Types preserved** across the round trip — `Loader.SaveVar("count", 5)` then `Loader.LoadVar("count")` returns the number `5`, not the string `"5"`. Same for booleans and strings.
  - **Nil for missing keys** — `Loader.LoadVar("does_not_exist")` returns `nil`, standard Lua idiom for defaults: `local x = Loader.LoadVar("progress") or 0`.
  - **Atomic writes** — each save writes to `lua_loader_data.ini.tmp` then `MoveFileExA(MOVEFILE_REPLACE_EXISTING)`. A crash mid-write can't leave a truncated file.
  - **Flat namespace** — a single global namespace shared by all scripts. Convention (documented on the wiki): prefix your keys with your script's name (`MyMod_progress` not `progress`) to avoid collisions with other mods.
  - **String semantics**: each `SaveVar` with a string value allocates a fresh `TString`; the previous value's string stays valid for any Lua variable still holding a reference to a prior `LoadVar` result. Memory grows with write frequency (1000 writes × 100 chars ≈ 100 KB), bounded and acceptable for a game session.

### Changed (perf)

- **Fast-path input functions**: `Loader.IsKeyDown`, `Loader.GetKeyboardState`, `Loader.PopKeyEvents`, `Loader.IsGameFocused`, and every `math.*` function had 6+ `VirtualQuery` syscalls of defensive validation on the hot path (`LooksLikeLuaState` + individual `SafeProbe` on base and top). Removed — when Lua's own dispatch calls a `luaL_register`-installed C function, `L`/`base`/`top` are engine-guaranteed valid, and the `LUA_MINSTACK` reservation covers the one-slot push. **Hot-path cost drops from ~15 µs to ~0.81 µs per call** (measured: 500,000 `IsKeyDown` calls in 404 ms of isolated execution time, ~1.24 M calls/sec). A script can now safely call `Loader.IsKeyDown(vk)` 20,000 times per frame at 60 FPS while using <2% of the frame budget.

  Defensive checks retained on `Loader.Printf` and `Tcp.Send` — those are I/O-bound anyway, so the check cost is noise there.

### Notes for consumers

- `Loader.IsKeyDown` and its siblings now officially carry a **"safe in hot loops"** guarantee — the previous implicit assumption is now backed by measured data. The wiki page notes will be updated to reflect that.
- The `math.*` functions got the same fast-path treatment via the `MATH_ONEARG` / `MATH_TWOARG` macros, so `math.sin`/`math.cos`/etc. also drop to ~sub-µs per call. Also safe in per-frame loops.

### Verification

- `SaveVar`/`LoadVar` round-trip: **10/10** across number, string, boolean, missing-key, type-preservation, overwrite, and newline-escape cases.
- On-disk file format: verified human-readable, hand-editable, correct atomic replace.
- `IsKeyDown` throughput: measured **~0.81 µs/call**, **~1.24 M calls/sec**.
- Full stress suite (15 phases): **15/15 pass**, no regressions.
- Watchdog: armed once at boot, fired 0 times through the full session — no false positives from either the new subsystem or the fast-path changes.

## [v0.2.2] - 2026-07-06

Only `lua-bridge-DEV` bumped (0.2.1 → 0.2.2). Defensive addition: a background watchdog that self-heals the bridge from silent stuck-state conditions users have occasionally reported. No new user-facing features, no behavior changes to any hot path — the watchdog stays completely dormant unless it detects a real problem.

### Added

- **Bridge self-healing watchdog.** A dedicated background thread that wakes every ~2 seconds and, if the queue has pending chunks AND the game is running detours AND no pump progress has happened for `watchdog_stuck_ms` (default **8000**), force-resets the bridge's stuck-state candidates and logs a comprehensive diagnostic line. Reset actions: `hotWork = 1`, signal `PumpQueue` to clear its per-thread `t_inBridgeExec` flag (via a compare-exchange handshake), null out `g_LuaState`, memset the seen-L cache to zero. Next detour fire cleanly re-captures and pump resumes — no reboot required. Configurable via `watchdog_stuck_ms` in `lua_bridge_DEV.ini`; set to 0 to disable.
- **Three cheap timestamp probes** feeding the watchdog's decision logic: `g_lastDetourFireTick` (updated by every detour), `g_lastPumpAttemptTick` (updated when `GatedPump` enters its slow path), `g_lastPumpProgressTick` (updated after every successful chunk drain). Each is a single volatile store per event; measured cost: unmeasurably small, no fast-path impact.

### Diagnostic

When the watchdog fires, it logs four lines that describe exactly which stuck pattern was seen — one of two categories are distinguishable:
- `hotWork-stuck-at-0` (GatedPump never enters slow path) — the ms-since-slowpath timestamp reveals this
- `PumpQueue-not-draining` (t_inBridgeExec stuck TRUE, or LooksLikeLuaState failing on stale L) — slowpath is being attempted but no progress

Users seeing repeated `WATCHDOG` fires in their `lua_bridge_DEV.log` should send those lines upstream so we can finally diagnose the root cause of the intermittent stalls that motivated the watchdog. The self-heal is a safety net, not a fix — every fire indicates a real bug we still want to eventually eliminate.

### Notes

- `g_seenL[8]` was refactored from a `static` local inside `CaptureL` to file-scope so the watchdog can reset it directly. No behavioral change; same array, same lookup semantics.
- Cool-down of `stuck_ms / 2` between resets prevents the watchdog from hammering on a still-stuck bridge.
- Full stress suite (15 phases) run against this build: 15/15 pass, watchdog fired 0 times during 17s of aggressive stress including 256 KB chunks, 200-chunk queue floods, TCP-send bursts, and 1000-call Loader.Printf loops. No false positives observed under realistic load.

## [v0.2.1] - 2026-07-05

Only `lua-bridge-DEV` bumped (0.2.0 → 0.2.1). Stability / correctness patch focused on OnKey reentrancy protection and two small polyfill nits caught in the v0.2.0 code review.

### Added

- **Per-script OnKey cooldown.** Rapid double-presses of the same hotkey were queueing two back-to-back runs of a script; sequential (not concurrent) execution, but many gameplay scripts aren't reentrant and the second run running on state the first left behind could destabilize the engine. `LoaderKeyThread` now tracks `last_fired_tick` per script and skips re-firing if the last fire was within `loader_onkey_cooldown_ms` (default **250 ms**). The first throttle per script per session logs `[!] lua_bridge: OnKey '<key>' throttled (...)` so users notice the cooldown is engaging; subsequent throttles are silent to avoid log spam. Set `loader_onkey_cooldown_ms = 0` in `lua_bridge_DEV.ini` to disable. Fully compatible with `GetTickCount` wraparound (~49.7-day cycle) via unsigned subtraction.

### Fixed

- **`assert` error message location.** The polyfill's `error(msg or 'assertion failed!')` used the default level (1), which pointed error messages at the polyfill chunk (`[string "if math then..."]:1: bad msg`) instead of at the caller of `assert(...)`. Now uses `error(..., 2)` to skip the assert function frame — error messages now report the caller's location, matching stock Lua semantics. Critical for anyone debugging scripts with real error messages.
- **Polyfill success log is honest.** Previously logged `[*] polyfill applied ...` unconditionally, even if `LuaDoString` returned a compile error or internal bridge failure. Now checks the result buffer for `[compile]` or `[bridge]` prefixes and logs `[!] polyfill FAILED to apply: ...` in those cases. Prevents future silent breakage from hiding behind a misleading success line.

### Notes

`lua_loader.ini` still does not auto-prune stale script entries when the corresponding `.lua` file is deleted — this remains intentional (a moved `.lua` returning to its folder should keep its binding). If a specific user report shows the ini growing unmanageable, we'll add an opt-in `loader_prune_stale_ini` flag then.

## [v0.2.0] - 2026-07-05

Only `lua-bridge-DEV` bumped this release (0.1.6 → 0.2.0). The version-family jump (0.1.x → 0.2.x) reflects that the Lua environment inside the game has grown from "a bridge you can send chunks to" into a **usable general-purpose Lua runtime**. AI-assisted script authors can now reach for `math.sqrt`, `math.pi`, `assert(x, msg)`, `math.random`, etc. and have them just work — the stripped stdlib is no longer a papercut on every fresh script.

`debug-overlay-DEV` and `multiplayer-restore-DEV` stay at 0.1.5. Both are stable; nothing about them changed.

### Added

**Full Lua stdlib parity for math and assert** — a stdlib-completeness probe (run against the live game) identified 19 missing math functions and one critical missing base function. All are now available:

- **`math.sin`, `math.cos`, `math.tan`** — trig (`sin`/`cos` shipped in v0.1.6; `tan` new here)
- **`math.asin`, `math.acos`, `math.atan`, `math.atan2`** — inverse trig
- **`math.sinh`, `math.cosh`, `math.tanh`** — hyperbolic
- **`math.sqrt`, `math.log`, `math.log10`** — the ones AI-generated scripts reach for constantly
- **`math.fmod`, `math.ldexp`, `math.modf`, `math.frexp`** — the low-level number-manipulation set
- **`math.random(...)`, `math.randomseed(x)`** — matches stock Lua 5.1 semantics (`random()` / `random(n)` / `random(m, n)` all supported)
- **`math.pi`, `math.huge`** — constants, injected via a Lua polyfill chunk since `luaL_register` only takes functions
- **`assert(v, msg)`** — polyfilled in Lua on top of the engine's existing `error`. Idempotent (`if not _G.assert then`), re-applied on every pump batch so `_G` wipes don't strand it

All backed by the C stdlib's single-precision routines with the same `SafeProbe` + type-tag safety wrapping used across the rest of the file. Registered via the custom-ABI `luaL_register` path, additive to the engine's existing `math.floor` / `math.abs` / `math.max` / `math.min` / etc.

### Fixed

**`LoaderKeyThread` file-exists guard.** Pressing a hotkey whose backing `.lua` file had been deleted after game boot could destabilize the game. `GetFileAttributesA` now runs before every `fopen`; missing files log a clear warning line (`[!] lua_bridge: OnKey '<key>' bound to missing file: <name> (skipped)`) and are safely skipped.

### Changed

**Release workflow no longer ships sample scripts in the packaged zip.** When a user updates the mod through the modkit and the modkit's update logic does a clean-and-reinstall (as opposed to a diff-and-patch), any user-authored `.lua` files sharing the same `OnBoot/`, `OnLoad/`, `OnKey/` folders as our samples get wiped alongside them. Stripping the samples from the auto-deployed zip sidesteps that entirely — nothing in those folders belongs to the mod's install list, so the modkit has no reason to touch them. Sample `.lua` files stay in the repo as documentation.

### Documentation

- Wiki pointer ([wiki.mercs2.tools](https://wiki.mercs2.tools)) added to the top-level README and to the lua-bridge README (twice — intro callout and inside the Script Loader section). Users looking for sample scripts, deep-dives, and per-function reference now have one authoritative destination.

## [v0.1.6] - 2026-07-03

Only `lua-bridge-DEV` bumped this release (0.1.5 → 0.1.6). `debug-overlay-DEV` and `multiplayer-restore-DEV` stay at 0.1.5 — the modkit downloads each mod's assets from the release matching that mod's own `version` field, so leaving them alone is truthful and reflects that nothing about them changed.

### Added (lua-bridge)

Extensive `Loader.*` namespace additions turning the bridge into a full keyboard / focus API surface. Discovered adequate for co-op text chat via an adversarial capture test — see the notes at the bottom.

- **`Loader.GetKeyboardState()`** — returns a 256-byte string; each byte's high bit is set iff the corresponding virtual-key code is currently pressed. Backed by `GetAsyncKeyState` (system-wide physical state, not thread-message-queue). Consume with `string.byte(s, vk + 1)`.
- **`Loader.IsKeyDown(vk)`** — beginner-friendly single-key predicate. Boolean return.
- **`Loader.PopKeyEvents()`** — press-order event queue. Backed by a dedicated **~60 Hz C-side sampler thread** and a **128-slot ring buffer**, so a poll-once-per-frame client never misses a keystroke to timing. Returns a string of raw VK bytes; empty when idle. **Focus-gated**: keystrokes typed while the game process is not the foreground window are silently dropped, so co-op chat mods don't accidentally capture Discord messages.
- **`Loader.ClearKeyEvents()`** — explicit ring reset. Meant to be called at the moment a chat input opens so the first `PopKeyEvents()` after that returns only what the user typed *since*.
- **`Loader.IsGameFocused()`** — boolean; true iff the foreground window belongs to the game process. Uses process-ID match so it works across window styles (borderless, fullscreen, multi-window).

### Changed (lua-bridge)

- **REPL rx buffer bumped 4 KB → 64 KB.** A Lua chunk with any single line longer than 4096 bytes silently wedged the receive loop (server `recv`'d 0 more bytes, then closed the connection). Found by the stress harness's big-chunk test. 64 KB comfortably covers realistic line lengths.

### Notes for consumers

- `Loader.Printf` and `Tcp.Send` are each **several milliseconds per call** (~5 ms and ~15 ms respectively — the former's cost is Windows Defender scanning `.log` writes, the latter's is localhost TCP handshake + `TIME_WAIT` per fresh socket). **Do not call inside per-frame Lua loops** — ~150/sec saturates a full 60 FPS frame. Both are fine for occasional use.

## [v0.1.5] - 2026-07-01

### Added
- **Self-healing `.ini` in all three mods.** Each `.asi` now writes a commented default `.ini` next to itself on first launch if none is present. Users can drop the `.asi` alone and get an editable, fully-annotated config without hunting down the accompanying file. Existing `.ini` files are never overwritten — the check is a plain `fopen("r")` first-pass. A `[*] <mod>: wrote default ...` line is emitted to the mod's log when the file is generated so the behavior is visible.

### Removed
- **`multiplayer-restore-DEV`: cert-blindfold and clock-spoof hooks.** Live testing on the current cracked binary confirmed the FESL CA pubkey patch alone is sufficient for the private server's cert chain to validate — the `WinVerifyTrust` return-`ERROR_SUCCESS` hook and the Win32/CRT clock spoof (pinning time to 2012-06-15) were experimentation-era belt-and-braces layers. Both are now gone, along with their `hook_cert`, `hook_time`, and `spoof_clock` INI keys, all associated typedefs / detour functions / static originals, and the `-lwintrust` link dependency. Binary size dropped ~2.5 KB. The DNS redirect (`hook_dns`), FESL CA key patch (`patch_ca`), and b-version patch (`patch_bversion` / `bversion`) are unchanged. A short "Historical note" paragraph was left in the source header explaining why the hooks aren't there anymore, so future contributors reading git blame have the context.

## [v0.1.4] - 2026-07-01

### Added
- **Global `Loader.Printf` Lua function** — writes lines to a dedicated `lua_loader_printf.log` next to the .asi. Intended as a low-noise replacement for the engine's `Debug.Printf`, which is called thousands of times per frame from stock scripts and drowns out custom-script output. Exposed on the `Loader` global via the same custom register-argument ABI used for `Tcp.Send`.
- **`perf_monitor.lua` OnKey script** — press F5 to toggle a perf HUD on the debug-overlay showing post-GC Lua memory (`collectgarbage("count")`) and a refresh counter. Snapshot-per-press; press F5 again for a new reading or to hide.

### Fixed
- **`_G` wipe recovery** — the engine clears `_G` on some game-state transitions (menu → mission, cutscene entry, etc.), which previously wiped both `Tcp` and `Loader` permanently until game restart. The bridge now re-registers both libs at the start of every pump batch (`luaL_register` is idempotent), so state transitions can no longer strand the globals.
- **`Loader.Printf` stall** — dropped the per-call `FlushFileBuffers`, which was forcing a synchronous disk sync on the game's Lua thread and could freeze the bridge for seconds on slow disks / cloud-synced folders.

### Changed (performance)
- **`CaptureL` seen-set fast-path** — the seen-set pointer scan now runs *before* `LooksLikeLuaState`. When the engine flips back to a VM we've already registered (dozens–hundreds of times/sec), we skip 4× `VirtualQuery` syscalls in favor of a small L1-resident pointer compare. Biggest concrete hot-path win.
- **Single `g_hotWork` gate in `GatedPump`** — replaces 4 volatile loads + compares with one. Steady-state detour cost drops to a single volatile-load + short-circuit return.
- **Register once per pump batch** — `PumpQueue` now calls `RegisterTcpLib` / `RegisterLoaderLib` at the top of the batch rather than per chunk. A 20-chunk drain goes from 40 register calls to 2, without losing the `_G`-wipe defence.
- Register-log lines gated to first-fire-only so repeated re-registrations don't spam `lua_bridge_DEV.log`.

## [v2.0.0] - 2026-06-29

### Added
- **Global `Tcp.Send` Telemetry:**
  - Implemented standard WinSock client connections dynamically registered into the global `Tcp` namespace.
  - Used GCC x86 inline assembly to call the game's custom register-argument `luaL_register` ABI (`ECX=L`, `EAX=libname`, `[esp+4]=table`) at startup.
  - Added loopback security restriction preventing outgoing network connections outside the `127.0.0.0/8` IP space to protect user security.
- **Native Lua Loader:**
  - Auto-creates loading directories: `scripts/OnBoot`, `scripts/OnLoad`, and `scripts/OnKey`.
  - Scans directories recursively, supporting drop-in folders of scripts.
  - Auto-generates `lua_loader.ini` with execution priority levels and virtual key references.
- **Boot-Time & Level-Load Script Triggers:**
  - `OnBoot` folder executes immediately on VM capture.
  - `OnLoad` folder triggers safely when loading screen fades out (milestone `"GlobalExit - Complete"`), preventing main-thread engine crashes.
- **Thread-Optimized `OnKey` Loader:**
  - Spawns a background listener thread polling hotkeys at 30Hz using `GetAsyncKeyState`.
  - Offloads slow disk file I/O to the background thread to prevent frame stutters.
  - Queues loaded scripts safely to the main thread via thread-safe queue injection.
  - Supports script-defined default hotkeys (`local KEYVAL = "keyname"`) on first 10 lines of files.

### Changed
- Removed high-frequency socket server connect/disconnect logs from `lua_bridge.log` to prevent log bloat.
