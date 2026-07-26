"""Merc2 Lua Console — a small tkinter IDE for the Merc2Fix bridge.

Stdlib only. No pip installs. Just `py tools/lua_console.py`.

Features:
- Tabbed editor (Ctrl+T new tab, middle-click or close button to close).
- Lua syntax highlighting (keywords / strings / comments / numbers).
- Line numbers, soft tab indent, configurable font size.
- Execute via the toolbar button, Ctrl+Enter, or F5.
- Output panel below the editor; every execution appends, scrollable,
  with a Clear button. Each result is prefixed with the timestamp +
  the chunk's first line for context.
- Save / Open .lua files (Ctrl+S / Ctrl+Shift+S / Ctrl+O), recent files
  menu (last 8), per-tab unsaved-changes marker.
- Bridge status dot in the status bar — green when 127.0.0.1:27050
  accepts a TCP connect, red otherwise. Polled every 3 seconds.
- Settings (host, port, font size, recent files) persisted to
  lua_console.json next to this script.

Protocol matches lua_repl.py / dllmain.cpp's BridgeServerThread:
  send `<your chunk>\n<<<RUN>>>\n`, read until `<<<END>>>`.

Wire encoding is CP1252, not UTF-8 — the engine's text path is single-byte.
See execute_chunk(). Note also that this build of Lua parses `"\ddd"` byte
escapes as OCTAL, not decimal: o-umlaut is `"\366"`, not `"\246"`.
"""
from __future__ import annotations

import json
import os
import re
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, font, messagebox, ttk

# ----------------------------------------------------------------------------
# Bridge protocol
# ----------------------------------------------------------------------------
DEFAULT_HOST    = "127.0.0.1"
DEFAULT_PORT    = 27050
SENTINEL        = "<<<RUN>>>"
END_MARKER      = "<<<END>>>"
EXEC_TIMEOUT_S  = 120.0   # generous; in-game pumps can take a few seconds
PROBE_TIMEOUT_S = 0.4     # status-dot connect attempt
PROBE_INTERVAL  = 3.0     # status-dot poll cadence (s)

# ----------------------------------------------------------------------------
# Theme
# ----------------------------------------------------------------------------
BG_EDITOR     = "#1e1e1e"
FG_EDITOR     = "#d4d4d4"
BG_GUTTER     = "#2a2a2a"
FG_GUTTER     = "#7a7a7a"
BG_OUTPUT     = "#181818"
FG_OUTPUT     = "#cfcfcf"
SEL_BG        = "#264f78"
CARET         = "#d4d4d4"
HL_KEYWORD    = "#569cd6"
HL_STRING     = "#ce9178"
HL_COMMENT    = "#6a9955"
HL_NUMBER     = "#b5cea8"
HL_BUILTIN    = "#dcdcaa"
HL_OPERATOR   = "#d4d4d4"

LUA_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
}
LUA_BUILTINS = {
    "_G", "_VERSION", "assert", "collectgarbage", "dofile", "error",
    "getfenv", "getmetatable", "ipairs", "load", "loadfile", "loadstring",
    "module", "next", "pairs", "pcall", "print", "rawequal", "rawget",
    "rawlen", "rawset", "require", "select", "setfenv", "setmetatable",
    "tonumber", "tostring", "type", "unpack", "xpcall",
    # Mercenaries 2 namespaces of interest (verified in tools/engine_api.md)
    "Player", "Object", "Vehicle", "Weapon", "Sys", "Net", "Pda", "Ai",
    "Hud", "Cheat", "Debug", "Camera", "Sound", "Graphics", "Math",
    "Movie", "Airstrike",
}

# ----------------------------------------------------------------------------
# Settings persistence
# ----------------------------------------------------------------------------
SETTINGS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "lua_console.json")

def load_settings() -> dict:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(s: dict) -> None:
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except Exception:
        pass

# ----------------------------------------------------------------------------
# Editor tab — text widget + line numbers + highlighting
# ----------------------------------------------------------------------------
class EditorTab(ttk.Frame):
    """One script tab. Line-number gutter + editor + per-tab path/dirty state."""

    def __init__(self, parent: tk.Widget, font_family: str, font_size: int):
        super().__init__(parent)
        self.path: str | None = None
        self.dirty = False
        self._highlight_pending = False

        editor_font = font.Font(family=font_family, size=font_size)

        self.gutter = tk.Text(
            self, width=4, padx=6, takefocus=0, border=0,
            background=BG_GUTTER, foreground=FG_GUTTER,
            font=editor_font, state="disabled", cursor="arrow",
            wrap="none",
        )
        self.gutter.pack(side="left", fill="y")

        self.editor = tk.Text(
            self, undo=True, wrap="none", border=0,
            background=BG_EDITOR, foreground=FG_EDITOR,
            insertbackground=CARET, selectbackground=SEL_BG,
            font=editor_font, padx=8, pady=4,
            tabs=("4c",), tabstyle="tabular",
        )
        self.editor.pack(side="left", fill="both", expand=True)

        vbar = ttk.Scrollbar(self, orient="vertical", command=self._yview_both)
        vbar.pack(side="right", fill="y")
        self.editor.configure(yscrollcommand=lambda *a: self._on_yscroll(vbar, *a))
        self.gutter.configure(yscrollcommand=lambda *a: None)

        # Configure highlight tags
        for name, color in [
            ("kw", HL_KEYWORD), ("str", HL_STRING), ("com", HL_COMMENT),
            ("num", HL_NUMBER), ("blt", HL_BUILTIN),
        ]:
            self.editor.tag_configure(name, foreground=color)

        # Indent on Tab as 4 spaces (matches Lua convention, plays nicely
        # with the bridge's 4 KB chunk limit by being compact)
        self.editor.bind("<Tab>", self._on_tab)
        self.editor.bind("<<Modified>>", self._on_modified)
        self.editor.bind("<KeyRelease>", lambda e: self._schedule_highlight())

    # --- scrollbar plumbing (gutter mirrors editor) -----------------------
    def _yview_both(self, *args):
        self.editor.yview(*args)
        self.gutter.yview(*args)

    def _on_yscroll(self, vbar, first, last):
        vbar.set(first, last)
        self.gutter.yview_moveto(first)

    # --- input handlers ---------------------------------------------------
    def _on_tab(self, _event):
        self.editor.insert("insert", "    ")
        return "break"

    def _on_modified(self, _event):
        # tkinter only fires <<Modified>> once until we reset the flag.
        if self.editor.edit_modified():
            self.dirty = True
            self.editor.edit_modified(False)
            self._refresh_gutter()
            # Highlight on the next idle slot so big paste isn't blocked.
            self._schedule_highlight()
            # Tell the IDE so it can update the tab title.
            self.event_generate("<<TabDirty>>", when="tail")

    def _schedule_highlight(self):
        if self._highlight_pending:
            return
        self._highlight_pending = True
        self.after(80, self._do_highlight)

    # --- highlighting -----------------------------------------------------
    def _do_highlight(self):
        self._highlight_pending = False
        text = self.editor.get("1.0", "end-1c")

        for tag in ("kw", "str", "com", "num", "blt"):
            self.editor.tag_remove(tag, "1.0", "end")

        # Order matters: comments first, then strings, then keywords/numbers.
        # We tag by 1-based line + 0-based char offset (tkinter Text indices).
        def tag_spans(pattern, tag, flags=0):
            for m in pattern.finditer(text):
                self._tag_range(m.start(), m.end(), tag)

        # Comments
        comment_re = re.compile(r"--\[\[.*?\]\]|--[^\n]*", re.DOTALL)
        tag_spans(comment_re, "com")

        # Strings (single-quoted, double-quoted, long brackets [[ ]])
        string_re = re.compile(
            r"\[\[.*?\]\]"
            r"|\"(?:[^\"\\\n]|\\.)*\""
            r"|'(?:[^'\\\n]|\\.)*'",
            re.DOTALL,
        )
        tag_spans(string_re, "str")

        # Numbers
        number_re = re.compile(r"\b(?:0x[0-9a-fA-F]+|\d+\.?\d*(?:[eE][+-]?\d+)?)\b")
        tag_spans(number_re, "num")

        # Keywords / builtins
        for m in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text):
            word = m.group(0)
            if word in LUA_KEYWORDS:
                self._tag_range(m.start(), m.end(), "kw")
            elif word in LUA_BUILTINS:
                self._tag_range(m.start(), m.end(), "blt")

        self._refresh_gutter()

    def _tag_range(self, off_start: int, off_end: int, tag: str):
        self.editor.tag_add(
            tag,
            f"1.0 + {off_start} chars",
            f"1.0 + {off_end} chars",
        )

    # --- line numbers -----------------------------------------------------
    def _refresh_gutter(self):
        last_line = int(self.editor.index("end-1c").split(".")[0])
        self.gutter.configure(state="normal")
        self.gutter.delete("1.0", "end")
        self.gutter.insert("1.0", "\n".join(str(i) for i in range(1, last_line + 1)))
        self.gutter.configure(state="disabled")
        # Match the editor's scroll position so line numbers don't drift.
        self.gutter.yview_moveto(self.editor.yview()[0])

    # --- text access ------------------------------------------------------
    def get_text(self) -> str:
        return self.editor.get("1.0", "end-1c")

    def set_text(self, text: str):
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", text)
        self.editor.edit_reset()
        self.editor.edit_modified(False)
        self.dirty = False
        self._do_highlight()

    def focus_editor(self):
        self.editor.focus_set()

    def set_font_size(self, size: int):
        f = font.Font(font=self.editor["font"])
        f.configure(size=size)
        self.editor.configure(font=f)
        self.gutter.configure(font=f)
        self._refresh_gutter()

# ----------------------------------------------------------------------------
# Bridge client (synchronous, called from worker threads)
# ----------------------------------------------------------------------------
def execute_chunk(host: str, port: int, code: str) -> str:
    """Send one chunk, block until <<<END>>> or timeout. Returns the body."""
    try:
        s = socket.create_connection((host, port), timeout=5.0)
    except OSError as e:
        return f"[bridge] connect failed: {e}\n"
    s.settimeout(EXEC_TIMEOUT_S)
    try:
        payload = code.rstrip("\n") + "\n" + SENTINEL + "\n"
        # cp1252, not utf-8. The engine's text renderers consume strings as
        # single-byte CP1252, so sending UTF-8 puts two bytes where the
        # renderer wants one and "Möbius" arrives as "MÃ¶bius". Characters
        # with no CP1252 equivalent become "?" rather than raising, so a
        # stray emoji in a comment can't kill the send.
        s.sendall(payload.encode("cp1252", errors="replace"))
        buf = ""
        deadline = time.monotonic() + EXEC_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                return buf + f"\n[bridge] no <<<END>>> after {EXEC_TIMEOUT_S:.0f}s\n"
            if not chunk:
                break
            # Decode the same way, so a high byte the engine sent back renders
            # as the character it actually represents in-game.
            buf += chunk.decode("cp1252", errors="replace")
            if END_MARKER in buf:
                return buf.replace(END_MARKER, "").rstrip("\n") + "\n"
        return buf or "[bridge] empty response\n"
    finally:
        try: s.close()
        except OSError: pass

def probe_bridge(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=PROBE_TIMEOUT_S)
        s.close()
        return True
    except OSError:
        return False

# ----------------------------------------------------------------------------
# Main IDE
# ----------------------------------------------------------------------------
STARTER_SCRIPT = """-- Merc2 Lua console
-- Ctrl+Enter / F5 to execute. Ctrl+T new tab. Ctrl+S save.
return "Hello from Mercenaries 2 (cash = " .. Player.GetCash() .. ")"
"""

class LuaIDE(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Merc2 Lua Console")
        self.geometry("1280x800")
        self.configure(bg="#222")

        self.settings = load_settings()
        self.host = self.settings.get("host", DEFAULT_HOST)
        self.port = int(self.settings.get("port", DEFAULT_PORT))
        self.font_family = self.settings.get("font_family", "Consolas")
        self.font_size = int(self.settings.get("font_size", 11))
        self.recent: list[str] = self.settings.get("recent", [])

        self._build_menu()
        self._build_toolbar()
        self._build_main()
        self._build_statusbar()

        self.bind_all("<Control-Return>", lambda e: self._execute_current())
        self.bind_all("<F5>",              lambda e: self._execute_current())
        self.bind_all("<Control-t>",       lambda e: self._new_tab())
        self.bind_all("<Control-w>",       lambda e: self._close_current_tab())
        self.bind_all("<Control-s>",       lambda e: self._save_current())
        self.bind_all("<Control-S>",       lambda e: self._save_current_as())
        self.bind_all("<Control-o>",       lambda e: self._open_file())
        self.bind_all("<Control-n>",       lambda e: self._new_tab(STARTER_SCRIPT))
        self.bind_all("<Control-plus>",    lambda e: self._bump_font(+1))
        self.bind_all("<Control-minus>",   lambda e: self._bump_font(-1))

        self._new_tab(STARTER_SCRIPT)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Status poll loop
        self._stop_status = threading.Event()
        threading.Thread(target=self._status_loop, daemon=True).start()

    # --- ui construction --------------------------------------------------
    def _build_menu(self):
        m = tk.Menu(self)
        f = tk.Menu(m, tearoff=0)
        f.add_command(label="New Tab",           accelerator="Ctrl+T", command=self._new_tab)
        f.add_command(label="New (starter)",     accelerator="Ctrl+N", command=lambda: self._new_tab(STARTER_SCRIPT))
        f.add_command(label="Open…",             accelerator="Ctrl+O", command=self._open_file)
        f.add_separator()
        f.add_command(label="Save",              accelerator="Ctrl+S", command=self._save_current)
        f.add_command(label="Save As…",          accelerator="Ctrl+Shift+S", command=self._save_current_as)
        f.add_separator()
        self.recent_menu = tk.Menu(f, tearoff=0)
        f.add_cascade(label="Recent", menu=self.recent_menu)
        self._refresh_recent_menu()
        f.add_separator()
        f.add_command(label="Close Tab",         accelerator="Ctrl+W", command=self._close_current_tab)
        f.add_command(label="Quit",              command=self._on_close)
        m.add_cascade(label="File", menu=f)

        r = tk.Menu(m, tearoff=0)
        r.add_command(label="Execute",           accelerator="Ctrl+Enter / F5", command=self._execute_current)
        r.add_command(label="Clear Output",      command=self._clear_output)
        m.add_cascade(label="Run", menu=r)

        v = tk.Menu(m, tearoff=0)
        v.add_command(label="Font +1",           accelerator="Ctrl++", command=lambda: self._bump_font(+1))
        v.add_command(label="Font -1",           accelerator="Ctrl+-", command=lambda: self._bump_font(-1))
        m.add_cascade(label="View", menu=v)

        s = tk.Menu(m, tearoff=0)
        s.add_command(label="Bridge…",           command=self._edit_bridge)
        m.add_cascade(label="Settings", menu=s)

        self.config(menu=m)

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=4)
        bar.pack(side="top", fill="x")
        ttk.Button(bar, text="Execute (Ctrl+Enter)", command=self._execute_current).pack(side="left")
        ttk.Button(bar, text="New Tab",   command=self._new_tab).pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="Open…",     command=self._open_file).pack(side="left", padx=(4, 0))
        ttk.Button(bar, text="Save",      command=self._save_current).pack(side="left", padx=(4, 0))
        ttk.Button(bar, text="Clear Output", command=self._clear_output).pack(side="right")

    def _build_main(self):
        pane = ttk.Panedwindow(self, orient="vertical")
        pane.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(pane)
        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self._sync_title())
        # Middle-click on a tab to close it
        self.notebook.bind("<Button-2>", self._on_tab_middle_click)
        pane.add(self.notebook, weight=3)

        out_frame = ttk.Frame(pane)
        out_label = ttk.Label(out_frame, text="Output")
        out_label.pack(anchor="w", padx=6, pady=(4, 0))
        self.output = tk.Text(
            out_frame, height=12, wrap="word", state="disabled",
            background=BG_OUTPUT, foreground=FG_OUTPUT,
            insertbackground=CARET, padx=8, pady=4,
            font=(self.font_family, self.font_size),
        )
        ovb = ttk.Scrollbar(out_frame, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=ovb.set)
        self.output.pack(side="left", fill="both", expand=True)
        ovb.pack(side="right", fill="y")
        # Output tags for run-marker formatting
        self.output.tag_configure("marker", foreground="#7ab8ff")
        self.output.tag_configure("err",    foreground="#ff7a7a")
        pane.add(out_frame, weight=1)

    def _build_statusbar(self):
        sb = ttk.Frame(self, padding=(8, 2))
        sb.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar(value="ready")
        ttk.Label(sb, textvariable=self.status_var).pack(side="left")
        self.bridge_var = tk.StringVar(value=f"● {self.host}:{self.port}: checking…")
        self.bridge_lbl = ttk.Label(sb, textvariable=self.bridge_var, foreground="#888")
        self.bridge_lbl.pack(side="right")

    # --- tab management ---------------------------------------------------
    def _new_tab(self, initial_text: str = "") -> EditorTab:
        tab = EditorTab(self.notebook, self.font_family, self.font_size)
        title = "untitled"
        self.notebook.add(tab, text=title)
        self.notebook.select(tab)
        tab.bind("<<TabDirty>>", lambda e: self._sync_title())
        if initial_text:
            tab.set_text(initial_text)
        tab.focus_editor()
        return tab

    def _close_current_tab(self):
        tab = self._current_tab()
        if tab is None:
            return
        if tab.dirty:
            ans = messagebox.askyesnocancel(
                "Unsaved changes",
                f"Save changes to {os.path.basename(tab.path) if tab.path else 'untitled'}?",
            )
            if ans is None: return
            if ans and not self._save_tab(tab): return
        self.notebook.forget(tab)
        if not self.notebook.tabs():
            self._new_tab(STARTER_SCRIPT)

    def _on_tab_middle_click(self, event):
        try:
            idx = self.notebook.index(f"@{event.x},{event.y}")
        except tk.TclError:
            return
        self.notebook.select(idx)
        self._close_current_tab()

    def _current_tab(self) -> EditorTab | None:
        try:
            sel = self.notebook.select()
            if not sel: return None
            return self.notebook.nametowidget(sel)  # type: ignore[return-value]
        except (tk.TclError, KeyError):
            return None

    def _sync_title(self):
        for tab_id in self.notebook.tabs():
            tab: EditorTab = self.notebook.nametowidget(tab_id)
            base = os.path.basename(tab.path) if tab.path else "untitled"
            self.notebook.tab(tab_id, text=("● " if tab.dirty else "") + base)

    # --- file ops ---------------------------------------------------------
    def _open_file(self, path: str | None = None):
        if path is None:
            path = filedialog.askopenfilename(
                title="Open Lua file",
                filetypes=[("Lua scripts", "*.lua"), ("All files", "*.*")],
            )
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError as e:
            messagebox.showerror("Open failed", str(e))
            return
        tab = self._new_tab(text)
        tab.path = path
        tab.dirty = False
        self._add_recent(path)
        self._sync_title()

    def _save_current(self):
        tab = self._current_tab()
        if tab: self._save_tab(tab)

    def _save_current_as(self):
        tab = self._current_tab()
        if tab: self._save_tab(tab, force_picker=True)

    def _save_tab(self, tab: EditorTab, force_picker: bool = False) -> bool:
        path = tab.path
        if force_picker or not path:
            path = filedialog.asksaveasfilename(
                title="Save Lua file",
                defaultextension=".lua",
                filetypes=[("Lua scripts", "*.lua"), ("All files", "*.*")],
            )
            if not path: return False
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(tab.get_text())
        except OSError as e:
            messagebox.showerror("Save failed", str(e))
            return False
        tab.path = path
        tab.dirty = False
        self._add_recent(path)
        self._sync_title()
        self.status_var.set(f"saved {os.path.basename(path)}")
        return True

    def _add_recent(self, path: str):
        if path in self.recent:
            self.recent.remove(path)
        self.recent.insert(0, path)
        self.recent = self.recent[:8]
        self._refresh_recent_menu()
        self._persist_settings()

    def _refresh_recent_menu(self):
        m = self.recent_menu
        m.delete(0, "end")
        if not self.recent:
            m.add_command(label="(empty)", state="disabled")
            return
        for p in self.recent:
            label = p if len(p) < 60 else "…" + p[-58:]
            m.add_command(label=label, command=lambda pp=p: self._open_file(pp))

    # --- execute / output -------------------------------------------------
    def _execute_current(self):
        tab = self._current_tab()
        if tab is None: return
        code = tab.get_text()
        if not code.strip():
            self.status_var.set("nothing to execute")
            return
        first_line = (code.strip().splitlines() or [""])[0]
        if len(first_line) > 60: first_line = first_line[:57] + "…"
        ts = time.strftime("%H:%M:%S")
        self._append_output(f"\n--- {ts}  {first_line} ---\n", "marker")
        self.status_var.set("executing…")
        threading.Thread(
            target=self._exec_worker,
            args=(self.host, self.port, code),
            daemon=True,
        ).start()

    def _exec_worker(self, host: str, port: int, code: str):
        result = execute_chunk(host, port, code)
        # back to ui thread
        self.after(0, lambda: self._on_exec_done(result))

    def _on_exec_done(self, result: str):
        if result.startswith("[bridge]"):
            self._append_output(result, "err")
        else:
            self._append_output(result)
        self.status_var.set("done")

    def _append_output(self, text: str, tag: str | None = None):
        self.output.configure(state="normal")
        if tag:
            self.output.insert("end", text, (tag,))
        else:
            self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")

    # --- view / settings --------------------------------------------------
    def _bump_font(self, delta: int):
        self.font_size = max(7, min(36, self.font_size + delta))
        for tab_id in self.notebook.tabs():
            tab: EditorTab = self.notebook.nametowidget(tab_id)
            tab.set_font_size(self.font_size)
        self.output.configure(font=(self.font_family, self.font_size))
        self._persist_settings()

    def _edit_bridge(self):
        dlg = tk.Toplevel(self)
        dlg.title("Bridge")
        dlg.transient(self)
        dlg.grab_set()
        ttk.Label(dlg, text="Host:").grid(row=0, column=0, padx=6, pady=4, sticky="e")
        host_var = tk.StringVar(value=self.host)
        ttk.Entry(dlg, textvariable=host_var, width=24).grid(row=0, column=1, padx=6, pady=4)
        ttk.Label(dlg, text="Port:").grid(row=1, column=0, padx=6, pady=4, sticky="e")
        port_var = tk.StringVar(value=str(self.port))
        ttk.Entry(dlg, textvariable=port_var, width=24).grid(row=1, column=1, padx=6, pady=4)
        def ok():
            try:
                self.host = host_var.get().strip() or DEFAULT_HOST
                self.port = int(port_var.get())
            except ValueError:
                messagebox.showerror("Bridge", "Port must be an integer.")
                return
            self._persist_settings()
            self.bridge_var.set(f"● {self.host}:{self.port}: checking…")
            dlg.destroy()
        ttk.Button(dlg, text="OK", command=ok).grid(row=2, column=1, padx=6, pady=8, sticky="e")

    def _persist_settings(self):
        save_settings({
            "host": self.host,
            "port": self.port,
            "font_family": self.font_family,
            "font_size": self.font_size,
            "recent": self.recent,
        })

    # --- bridge status poll (background thread) ---------------------------
    def _status_loop(self):
        while not self._stop_status.is_set():
            up = probe_bridge(self.host, self.port)
            color = "#5fcf5f" if up else "#d96c6c"
            state = "up" if up else "down"
            text = f"● {self.host}:{self.port}: {state}"
            try:
                self.after(0, lambda c=color, t=text: (
                    self.bridge_var.set(t),
                    self.bridge_lbl.configure(foreground=c),
                ))
            except RuntimeError:
                return  # window already destroyed
            self._stop_status.wait(PROBE_INTERVAL)

    # --- shutdown ---------------------------------------------------------
    def _on_close(self):
        # Offer to save dirty tabs
        for tab_id in self.notebook.tabs():
            tab: EditorTab = self.notebook.nametowidget(tab_id)
            if not tab.dirty: continue
            ans = messagebox.askyesnocancel(
                "Unsaved changes",
                f"Save changes to {os.path.basename(tab.path) if tab.path else 'untitled'}?",
            )
            if ans is None: return  # cancel close entirely
            if ans and not self._save_tab(tab): return
        self._stop_status.set()
        self.destroy()

# ----------------------------------------------------------------------------
def main() -> int:
    app = LuaIDE()
    try:
        # Slightly nicer ttk theme on Windows if available
        style = ttk.Style(app)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except tk.TclError:
        pass
    app.mainloop()
    return 0

if __name__ == "__main__":
    sys.exit(main())
