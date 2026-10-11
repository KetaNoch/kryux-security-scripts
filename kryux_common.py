#!/usr/bin/env python3
"""KRYUX // SECURITY SUITE - gemeinsamer CLI-Kern (v3.0).

Wird von allen 46 Skripten in 01-08 genutzt (Import mit Fallback, damit jedes
Skript auch ohne diese Datei lauffaehig bleibt):

    try:
        import sys as _s; _s.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from kryux_common import banner, add_kryux_args, save_report
    except ImportError:
        def banner(*a, **k): pass
        def add_kryux_args(p): return p
        def save_report(*a, **k): pass

Funktionen:
  banner(tool, version, args=None) - ⬢ KRYUX-Banner nach stderr (JSON-stdout bleibt sauber)
  add_kryux_args(parser)           - haengt --out / --format / --no-banner an
  save_report(obj, out, fmt)       - JSON / Markdown-Export mit Statusmeldung
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KRYUX_VERSION = "3.0"
KRYUX_TAG = "KRYUX // SECURITY SUITE"
KRYUX_BANNER_SMALL = "⬢ KRYUX // SECURITY SUITE v3.0 — live system intel, no fake data"


def banner(tool: str = "", args=None) -> None:
    """Gibt das Kryux-Banner nach stderr aus (unterdrueckbar via --no-banner)."""
    try:
        if args is not None and getattr(args, "no_banner", False):
            return
    except Exception:
        pass
    try:
        print(f"{KRYUX_BANNER_SMALL}{' — ' + tool if tool else ''}", file=sys.stderr)
    except Exception:
        pass


def add_kryux_args(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Haengt Standard-Flags an (idempotent: vorhandene --out/--format/--no-banner werden erkannt)."""
    try:
        existing_dests = {a.dest for a in parser._actions}
        existing_opts: set[str] = set()
        for a in parser._actions:
            existing_opts.update(getattr(a, "option_strings", []))
        if "out" not in existing_dests and "--out" not in existing_opts:
            parser.add_argument("--out", default="", help="Report-Datei (.json/.md), sonst nur Konsole")
        if "format" not in existing_dests and "--format" not in existing_opts:
            parser.add_argument("--format", default="text", choices=["text", "json"],
                                help="Konsolenformat (text lesbar / json maschinenlesbar)")
        if "no_banner" not in existing_dests and "--no-banner" not in existing_opts:
            parser.add_argument("--no-banner", action="store_true", help="Kryux-Banner unterdruecken")
    except Exception:
        pass
    return parser


def save_report(obj, out: str, fmt: str = "json", tool: str = "") -> None:
    """Schreibt obj als JSON (dict/list) oder Markdown (str) nach out."""
    if not out:
        return
    p = Path(out)
    try:
        if isinstance(obj, str):
            p.write_text(obj, encoding="utf-8")
        else:
            p.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[KRYUX] {tool + ': ' if tool else ''}Report -> {p}", file=sys.stderr)
    except OSError as e:
        print(f"[KRYUX] Report schreiben fehlgeschlagen: {e}", file=sys.stderr)
