#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 34_keylogger_detector.py
"""34_keylogger_detector.py - DEFENSIV: erkennt Keylogger-Anzeichen.

KEIN Keylogger! Prüft nur: Autostart-Orte, Prozesse mit
verdächtigen Strings (keylog, SetWindowsHook, /dev/input).
Nur eigene Systeme, dokumentieren statt entfernen.
"""
import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

# --- KRYUX branding / common helpers (mit Fallback, keine harte Abhaengigkeit) ---
try:
    import sys as _kryux_s
    from pathlib import Path as _kryux_P
    _kryux_s.path.insert(0, str(_kryux_P(__file__).resolve().parents[1]))
    from kryux_common import banner as _kryux_banner, add_kryux_args as _kryux_add_args
    def _kryux_apply(p):
        try:
            return _kryux_add_args(p)
        except Exception:
            return p
except ImportError:
    def _kryux_banner(*a, **k):
        pass
    def _kryux_apply(p):
        return p


ETHIK = "Strikt defensiv: kein Abfangen von Tastatureingaben!"
VERD_STRINGS = ("keylog", "keystroke", "setwindowshook", "getasynckeystate",
                "pyhook", "pynput/keyboard", "/dev/input/event")


def check_autostart() -> list:
    """Listet verdächtige Autostart-Einträge (Linux)."""
    orte = [Path.home() / ".config/autostart",
            Path("/etc/xdg/autostart"), Path.home() / ".bashrc",
            Path.home() / ".profile"]
    funde = []
    for o in orte:
        if o.is_dir():
            for d in o.iterdir():
                txt = d.read_text(errors="ignore").lower() if d.is_file() else ""
                if any(v in txt for v in VERD_STRINGS):
                    funde.append(str(d))
        elif o.is_file():
            if any(v in o.read_text(errors="ignore").lower() for v in VERD_STRINGS):
                funde.append(str(o))
    return funde


def check_prozesse() -> list:
    """Sucht Prozesse mit verdächtigen Kommandozeilen."""
    funde = []
    try:
        out = subprocess.run(["ps", "-eo", "pid,args"], capture_output=True,
                             text=True, timeout=10).stdout.lower()
    except (OSError, subprocess.SubprocessError):
        return ["ps nicht verfügbar"]
    for zeile in out.splitlines():
        if any(v in zeile for v in VERD_STRINGS):
            funde.append(zeile.strip()[:160])
    return funde


def main() -> None:
    ap = argparse.ArgumentParser(description="Keylogger-Detector (nur defensiv!)")
    ap.add_argument("--report", default="", help="Optional Report-Datei")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("34_keylogger_detector.py", a)
    except Exception:
        pass
    print(ETHIK)
    fa, fp = check_autostart(), check_prozesse()
    print(f"[+] Autostart-Funde: {len(fa)}")
    for x in fa:
        print(f"  [!] {x}")
    print(f"[+] Prozess-Funde: {len(fp)}")
    for x in fp[:20]:
        print(f"  [!] {x}")
    if not fa and not fp:
        print("[+] Keine offensichtlichen Keylogger-Anzeichen.")
    else:
        print("[i] Bitte manuell prüfen, nichts automatisch löschen.")
    if a.report:
        Path(a.report).write_text(f"Autostart: {fa}\nProzesse: {fp}\n")
        print(f"[+] Report: {a.report}")
    report = {
        "tool": "34_keylogger_detector",
        "zeit": datetime.now().isoformat(),
        "anzahl_autostart": len(fa),
        "anzahl_prozesse": len(fp),
        "autostart": fa,
        "prozesse": fp[:20],
    }
    try:
        _fmt = getattr(a, "format", "text")
        _out = getattr(a, "out", "") or ""
        if _fmt == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False))
        if _out:
            try:
                _p = Path(_out)
                if _p.suffix.lower() == ".json":
                    _p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                else:
                    _zeilen = [f"# {report['tool']}", f"Autostart-Funde: {len(fa)}, Prozess-Funde: {len(fp)}", ""]
                    _zeilen += [f"- {x}" for x in (fa + fp[:20])] or ["- Keine Anzeichen."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
