#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 10_directory_enum.py
"""
10_directory_enum.py - Verzeichnis-Enumeration NUR im eigenen Labor (defensiv).

Beschreibung:
    Fragt Pfade an der eigenen Lab-URL an und meldet Status-Codes.
    Wortliste per --wordlist oder eingebaute Mini-Liste. Mit Delay
    (Rate-Limit) zum Schutz des eigenen Servers.

Verwendung:
    python3 10_directory_enum.py --url http://mein-labor.local --consent ICH_TESTE_MEIN_EIGENES_LABOR

Ethik:
    NUR eigene Systeme! Ohne --consent bricht das Skript ab.
    Niemals gegen Fremdsysteme einsetzen. Nur Standardlib.
"""
import argparse
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
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


MINI_LISTE = ["admin", "login", "dashboard", "api", "test",
              "backup", "config", "uploads", "server-status", ".git"]


def lade_wortliste(pfad: str):
    """Laedt Wortliste aus Datei (eine Zeile = ein Pfad)."""
    with open(pfad, "r", encoding="utf-8", errors="ignore") as f:
        return [z.strip().strip("/") for z in f if z.strip()]


def frage_an(url: str, timeout: int):
    """Sendet GET-Request, gibt (Status, Laenge) zurueck."""
    req = urllib.request.Request(url, headers={"User-Agent": "Lab-DirEnum/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as e:
        return e.code, 0
    except Exception as e:
        return f("Fehler: {e}"), 0


def f(a):
    """Kleine Hilfe um lange Zeilen zu vermeiden (gibt a zurueck)."""
    return a


def main():
    parser = argparse.ArgumentParser(description="Dir-Enum nur im eigenen Labor.")
    parser.add_argument("--url", required=True, help="Basis-URL, z.B. http://mein-labor.local")
    parser.add_argument("--wordlist", default=None, help="Pfad zu Wortliste (optional)")
    parser.add_argument("--delay", type=float, default=0.5, help="Pause zw. Requests in Sek. (Standard: 0.5)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in Sekunden")
    parser.add_argument("--consent", required=True, help="Muss 'ICH_TESTE_MEIN_EIGENES_LABOR' sein.")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("10_directory_enum.py", args)
    except Exception:
        pass
    if args.consent != "ICH_TESTE_MEIN_EIGENES_LABOR":
        print("[!] Abbruch: Consent fehlt. Nur eigenes Labor testen!")
        return
    basis = args.url.rstrip("/")
    woerter = lade_wortliste(args.wordlist) if args.wordlist else MINI_LISTE
    print(f"[*] Starte Dir-Enum auf {basis} ({len(woerter)} Pfade, Delay {args.delay}s)")
    ergebnisse = []
    for wort in woerter:
        ziel = f"{basis}/{wort}"
        status, laenge = frage_an(ziel, args.timeout)
        ergebnisse.append({"pfad": f"/{wort}", "status": status, "laenge": laenge})
        mark = "[OK]" if status in (200, 301, 302, 403) else "[--]"
        print(f"{mark} {status} ({laenge} Bytes) -> /{wort}")
        time.sleep(max(0.0, args.delay))
    print("[=] Fertig. Auffaellige Pfade (200/403) am eigenen System pruefen.")
    report = {
        "tool": "10_directory_enum.py",
        "url": basis,
        "ergebnisse": ergebnisse,
        "anzahl": len(ergebnisse),
        "zeit": datetime.now(timezone.utc).isoformat(),
    }
    fmt = getattr(args, "format", "text")
    out = getattr(args, "out", "")
    if fmt == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    if out:
        try:
            p = Path(out)
            if p.suffix.lower() == ".json":
                p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            else:
                zeilen = ["# Directory-Enum Report", f"URL: {basis}"]
                zeilen += [f"{e['status']} ({e['laenge']} Bytes) -> {e['pfad']}"
                           for e in ergebnisse] or ["(keine Pfade)"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
