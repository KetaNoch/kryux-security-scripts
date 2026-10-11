#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 07_traceroute_tool.py
"""Traceroute-Werkzeug fuer das eigene Labornetz.
Nur fuer eigene Systeme / Labor! Keine fremden Ziele verfolgen.
Defensiv + edukativ: zeigt Route per scapy oder System-traceroute.
"""
import argparse
import json
import subprocess  # Fallback auf System-traceroute/tracert
import platform  # Betriebssystem fuer Befehlswahl
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



def scapy_trace(ziel, max_hops, timeout):
    """Traceroute mit scapy; Rueckgabe True bei Erfolg, sonst False."""
    try:
        from scapy.all import IP, ICMP, sr1  # optional
    except ImportError:
        return False  # scapy fehlt -> Fallback
    print("[*] scapy-Modus (braucht Root im Labor).")
    try:
        for ttl in range(1, max_hops + 1):
            paket = IP(dst=ziel, ttl=ttl) / ICMP()  # TTL schrittweise erhoehen
            antwort = sr1(paket, timeout=timeout, verbose=0)
            if antwort is None:
                print(f"{ttl:2d}  * * * (Timeout)")
            else:
                print(f"{ttl:2d}  {antwort.src}")
                if antwort.src == ziel or antwort.type == 0:
                    break  # Ziel erreicht (Echo Reply)
        return True
    except PermissionError:
        print("[Fehler] scapy braucht Root-Rechte.")
    except OSError as fehler:
        print(f"[Fehler] scapy-Trace: {fehler}")
    return False


def system_trace(ziel, max_hops):
    """Fallback: nutzt traceroute (Linux) oder tracert (Windows)."""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["tracert", "-h", str(max_hops), ziel]
        else:
            cmd = ["traceroute", "-m", str(max_hops), ziel]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        print(proc.stdout if proc.stdout else "(keine Ausgabe)")
        if proc.stderr:
            print(f"[Hinweis] {proc.stderr[:500]}")
    except FileNotFoundError:
        print("[Fehler] Weder traceroute noch tracert gefunden.")
    except subprocess.TimeoutExpired:
        print("[Fehler] System-Traceroute hat zu lange gedauert.")
    except OSError as fehler:
        print(f"[Fehler] Systemaufruf: {fehler}")


def main():
    """Parst Ziel und startet scapy- oder System-Traceroute."""
    parser = argparse.ArgumentParser(description="Traceroute (nur eigenes Labor!)")
    parser.add_argument("--ziel", required=True, help="Ziel-Host, z.B. 192.168.1.1")
    parser.add_argument("--max-hops", type=int, default=20, help="Max. Hops (1-64)")
    parser.add_argument("--timeout", type=int, default=2, help="Timeout je Hop (s)")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("07_traceroute_tool.py", args)
    except Exception:
        pass
    if not 1 <= args.max_hops <= 64:
        print("[Fehler] --max-hops muss 1-64 sein.")
        return
    print(f"[*] Route zu {args.ziel} ... Nur eigenes Labor!")
    try:
        ok = scapy_trace(args.ziel, args.max_hops, args.timeout)
    except Exception as fehler:  # defensiv: scapy nie abstuerzen lassen
        print(f"[Hinweis] scapy-Modus uebersprungen: {fehler}")
        ok = False
    if not ok:
        print("[*] Fallback: System-traceroute.")
        system_trace(args.ziel, args.max_hops)
    print("[*] Fertig.")
    report = {
        "tool": "07_traceroute_tool.py",
        "ziel": args.ziel,
        "max_hops": args.max_hops,
        "modus": "scapy" if ok else "system",
        "hinweis": "Routenausgabe siehe Konsolenausgabe (Hop-Auflistung).",
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
                zeilen = ["# Traceroute Report", f"Ziel: {args.ziel}",
                          f"Max-Hops: {args.max_hops}", f"Modus: {report['modus']}"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
