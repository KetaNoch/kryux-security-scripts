#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 13_clickjacking_test.py
"""
13_clickjacking_test.py - Clickjacking-Schutz pruefen (defensiv).

Beschreibung:
    Prueft X-Frame-Options und CSP frame-ancestors einer URL und
    gibt eine gerenderte Bewertung aus: GESCHUETZT / TEILWEISE /
    VERWUNDBAR (Framing moeglich).

Verwendung:
    python3 13_clickjacking_test.py --url https://mein-labor.local

Ethik:
    NUR eigene Systeme / Labor testen! Kein echtes Framing,
    nur Header-Auswertung. Nur Standardlib (urllib, argparse).
"""
import argparse
import json
import ssl
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



def hole_header(url: str, timeout: int):
    """Holt Antwort-Header (Dict kleingeschrieben) oder leeres Dict."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "Lab-ClickjackCheck/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {k.lower(): v for k, v in r.getheaders()}
    except urllib.error.HTTPError as e:
        return {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
    except Exception as e:
        print(f"[!] Abruf fehlgeschlagen: {e}")
        return {}


def bewerte(header: dict):
    """Bewertet Framing-Schutz anhand XFO und CSP frame-ancestors."""
    xfo = header.get("x-frame-options", "").strip().upper()
    csp = header.get("content-security-policy", "")
    hat_frame_ancestors = "frame-ancestors" in csp.lower()
    if xfo in ("DENY", "SAMEORIGIN") or ("'none'" in csp.lower() and hat_frame_ancestors):
        return "GESCHUETZT", f"XFO={xfo or '-'}, CSP frame-ancestors vorhanden={hat_frame_ancestors}"
    if xfo or hat_frame_ancestors:
        return "TEILWEISE", f"XFO={xfo or '-'}, CSP-Ausschnitt: {csp[:120] or '-'}"
    return "VERWUNDBAR", "Weder X-Frame-Options noch CSP frame-ancestors gesetzt."


def main():
    parser = argparse.ArgumentParser(description="Clickjacking-Schutz pruefen (nur eigenes Labor).")
    parser.add_argument("--url", required=True, help="Ziel-URL, z.B. https://mein-labor.local")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in Sekunden")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("13_clickjacking_test.py", args)
    except Exception:
        pass
    print(f"[*] Pruefe Clickjacking-Schutz: {args.url} (nur eigenes System!)")
    header = hole_header(args.url, args.timeout)
    if not header:
        print("[!] Abbruch: keine Header erhalten.")
        return
    print(f"[*] X-Frame-Options: {header.get('x-frame-options', '(fehlt)')}")
    print(f"[*] CSP: {header.get('content-security-policy', '(fehlt)')[:200]}")
    stufe, begruendung = bewerte(header)
    symbol = {"GESCHUETZT": "[OK]", "TEILWEISE": "[~]", "VERWUNDBAR": "[!]"}[stufe]
    print(f"{symbol} Bewertung: {stufe} - {begruendung}")
    if stufe == "VERWUNDBAR":
        print("[!] Empfehlung: X-Frame-Options: DENY/SAMEORIGIN oder CSP frame-ancestors setzen.")
    else:
        print("[=] Schutz am eigenen System ggf. per Iframe-Labortest verifizieren.")
    report = {
        "tool": "13_clickjacking_test.py",
        "url": args.url,
        "x_frame_options": header.get("x-frame-options", ""),
        "csp": header.get("content-security-policy", ""),
        "bewertung": stufe,
        "begruendung": begruendung,
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
                zeilen = ["# Clickjacking Report", f"URL: {args.url}",
                          f"Bewertung: {stufe}", begruendung]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
