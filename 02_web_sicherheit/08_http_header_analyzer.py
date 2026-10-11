#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 08_http_header_analyzer.py
"""
08_http_header_analyzer.py - HTTP-Security-Header analysieren (defensiv).

Beschreibung:
    Ruft eine URL ab und bewertet sicherheitsrelevante HTTP-Header:
    HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy und Permissions-Policy.

Verwendung:
    python3 08_http_header_analyzer.py --url https://mein-labor.local

Ethik:
    NUR eigene Systeme / Labor testen! Keine fremden Systeme scannen.
    Nur Standardbibliothek (urllib, ssl, argparse).
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


PRUEFUNGEN = [
    ("strict-transport-security", "HSTS schuetzt vor Downgrade auf HTTP."),
    ("content-security-policy", "CSP begrenzt erlaubte Skript-/Content-Quellen."),
    ("x-frame-options", "Schutz vor Clickjacking."),
    ("x-content-type-options", "Verhindert MIME-Sniffing (nosniff erwartet)."),
    ("referrer-policy", "Begrenzt Referrer-Leaks."),
    ("permissions-policy", "Begrenzt Browser-Features (Kamera, Mic, ...)."),
]


def hole_header(url: str, timeout: int):
    """Ruft URL ab und gibt (Status, Header-Dict kleingeschrieben) zurueck."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "Lab-HeaderCheck/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            status = r.status
            header = {k.lower(): v for k, v in r.getheaders()}
            return status, header
    except urllib.error.HTTPError as e:
        header = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        return e.code, header
    except Exception as e:
        print(f"[!] Abruf fehlgeschlagen: {e}")
        return None, {}


def bewerte(header: dict):
    """Bewertet Header und gibt (Punkte, Max, Details) zurueck."""
    punkte, details = 0, []
    for name, hinweis in PRUEFUNGEN:
        wert = header.get(name)
        if wert:
            punkte += 1
            details.append(f"[OK] {name}: {wert[:100]}")
        else:
            details.append(f"[FEHLT] {name} - {hinweis}")
    return punkte, len(PRUEFUNGEN), details


def main():
    parser = argparse.ArgumentParser(description="HTTP-Security-Header pruefen (nur eigenes Labor).")
    parser.add_argument("--url", required=True, help="Ziel-URL, z.B. https://mein-labor.local")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in Sekunden (Standard: 10)")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("08_http_header_analyzer.py", args)
    except Exception:
        pass
    print(f"[*] Pruefe: {args.url} (nur eigenes System!)")
    status, header = hole_header(args.url, args.timeout)
    if status is None:
        print("[!] Abbruch: URL nicht erreichbar.")
        return
    print(f"[*] HTTP-Status: {status}")
    punkte, maximum, details = bewerte(header)
    for zeile in details:
        print(zeile)
    prozent = round(100 * punkte / maximum)
    note = "GUT" if prozent >= 83 else "MITTEL" if prozent >= 50 else "SCHWACH"
    print(f"[=] Bewertung: {punkte}/{maximum} ({prozent}%) -> {note}")
    if note != "GUT":
        print("[!] Empfehlung: Fehlende Header am eigenen Server haerten.")
    report = {
        "tool": "08_http_header_analyzer.py",
        "url": args.url,
        "status": status,
        "punkte": punkte,
        "maximum": maximum,
        "prozent": prozent,
        "note": note,
        "header": header,
        "details": details,
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
                zeilen = ["# HTTP-Header Report", f"URL: {args.url}",
                          f"Status: {status}",
                          f"Bewertung: {punkte}/{maximum} ({prozent}%) -> {note}"]
                zeilen += details
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
