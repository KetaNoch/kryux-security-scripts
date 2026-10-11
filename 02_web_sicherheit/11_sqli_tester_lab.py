#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 11_sqli_tester_lab.py
"""
11_sqli_tester_lab.py - Error-Based SQLi-Hinweissuche NUR im Labor (defensiv).

Beschreibung:
    Sendet harmlose Zeichen (', ", OR-Fragment) an einen Parameter
    der EIGENEN Lab-URL und sucht in Antworten nach reflektierten
    Datenbank-Fehlermeldungen. Kein Exploit, kein Dump, kein Bypass.

Verwendung:
    python3 11_sqli_tester_lab.py --url "http://labor.local/suche?q=test" --consent ICH_TESTE_MEIN_EIGENES_LABOR

Ethik:
    AUSDRUECKLICHER CONSENT erforderlich! Nur eigene Systeme/Labor.
    Abbruch ohne --consent. Nur Standardlib (urllib, re, argparse).
"""
import argparse
import json
import re
import urllib.parse
import urllib.request
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


PAYLOADS = ["'", '"', "' OR '1'='1"]
FEHLER_MUSTER = re.compile(r"(sql syntax|mysql|sqlite|ora-\d+|postgresql|"
                           r"odbc|jdbc|db2|conversion failed|unclosed quotation)",
                           re.IGNORECASE)


def hole_text(url: str, timeout: int):
    """Laedt URL und gibt Antworttext (max. 20000 Zeichen) zurueck."""
    req = urllib.request.Request(url, headers={"User-Agent": "Lab-SQLiCheck/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")[:20000]


def teste_payload(basis_url: str, timeout: int):
    """Haengt Payloads an URL an und sucht DB-Fehlertexte."""
    teile = list(urllib.parse.urlparse(basis_url))
    ergebnisse = []
    for p in PAYLOADS:
        query = urllib.parse.parse_qsl(teile[4], keep_blank_values=True)
        if not query:
            test_url = basis_url + urllib.parse.quote(p)
        else:
            query[-1] = (query[-1][0], query[-1][1] + p)
            teile[4] = urllib.parse.urlencode(query)
            test_url = urllib.parse.urlunparse(teile)
        try:
            text = hole_text(test_url, timeout)
        except Exception as e:
            ergebnisse.append((p, f"Abruffehler: {e}"))
            continue
        treffer = FEHLER_MUSTER.search(text)
        status = f"DB-Fehlerhinweis: {treffer.group(0)[:60]}" if treffer else "kein DB-Fehlertext"
        ergebnisse.append((p, status))
    return ergebnisse


def main():
    parser = argparse.ArgumentParser(description="SQLi-Hinweissuche nur im eigenen Labor.")
    parser.add_argument("--url", required=True, help="Eigene Lab-URL inkl. Parameter")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in Sekunden")
    parser.add_argument("--consent", required=True, help="Muss 'ICH_TESTE_MEIN_EIGENES_LABOR' sein.")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("11_sqli_tester_lab.py", args)
    except Exception:
        pass
    if args.consent != "ICH_TESTE_MEIN_EIGENES_LABOR":
        print("[!] Abbruch: Consent fehlt. Nur eigenes Labor testen!")
        return
    print(f"[*] Teste (harmlos, nur Fehlertexte): {args.url}")
    ergebnisse = teste_payload(args.url, args.timeout)
    for payload, befund in ergebnisse:
        print(f"  Payload {payload!r:12} -> {befund}")
    print("[=] Bei Treffern: Prepared Statements + Fehlerseiten am eigenen Code fixen.")
    print("[!] Niemals gegen Fremdsysteme einsetzen!")
    report = {
        "tool": "11_sqli_tester_lab.py",
        "url": args.url,
        "befunde": [{"payload": p, "status": s} for p, s in ergebnisse],
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
                zeilen = ["# SQLi-Lab Report", f"URL: {args.url}"]
                zeilen += [f"Payload {e['payload']!r} -> {e['status']}" for e in report["befunde"]]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
