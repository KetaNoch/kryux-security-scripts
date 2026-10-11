#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 12_xss_tester_lab.py
"""
12_xss_tester_lab.py - Reflected-XSS-Check NUR im Labor (defensiv).

Beschreibung:
    Sendet einen harmlosen Marker-String an die EIGENE Lab-URL und
    prueft, ob er unescaped (roh mit < >) reflektiert wird.
    KEIN echter Exploit, kein <script>-Payload, nur Escaping-Check.

Verwendung:
    python3 12_xss_tester_lab.py --url "http://labor.local/suche?q=test" --consent ICH_TESTE_MEIN_EIGENES_LABOR

Ethik:
    AUSDRUECKLICHER CONSENT erforderlich! Nur eigene Systeme/Labor.
    Nur Standardlib (urllib, html, argparse).
"""
import argparse
import html
import json
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


MARKER = "ReflektTestAbC123"
MARKER_ROH = MARKER + "<>'\"()"


def hole_text(url: str, timeout: int):
    """Laedt URL und gibt Antworttext (max. 20000 Zeichen) zurueck."""
    req = urllib.request.Request(url, headers={"User-Agent": "Lab-XSSCheck/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")[:20000]


def baue_test_url(basis_url: str):
    """Haengt harmlosen Marker an letzten Query-Parameter an."""
    teile = list(urllib.parse.urlparse(basis_url))
    query = urllib.parse.parse_qsl(teile[4], keep_blank_values=True)
    if not query:
        return basis_url + urllib.parse.quote(MARKER_ROH)
    query[-1] = (query[-1][0], MARKER_ROH)
    teile[4] = urllib.parse.urlencode(query)
    return urllib.parse.urlunparse(teile)


def main():
    parser = argparse.ArgumentParser(description="XSS-Escaping-Check nur im eigenen Labor.")
    parser.add_argument("--url", required=True, help="Eigene Lab-URL inkl. Parameter")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in Sekunden")
    parser.add_argument("--consent", required=True, help="Muss 'ICH_TESTE_MEIN_EIGENES_LABOR' sein.")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("12_xss_tester_lab.py", args)
    except Exception:
        pass
    if args.consent != "ICH_TESTE_MEIN_EIGENES_LABOR":
        print("[!] Abbruch: Consent fehlt. Nur eigenes Labor testen!")
        return
    test_url = baue_test_url(args.url)
    print(f"[*] Teste (harmloser Marker, kein Exploit): {test_url}")
    try:
        text = hole_text(test_url, args.timeout)
    except Exception as e:
        print(f"[!] Abruf fehlgeschlagen: {e}")
        return
    if MARKER not in text:
        befund = "nicht_reflektiert"
        print("[OK] Marker nicht reflektiert - vermutlich kein Reflected-XSS-Risiko.")
    elif MARKER_ROH in text:
        befund = "unescaped_reflektiert"
        print("[!] WARNUNG: Input UNESCAPED reflektiert (< > roh enthalten).")
        print("[!] Fix: Output-Encoding (html.escape) + CSP am eigenen Code.")
    elif html.escape(MARKER_ROH) in text:
        befund = "escaped_reflektiert"
        print("[OK] Marker nur escaped reflektiert - Escaping scheint aktiv.")
    else:
        befund = "teilweise_reflektiert"
        print("[?] Marker teilweise reflektiert - manuell im Labor pruefen.")
    print("[!] Niemals gegen Fremdsysteme einsetzen!")
    report = {
        "tool": "12_xss_tester_lab.py",
        "url": args.url,
        "test_url": test_url,
        "befund": befund,
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
                zeilen = ["# XSS-Lab Report", f"URL: {args.url}", f"Befund: {befund}"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
