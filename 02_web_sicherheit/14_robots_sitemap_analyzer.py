#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 14_robots_sitemap_analyzer.py
"""
14_robots_sitemap_analyzer.py - robots.txt + sitemap.xml auswerten (defensiv).

Beschreibung:
    Laedt robots.txt und sitemap.xml der EIGENEN Seite, listet
    Disallow-Pfade und warnt vor sensiblen Pfaden (/admin, /backup,
    /config, /.git u.a.). Keine aggressiven Follow-up-Scans.

Verwendung:
    python3 14_robots_sitemap_analyzer.py --url https://mein-labor.local

Ethik:
    NUR eigene Systeme / Labor testen! Oeffentliche Dateien werden
    nur gelesen, nicht ausgenutzt. Nur Standardlib.
"""
import argparse
import json
import re
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


SENSIBEL = ["/admin", "/backup", "/config", "/.git", "/.env",
            "/private", "/test", "/dev", "/db", "/dump", "/api"]


def lade_text(url: str, timeout: int):
    """Laedt Textdatei oder gibt '' bei Fehler zurueck."""
    req = urllib.request.Request(url, headers={"User-Agent": "Lab-RobotsCheck/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")[:50000]
    except Exception as e:
        print(f"[--] {url} nicht ladbar: {e}")
        return ""


def parse_disallow(robots: str):
    """Extrahiert Disallow-Zeilen aus robots.txt."""
    return re.findall(r"(?im)^disallow:\s*(\S+)", robots)


def parse_sitemap(xml_text: str):
    """Extrahiert <loc>-URLs aus sitemap.xml (max. 50)."""
    return re.findall(r"<loc>(.*?)</loc>", xml_text, re.IGNORECASE)[:50]


def main():
    parser = argparse.ArgumentParser(description="robots.txt/sitemap.xml pruefen (nur eigenes Labor).")
    parser.add_argument("--url", required=True, help="Basis-URL, z.B. https://mein-labor.local")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in Sekunden")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("14_robots_sitemap_analyzer.py", args)
    except Exception:
        pass
    basis = args.url.rstrip("/")
    print(f"[*] Analysiere {basis} (nur eigenes System!)")
    robots = lade_text(basis + "/robots.txt", args.timeout)
    disallows = parse_disallow(robots) if robots else []
    print(f"[*] Disallow-Eintraege ({len(disallows)}):")
    for pfad in disallows or ["(keine gefunden)"]:
        print(f"    - {pfad}")
    warnungen = [p for p in disallows if any(s in p.lower() for s in SENSIBEL)]
    for pfad in warnungen:
        print(f"[!] WARNUNG: Sensibler Pfad offengelegt: {pfad} - Zugriff haerten!")
    sitemap = lade_text(basis + "/sitemap.xml", args.timeout)
    urls = parse_sitemap(sitemap) if sitemap else []
    print(f"[*] Sitemap-URLs ({len(urls)} gezeigt, max. 50):")
    for u in urls or ["(keine gefunden)"]:
        print(f"    - {u}")
    print("[=] Hinweis: Sensible Pfade nicht nur verstecken, sondern per Auth schuetzen.")
    report = {
        "tool": "14_robots_sitemap_analyzer.py",
        "url": basis,
        "disallows": disallows,
        "warnungen": warnungen,
        "sitemap_urls": urls,
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
                zeilen = ["# Robots/Sitemap Report", f"URL: {basis}",
                          f"Disallows ({len(disallows)}): {', '.join(disallows) or 'keine'}",
                          f"Warnungen ({len(warnungen)}): {', '.join(warnungen) or 'keine'}",
                          f"Sitemap-URLs: {len(urls)}"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
