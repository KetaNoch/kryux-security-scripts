#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 29_bruteforce_detector.py
"""29_bruteforce_detector.py - Erkennt Brute-Force-Angriffe in Logdateien.

Nur zur defensiven Nutzung auf eigenen Systemen / mit Einwilligung.
Analysiert Auth-Logs (z.B. /var/log/auth.log) und meldet IPs
mit vielen Fehlversuchen. Erstellt Blockliste + Report.
"""
import argparse
import json
import re
from collections import Counter
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


ETHIK_HINWEIS = "Nur defensiv auf eigenen Systemen einsetzen!"

IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
FAIL_RE = re.compile(r"(Failed|failure|invalid|denied)", re.IGNORECASE)


def analysiere_log(pfad: Path) -> Counter:
    """Zählt fehlgeschlagene Logins pro IP."""
    zaehler = Counter()
    with pfad.open(errors="ignore") as f:
        for zeile in f:
            if FAIL_RE.search(zeile):
                m = IP_RE.search(zeile)
                if m:
                    zaehler[m.group(1)] += 1
    return zaehler


def main() -> None:
    p = argparse.ArgumentParser(description="Brute-Force-Detector (defensiv)")
    p.add_argument("--log", required=True, help="Pfad zur Logdatei")
    p.add_argument("--schwelle", type=int, default=5, help="Versuche ab Block (Default 5)")
    p.add_argument("--blockliste", default="blockliste.txt", help="Ausgabe Blockliste")
    p.add_argument("--report", default="bruteforce_report.txt", help="Report-Datei")
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("29_bruteforce_detector.py", a)
    except Exception:
        pass

    log = Path(a.log)
    if not log.is_file():
        print(f"[!] Logdatei fehlt: {log}")
        return
    counts = analysiere_log(log)
    verdaechtig = {ip: n for ip, n in counts.items() if n >= a.schwelle}
    print(f"[+] {len(counts)} IPs mit Fehlversuchen, {len(verdaechtig)} über Schwelle {a.schwelle}")
    for ip, n in sorted(verdaechtig.items(), key=lambda x: -x[1]):
        print(f"  {ip}: {n}x")

    Path(a.blockliste).write_text("\n".join(sorted(verdaechtig)) + "\n" if verdaechtig else "")
    with open(a.report, "w") as r:
        r.write("Brute-Force-Report (defensiv)\n" + ETHIK_HINWEIS + "\n\n")
        for ip, n in counts.most_common(20):
            mark = "BLOCK" if n >= a.schwelle else "ok"
            r.write(f"{ip:16} {n:4} {mark}\n")
    print(f"[+] Blockliste: {a.blockliste}, Report: {a.report}")
    report = {
        "tool": "29_bruteforce_detector",
        "target": str(log),
        "zeit": datetime.now().isoformat(),
        "schwelle": a.schwelle,
        "anzahl_ips": len(counts),
        "anzahl_verdaechtig": len(verdaechtig),
        "verdaechtig": dict(sorted(verdaechtig.items(), key=lambda x: -x[1])),
        "top": dict(counts.most_common(20)),
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
                    _zeilen = [f"# {report['tool']}", f"Log: {log}, Schwelle: {a.schwelle}",
                               f"IPs: {len(counts)}, Verdaechtig: {len(verdaechtig)}", ""]
                    _zeilen += [f"- {ip}: {n}x" for ip, n in report["verdaechtig"].items()] or ["- Keine Verdaechtigen."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
