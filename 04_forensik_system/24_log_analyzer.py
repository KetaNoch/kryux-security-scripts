#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 24_log_analyzer.py
"""Log-Analyzer - Erkennt Failed-Logins & Brute-Force im Syslog (defensiv).

Nur eigene Logs auswerten. Keine Anmeldedaten speichern.
Verwendung: python3 24_log_analyzer.py -f /var/log/auth.log [--top 10]
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


ETHIK = "Nur eigene Logdateien mit Berechtigung analysieren (DSGVO beachten)."
FAIL_RE = re.compile(r"Failed password|authentication failure|Failed login", re.I)
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def analysiere(pfad: Path, top_n: int):
    fails_pro_ip, fails_total, zeilen = Counter(), 0, 0
    try:
        text = pfad.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        print(f"[!] Kann {pfad} nicht lesen: {e}")
        return 0, 0, {}
    for zeile in text:
        zeilen += 1
        if FAIL_RE.search(zeile):
            fails_total += 1
            m = IP_RE.search(zeile)
            if m:
                fails_pro_ip[m.group(1)] += 1
    print(f"[+] Zeilen: {zeilen}, Failed-Logins: {fails_total}")
    print(f"--- Top {top_n} IPs ---")
    for ip, n in fails_pro_ip.most_common(top_n):
        mark = " <-- BRUTE-FORCE-VERDACHT (>5)" if n > 5 else ""
        print(f"  {ip}: {n}{mark}")
    if not fails_pro_ip:
        print("Keine IPs mit Fehlversuchen gefunden.")
    return zeilen, fails_total, dict(fails_pro_ip.most_common(top_n))


def main():
    p = argparse.ArgumentParser(description="Auth-/Syslog auf Angriffe pruefen.")
    p.add_argument("-f", "--file", default="/var/log/auth.log")
    p.add_argument("--top", type=int, default=10)
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("24_log_analyzer.py", a)
    except Exception:
        pass
    print(f"Hinweis: {ETHIK}")
    _erg = analysiere(Path(a.file), a.top) or (0, 0, {})
    zeilen, fails_total, top_ips = _erg
    report = {
        "tool": "24_log_analyzer",
        "target": str(a.file),
        "zeit": datetime.now().isoformat(),
        "zeilen": zeilen,
        "failed_logins": fails_total,
        "top_ips": top_ips,
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
                    _zeilen = [f"# {report['tool']}", f"Datei: {report['target']}",
                               f"Zeilen: {zeilen}, Failed-Logins: {fails_total}", ""]
                    _zeilen += [f"- {ip}: {n}" for ip, n in (top_ips or {}).items()] or ["- Keine IPs gefunden."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
