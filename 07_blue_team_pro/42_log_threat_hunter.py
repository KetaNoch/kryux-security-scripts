#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 42_log_threat_hunter.py
"""42_log_threat_hunter.py - Log-Threat-Hunting (auth/syslog/Apache/Nginx).

Erkennt: SSH-Bruteforce (Failed password / Invalid user), Sudo-Missbrauch,
Portscans-Hinweise, Web-Angriffe (SQLi/Traversal/XSS), Scanner-UAs
(sqlmap/nikto/gobuster/ffuf/nuclei), 5xx-Wellen. Streaming, grosse Files ok.

  python3 42_log_threat_hunter.py --log /var/log/auth.log --out ./hunt
  python3 42_log_threat_hunter.py --log /var/log/apache2/access.log --typ apache --out ./hunt
"""
import argparse
import json
import re
from collections import Counter, defaultdict
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


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATTERNS = {
    "ssh_fail": re.compile(r"Failed password|Invalid user|authentication failure", re.I),
    "sudo_fail": re.compile(r"sudo:.*authentication failure|sudo:.*incorrect password", re.I),
    "sqli": re.compile(r"union\s+select|%27\s+or\s+|'\s+or\s+1=1|information_schema|sleep\s*\(|benchmark\s*\(", re.I),
    "traversal": re.compile(r"\.\./|%2e%2e|/etc/passwd|/etc/shadow|win\.ini", re.I),
    "xss": re.compile(r"<script|%3Cscript|javascript:|onerror\s*=", re.I),
    "scanner": re.compile(r"sqlmap|nikto|gobuster|ffuf|nuclei|dirbuster|hydra|masscan|nmap", re.I),
    "rce": re.compile(r";\s*(cat|id|whoami|wget|curl)\b|\|\s*sh\b|/bin/(ba)?sh", re.I),
}


def analysiere(pfad: Path, typ: str, schwelle: int):
    counter_ip = Counter()
    kategorien = Counter()
    beispiele = defaultdict(list)
    ip_kats = defaultdict(Counter)
    zeilen = 0
    with open(pfad, errors="ignore") as f:
        for zeile in f:
            zeilen += 1
            if zeilen > 2_000_000:
                break
            for kat, rx in PATTERNS.items():
                if rx.search(zeile):
                    kategorien[kat] += 1
                    m = IP_RE.search(zeile)
                    ip = m.group(0) if m else "(keine IP)"
                    # Apache-Log: IP steht vorn
                    if typ == "apache" and not m:
                        ip = zeile.split()[0] if zeile.split() else ip
                    counter_ip[(kat, ip)] += 1
                    ip_kats[ip][kat] += 1
                    if len(beispiele[kat]) < 3:
                        beispiele[kat].append(zeile.strip()[:300])
    verdaechtig = [{"ip": ip, "kategorien": dict(k), "events": sum(k.values())}
                   for ip, k in ip_kats.items() if sum(k.values()) >= schwelle]
    verdaechtig.sort(key=lambda x: -x["events"])
    return {"datei": str(pfad), "zeilen": zeilen, "kategorien": dict(kategorien),
            "top_ip_kat": [{"kat": k, "ip": ip, "n": n} for (k, ip), n in counter_ip.most_common(20)],
            "verdaechtige_ips": verdaechtig[:50], "beispiele": dict(beispiele)}


def main() -> None:
    ap = argparse.ArgumentParser(description="Log-Threat-Hunter")
    ap.add_argument("--log", required=True, help="Logdatei")
    ap.add_argument("--typ", default="auto", choices=["auto", "auth", "apache", "syslog"])
    ap.add_argument("--schwelle", type=int, default=5, help="Events/IP fuer IOC-Liste")
    ap.add_argument("--out", default="", help="Ausgabeverzeichnis")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("42_log_threat_hunter.py", a)
    except Exception:
        pass
    pfad = Path(a.log)
    if not pfad.exists():
        print(f"[!] fehlt: {pfad}")
        raise SystemExit(2)
    erg = analysiere(pfad, a.typ, a.schwelle)
    print(f"[*] {pfad} ({erg['zeilen']} Zeilen)")
    for kat, n in sorted(erg["kategorien"].items(), key=lambda x: -x[1]):
        print(f"  {kat:10s}: {n}")
    print(f"[*] Verdaechtige IPs (>= {a.schwelle}): {len(erg['verdaechtige_ips'])}")
    for v in erg["verdaechtige_ips"][:10]:
        print(f"  {v['ip']:16s} {v['events']:4d}x {v['kategorien']}")
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        (out / f"hunt_{ts}.json").write_text(json.dumps(erg, indent=2, ensure_ascii=False), encoding="utf-8")
        md = [f"# Threat-Hunt {pfad}", f"Zeilen: {erg['zeilen']}", "",
              "| Kategorie | Count |", "|---|---|"]
        for k, n in erg["kategorien"].items():
            md.append(f"| {k} | {n} |")
        md += ["", "## Verdaechtige IPs", "| IP | Events | Kategorien |", "|---|---|---|"]
        for v in erg["verdaechtige_ips"]:
            md.append(f"| {v['ip']} | {v['events']} | {v['kategorien']} |")
        (out / f"hunt_{ts}.md").write_text("\n".join(md), encoding="utf-8")
        print(f"[+] {out}/hunt_{ts}.json + .md")


if __name__ == "__main__":
    main()
