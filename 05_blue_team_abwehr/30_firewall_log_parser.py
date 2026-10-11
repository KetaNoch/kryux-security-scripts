#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 30_firewall_log_parser.py
"""30_firewall_log_parser.py - Parst UFW/iptables-Logs (defensiv).

Nur für eigene Systeme. Beispiel UFW-Zeile:
... [UFW BLOCK] ... SRC=1.2.3.4 DST=... PROTO=TCP SPT=... DPT=22 ...
Erstellt Top-IPs/Ports + ASCII-Histogramm.
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


ETHIK = "Defensiv: nur eigene Firewall-Logs auswerten."

SRC_RE = re.compile(r"SRC=([\d.]+)")
DPT_RE = re.compile(r"DPT=(\d+)")


def parse_log(pfad: Path):
    """Parst Log, liefert Counter für IPs und Ports."""
    ips, ports = Counter(), Counter()
    total = blocks = 0
    with pfad.open(errors="ignore") as f:
        for zeile in f:
            total += 1
            if "BLOCK" in zeile or "DROP" in zeile or "REJECT" in zeile:
                blocks += 1
                s, d = SRC_RE.search(zeile), DPT_RE.search(zeile)
                if s:
                    ips[s.group(1)] += 1
                if d:
                    ports[d.group(1)] += 1
    return total, blocks, ips, ports


def histogramm(counter: Counter, titel: str, top: int = 10) -> str:
    """Erzeugt ASCII-Histogramm."""
    out = [f"\n{titel}:"]
    if not counter:
        return "\n".join(out) + "\n  (keine Daten)"
    maxv = max(v for _, v in counter.most_common(top))
    for k, v in counter.most_common(top):
        balken = "#" * int(30 * v / maxv) if maxv else ""
        out.append(f"  {k:>16} {v:5} |{balken}")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description="UFW/iptables Log-Parser (defensiv)")
    ap.add_argument("--log", required=True, help="Firewall-Logdatei")
    ap.add_argument("--top", type=int, default=10, help="Top-N Anzeige")
    ap.add_argument("--report", default="", help="Optional Report-Datei")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("30_firewall_log_parser.py", a)
    except Exception:
        pass

    pfad = Path(a.log)
    if not pfad.is_file():
        print(f"[!] Datei fehlt: {pfad}")
        return
    total, blocks, ips, ports = parse_log(pfad)
    text = f"Zeilen: {total}, Blocks/Drops: {blocks}\n{ETHIK}"
    text += histogramm(ips, f"Top {a.top} geblockte IPs", a.top)
    text += histogramm(ports, f"Top {a.top} geblockte Ports", a.top)
    print(text)
    if a.report:
        Path(a.report).write_text(text + "\n")
        print(f"[+] Report: {a.report}")
    report = {
        "tool": "30_firewall_log_parser",
        "target": str(pfad),
        "zeit": datetime.now().isoformat(),
        "zeilen": total,
        "blocks": blocks,
        "top_ips": dict(ips.most_common(a.top)),
        "top_ports": dict(ports.most_common(a.top)),
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
                    _zeilen = [f"# {report['tool']}", f"Log: {pfad}", f"Zeilen: {total}, Blocks: {blocks}", ""]
                    _zeilen += [f"- {ip}: {n}" for ip, n in report["top_ips"].items()] or ["- Keine IPs."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
