#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 04_arp_scanner.py
"""ARP-Scanner fuer das Heimlabor (gleicher Layer-2-Bereich).
Nur fuer eigene Systeme / Labor! Nur eigenes LAN scannen.
Defensiv + edukativ: zeigt MAC-IP-Zuordnungen im Labornetz.
"""
import argparse
import ipaddress  # Netzbereich validieren
import json
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



def scapy_scan(netz_str, timeout):
    """Versucht ARP-Scan mit scapy; gibt Liste (IP, MAC) oder None zurueck."""
    try:
        from scapy.all import ARP, Ether, srp  # optional, nur im Labor
    except ImportError:
        return None  # scapy fehlt -> Fallback nutzen
    try:
        pakete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=netz_str)
        antworten, _ = srp(pakete, timeout=timeout, verbose=0)
        treffer = []
        for _, antwort in antworten:
            treffer.append((antwort.psrc, antwort.hwsrc))
        return treffer
    except PermissionError:
        print("[Fehler] scapy braucht Root/Admin-Rechte im Labor.")
        return []
    except OSError as fehler:
        print(f"[Fehler] scapy-Scan fehlgeschlagen: {fehler}")
        return []


def proc_arp_fallback():
    """Fallback: liest bekannten ARP-Cache aus /proc/net/arp (Linux)."""
    treffer = []
    try:
        with open("/proc/net/arp", "r", encoding="utf-8") as datei:
            zeilen = datei.readlines()[1:]  # Kopfzeile ueberspringen
        for zeile in zeilen:
            teile = zeile.split()
            if len(teile) >= 4:
                ip, mac = teile[0], teile[3]
                if mac != "00:00:00:00:00:00":
                    treffer.append((ip, mac))
    except FileNotFoundError:
        print("[Hinweis] /proc/net/arp fehlt (kein Linux?). Nutze scapy im Labor.")
    except OSError as fehler:
        print(f"[Fehler] ARP-Tabelle nicht lesbar: {fehler}")
    return treffer


def main():
    """Parst Netz, nutzt scapy oder Fallback und listet Hosts."""
    parser = argparse.ArgumentParser(description="ARP-Scan (nur eigenes Labor-LAN!)")
    parser.add_argument("--netz", required=True, help="z.B. 192.168.1.0/24")
    parser.add_argument("--timeout", type=int, default=2, help="Timeout je Anfrage (s)")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("04_arp_scanner.py", args)
    except Exception:
        pass
    try:
        ipaddress.ip_network(args.netz, strict=False)  # nur validieren
    except ValueError as fehler:
        print(f"[Fehler] Ungueltiges Netz: {fehler}")
        return
    print(f"[*] ARP-Scan in {args.netz} ... Nur eigenes Labor!")
    ergebnis = scapy_scan(args.netz, args.timeout)
    if ergebnis is None:  # scapy nicht installiert
        print("[*] scapy fehlt -> Fallback auf ARP-Cache (/proc/net/arp).")
        ergebnis = proc_arp_fallback()
    if not ergebnis:
        print("[*] Keine Eintraege. Hinweis: Labor-LAN + Root pruefen.")
    for ip, mac in sorted(ergebnis):
        print(f"[HOST] {ip} -> {mac}")
    print(f"[*] Fertig. {len(ergebnis)} Eintraege.")
    report = {
        "tool": "04_arp_scanner.py",
        "netz": args.netz,
        "hosts": [{"ip": ip, "mac": mac} for ip, mac in sorted(ergebnis)],
        "anzahl": len(ergebnis),
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
                zeilen = ["# ARP-Scan Report", f"Netz: {args.netz}"]
                zeilen += [f"{e['ip']} -> {e['mac']}" for e in report["hosts"]] or ["(keine Eintraege)"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
