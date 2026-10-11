#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 06_packet_sniffer.py
"""Einfacher Paket-Zaehler / Sniffer fuer das eigene Labor.
Nur fuer eigene Systeme / Labor! Braucht Root (RAW-Socket).
Defensiv + edukativ: zaehlt TCP/UDP/ICMP/Andere passiv mit.
"""
import argparse
import json
import socket  # RAW-Socket (Linux)
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


def scapy_modus(anzahl):
    """Optional: scapy-Sniffer; Zaehler-Dict bei Erfolg, sonst None."""
    try:
        from scapy.all import sniff  # optional
    except ImportError:
        return None
    zaehler = {"tcp": 0, "udp": 0, "icmp": 0, "andere": 0}

    def behandle(p):  # Callback pro Paket, zaehlt Typ
        for name, schicht in (("tcp", "TCP"), ("udp", "UDP"), ("icmp", "ICMP")):
            if p.haslayer(schicht):
                zaehler[name] += 1
                return
        zaehler["andere"] += 1

    try:
        print("[*] scapy-Modus aktiv (Root noetig).")
        sniff(count=anzahl, prn=behandle, store=False, timeout=60)
        print(f"[*] Ergebnis: {zaehler}")
        return zaehler
    except PermissionError:
        print("[Fehler] scapy braucht Root-Rechte.")
    except OSError as fehler:
        print(f"[Fehler] scapy-Sniff: {fehler}")
    return None


def raw_modus(anzahl, timeout):
    """Zaehlt Pakete per RAW-Socket; gibt Zaehler-Dict oder None zurueck."""
    zaehler = {"tcp": 0, "udp": 0, "icmp": 0, "andere": 0}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except PermissionError:
        print("[Fehler] RAW-Socket braucht Root (sudo noetig).")
        return None
    except OSError as fehler:
        print(f"[Fehler] Socket konnte nicht geoeffnet werden: {fehler}")
        return None
    sock.settimeout(timeout)
    print(f"[*] RAW-Modus: hoere {anzahl} Pakete mit (Root aktiv).")
    gelesen = 0
    try:
        while gelesen < anzahl:
            try:
                daten, _ = sock.recvfrom(65535)  # ganzes IP-Paket
            except socket.timeout:
                print("[!] Timeout beim Warten auf Pakete.")
                break
            if len(daten) < 20:
                continue  # kein gueltiger IP-Header
            protokoll = daten[9]  # 9. Byte = Protokollnummer
            zuordnung = {6: "tcp", 17: "udp", 1: "icmp"}  # TCP/UDP/ICMP
            zaehler[zuordnung.get(protokoll, "andere")] += 1
            gelesen += 1
    except KeyboardInterrupt:
        print("\n[!] Abgebrochen.")
    finally:
        sock.close()
    print(f"[*] Ergebnis: {zaehler}")
    return zaehler


def main():
    """CLI: Modus waehlen und Paket-Zaehler starten."""
    parser = argparse.ArgumentParser(description="Paket-Sniffer (nur Labor, Root!)")
    parser.add_argument("--anzahl", type=int, default=20, help="Paketanzahl")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout (s)")
    parser.add_argument("--scapy", action="store_true", help="scapy nutzen falls da")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("06_packet_sniffer.py", args)
    except Exception:
        pass
    print("[Hinweis] Nur eigener Traffic / eigenes Labor mitschneiden!")
    modus = "raw"
    zaehler = None
    if args.scapy:
        zaehler = scapy_modus(args.anzahl)
        if zaehler is None:
            print("[*] scapy fehlt -> RAW-Fallback.")
            zaehler = raw_modus(args.anzahl, args.timeout)
        else:
            modus = "scapy"
    else:
        zaehler = raw_modus(args.anzahl, args.timeout)
    report = {
        "tool": "06_packet_sniffer.py",
        "modus": modus,
        "anzahl": args.anzahl,
        "zaehler": zaehler or {},
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
                zeilen = ["# Paket-Sniffer Report", f"Modus: {modus}",
                          f"Zaehler: {zaehler or {}}"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
