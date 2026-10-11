#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 01_port_scanner.py
"""TCP Connect Port-Scanner fuer das eigene Labor.
Nur fuer eigene Systeme / Labor! Niemals fremde Systeme scannen.
Defensiv + edukativ: prueft offene Ports am eigenen Host.
"""
import argparse
import concurrent.futures  # ThreadPool fuer parallele Scans
import json
import socket
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



def parse_ports(port_str):
    """Wandelt '1-1024' oder '80,443' in eine sortierte Portliste um."""
    ports = set()
    try:
        for teil in port_str.split(","):
            teil = teil.strip()
            if "-" in teil:  # Bereich wie 20-25
                start, ende = teil.split("-", 1)
                start, ende = int(start), int(ende)
                if not 1 <= start <= ende <= 65535:
                    raise ValueError("Portbereich ungueltig")
                ports.update(range(start, ende + 1))
            else:  # Einzelport
                port = int(teil)
                if not 1 <= port <= 65535:
                    raise ValueError("Port ungueltig")
                ports.add(port)
    except ValueError as fehler:
        raise argparse.ArgumentTypeError(f"Ungueltige Ports: {fehler}")
    return sorted(ports)


def scan_port(host, port, timeout):
    """Prueft einen TCP-Port per Connect; gibt Portnr. oder None zurueck."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)  # Timeout gegen Haenger
            if sock.connect_ex((host, port)) == 0:
                return port  # 0 bedeutet: Verbindung erfolgreich
    except socket.gaierror:
        return None  # Hostfehler wird in main() gemeldet
    except OSError as fehler:
        print(f"[Fehler] Socket-Fehler bei Port {port}: {fehler}")
    return None


def main():
    """Liest CLI-Argumente und startet den ThreadPool-Scan."""
    parser = argparse.ArgumentParser(description="TCP Connect Scan (nur eigenes Labor!)")
    parser.add_argument("--host", required=True, help="Ziel-Host, z.B. 127.0.0.1")
    parser.add_argument("--ports", default="1-1024", help="Ports: '1-1024' oder '80,443'")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in Sekunden")
    parser.add_argument("--threads", type=int, default=100, help="Anzahl Threads")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("01_port_scanner.py", args)
    except Exception:
        pass
    try:
        ziel_ip = socket.gethostbyname(args.host)  # Hostnamen aufloesen
    except socket.gaierror:
        print(f"[Fehler] Host {args.host} kann nicht aufgeloest werden.")
        return
    print(f"[*] Scanne {args.host} ({ziel_ip}) ... Nur eigenes Labor!")
    offen = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            auftraege = {pool.submit(scan_port, ziel_ip, p, args.timeout): p
                         for p in parse_ports(args.ports)}
            for zukunft in concurrent.futures.as_completed(auftraege):
                ergebnis = zukunft.result()  # Portnr. oder None
                if ergebnis is not None:
                    offen.append(ergebnis)
                    print(f"[OFFEN] Port {ergebnis}/tcp")
    except KeyboardInterrupt:
        print("\n[!] Scan durch Benutzer abgebrochen.")
    print(f"[*] Fertig. Offene Ports: {sorted(offen) if offen else 'keine'}")
    report = {
        "tool": "01_port_scanner.py",
        "host": args.host,
        "ziel_ip": ziel_ip,
        "offene_ports": sorted(offen),
        "anzahl_offen": len(offen),
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
                zeilen = ["# Port-Scan Report",
                          f"Host: {args.host} ({ziel_ip})",
                          f"Offene Ports: {', '.join(map(str, sorted(offen))) if offen else 'keine'}"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
