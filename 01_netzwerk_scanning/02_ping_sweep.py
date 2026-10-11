#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 02_ping_sweep.py
"""Ping-Sweep ueber ein Subnetz, z.B. 192.168.1.0/24.
Nur fuer eigene Systeme / Labor! Nur das eigene Netz pruefen.
Defensiv + edukativ: findet lebende Hosts im Heimlabor.
"""
import argparse
import concurrent.futures  # parallele Abfragen beschleunigen
import ipaddress  # Subnetz aufzaehlen und validieren
import json
import platform  # Windows-/Linux-ping-Parameter unterscheiden
import subprocess  # System-ping aufrufen (ICMP)
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



def ping_host(ip_str, timeout):
    """Pingt eine IP einmal an; gibt IP-String bei Erfolg zurueck."""
    system = platform.system().lower()  # 'linux', 'windows', ...
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_str]
        else:  # Linux / macOS
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip_str]
        ergebnis = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        if ergebnis.returncode == 0:
            return ip_str  # Host lebt
    except subprocess.TimeoutExpired:
        pass  # keine Antwort -> gilt als inaktiv
    except FileNotFoundError:
        print("[Fehler] 'ping'-Befehl nicht gefunden.")
    except OSError as fehler:
        print(f"[Fehler] bei {ip_str}: {fehler}")
    return None


def main():
    """Parst Subnetz und startet den parallelen Ping-Sweep."""
    parser = argparse.ArgumentParser(description="Ping-Sweep (nur eigenes Labor!)")
    parser.add_argument("--netz", required=True, help="Subnetz, z.B. 192.168.1.0/24")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout je Host (s)")
    parser.add_argument("--threads", type=int, default=64, help="Anzahl Threads")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("02_ping_sweep.py", args)
    except Exception:
        pass
    try:
        netz = ipaddress.ip_network(args.netz, strict=False)  # Netz validieren
    except ValueError as fehler:
        print(f"[Fehler] Ungueltiges Subnetz: {fehler}")
        return
    if netz.num_addresses > 1024:
        print("[Fehler] Subnetz zu gross (max. 1024 Adressen im Labor).")
        return
    ziele = [str(ip) for ip in netz.hosts()]  # Netzwerk-/Broadcast-Adresse auslassen
    print(f"[*] Sweep in {netz} ({len(ziele)} Hosts) ... Nur eigenes Labor!")
    lebend = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
            auftraege = {pool.submit(ping_host, ip, args.timeout): ip for ip in ziele}
            for zukunft in concurrent.futures.as_completed(auftraege):
                treffer = zukunft.result()
                if treffer:
                    lebend.append(treffer)
                    print(f"[LEBT] {treffer}")
    except KeyboardInterrupt:
        print("\n[!] Abgebrochen durch Benutzer.")
    print(f"[*] Fertig. Lebende Hosts ({len(lebend)}): {sorted(lebend)}")
    report = {
        "tool": "02_ping_sweep.py",
        "netz": str(netz),
        "lebende_hosts": sorted(lebend),
        "anzahl": len(lebend),
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
                zeilen = ["# Ping-Sweep Report", f"Netz: {netz}",
                          f"Lebende Hosts ({len(lebend)}): {', '.join(sorted(lebend)) if lebend else 'keine'}"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
