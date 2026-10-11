#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 03_banner_grabber.py
"""Banner Grabber: liest Dienst-Banner per Socket aus.
Nur fuer eigene Systeme / Labor! Keine fremden Dienste abfragen.
Defensiv + edukativ: Service-Version zur Inventur erkennen.
"""
import argparse
import concurrent.futures  # parallele Banner-Abfragen (fix 20 Worker)
import json
import socket  # TCP-Verbindung und Banner-Empfang
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



def grab_banner(host, port, timeout):
    """Verbindet sich, liest Banner und schaetzt den Dienst."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)  # gegen Haenger absichern
            sock.connect((host, port))  # TCP-Handshake
            try:
                # Manche Dienste senden Banner sofort, andere erst nach Enter
                sock.sendall(b"\r\n")
            except OSError:
                pass
            daten = sock.recv(2048)  # max. 2 KB Banner lesen
            banner = daten.decode("utf-8", errors="replace").strip()
            dienst = rate_dienst(port, banner)  # grobe Einschaetzung
            return banner if banner else "(leeres Banner)", dienst
    except socket.timeout:
        return "(Timeout: kein Banner)", "unbekannt"
    except ConnectionRefusedError:
        return "(Verbindung abgelehnt)", "geschlossen?"
    except socket.gaierror:
        return "(Host unbekannt)", "fehler"
    except OSError as fehler:
        return f"(Socket-Fehler: {fehler})", "fehler"


def rate_dienst(port, banner):
    """Schaetzt den Dienst anhand von Port und Bannertext."""
    text = banner.lower()
    if "ssh" in text or port == 22:
        return "SSH (vermutet)"
    if "http" in text or port in (80, 8080, 8000):
        return "HTTP (vermutet)"
    if port == 443:
        return "HTTPS (vermutet)"
    if "ftp" in text or port == 21:
        return "FTP (vermutet)"
    if "smtp" in text or port == 25:
        return "SMTP (vermutet)"
    return "unbekannt/allgemein"


def main():
    """Liest CLI-Argumente und gibt Banner + Einschaetzung aus."""
    parser = argparse.ArgumentParser(description="Banner Grabber (nur eigenes Labor!)")
    parser.add_argument("--host", required=True, help="Ziel-Host, z.B. 127.0.0.1")
    parser.add_argument("--ports", default="80", help="Ports: '80' oder '22,80,443'")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout in Sekunden")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("03_banner_grabber.py", args)
    except Exception:
        pass
    try:
        ziele = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        print("[Fehler] Ports muessen Zahlen sein, z.B. '22,80,443'.")
        return
    print(f"[*] Banner-Abfrage bei {args.host} ... Nur eigene Systeme!")
    gueltig = [p for p in ziele if 1 <= p <= 65535]
    for p in ziele:
        if p not in gueltig:
            print(f"[!] Port {p} uebersprungen (ungueltig).")
    befunde = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        auftraege = {pool.submit(grab_banner, args.host, p, args.timeout): p for p in gueltig}
        for zukunft in concurrent.futures.as_completed(auftraege):
            port = auftraege[zukunft]
            try:
                befunde[port] = zukunft.result()  # (banner, dienst)
            except Exception as fehler:  # defensiv: kein Thread-Absturz
                befunde[port] = (f"(Fehler: {fehler})", "fehler")
    for port in gueltig:
        banner, dienst = befunde[port]
        print(f"[Port {port}] Dienst: {dienst}")
        print(f"  Banner: {banner[:300]}")  # Ausgabe kuerzen
    print("[*] Fertig.")
    report = {
        "tool": "03_banner_grabber.py",
        "host": args.host,
        "befunde": [{"port": p, "dienst": d, "banner": b}
                    for p, (b, d) in sorted(befunde.items())],
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
                zeilen = ["# Banner-Grabber Report", f"Host: {args.host}"]
                zeilen += [f"Port {e['port']}: {e['dienst']} | {e['banner'][:120]}"
                           for e in report["befunde"]] or ["(keine gueltigen Ports)"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
