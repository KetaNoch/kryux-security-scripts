#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 09_ssl_tls_checker.py
"""
09_ssl_tls_checker.py - TLS-Zertifikat und Verbindung pruefen (defensiv).

Beschreibung:
    Prueft Zertifikat eines eigenen Servers: Ablaufdatum, Issuer,
    Subject, SANs und ausgehandelte TLS-Version. Warnt bei
    Ablauf in unter 30 Tagen.

Verwendung:
    python3 09_ssl_tls_checker.py --host mein-labor.local --port 443

Ethik:
    NUR eigene Systeme / Labor testen! Keine fremden Systeme scannen.
    Nur Standardbibliothek (ssl, socket, argparse).
"""
import argparse
import json
import socket
import ssl
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


WARN_TAGE = 30


def hole_zertifikat(host: str, port: int, timeout: int):
    """Verbindet sich per TLS und gibt Zertifikat + TLS-Version zurueck."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            zert = tls.getpeercert()
            version = tls.version()
            return zert, version


def parse_datum(datum_str: str):
    """Wandelt ASN1-Datum aus getpeercert in datetime um."""
    sek = ssl.cert_time_to_seconds(datum_str)
    return datetime.fromtimestamp(sek, tz=timezone.utc)


def name_zu_str(namenstupel):
    """Wandelt ((('commonName', 'x'),),) in lesbaren String um."""
    teile = []
    for rdn in namenstupel:
        for schluessel, wert in rdn:
            teile.append(f"{schluessel}={wert}")
    return ", ".join(teile)


def main():
    parser = argparse.ArgumentParser(description="TLS-Zertifikat pruefen (nur eigenes Labor).")
    parser.add_argument("--host", required=True, help="Hostname, z.B. mein-labor.local")
    parser.add_argument("--port", type=int, default=443, help="Port (Standard: 443)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in Sekunden")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("09_ssl_tls_checker.py", args)
    except Exception:
        pass
    print(f"[*] Pruefe {args.host}:{args.port} (nur eigenes System!)")
    try:
        zert, version = hole_zertifikat(args.host, args.port, args.timeout)
    except Exception as e:
        print(f"[!] TLS-Verbindung fehlgeschlagen: {e}")
        return
    print(f"[*] TLS-Version: {version}")
    if version in ("TLSv1", "TLSv1.1"):
        print("[!] WARNUNG: Veraltete TLS-Version - bitte TLS 1.2+ aktivieren.")
    ablauf = parse_datum(zert["notAfter"])
    rest = (ablauf - datetime.now(timezone.utc)).days
    print(f"[*] Subject: {name_zu_str(zert.get('subject', []))}")
    print(f"[*] Issuer:  {name_zu_str(zert.get('issuer', []))}")
    print(f"[*] Gueltig bis: {ablauf:%Y-%m-%d %H:%M UTC} ({rest} Tage)")
    sans = [v for t, v in zert.get("subjectAltName", []) if t == "DNS"]
    print(f"[*] SANs: {', '.join(sans) if sans else '(keine)'}")
    if rest < 0:
        print("[!] KRITISCH: Zertifikat ABGELAUFEN - sofort erneuern!")
    elif rest < WARN_TAGE:
        print(f"[!] WARNUNG: Ablauf in unter {WARN_TAGE} Tagen - Erneuerung planen.")
    else:
        print("[OK] Zertifikat gueltig.")
    status = "abgelaufen" if rest < 0 else "laeuft_bald_ab" if rest < WARN_TAGE else "gueltig"
    report = {
        "tool": "09_ssl_tls_checker.py",
        "host": args.host,
        "port": args.port,
        "tls_version": version,
        "subject": name_zu_str(zert.get("subject", [])),
        "issuer": name_zu_str(zert.get("issuer", [])),
        "gueltig_bis": ablauf.isoformat(),
        "rest_tage": rest,
        "sans": sans,
        "status": status,
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
                zeilen = ["# TLS-Check Report", f"Host: {args.host}:{args.port}",
                          f"TLS-Version: {version}",
                          f"Gueltig bis: {ablauf:%Y-%m-%d %H:%M UTC} ({rest} Tage)",
                          f"Status: {status}"]
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
