#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 05_dns_enum.py
"""DNS-Enumeration fuer eigene Domains im Labor.
Nur fuer eigene Systeme / Labor! Keine fremden Domains ausforschen.
Defensiv + edukativ: A/MX/NS/TXT per Socket + nslookup-Fallback.
"""
import argparse
import json
import socket  # Basisausloesung ohne Zusatzpakete
import subprocess  # nslookup-Fallback aufrufen
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



def socket_lookup(domain):
    """Loest A-Record via Socket auf; Rueckgabe (host, alias, ip-liste)."""
    try:
        return socket.gethostbyname_ex(domain)  # Standardlib, kein dnspython
    except socket.gaierror as fehler:
        print(f"[Fehler] A-Lookup fehlgeschlagen: {fehler}")
        return (domain, [], [])


def try_dnspython(domain):
    """Versucht dnspython fuer MX/NS/TXT; None wenn nicht installiert."""
    try:
        import dns.resolver  # optional, nur falls vorhanden
    except ImportError:
        return None  # kein dnspython -> Fallback unten
    ergebnis = {}
    try:
        for typ in ("MX", "NS", "TXT"):
            antworten = dns.resolver.resolve(domain, typ, lifetime=5)
            ergebnis[typ] = [str(r).strip() for r in antworten]
    except Exception as fehler:  # defensiv: jede DNS-Ausnahme abfangen
        print(f"[Hinweis] dnspython-Abfrage unvollstaendig: {fehler}")
    return ergebnis


def nslookup_fallback(domain, typ):
    """Fragt einen Recordtyp per 'nslookup' ab; Liste oder Leerliste."""
    try:
        proc = subprocess.run(["nslookup", f"-type={typ}", domain],
                              capture_output=True, text=True, timeout=10)
        zeilen = [z.strip() for z in proc.stdout.splitlines() if z.strip()]
        return zeilen[:20]  # Ausgabe begrenzen
    except FileNotFoundError:
        print("[Fehler] 'nslookup' nicht gefunden.")
    except subprocess.TimeoutExpired:
        print(f"[Fehler] nslookup-Timeout bei {typ}.")
    except OSError as fehler:
        print(f"[Fehler] nslookup: {fehler}")
    return []


def main():
    """Fragt A/MX/NS/TXT ab und druckt Ergebnisse uebersichtlich."""
    parser = argparse.ArgumentParser(description="DNS-Enum (nur eigene Domains!)")
    parser.add_argument("--domain", required=True, help="z.B. example.local")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("05_dns_enum.py", args)
    except Exception:
        pass
    domain = args.domain.strip()
    print(f"[*] DNS-Abfrage fuer {domain} ... Nur eigenes Labor!")
    host, alias, ips = socket_lookup(domain)
    print(f"[A] Host: {host} | Aliase: {alias or '-'} | IPs: {ips or '-'}")
    daten = try_dnspython(domain)
    if daten is None:  # Fallback ohne Zusatz-Abhaengigkeit
        print("[*] dnspython fehlt -> nslookup-Fallback.")
        daten = {}
        for typ in ("MX", "NS", "TXT"):
            daten[typ] = nslookup_fallback(domain, typ)
    for typ in ("MX", "NS", "TXT"):
        werte = daten.get(typ, [])
        print(f"[{typ}] {len(werte)} Eintraege:")
        for eintrag in werte[:10]:
            print(f"  - {eintrag}")
    print("[*] Fertig.")
    report = {
        "tool": "05_dns_enum.py",
        "domain": domain,
        "a_record": {"host": host, "aliase": alias, "ips": ips},
        "records": {typ: daten.get(typ, []) for typ in ("MX", "NS", "TXT")},
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
                zeilen = ["# DNS-Enum Report", f"Domain: {domain}",
                          f"A: host={host}, aliase={alias or '-'}, ips={ips or '-'}"]
                for typ in ("MX", "NS", "TXT"):
                    zeilen.append(f"{typ}: {len(daten.get(typ, []))} Eintraege")
                p.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
        except OSError as fehler:
            print(f"[Fehler] Report schreiben fehlgeschlagen: {fehler}")


if __name__ == "__main__":
    main()
