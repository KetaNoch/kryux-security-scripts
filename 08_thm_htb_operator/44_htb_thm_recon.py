#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 44_htb_thm_recon.py
"""44_htb_thm_recon.py - Recon-Arbeitsplatz fuer THM/HTB-Labs (nur Lab-Ziele!).

Kette: Ping-Check -> schneller TCP-Connect-Scan -> Banner-Grab -> HTTP-Erkennung
-> Directory-Enum (Wortliste) -> VHost-Enum (Host-Header-Fuzz). Alles geloggt
als recon.json + notes.md fuer das Lab-Tagebuch. Threads, Timeouts, Stop bei Strg+C.

Nur eigene Lab-Maschinen (VPN-IP 10.x / TryHackMe / HTB)! Bezug von --wordlist
als Textdatei (eine Zeile pro Pfad). Erfordert --i-have-authorization (Lab-Regeln).

  python3 44_htb_thm_recon.py --target 10.10.10.5 --i-have-authorization --ports top100 --out ./lab_maschine
"""
import argparse
import concurrent.futures
import json
import socket
import subprocess
import sys
import urllib.request
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


TOP100 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
          3306, 3389, 5900, 8080, 8000, 8888, 8443, 27017, 6379, 9200, 11211, 513, 514,
          1099, 1521, 5432, 1433, 5985, 5986, 47001, 10250, 3000, 5000, 9000]
KLEIN_WORTLISTE = ["admin", "login", "robots.txt", "sitemap.xml", ".git/HEAD", "api",
                   "dashboard", "uploads", "backup", "config", "server-status", "phpmyadmin"]


def tcp_offen(ip, port, timeout=0.8):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def banner(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except OSError:
                pass
            return s.recv(1024).decode("utf-8", errors="ignore").strip().replace("\n", " | ")[:300]
    except Exception as e:
        return f"n/a ({e})"


def http_get(url, host_header=None, timeout=8):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "THM-HTB-Recon/1.0"})
        if host_header:
            req.add_header("Host", host_header)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, len(r.read(200000))
    except Exception as e:
        code = getattr(e, "code", 0) or 0
        return code, 0


def main() -> None:
    ap = argparse.ArgumentParser(description="THM/HTB Recon-Arbeitsplatz (nur Lab!)")
    ap.add_argument("--target", required=True, help="Lab-IP, z.B. 10.10.10.5")
    ap.add_argument("--i-have-authorization", action="store_true", help="PFLICHT: Lab-Maschine aktiv, Regeln akzeptiert")
    ap.add_argument("--ports", default="top100", help="'top100' oder '80,443,8080' oder '1-1000'")
    ap.add_argument("--wordlist", default="", help="Pfad-Wortliste (optional)")
    ap.add_argument("--vhosts", default="", help="VHost-Wortliste, Komma-separiert oder Datei (optional)")
    ap.add_argument("--base-url", default="", help="Basis-URL, default http://target/")
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--out", default="./lab_recon", help="Workspace-Verzeichnis")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("44_htb_thm_recon.py", a)
    except Exception:
        pass
    if not a.i_have_authorization:
        print("[!] --i-have-authorization fehlt. Nur aktive Lab-Maschinen testen.", file=sys.stderr)
        sys.exit(1)
    try:
        ip = socket.gethostbyname(a.target)
    except socket.gaierror:
        print("[!] Ziel nicht aufloesbar"); sys.exit(2)

    # Ports aufloesen
    if a.ports == "top100":
        ports = TOP100
    else:
        ports = set()
        for teil in a.ports.split(","):
            teil = teil.strip()
            if "-" in teil:
                s, e = teil.split("-", 1)
                ports.update(range(int(s), int(e) + 1))
            elif teil.isdigit():
                ports.add(int(teil))
        ports = sorted(p for p in ports if 1 <= p <= 65535)[:2000]

    print(f"[*] Ziel {a.target} ({ip}), {len(ports)} Ports ...")
    ping = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, text=True)
    lebt = ping.returncode == 0
    print(f"[*] Ping: {'lebt' if lebt else 'kein ICMP (macht nichts, weiter mit TCP)'}")

    offen = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.threads) as pool:
        futs = {pool.submit(tcp_offen, ip, p): p for p in ports}
        for f in concurrent.futures.as_completed(futs):
            if f.result():
                offen.append(futs[f])
                print(f"[OFFEN] {futs[f]}/tcp")
    offen.sort()
    banners = {p: banner(ip, p) for p in offen}
    for p in offen:
        print(f"  Banner {p}: {banners[p][:120]}")

    base = a.base_url or f"http://{a.target}/"
    http_ports = [p for p in offen if p in (80, 8000, 8080, 8443, 8888, 3000, 5000, 9000)] or ([80] if 80 in offen else [])
    dirs = {}
    if http_ports:
        if a.wordlist and Path(a.wordlist).exists():
            woerter = Path(a.wordlist).read_text(errors="ignore").splitlines()[:500]
            woerter = [w.strip().strip("/") for w in woerter if w.strip() and not w.startswith("#")]
        else:
            woerter = KLEIN_WORTLISTE
        print(f"[*] Dir-Enum auf {base} ({len(woerter)} Pfade)...")
        def check(pfad):
            code, size = http_get(base.rstrip("/") + "/" + pfad)
            return pfad, code, size
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            for pfad, code, size in pool.map(check, woerter):
                if code and code not in (404, 0):
                    dirs[pfad] = {"code": code, "size": size}
                    print(f"  [{code}] /{pfad} ({size} B)")
    vhosts = {}
    if a.vhosts:
        vp = Path(a.vhosts)
        kandidaten = vp.read_text(errors="ignore").splitlines() if vp.exists() else a.vhosts.split(",")
        kandidaten = [k.strip() for k in kandidaten if k.strip()][:100]
        basis_code, basis_size = http_get(base)
        for v in kandidaten:
            code, size = http_get(base, host_header=v)
            if code != 0 and (code != basis_code or abs(size - basis_size) > 500):
                vhosts[v] = {"code": code, "size": size}
                print(f"  [VHOST] {v} -> {code} ({size} B)")

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    erg = {"target": a.target, "ip": ip, "zeit": datetime.now(timezone.utc).isoformat(),
           "ping_ok": lebt, "offene_ports": offen, "banner": banners,
           "base_url": base, "dirs": dirs, "vhosts": vhosts}
    (out / "recon.json").write_text(json.dumps(erg, indent=2), encoding="utf-8")
    (out / "notes.md").write_text(
        f"# Lab-Notizen {a.target} ({ip})\n\nOffene Ports: {offen}\n\n"
        + "".join(f"- {p}/tcp: {banners[p][:150]}\n" for p in offen)
        + f"\nDirs ({base}): {dirs or 'keine Treffer'}\nVHosts: {vhosts or '-'}\n\n"
        "## Naechste Schritte\n- [ ] Service-Versionen manuell verifizieren (nmap -sV mit Freigabe)\n"
        "- [ ] Web manuell klicken + Burp/DevTools\n- [ ] 45er PrivEsc-Checker erst nach Shell\n", encoding="utf-8")
    print(f"[+] {out}/recon.json + notes.md")


if __name__ == "__main__":
    main()
