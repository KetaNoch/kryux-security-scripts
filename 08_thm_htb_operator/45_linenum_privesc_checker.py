#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 45_linenum_privesc_checker.py
"""45_linenum_privesc_checker.py - Linux PrivEsc-Enum (LinPEAS-light, NUR CHECKS).

Fuehrt NUR lesende Checks aus, kein Exploit, keine Passwort-Angriffe:
  Kernel/Distro/Sudo-Rechte (sudo -l -n)/SUID/SGID/Capabilities/Cron-Jobs/
  beschreibbare PATH-Verzeichnisse/Docker-Gruppe+Socket/NFS/History-Secrets
  (nur Vorkommen, keine Ausgabe von Secrets)/SSH-Keys/Prozesse als root.
Gibt gescorte Hints (hoch/mittel/info) + JSON/MD. Ideal nach erster Shell
in THM/HTB-Labs oder beim Kunden mit Freigabe.

  python3 45_linenum_privesc_checker.py --out ./privesc
"""
import argparse
import json
import os
import stat
import subprocess
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



def run(cmd, timeout=12):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()[:12000]
    except Exception as e:
        return f"n/a: {e}"


def main() -> None:
    ap = argparse.ArgumentParser(description="PrivEsc-Checker (nur lesende Hints)")
    ap.add_argument("--out", default="", help="Ausgabeverzeichnis")
    ap.add_argument("--max-suid", type=int, default=60)
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("45_linenum_privesc_checker.py", a)
    except Exception:
        pass
    hints = []

    def hint(stufe, titel, detail):
        hints.append({"stufe": stufe, "titel": titel, "detail": detail[:600]})

    # Basis
    hint("info", "Kernel/Distro", (run(["uname", "-a"]) + " | " + run(["cat", "/etc/os-release"]).splitlines()[0] if run(["cat", "/etc/os-release"]) else "")[:300])
    hint("info", "Aktueller User/Groups", run(["id"]))
    # Sudo (nicht-interaktiv, kein Passwort-Prompt)
    sudo = run(["sudo", "-l", "-n"])
    if "not allowed" in sudo or "password is required" in sudo or "interactive authentication" in sudo or sudo.strip().startswith("n/a"):
        hint("info", "Sudo-Rechte", "keine passwortlosen sudo-Rechte (oder sudo erfordert Passwort)")
    else:
        stufe = "hoch" if "(ALL" in sudo or "NOPASSWD" in sudo else "mittel"
        hint(stufe, "Sudo-Rechte pruefen", sudo[:600])
    # SUID (nur echte Pfade; Standard-Bins wie chsh/ssh-keysign sind normal)
    suid_raw = run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"], timeout=25)
    suid = [l for l in suid_raw.splitlines() if l.startswith("/")]
    suid = suid[:a.max_suid]
    interessant = [x for x in suid if any(b in x for b in
                   ("nmap", "/vim", "/vi", "/less", "/more", "/find", "/bash", "/sh", "python", "perl",
                    "ruby", "/awk", "/env", "/man", "/wget", "/curl", "/gcc", "/gdb", "/strace"))]
    hint("hoch" if interessant else "info", "SUID-Binaerdateien",
         f"{len(suid)} SUID; interessant: {interessant or 'keine'}")
    # Capabilities
    caps = run(["getcap", "-r", "/", "/usr/bin", "/bin"], timeout=20)
    hint("mittel" if caps and "n/a" not in caps and caps.strip() else "info",
         "Capabilities", caps[:600] or "keine/kein getcap")
    # Cron
    cron = run(["cat", "/etc/crontab"]) + "\n" + run(["ls", "-la", "/etc/cron.d/"]) + "\n" + run(["crontab", "-l"])
    schreibbar_cron = " (manuell: ls -l auf Cron-Skripte, schreibbar?)" 
    hint("mittel" if ".sh" in cron or "/" in cron else "info", "Cron-Jobs", (cron[:600] + schreibbar_cron))
    # PATH beschreibbar
    schreibbar = []
    for d in os.environ.get("PATH", "").split(":"):
        if d and Path(d).exists() and os.access(d, os.W_OK):
            schreibbar.append(d)
    hint("hoch" if schreibbar else "info", "Beschreibbare PATH-Dirs", str(schreibbar or "keine"))
    # Docker
    docker = run(["id"]) + run(["ls", "-la", "/var/run/docker.sock"])
    if "docker" in docker:
        hint("hoch", "Docker-Gruppe/Socket", "Docker-Mitgliedschaft oder Socket -> Container-Escape-Pfad pruefen (GTFOBins, kein Exploit hier)")
    else:
        hint("info", "Docker", "kein Docker-Hinweis")
    # NFS / Sudo-Version / SSH-Keys
    hint("info", "NFS/Exports", run(["cat", "/etc/exports"]) or "keine exports")
    hint("info", "Sudo-Version", run(["sudo", "--version"]).splitlines()[0] if "n/a" not in run(["sudo", "--version"]) else "n/a")
    keys = run(["ls", "-la", "~/.ssh/"]) + run(["ls", "-la", "/home"])
    hint("info", "SSH-Keys/Home-Uebersicht", keys[:400])
    # History-Secrets nur zaehlen, nicht dumpen
    n_secrets = 0
    for hf in list(Path.home().glob(".bash_history")) + list(Path.home().glob(".zsh_history")):
        try:
            txt = hf.read_text(errors="ignore")
            n_secrets += sum(1 for w in ("password", "passwd", "token", "secret", "api_key", "mysql", "sshpass") if w in txt.lower())
        except Exception:
            pass
    hint("mittel" if n_secrets else "info", "History-Secrets (nur Zaehler)",
         f"{n_secrets} Keyword-Treffer in Shell-History (Details manuell mit less pruefen, nicht kopieren)")
    # Root-Prozesse Stichprobe
    procs = run(["ps", "aux"])
    root_procs = [l for l in procs.splitlines() if l.split() and "root" in l.split()[0]][:8]
    hint("info", "Root-Prozesse (Stichprobe)", "; ".join(root_procs)[:500])

    order = {"hoch": 0, "mittel": 1, "info": 2}
    hints.sort(key=lambda x: order.get(x["stufe"], 9))
    print(f"[*] {len(hints)} Checks, {sum(1 for h in hints if h['stufe']=='hoch')} hoch")
    for h in hints:
        print(f"  [{h['stufe'].upper():6s}] {h['titel']}: {h['detail'][:180]}")
    print("[*] Hinweis: Das sind nur Pruefpfade (GTFOBins/Manual). Keine Auto-Exploits - bewusst.")
    if a.out:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "privesc.json").write_text(json.dumps(
            {"zeit": datetime.now(timezone.utc).isoformat(), "hints": hints}, indent=2, ensure_ascii=False), encoding="utf-8")
        md = ["# PrivEsc-Hints", ""]
        for h in hints:
            md += [f"## [{h['stufe'].upper()}] {h['titel']}", h["detail"], ""]
        (out / "privesc.md").write_text("\n".join(md), encoding="utf-8")
        print(f"[+] {out}/privesc.json + privesc.md")


if __name__ == "__main__":
    main()
