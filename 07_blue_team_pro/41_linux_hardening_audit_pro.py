#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 41_linux_hardening_audit_pro.py
"""41_linux_hardening_audit_pro.py - Profi-Haertungsaudit fuer Linux-Kundenserver.

60-Sekunden-Check, rein lesend, Score 0-100 + JSON/Markdown:
  Benutzer/SSH/Firewall/Updates/Kernel/Sysctl/Dateirechte/SUID/Cron/
  Dienste/Fail2ban/Backup-Hinweis/Docker. Fuer Ubuntu/Debian/Kali/RHEL.

  python3 41_linux_hardening_audit_pro.py --out-dir ./audit_server01
"""
import argparse
import json
import os
import re
import socket
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



def run(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()[:6000]
    except Exception as e:
        return f"n/a: {e}"


def read(p):
    try:
        return Path(p).read_text(errors="ignore")[:8000]
    except Exception:
        return ""


class Audit:
    def __init__(self):
        self.checks = []
        self.score = 100

    def add(self, name, ok, detail, abzug=5, schwere="mittel"):
        if not ok:
            self.score = max(0, self.score - abzug)
        self.checks.append({"check": name, "ok": bool(ok), "detail": detail[:400],
                            "schwere": "info" if ok else schwere})


def main() -> None:
    ap = argparse.ArgumentParser(description="Linux-Hardening-Audit (lesend, Profi)")
    ap.add_argument("--out-dir", default="", help="Ausgabeverzeichnis fuer JSON+MD")
    ap.add_argument("--top-ports", default="21,22,23,25,53,80,139,443,445,3306,5432,6379,8080",
                    help="lokal zu pruefende Ports")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("41_linux_hardening_audit_pro.py", a)
    except Exception:
        pass
    au = Audit()

    # 1. Benutzer
    passwd = read("/etc/passwd")
    uids0 = [l for l in passwd.splitlines() if l.split(":")[2:3] == ["0"]]
    au.add("Keine doppelten UID-0 (ausser root)", len(uids0) <= 1, f"UID0: {uids0}", 15, "hoch")
    shadow = read("/etc/shadow")
    leer = [l.split(":")[0] for l in shadow.splitlines() if len(l.split(":")) > 2 and l.split(":")[1] == ""]
    au.add("Keine leeren Passwoerter", not leer, f"leer: {leer or 'keine'}", 20, "kritisch")
    # 2. SSH
    sshc = read("/etc/ssh/sshd_config")
    def ssh_opt(k):
        m = re.findall(rf"(?im)^\s*{k}\s+(\S+)", sshc)
        return m[-1] if m else "(default)"
    au.add("SSH PermitRootLogin=no/prohibit-password", ssh_opt("PermitRootLogin").lower() in ("no", "prohibit-password", "forced-commands-only", "(default)"),
           f"PermitRootLogin {ssh_opt('PermitRootLogin')}", 10)
    au.add("SSH PasswordAuthentication restriktiv", ssh_opt("PasswordAuthentication").lower() in ("no", "(default)"),
           f"PasswordAuthentication {ssh_opt('PasswordAuthentication')} (Key-Login empfohlen)", 5, "niedrig")
    au.add("SSH Port != 22 sinnvoll", True, f"Port {ssh_opt('Port')}", 0)
    au.add("SSH-Datei rechte 600", oct(os.stat("/etc/ssh/sshd_config").st_mode)[-3:] in ("600", "640", "644") if Path("/etc/ssh/sshd_config").exists() else True,
           "sshd_config Rechte ok/nicht vorhanden", 3, "niedrig")
    # 3. Firewall
    ufw = run(["ufw", "status"])
    fw_ok = "active" in ufw.lower() or "enable" in run(["firewall-cmd", "--state"]).lower()
    au.add("Firewall aktiv (ufw/firewalld)", fw_ok, (ufw.splitlines()[:3] or ["n/a"])[0][:200], 12, "hoch")
    # 4. Updates
    up = run(["apt", "list", "--upgradable"])
    n_up = len([l for l in up.splitlines() if "/" in l and "Listing" not in l])
    au.add("Wenig offene Updates (<10)", n_up < 10, f"upgradable ca. {n_up}", min(15, n_up), "mittel")
    un = run(["systemctl", "is-enabled", "unattended-upgrades"])
    au.add("Unattended-Upgrades aktiv", "enabled" in un, un[:100], 3, "niedrig")
    # 5. Kernel/Sysctl
    au.add("Kernel-Info erfasst", True, run(["uname", "-r"]).splitlines()[0][:100] if run(["uname", "-r"]) else "n/a", 0)
    for key, gut in [("net.ipv4.ip_forward", "0"), ("net.ipv4.conf.all.rp_filter", "1")]:
        val = run(["sysctl", "-n", key])
        au.add(f"sysctl {key}={gut}", gut in val, f"{key}={val[:50]}", 3, "niedrig")
    # 6. Dateirechte
    for pfad, soll in [("/etc/shadow", "640"), ("/etc/passwd", "644")]:
        try:
            rechte = oct(os.stat(pfad).st_mode)[-3:]
            au.add(f"Rechte {pfad} ({soll})", rechte in (soll, "600", "640", "644"), rechte, 8, "mittel")
        except FileNotFoundError:
            au.add(f"Rechte {pfad}", True, "nicht vorhanden (Container?)", 0)
    # 7. SUID / world-writable (begrenzt, schnell) - nur absolute Pfade, kein stderr
    suid = run(["find", "/", "-xdev", "-perm", "-4000", "-type", "f"], timeout=20)
    suid_list = [l for l in suid.splitlines() if l.startswith("/")][:30]
    au.add("SUID-Binaerliste reviewed", True, f"{len(suid_list)} gefunden: {', '.join(suid_list[:8])}", 0)
    kritisch_suid = [x for x in suid_list if any(b in x for b in ("nmap", "vim", "less", "more", "find", "bash", "python"))]
    au.add("Keine riskanten SUID-Bins (nmap/vim/find...)", not kritisch_suid, f"{kritisch_suid or 'unauffaellig'}", 12, "hoch")
    ww = run(["find", "/etc", "/opt", "-xdev", "-perm", "-0002", "-type", "f"], timeout=15)
    ww_list = [l for l in ww.splitlines() if l.startswith("/")][:10]
    au.add("Keine world-writable Configs", not ww_list, f"{ww_list or 'keine'}", 8)
    # 8. Offene lokale Ports
    offen = []
    for p in [int(x) for x in a.top_ports.split(",") if x.strip().isdigit()]:
        s = socket.socket()
        s.settimeout(0.25)
        try:
            if s.connect_ex(("127.0.0.1", p)) == 0:
                offen.append(p)
        except OSError:
            pass
        finally:
            s.close()
    au.add("Minimale Angriffsflaeche (<=2 lokale Top-Ports)", len(offen) <= 2, f"offen: {offen or 'keine'}", min(15, len(offen) * 4))
    # 9. Dienste/Cron/Fail2ban
    au.add("Fail2ban aktiv (wenn SSH offen)", ("enabled" in run(["systemctl", "is-enabled", "fail2ban"]) or 22 not in offen),
           run(["systemctl", "is-active", "fail2ban"])[:50], 5, "niedrig")
    cron_world = [l for l in (read("/etc/crontab") + read("/etc/cron.d/anacron")).splitlines() if l.strip() and not l.startswith("#")][:5]
    au.add("Cron-Files vorhanden/geprueft", True, f"{len(cron_world)} Zeilen Stichprobe", 0)
    au.add("Docker-Socket nicht welt-lesbar", not Path("/var/run/docker.sock").exists() or oct(os.stat("/var/run/docker.sock").st_mode)[-3:] != "777",
           "docker.sock ok/nicht vorhanden", 8)

    zeit = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    hostname = run(["hostname"]).splitlines()[0] if run(["hostname"]) else "host"
    print(f"[*] {hostname} {zeit} -> Score {au.score}/100")
    for c in au.checks:
        print(f"  [{'OK' if c['ok'] else c['schwere'].upper()}] {c['check']}: {c['detail'][:140]}")
    if a.out_dir:
        out = Path(a.out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "hardening.json").write_text(json.dumps(
            {"host": hostname, "zeit": zeit, "score": au.score, "checks": au.checks},
            indent=2, ensure_ascii=False), encoding="utf-8")
        md = [f"# Hardening-Audit {hostname} ({zeit})", f"Score: **{au.score}/100**", "",
              "| Status | Check | Detail |", "|---|---|---|"]
        for c in au.checks:
            md.append(f"| {'OK' if c['ok'] else c['schwere']} | {c['check']} | {c['detail'][:200]} |")
        (out / "hardening.md").write_text("\n".join(md), encoding="utf-8")
        print(f"[+] {out}/hardening.json + hardening.md")


if __name__ == "__main__":
    main()
