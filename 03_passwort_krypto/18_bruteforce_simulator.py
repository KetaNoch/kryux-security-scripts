#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 18_bruteforce_simulator.py
"""KRYUX // SECURITY SUITE v3.0 – 18_bruteforce_simulator.py
Login-Hardening-Auditor (echt, lesend) + Rate-Limit-Simulation (Lernmodus).
Standard: prueft reale System-Konfiguration (PAM faillock, pwquality, SSH
MaxAuthTries/LoginGraceTime/PasswordAuthentication) und vergibt Score.
--simulate: faehrt zusaetzlich lokale Dummy-Simulation (kein Netz, kein Angriff).
Verwendung: python3 18_bruteforce_simulator.py [--simulate --versuche 20 --max-fails 5]
"""
import argparse
import json
import re
import time
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


def _read(pfad: str) -> str:
    try:
        return Path(pfad).read_text(errors="ignore")
    except OSError:
        return ""


def audit() -> dict:
    """Sammelt reale Lockout/Rate-Limit-Einstellungen, rein lesend."""
    befunde = []

    def add(name, ok, detail, schwere="mittel"):
        befunde.append({"check": name, "ok": bool(ok), "detail": detail[:250],
                        "schwere": "info" if ok else schwere})

    pam = _read("/etc/pam.d/common-auth") + _read("/etc/pam.d/system-auth") + _read("/etc/pam.d/sshd")
    faillock = "faillock" in pam or "pam_tally2" in pam
    add("PAM-Lockout (faillock/tally2)", faillock,
        "faillock/tally2 in PAM gefunden" if faillock else "kein PAM-Lockout gefunden (pam_faillock einrichten)", "hoch")
    deny = re.findall(r"deny\s*=\s*(\d+)", pam)
    add("PAM deny-Schwelle gesetzt", bool(deny), f"deny={deny[-1]}" if deny else "kein deny= in PAM", "mittel")
    unlock = re.findall(r"unlock_time\s*=\s*(\d+)", pam)
    add("PAM unlock_time gesetzt", bool(unlock), f"unlock_time={unlock[-1]}s" if unlock else "kein unlock_time", "niedrig")
    pwq = _read("/etc/security/pwquality.conf")
    minlen = re.findall(r"(?m)^\s*minlen\s*=\s*(\d+)", pwq)
    add("pwquality minlen>=12", bool(minlen) and int(minlen[-1]) >= 12,
        f"minlen={minlen[-1]}" if minlen else "minlen nicht gesetzt", "mittel")
    ssh = _read("/etc/ssh/sshd_config")

    def ssh_opt(key):
        m = re.findall(rf"(?im)^\s*{key}\s+(\S+)", ssh)
        return m[-1] if m else "(default)"

    mat = ssh_opt("MaxAuthTries")
    add("SSH MaxAuthTries<=4", mat == "(default)" or (mat.isdigit() and int(mat) <= 4),
        f"MaxAuthTries {mat} (default 6, empfohlen <=4)", "mittel")
    lgt = ssh_opt("LoginGraceTime")
    add("SSH LoginGraceTime<=60s", lgt in ("(default)", "60", "30", "45", "1m"),
        f"LoginGraceTime {lgt}", "niedrig")
    add("SSH PasswordAuth/Key-only erwogen", True,
        f"PasswordAuthentication {ssh_opt('PasswordAuthentication')} (Key-Login + fail2ban empfohlen)", "info")
    fb = Path("/etc/fail2ban/jail.local").exists() or Path("/etc/fail2ban/jail.conf").exists()
    add("Fail2ban installiert", fb, "jail-Konfiguration vorhanden" if fb else "fail2ban fehlt (apt install fail2ban)", "mittel")
    score = 100
    for b in befunde:
        if not b["ok"]:
            score -= {"hoch": 20, "mittel": 10, "niedrig": 5}.get(b["schwere"], 5)
    return {"befunde": befunde, "score": max(0, score)}


class DummyLogin:
    """Lokale Rate-Limit-Simulation (Lernmodus, kein Netz)."""

    def __init__(self, max_fails: int = 5, sperrzeit: float = 5.0):
        self.max_fails = max_fails
        self.sperrzeit = sperrzeit
        self.fails = 0
        self.gesperrt_bis = 0.0

    def login(self, versuch: str) -> str:
        jetzt = time.time()
        if jetzt < self.gesperrt_bis:
            return f"LOCKED ({self.gesperrt_bis - jetzt:.1f}s verbleibend)"
        time.sleep(0.05)
        if versuch == "Geheim123!":
            self.fails = 0
            return "OK"
        self.fails += 1
        if self.fails >= self.max_fails:
            self.gesperrt_bis = jetzt + self.sperrzeit
            return "LOCKED (Limit erreicht)"
        return "FAIL"


def main() -> None:
    parser = argparse.ArgumentParser(description="KRYUX Login-Hardening-Audit (lesend) + Lern-Simulation.")
    parser.add_argument("--simulate", action="store_true", help="Zusaetzlich lokale Dummy-Simulation fahren")
    parser.add_argument("--versuche", type=int, default=20, help="Simulations-Versuche (nur mit --simulate)")
    parser.add_argument("--max-fails", type=int, default=5, help="Fails bis Lockout (Simulation)")
    parser.add_argument("--sperrzeit", type=float, default=5.0, help="Sperre in Sek. (Simulation)")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("18_bruteforce_simulator.py", args)
    except Exception:
        pass
    erg = audit()
    print(f"[KRYUX] Login-Hardening Score: {erg['score']}/100")
    for b in erg["befunde"]:
        print(f"  [{'OK' if b['ok'] else b['schwere'].upper()}] {b['check']}: {b['detail'][:140]}")
    sim = None
    if args.simulate:
        dienst = DummyLogin(args.max_fails, args.sperrzeit)
        fails = locks = 0
        start = time.perf_counter()
        for i in range(1, args.versuche + 1):
            ergebnis = dienst.login(f"falsch{i}")
            if ergebnis.startswith("LOCKED"):
                locks += 1
            else:
                fails += 1
        dauer = time.perf_counter() - start
        sim = {"versuche": args.versuche, "fails": fails, "locked": locks, "dauer_s": round(dauer, 2)}
        print(f"[KRYUX] Simulation: {fails} FAILs, {locks} LOCKEDs in {dauer:.2f}s — "
              "Rate-Limit + Lockout + Delay machen Bruteforce unpraktikabel.")
    report = {"tool": "18_login_hardening", "kryux": "v3.0",
              "zeit": datetime.now(timezone.utc).isoformat(),
              "score": erg["score"], "befunde": erg["befunde"], "simulation": sim}
    if getattr(args, "format", "text") == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    if getattr(args, "out", ""):
        try:
            Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[KRYUX] Report -> {args.out}")
        except OSError as e:
            print(f"[KRYUX] Report fehlgeschlagen: {e}")


if __name__ == "__main__":
    main()
