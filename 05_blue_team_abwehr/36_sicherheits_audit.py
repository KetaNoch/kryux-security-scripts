#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 36_sicherheits_audit.py
"""36_sicherheits_audit.py - Mini-Sicherheitsaudit für Linux (defensiv).

Prüft: offene Ports (via /proc/net/tcp), apt-Updates, UFW-Status,
Passwortrichtlinie (/etc/login.defs). Vergibt Score 0-100. Nur lesend!
"""
import argparse
import json
import socket
import subprocess
from datetime import datetime
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


ETHIK = "Nur lesende Checks auf eigenem System, keine Änderungen."


def offene_ports() -> list:
    """Liest lauschende Ports via socket (localhost-Connect-Test Top-Ports)."""
    offen = []
    for port in (21, 22, 23, 25, 53, 80, 139, 443, 445, 3306, 8080):
        s = socket.socket()
        s.settimeout(0.3)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                offen.append(port)
        except OSError:
            pass
        finally:
            s.close()
    return offen


def befehl(cmd: list) -> str:
    """Führt Befehl lesend aus, gibt Output oder Fehler zurück."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return (r.stdout + r.stderr)[:800]
    except (OSError, subprocess.SubprocessError) as e:
        return f"n/a: {e}"


def main() -> None:
    ap = argparse.ArgumentParser(description="Mini-Sicherheitsaudit (defensiv, lesend)")
    ap.add_argument("--report", default="", help="Optional Report-Datei")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("36_sicherheits_audit.py", a)
    except Exception:
        pass
    print(ETHIK)
    score, zeilen = 100, []
    ports = offene_ports()
    zeilen.append(f"Offene lokale Ports (Top-Check): {ports or 'keine'}")
    score -= min(30, len(ports) * 5)
    apt = befehl(["apt", "list", "--upgradable"])
    n_up = max(0, len([l for l in apt.splitlines() if "/" in l]) )
    zeilen.append(f"Aktualisierbare Pakete (apt): ca. {n_up}")
    score -= min(30, n_up * 2)
    ufw = befehl(["ufw", "status"])
    fw_ok = "active" in ufw.lower()
    zeilen.append(f"Firewall aktiv: {fw_ok}")
    score -= 0 if fw_ok else 20
    login_defs = Path("/etc/login.defs").read_text(errors="ignore") if Path("/etc/login.defs").exists() else ""
    pw_ok = "PASS_MAX_DAYS" in login_defs
    zeilen.append(f"Passwortrichtlinie gesetzt: {pw_ok}")
    score -= 0 if pw_ok else 10
    score = max(0, score)
    print("\n".join(f"  {z}" for z in zeilen))
    print(f"Gesamt-Score: {score}/100")
    if a.report:
        Path(a.report).write_text("\n".join(zeilen) + f"\nScore: {score}/100\n")
        print(f"[+] Report: {a.report}")
    report = {
        "tool": "36_sicherheits_audit",
        "zeit": datetime.now().isoformat(),
        "score": score,
        "offene_ports": ports,
        "paket_updates": n_up,
        "firewall_aktiv": fw_ok,
        "passwortrichtlinie_ok": pw_ok,
        "befunde": zeilen,
    }
    try:
        _fmt = getattr(a, "format", "text")
        _out = getattr(a, "out", "") or ""
        if _fmt == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False))
        if _out:
            try:
                _p = Path(_out)
                if _p.suffix.lower() == ".json":
                    _p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                else:
                    _zeilen = [f"# {report['tool']}", f"Score: {score}/100", ""]
                    _zeilen += [f"- {z}" for z in zeilen]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
