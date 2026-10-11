#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 28_permission_auditor.py
"""Permission-Auditor - World-writable, SUID/SGID, SSH-Rechte (defensiv).

Aendert nichts (read-only Audit). Nur eigene Pfade / mit Genehmigung.
Verwendung: python3 28_permission_auditor.py [-p /home/user /etc] [-o report.txt]
"""
import argparse
import json
import os
import stat
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


ETHIK = "Nur Audit, keine Rechte aendern; fremde Home-Verzeichnisse meiden."
SSH_SOLL = {".ssh": 0o700, "authorized_keys": 0o600, "id_rsa": 0o600, "config": 0o600}


def audit_pfad(root: Path, befunde: list):
    for verz, _, dateien in os.walk(root, onerror=lambda e: None):
        for n in dateien:
            f = Path(verz) / n
            try:
                st = f.lstat()
            except OSError:
                continue
            mode = stat.S_IMODE(st.st_mode)
            if mode & stat.S_IWOTH:
                befunde.append(f"[WW] world-writable: {f} ({oct(mode)})")
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                befunde.append(f"[SUID/SGID] {f} ({oct(mode)})")


def audit_ssh(befunde: list):
    ssh = Path.home() / ".ssh"
    if not ssh.exists():
        befunde.append("[SSH] ~/.ssh fehlt (ok, falls kein SSH genutzt wird)")
        return
    mode = stat.S_IMODE(ssh.stat().st_mode)
    if mode != 0o700:
        befunde.append(f"[SSH] ~/.ssh hat {oct(mode)} statt 0o700")
    for datei, soll in SSH_SOLL.items():
        if datei == ".ssh":
            continue
        f = ssh / datei
        if f.exists() and stat.S_IMODE(f.stat().st_mode) != soll:
            befunde.append(f"[SSH] {f} hat {oct(stat.S_IMODE(f.stat().st_mode))} statt {oct(soll)}")


def main():
    p = argparse.ArgumentParser(description="Dateirechte-Audit (nur lesend).")
    p.add_argument("-p", "--pfade", nargs="+", default=[str(Path.home())])
    p.add_argument("-o", "--output", default="perm_audit.txt")
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("28_permission_auditor.py", a)
    except Exception:
        pass
    befunde = [f"Hinweis: {ETHIK}"]
    for root in a.pfade:
        if Path(root).exists():
            audit_pfad(Path(root), befunde)
        else:
            befunde.append(f"[!] Pfad fehlt: {root}")
    audit_ssh(befunde)
    Path(a.output).write_text("\n".join(befunde) + "\n", encoding="utf-8")
    print(f"[+] {len(befunde)} Zeilen -> {a.output}")
    for b in befunde[:20]:
        print(f"  {b}")
    report = {
        "tool": "28_permission_auditor",
        "zeit": datetime.now().isoformat(),
        "pfade": a.pfade,
        "anzahl": len(befunde),
        "befunde": befunde,
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
                    _zeilen = [f"# {report['tool']}", f"Pfade: {', '.join(a.pfade)}", ""]
                    _zeilen += [f"- {x}" for x in befunde] or ["- Keine Befunde."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
