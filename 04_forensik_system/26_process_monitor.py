#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 26_process_monitor.py
"""Process-Monitor - Prozess-Snapshot, CPU-Warnung, Pfadcheck (defensiv).

Beendet keine Prozesse, nur Beobachtung. Mit psutil-Fallback auf /proc.
Verwendung: python3 26_process_monitor.py [-o snapshot.json] [--cpu 80]
"""
import argparse
import json
import os
import sys
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


ETHIK = "Nur eigene Systeme ueberwachen; keine Prozesse manipulieren."
SYSTEM_PFADE = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")


def prozesse_psutil(cpu_limit):
    import psutil

    out = []
    for pr in psutil.process_iter(["pid", "name", "exe", "cpu_percent"]):
        try:
            info = pr.info
            info["warnung"] = (info.get("cpu_percent") or 0) > cpu_limit
            out.append(info)
        except Exception:  # noqa: BLE001
            continue
    return out


def prozesse_proc():
    out = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            name = (Path(f"/proc/{pid}/comm").read_text().strip())
            exe = os.readlink(f"/proc/{pid}/exe")
            out.append({"pid": int(pid), "name": name, "exe": exe,
                        "warnung": exe and not exe.startswith(SYSTEM_PFADE)})
        except OSError:
            continue
    return out


def main():
    p = argparse.ArgumentParser(description="Prozesse auflisten & verdaechtige melden.")
    p.add_argument("-o", "--output", default="proc_snapshot.json")
    p.add_argument("--cpu", type=int, default=80, help="CPU-Schwelle in Prozent")
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("26_process_monitor.py", a)
    except Exception:
        pass
    try:
        procs = prozesse_psutil(a.cpu)
        quelle = "psutil"
    except ImportError:
        if not Path("/proc").exists():
            print("[!] Weder psutil noch /proc verfuegbar.", file=sys.stderr)
            sys.exit(1)
        procs = prozesse_proc()
        quelle = "/proc"
    Path(a.output).write_text(json.dumps(procs, indent=2, default=str), encoding="utf-8")
    verd = [x for x in procs if x.get("warnung")]
    print(f"[+] {len(procs)} Prozesse ({quelle}), Snapshot: {a.output}")
    print(f"[!] Auffaellig: {len(verd)}")
    for v in verd[:15]:
        print(f"  PID {v.get('pid')} {v.get('name')} exe={v.get('exe')}")
    report = {
        "tool": "26_process_monitor",
        "zeit": datetime.now().isoformat(),
        "quelle": quelle,
        "anzahl_prozesse": len(procs),
        "anzahl_auffaellig": len(verd),
        "befunde": verd[:50],
    }
    try:
        _fmt = getattr(a, "format", "text")
        _out = getattr(a, "out", "") or ""
        if _fmt == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        if _out:
            try:
                _p = Path(_out)
                if _p.suffix.lower() == ".json":
                    _p.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
                else:
                    _zeilen = [f"# {report['tool']}", f"Prozesse: {len(procs)} ({quelle}), Auffaellig: {len(verd)}", ""]
                    _zeilen += [f"- PID {v.get('pid')} {v.get('name')} exe={v.get('exe')}" for v in verd[:20]] or ["- Keine Auffaelligkeiten."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
