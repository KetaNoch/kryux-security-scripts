#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 22_system_info_collector.py
"""System-Info-Collector - Sammelt forensische Systembasisdaten (defensiv).

Nur fuer eigene Systeme / mit Einwilligung. Keine Veraenderung am System.
Verwendung: python3 22_system_info_collector.py [-o report.json] [--format json|txt]
"""
import argparse
import getpass
import json
import os
import platform
import shutil
import socket
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


ETHIK = "Nur eigene Systeme oder mit schriftlicher Genehmigung analysieren."


def sammle_netzwerk():
    infos = {"hostname": socket.gethostname(), "interfaces": []}
    try:
        out = os.popen("ip -o addr show 2>/dev/null || ifconfig 2>/dev/null").read()
        infos["roh"] = out[:2000]
    except Exception as e:  # noqa: BLE001
        infos["fehler"] = str(e)
    return infos


def sammle_system():
    mem, cpu = {}, {}
    try:
        with open("/proc/meminfo") as f:
            for z in f:
                if z.startswith(("MemTotal", "MemAvailable")):
                    k, v = z.split(":", 1)
                    mem[k.strip()] = v.strip()
    except OSError:
        mem["hinweis"] = "kein /proc (evtl. kein Linux)"
    try:
        with open("/proc/cpuinfo") as f:
            cpu["model"] = next((l.split(":", 1)[1].strip() for l in f if "model name" in l), "unbekannt")
    except OSError:
        cpu["model"] = platform.processor() or "unbekannt"
    try:
        import psutil  # optional

        mem["ram_%"] = psutil.virtual_memory().percent
        cpu["cpu_%"] = psutil.cpu_percent(interval=0.5)
    except ImportError:
        mem["ram_%"] = cpu["cpu_%"] = "psutil fehlt"
    return {
        "os": f"{platform.system()} {platform.release()}",
        "version": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "user": getpass.getuser(),
        "cpu": cpu,
        "ram": mem,
        "disk": shutil.disk_usage("/")._asdict(),
        "netz": sammle_netzwerk(),
        "ethik": ETHIK,
    }


def main():
    p = argparse.ArgumentParser(description="Sammelt Systembasisdaten als Report.")
    p.add_argument("-o", "--output", default="system_report.json")
    p.add_argument("--format", choices=["json", "txt"], default="json")
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("22_system_info_collector.py", a)
    except Exception:
        pass
    daten = sammle_system()
    if a.format == "json":
        with open(a.output, "w", encoding="utf-8") as f:
            json.dump(daten, f, indent=2, ensure_ascii=False)
    else:
        with open(a.output, "w", encoding="utf-8") as f:
            for k, v in daten.items():
                f.write(f"{k}: {v}\n")
    print(f"[+] Report gespeichert: {a.output}")
    report = {
        "tool": "22_system_info_collector",
        "target": daten.get("netz", {}).get("hostname", socket.gethostname()),
        "zeit": datetime.now().isoformat(),
        "befunde": daten,
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
                    _zeilen = [f"# {report['tool']}", f"Host: {report['target']}", f"Zeit: {report['zeit']}", ""]
                    _zeilen += [f"- {k}: {v}" for k, v in daten.items()]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
