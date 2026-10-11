#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 27_usb_detector.py
"""USB-Detector - Erkennt USB-Geraete & neue Block-Devices (defensiv).

Nur lesend via lsusb / /sys/bus/usb. Baseline-Vergleich meldet neue Geraete.
Verwendung: --init Baseline speichern, --check auf neue Geraete pruefen.
"""
import argparse
import json
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


ETHIK = "Nur eigene Rechner ueberwachen; keine Geraete blockieren/umgehen."
BASE_DEFAULT = "usb_baseline.json"


def per_lsusb():
    try:
        r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return sorted(r.stdout.splitlines())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def per_sysfs():
    ger = []
    for p in Path("/sys/bus/usb/devices").glob("*-*"):
        try:
            prod = (p / "product").read_text().strip()
            manu = (p / "manufacturer").read_text().strip() if (p / "manufacturer").exists() else "?"
            ger.append(f"{p.name}: {manu} {prod}")
        except OSError:
            continue
    return sorted(ger)


def block_devices():
    ger = []
    for p in Path("/sys/block").iterdir():
        if (p / "removable").exists():
            try:
                if (p / "removable").read_text().strip() == "1":
                    ger.append(p.name)
            except OSError:
                continue
    return sorted(ger)


def snapshot():
    return {"usb": per_lsusb() or per_sysfs(), "removable_block": block_devices()}


def main():
    p = argparse.ArgumentParser(description="USB-Geraete erkennen & loggen.")
    p.add_argument("--init", action="store_true")
    p.add_argument("--check", action="store_true")
    p.add_argument("-b", "--baseline", default=BASE_DEFAULT)
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("27_usb_detector.py", a)
    except Exception:
        pass
    if a.init:
        Path(a.baseline).write_text(json.dumps(snapshot(), indent=2), encoding="utf-8")
        print(f"[+] Baseline gespeichert: {a.baseline}")
        report = {
            "tool": "27_usb_detector",
            "modus": "init",
            "zeit": datetime.now().isoformat(),
            "baseline": a.baseline,
            "befunde": snapshot(),
        }
    elif a.check:
        alt = set(json.loads(Path(a.baseline).read_text(encoding="utf-8"))["usb"])
        neu = snapshot()
        diff = set(neu["usb"]) - alt
        print(f"[+] USB gesamt: {len(neu['usb'])}, neu: {len(diff)}")
        for d in sorted(diff):
            print(f"  [NEU] {d}")
        print(f"  Wechsel-Datentraeger: {', '.join(neu['removable_block']) or '-'}")
        report = {
            "tool": "27_usb_detector",
            "modus": "check",
            "zeit": datetime.now().isoformat(),
            "baseline": a.baseline,
            "anzahl_gesamt": len(neu["usb"]),
            "anzahl_neu": len(diff),
            "neu": sorted(diff),
            "removable_block": neu["removable_block"],
        }
    else:
        _snap = snapshot()
        for z in _snap["usb"]:
            print(z)
        report = {
            "tool": "27_usb_detector",
            "modus": "list",
            "zeit": datetime.now().isoformat(),
            "anzahl": len(_snap["usb"]),
            "befunde": _snap,
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
                    _zeilen = [f"# {report['tool']} ({report['modus']})", f"Zeit: {report['zeit']}", ""]
                    _zeilen += [f"- {x}" for x in report.get("neu", report.get("befunde", {}).get("usb", []) if isinstance(report.get("befunde"), dict) else [])] or ["- Keine neuen Geraete."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
