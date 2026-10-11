#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 23_file_integrity_monitor.py
"""File-Integrity-Monitor - SHA256-Baseline & Veraenderungspruefung (defensiv).

Nur eigene Verzeichnisse ueberwachen. Liest Dateien nur zum Hashen.
Verwendung: init:  ... --init -p /etc/meinapp -b baseline.json
             check: ... --check -b baseline.json
"""
import argparse
import hashlib
import json
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


ETHIK = "Nur eigene Verzeichnisse pruefen, keine fremden Daten kopieren."


def sha256_von(pfad: Path) -> str:
    h = hashlib.sha256()
    with pfad.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline_erstellen(pfade, ausgabe):
    base = {}
    for p in pfade:
        root = Path(p)
        if not root.exists():
            print(f"[!] Pfad fehlt: {root}", file=sys.stderr)
            continue
        files = [root] if root.is_file() else list(root.rglob("*"))
        for f in files:
            if f.is_file() and not f.is_symlink():
                try:
                    base[str(f)] = sha256_von(f)
                except OSError as e:
                    print(f"[!] {f}: {e}", file=sys.stderr)
    Path(ausgabe).write_text(json.dumps(base, indent=2), encoding="utf-8")
    print(f"[+] Baseline: {len(base)} Dateien -> {ausgabe}")
    return len(base)


def baseline_pruefen(baseline_datei):
    base = json.loads(Path(baseline_datei).read_text(encoding="utf-8"))
    geaendert, geloescht, neu = [], [], []
    aktuell = {}
    for datei in base:
        p = Path(datei)
        if not p.exists():
            geloescht.append(datei)
            continue
        try:
            aktuell[datei] = sha256_von(p)
            if aktuell[datei] != base[datei]:
                geaendert.append(datei)
        except OSError:
            geloescht.append(datei)
    print(f"Geaendert: {len(geaendert)}, Geloescht: {len(geloescht)}")
    for d in geaendert:
        print(f"  [M] {d}")
    for d in geloescht:
        print(f"  [D] {d}")
    return geaendert, geloescht


def main():
    p = argparse.ArgumentParser(description="Dateiintegritaet per SHA256 ueberwachen.")
    p.add_argument("--init", action="store_true", help="Baseline erstellen")
    p.add_argument("--check", action="store_true", help="Baseline pruefen")
    p.add_argument("-p", "--pfade", nargs="+", default=["."])
    p.add_argument("-b", "--baseline", default="baseline.json")
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("23_file_integrity_monitor.py", a)
    except Exception:
        pass
    if a.init:
        _n = baseline_erstellen(a.pfade, a.baseline) or 0
        report = {
            "tool": "23_file_integrity_monitor",
            "modus": "init",
            "zeit": datetime.now().isoformat(),
            "baseline": a.baseline,
            "dateien": _n,
            "geaendert": [],
            "geloescht": [],
        }
    elif a.check:
        geaendert, geloescht = baseline_pruefen(a.baseline)
        report = {
            "tool": "23_file_integrity_monitor",
            "modus": "check",
            "zeit": datetime.now().isoformat(),
            "baseline": a.baseline,
            "geaendert": geaendert,
            "geloescht": geloescht,
            "anzahl_geaendert": len(geaendert),
            "anzahl_geloescht": len(geloescht),
        }
    else:
        p.error("Bitte --init oder --check angeben.")
        return
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
                    _zeilen = [f"# {report['tool']} ({report['modus']})", f"Baseline: {report['baseline']}", ""]
                    _zeilen += [f"- [M] {x}" for x in report.get("geaendert", [])]
                    _zeilen += [f"- [D] {x}" for x in report.get("geloescht", [])] or ["- Keine Abweichungen."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
