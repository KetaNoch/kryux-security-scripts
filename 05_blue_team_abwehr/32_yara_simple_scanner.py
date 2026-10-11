#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 32_yara_simple_scanner.py
"""32_yara_simple_scanner.py - Simple YARA-ähnliche Signatursuche (defensiv).

Regel als JSON: {"name": "...", "strings": [...], "regex": [...], "hex": ["4d5a.."]}
Durchsucht Dateien nach Strings/Regex/Hex. Nur eigene Systeme scannen.
"""
import argparse
import binascii
import json
import re
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


ETHIK = "Defensiv: nur eigene Verzeichnisse mit Zustimmung scannen."


def lade_regel(pfad: Path) -> dict:
    """Lädt JSON-Regel mit keys: strings, regex, hex."""
    daten = json.loads(pfad.read_text(encoding="utf-8", errors="ignore"))
    return {"name": daten.get("name", pfad.stem), "strings": daten.get("strings", []),
            "regex": daten.get("regex", []), "hex": daten.get("hex", [])}


def pruefe_datei(pfad: Path, regel: dict) -> list:
    """Gibt Liste der Treffer zurück."""
    treffer = []
    try:
        roh = pfad.read_bytes()
        text = roh.decode("utf-8", errors="ignore")
    except OSError:
        return treffer
    for s in regel["strings"]:
        if s and s in text:
            treffer.append(f"string:{s}")
    for rx in regel["regex"]:
        try:
            if rx and re.search(rx, text):
                treffer.append(f"regex:{rx}")
        except re.error:
            continue
    hexblob = binascii.hexlify(roh).decode().lower()
    for hx in regel["hex"]:
        muster = hx.lower().replace(" ", "")
        rx = muster.replace("..", ".").replace("??", ".")
        rx = rx.replace(".", r"[0-9a-f]{2}")
        if re.search(rx, hexblob):
            treffer.append(f"hex:{hx}")
    return treffer


def main() -> None:
    ap = argparse.ArgumentParser(description="Simpler Signatur-Scanner (defensiv)")
    ap.add_argument("--regel", required=True, help="JSON-Regeldatei")
    ap.add_argument("--pfad", required=True, help="Datei oder Ordner zum Scannen")
    ap.add_argument("--max-bytes", type=int, default=5_000_000, help="Max Dateigröße")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("32_yara_simple_scanner.py", a)
    except Exception:
        pass

    regel = lade_regel(Path(a.regel))
    ziel = Path(a.pfad)
    dateien = [ziel] if ziel.is_file() else list(ziel.rglob("*")) if ziel.is_dir() else []
    print(f"[+] Regel '{regel['name']}'. {ETHIK}")
    hits = 0
    hits_detail = []
    for d in dateien:
        if d.is_file():
            try:
                if d.stat().st_size > a.max_bytes:
                    continue
            except OSError:
                continue
            t = pruefe_datei(d, regel)
            if t:
                hits += 1
                hits_detail.append({"datei": str(d), "treffer": t})
                print(f"[!] {d}: {', '.join(t)}")
    print(f"[+] Fertig: {len(dateien)} Objekte, {hits} Treffer.")
    report = {
        "tool": "32_yara_simple_scanner",
        "target": str(ziel),
        "zeit": datetime.now().isoformat(),
        "regel": regel.get("name", ""),
        "objekte": len(dateien),
        "anzahl_treffer": hits,
        "befunde": hits_detail,
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
                    _zeilen = [f"# {report['tool']}", f"Regel: {report['regel']}, Objekte: {len(dateien)}, Treffer: {hits}", ""]
                    _zeilen += [f"- {h['datei']}: {', '.join(h['treffer'])}" for h in hits_detail] or ["- Keine Treffer."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
