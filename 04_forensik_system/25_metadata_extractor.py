#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 25_metadata_extractor.py
"""Metadata-Extractor - Datei-Metadaten, JPEG-Marker & PDF-Author (defensiv).

Aendert keine Dateien, liest nur. Pillow-frei via struct/Regex.
Verwendung: python3 25_metadata_extractor.py -f bild.jpg / dok.pdf
"""
import argparse
import json
import re
import struct
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


ETHIK = "Nur eigene Dateien analysieren; Metadaten koennen privat sein."
PDF_RE = {"Author": re.compile(rb"/Author\s*\((.*?)\)"), "Title": re.compile(rb"/Title\s*\((.*?)\)"),
          "Producer": re.compile(rb"/Producer\s*\((.*?)\)")}


def basis_meta(pfad: Path) -> dict:
    st = pfad.stat()
    return {"datei": str(pfad), "groesse_bytes": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "ctime": datetime.fromtimestamp(st.st_ctime).isoformat(),
            "endung": pfad.suffix.lower()}


def jpeg_marker(pfad: Path) -> list:
    """Parst JPEG-Marker (SOI/APPn/COM) ohne Pillow, gibt Markerliste zurueck."""
    marker = []
    try:
        data = pfad.read_bytes()[:65536]
        if data[:2] != b"\xff\xd8":
            return ["kein JPEG (SOI fehlt)"]
        i = 2
        while i + 4 < len(data):
            if data[i] != 0xFF:
                break
            code = data[i + 1]
            if code in (0xD8, 0xD9) or 0xD0 <= code <= 0xD7:
                marker.append(f"FF {code:02X} (stand-alone)")
                i += 2
                continue
            (laenge,) = struct.unpack(">H", data[i + 2:i + 4])
            name = "APP" + str(code - 0xE0) if 0xE0 <= code <= 0xEF else f"{code:02X}"
            marker.append(f"FF {code:02X} ({name}), Laenge {laenge}")
            i += 2 + laenge
            if len(marker) > 20:
                break
    except OSError as e:
        marker.append(f"Fehler: {e}")
    return marker


def pdf_meta(pfad: Path) -> dict:
    try:
        roh = pfad.read_bytes()[:200000]
    except OSError as e:
        return {"fehler": str(e)}
    out = {}
    for k, rx in PDF_RE.items():
        m = rx.search(roh)
        out[k] = m.group(1).decode("latin-1", "replace") if m else "-"
    return out


def main():
    p = argparse.ArgumentParser(description="Metadaten extrahieren (read-only).")
    p.add_argument("-f", "--files", nargs="+", required=True)
    p = _kryux_apply(p)
    a = p.parse_args()
    try:
        _kryux_banner("25_metadata_extractor.py", a)
    except Exception:
        pass
    _funde = []
    for name in a.files:
        pfad = Path(name)
        if not pfad.is_file():
            print(f"[!] Fehlt: {name}", file=sys.stderr)
            continue
        meta = basis_meta(pfad)
        print(f"\n== {meta['datei']} ({meta['groesse_bytes']} B, mtime {meta['mtime']})")
        extra = {}
        if meta["endung"] in (".jpg", ".jpeg"):
            extra["jpeg_marker"] = jpeg_marker(pfad)
            for m in extra["jpeg_marker"]:
                print(f"  JPEG: {m}")
        elif meta["endung"] == ".pdf":
            extra["pdf"] = pdf_meta(pfad)
            for k, v in extra["pdf"].items():
                print(f"  PDF-{k}: {v}")
        else:
            print("  (Kein Spezialparser fuer diesen Typ)")
        _funde.append({**meta, **extra})
    report = {
        "tool": "25_metadata_extractor",
        "zeit": datetime.now().isoformat(),
        "dateien": a.files,
        "anzahl": len(_funde),
        "befunde": _funde,
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
                    _zeilen = [f"# {report['tool']}", f"Dateien: {len(_funde)}", ""]
                    _zeilen += [f"- {m.get('datei')}: {m.get('groesse_bytes')} B" for m in _funde] or ["- Keine Dateien."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
