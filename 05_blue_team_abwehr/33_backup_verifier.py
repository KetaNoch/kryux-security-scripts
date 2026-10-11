#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 33_backup_verifier.py
"""33_backup_verifier.py - Prüft Backup-Ordner (defensiv, lokal).

Checks: Existenz, Alter (max Stunden), Dateianzahl, SHA256-Vergleich
Quelle vs Backup. Schreibt Report. Keine Cloud, nur Standardlib.
"""
import argparse
import hashlib
import json
import time
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


ETHIK = "Defensiv: nur eigene Backup-Pfade prüfen, keine fremden Daten."


def sha256(pfad: Path) -> str:
    """SHA256 einer Datei."""
    h = hashlib.sha256()
    with pfad.open("rb") as f:
        for c in iter(lambda: f.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def sammle(pfad: Path) -> dict:
    """Mappt relativer Pfad -> Hash für alle Dateien."""
    out = {}
    for d in pfad.rglob("*"):
        if d.is_file():
            try:
                out[str(d.relative_to(pfad))] = sha256(d)
            except OSError:
                out[str(d.relative_to(pfad))] = "FEHLER"
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Backup-Verifier (defensiv)")
    ap.add_argument("--quelle", required=True, help="Quell-Ordner")
    ap.add_argument("--backup", required=True, help="Backup-Ordner")
    ap.add_argument("--max-alter-std", type=float, default=24, help="Max Backup-Alter Std.")
    ap.add_argument("--report", default="backup_report.txt", help="Report-Datei")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("33_backup_verifier.py", a)
    except Exception:
        pass

    q, b = Path(a.quelle), Path(a.backup)
    fehler = []
    alter_h = None
    fehlend, abweich = [], []
    n_q, n_b = 0, 0
    if not q.is_dir():
        fehler.append(f"Quelle fehlt: {q}")
    if not b.is_dir():
        fehler.append(f"Backup fehlt: {b}")
    alter_ok = True
    if b.is_dir():
        alter_h = (time.time() - b.stat().st_mtime) / 3600
        print(f"[+] Backup-Alter: {alter_h:.1f}h (Limit {a.max_alter_std}h)")
        alter_ok = alter_h <= a.max_alter_std
        if not alter_ok:
            fehler.append("Backup zu alt!")
    if not fehler:
        hq, hb = sammle(q), sammle(b)
        n_q, n_b = len(hq), len(hb)
        fehlend = sorted(set(hq) - set(hb))
        abweich = sorted(k for k in hq if k in hb and hq[k] != hb[k])
        fehler += [f"Fehlt: {x}" for x in fehlend]
        fehler += [f"Abweichender Hash: {x}" for x in abweich]
        print(f"[+] Quelle: {len(hq)}, Backup: {len(hb)}, fehlt: {len(fehlend)}, abweichend: {len(abweich)}")
    status = "OK" if not fehler else "FEHLER"
    bericht = f"Backup-Report: {status}\n{ETHIK}\nQuelle={q} Backup={b}\n"
    bericht += "\n".join(fehler) if fehler else "Alle Hashes stimmen überein.\n"
    Path(a.report).write_text(bericht + "\n")
    print(f"[{status}] Report: {a.report}")
    report = {
        "tool": "33_backup_verifier",
        "zeit": datetime.now().isoformat(),
        "quelle": str(q),
        "backup": str(b),
        "status": status,
        "alter_std": round(alter_h, 2) if alter_h is not None else None,
        "anzahl_quelle": n_q,
        "anzahl_backup": n_b,
        "fehlend": fehlend,
        "abweichend": abweich,
        "befunde": fehler,
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
                    _zeilen = [f"# {report['tool']}", f"Status: {status}", f"Quelle={q} Backup={b}", ""]
                    _zeilen += [f"- {x}" for x in fehler] or ["- Alle Hashes stimmen ueberein."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
