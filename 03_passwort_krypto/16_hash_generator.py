#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 16_hash_generator.py
"""16 - Hash-Generator und Hash-Typ-Erkennung (defensiv/edukativ).
Erzeugt Hashes eigener Eingaben zu Lernzwecken. Kein Angriffswerkzeug.
Verwendung: python3 16_hash_generator.py --text "hallo" --identify <hash>
"""
import argparse  # Argumente parsen
import hashlib  # Hashfunktionen aus der Standardlib
import json
import secrets  # Sichere Zufallswerte fuer Salt
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



def erzeuge_hashes(text: str) -> dict:
    """Erzeugt MD5/SHA1/SHA256/SHA512 plus PBKDF2-Hash."""
    daten = text.encode("utf-8")  # Eingabe in Bytes umwandeln
    salt = secrets.token_hex(8)  # 8-Byte-Salt als Hex erzeugen
    # PBKDF2 als bcrypt-Ersatz (Standardlib, 100k Iterationen)
    pbkdf2 = hashlib.pbkdf2_hmac("sha256", daten, salt.encode(), 100_000)
    return {  # Alle Hashes als Dictionary zurueckgeben
        "MD5": hashlib.md5(daten).hexdigest(),  # 32 Hex-Zeichen
        "SHA1": hashlib.sha1(daten).hexdigest(),  # 40 Hex-Zeichen
        "SHA256": hashlib.sha256(daten).hexdigest(),  # 64 Hex-Zeichen
        "SHA512": hashlib.sha512(daten).hexdigest(),  # 128 Hex-Zeichen
        "PBKDF2-SHA256": f"{salt}${pbkdf2.hex()}",  # Salt$Hash-Format
    }


def identifiziere(hashwert: str) -> str:
    """Schaetzt den Hash-Typ anhand Laenge und Praefix."""
    h = hashwert.strip().lower()  # Leerzeichen entfernen, normieren
    if h.startswith("$2b$") or h.startswith("$2a$"):  # bcrypt-Praefix?
        return "bcrypt (Praefix $2b$/$2a$ erkannt)"  # Hinweis geben
    if "$" in h and len(h.split("$")) == 2:  # Eigenes PBKDF2-Format?
        return "PBKDF2 (Salt$Hash-Format)"  # Vermutung ausgeben
    laenge = len(h)  # Hex-Laenge bestimmen
    if laenge == 32:  # MD5 hat 128 Bit = 32 Hex-Zeichen
        return "vermutlich MD5 (32 Hex-Zeichen)"  # Hinweis
    if laenge == 40:  # SHA1 hat 160 Bit = 40 Hex-Zeichen
        return "vermutlich SHA1 (40 Hex-Zeichen)"  # Hinweis
    if laenge == 64:  # SHA256 hat 256 Bit = 64 Hex-Zeichen
        return "vermutlich SHA256 (64 Hex-Zeichen)"  # Hinweis
    if laenge == 128:  # SHA512 hat 512 Bit = 128 Hex-Zeichen
        return "vermutlich SHA512 (128 Hex-Zeichen)"  # Hinweis
    return "unbekannt (Laenge/Praefix passt nicht)"  # Fallback


def main() -> None:
    """Einstiegspunkt: Hashes erzeugen oder Hash-Typ identifizieren."""
    parser = argparse.ArgumentParser(description="Hash-Labor fuer eigene Daten.")
    parser.add_argument("--text", default="", help="Eigener Text zum Hashen")
    parser.add_argument("--identify", default="", help="Hashwert zur Typ-Erkennung")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("16_hash_generator.py", args)
    except Exception:
        pass  # Argumente auswerten
    if args.text:  # Text zum Hashen gegeben?
        hashes = erzeuge_hashes(args.text)  # Alle Hashes berechnen
        for name, wert in hashes.items():  # Jeden Hash ausgeben
            print(f"{name}: {wert}")  # Name und Wert zeigen
        print("Hinweis: MD5/SHA1 nur zu Lernzwecken, produktiv PBKDF2/bcrypt nutzen.")
    else:
        hashes = {}
    if args.identify:  # Hash zur Erkennung gegeben?
        typ = identifiziere(args.identify)  # Typ schaetzen
        print(f"Erkennung: {typ}")  # Ergebnis ausgeben
    else:
        typ = ""
    if not args.text and not args.identify:  # Keine Option gesetzt?
        parser.print_help()  # Hilfe anzeigen
    report = {
        "tool": "16_hash_generator",
        "zeit": datetime.now().isoformat(),
        "input_len": len(args.text) if args.text else 0,
        "hashes": hashes,
        "identify_len": len(args.identify) if args.identify else 0,
        "erkennung": typ,
    }
    try:
        _fmt = getattr(args, "format", "text")
        _out = getattr(args, "out", "") or ""
        if _fmt == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False))
        if _out:
            try:
                _p = Path(_out)
                if _p.suffix.lower() == ".json":
                    _p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                else:
                    _zeilen = [f"# {report['tool']}", f"Erkennung: {typ or '-'}", ""]
                    _zeilen += [f"- {k}: {v}" for k, v in hashes.items()] or ["- Keine Hashes erzeugt."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()  # Skript nur bei direktem Aufruf starten
