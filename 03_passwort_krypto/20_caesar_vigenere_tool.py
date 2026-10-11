#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 20_caesar_vigenere_tool.py
"""KRYUX // SECURITY SUITE v3.0 – 20_caesar_vigenere_tool.py
Klassische Chiffren: korrektes Caesar/Vigenere + Caesar-Cracker (Chi-Quadrat
gegen deutsche+englische Frequenzen) + Datei-Modus + Reports. NUR Lernen/CTF -
historisch gebrochen, NIEMALS echte Geheimnisse! Dafuer Skript 19 nutzen.
Verwendung: python3 20_caesar_vigenere_tool.py caesar --text HALLO --shift 3
             python3 20_caesar_vigenere_tool.py crack --text KRYYB --top 3
"""
import argparse
import json
import string
from datetime import datetime, timezone
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

# Referenzfrequenzen Englisch A-Z (Standard-Tabelle, Summe ~1.0)
REFERENZ = [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697, 0.0015,
            0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0009, 0.0599, 0.0633, 0.0906,
            0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007]
WORTBONUS = (" THE ", " AND ", " DER ", " DIE ", " UND ", "OVER", "QUICK", "BROWN", "FLAG", "THM", "HTB")


def caesar(text: str, shift: int) -> str:
    """Verschiebt Buchstaben um shift (entschluesseln mit -shift)."""
    ergebnis = []
    for zeichen in text:
        if zeichen.isalpha():
            basis = ord("A") if zeichen.isupper() else ord("a")
            ergebnis.append(chr((ord(zeichen) - basis + shift) % 26 + basis))
        else:
            ergebnis.append(zeichen)
    return "".join(ergebnis)


def chi_quadrat(text: str) -> float:
    """Bewertet Deutsch/Englisch-Aehnlichkeit (kleiner = besser).

    Lange Texte: Chi-Quadrat gegen Referenzfrequenzen. Kurze CTF-Texte (<10
    Buchstaben): Fallback ueber haeufige Substrings (DER/DIE/THE/AND/...).
    """
    buchstaben = [c.upper() for c in text if c.isalpha()]
    if len(buchstaben) >= 10:
        n = len(buchstaben)
        score = 0.0
        for i in range(26):
            beobachtet = sum(1 for c in buchstaben if ord(c) - 65 == i)
            erwartet = n * REFERENZ[i]
            score += (beobachtet - erwartet) ** 2 / (erwartet or 1)
        # Wort-Bonus: echte Woerter schlagen Pangram-Rauschen
        gepolstert = " " + "".join(buchstaben) + " "
        bonus = sum(12.0 for w in WORTBONUS if w.strip() in "".join(buchstaben) or w in gepolstert)
        return score - bonus
    oben = "".join(buchstaben)
    treffer = sum(oben.count(s) for s in
                  ("DER", "DIE", "UND", "THE", "AND", "ION", "EN", "ER", "CH", "EI", "OU", "TH"))
    return 50.0 - treffer * 10.0


def caesar_crack(text: str, top: int = 3) -> list:
    """Gibt Top-N Kandidaten (shift, klartext, score) nach Chi-Quadrat zurueck."""
    kandidaten = []
    for shift in range(26):
        klar = caesar(text, -shift)
        kandidaten.append({"shift": shift, "klartext": klar, "score": round(chi_quadrat(klar), 2)})
    kandidaten.sort(key=lambda k: k["score"])
    return kandidaten[:max(1, top)]


def vigenere(text: str, schluessel: str, decrypt: bool = False) -> str:
    """Vigenere-Ver-/Entschluesselung mit Schluesselwort (A=0 ... Z=25)."""
    if not schluessel.isalpha():
        raise SystemExit("[KRYUX] Schluesselwort nur A-Z.")
    schluessel = schluessel.upper()
    ergebnis, j = [], 0
    for zeichen in text:
        if zeichen.isalpha():
            offset = ord(schluessel[j % len(schluessel)]) - 65
            if decrypt:
                offset = -offset
            basis = ord("A") if zeichen.isupper() else ord("a")
            ergebnis.append(chr((ord(zeichen) - basis + offset) % 26 + basis))
            j += 1
        else:
            ergebnis.append(zeichen)
    return "".join(ergebnis)


def _eingabe(args) -> str:
    if getattr(args, "file", ""):
        p = Path(args.file)
        if not p.exists():
            raise SystemExit(f"[KRYUX] Datei fehlt: {p}")
        return p.read_text(errors="ignore")[:20000]
    return args.text


def main() -> None:
    """Einstiegspunkt: caesar/vigenere/crack + Datei-Modus + Report."""
    parser = argparse.ArgumentParser(description="KRYUX Klassische Chiffren (Lernen/CTF).")
    sub = parser.add_subparsers(dest="chiffre", required=True)
    c = sub.add_parser("caesar", help="Caesar ver-/entschluesseln")
    c.add_argument("--text", default="", help="Eigener Uebungstext")
    c.add_argument("--file", default="", help="Alternativ Textdatei (eigene!)")
    c.add_argument("--shift", type=int, default=3, help="Verschiebung")
    k = sub.add_parser("crack", help="Caesar-Cracker (Chi-Quadrat, eigener CTF-Text)")
    k.add_argument("--text", default="", help="Chiffretext")
    k.add_argument("--file", default="", help="Alternativ Datei")
    k.add_argument("--top", type=int, default=3, help="Top-N Kandidaten")
    v = sub.add_parser("vigenere", help="Vigenere ver-/entschluesseln")
    v.add_argument("--text", default="", help="Eigener Uebungstext")
    v.add_argument("--file", default="", help="Alternativ Datei")
    v.add_argument("--key", required=True, help="Schluesselwort (nur A-Z)")
    v.add_argument("--decrypt", action="store_true", help="Entschluesseln")
    for _sub in (c, k, v):  # Kryux-Flags auch nach Subcommand nutzbar
        _sub = _kryux_apply(_sub)
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("20_caesar_vigenere_tool.py", args)
    except Exception:
        pass
    report = {"tool": "20_klassik", "kryux": "v3.0",
              "zeit": datetime.now(timezone.utc).isoformat(), "modus": args.chiffre}
    if args.chiffre == "caesar":
        text = _eingabe(args) if (args.text or args.file) else (_ for _ in ()).throw(
            SystemExit("[KRYUX] --text oder --file angeben."))
        erg = caesar(text, args.shift)
        print(erg)
        report.update({"shift": args.shift, "ergebnis": erg[:2000], "laenge": len(text)})
    elif args.chiffre == "crack":
        text = _eingabe(args) if (args.text or args.file) else (_ for _ in ()).throw(
            SystemExit("[KRYUX] --text oder --file angeben."))
        kandidaten = caesar_crack(text, args.top)
        for kd in kandidaten:
            print(f"shift {kd['shift']:2d} (score {kd['score']:8.1f}): {kd['klartext'][:160]}")
        report.update({"kandidaten": kandidaten})
    else:
        text = _eingabe(args) if (args.text or args.file) else (_ for _ in ()).throw(
            SystemExit("[KRYUX] --text oder --file angeben."))
        erg = vigenere(text, args.key, args.decrypt)
        print(erg)
        report.update({"key_len": len(args.key), "decrypt": args.decrypt,
                       "ergebnis": erg[:2000], "laenge": len(text)})
    if getattr(args, "format", "text") == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    if getattr(args, "out", ""):
        try:
            Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[KRYUX] Report -> {args.out}")
        except OSError as e:
            print(f"[KRYUX] Report fehlgeschlagen: {e}")
    print(f"[KRYUX] Hinweis: Schul-Chiffren - gebrochen seit Jahrhunderten. "
          f"Alphabet: {string.ascii_uppercase[:8]}... (26 Zeichen)")


if __name__ == "__main__":
    main()
