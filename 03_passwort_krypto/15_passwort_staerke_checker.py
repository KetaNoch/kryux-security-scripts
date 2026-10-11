#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 15_passwort_staerke_checker.py
"""15 - Passwort-Staerke-Checker (defensiv/edukativ).
Nur zur Pruefung eigener Passwoerter. Keine Angriffe auf fremde Konten.
Verwendung: python3 15_passwort_staerke_checker.py --passwort "MeinPasswort123!"
"""
import argparse  # Kommandozeilen-Argumente auswerten
import json
import math  # Logarithmus fuer Entropie-Berechnung
import re  # Pruefung der Zeichenklassen per Regex
import string  # Definition der Zeichenmengen
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


# Kleiner Auszug der Top-100-Liste (haeufigste Passwoerter, edukativ)
TOP_PASSWOERTER = [
    "123456", "password", "123456789", "qwerty", "12345678",
    "12345", "1234567", "1234567890", "letmein", "welcome",
    "admin", "monkey", "dragon", "123123", "password1",
    "qwerty123", "abc123", "passwort", "hallo123", "sommer2024",
]


def berechne_pool(passwort: str) -> int:
    """Bestimmt die Groesse des Zeichenvorrats (Pool)."""
    pool = 0  # Startwert fuer Zeichenvorrat
    if re.search(r"[a-z]", passwort):  # Kleinbuchstaben vorhanden?
        pool += 26  # 26 Kleinbuchstaben addieren
    if re.search(r"[A-Z]", passwort):  # Grossbuchstaben vorhanden?
        pool += 26  # 26 Grossbuchstaben addieren
    if re.search(r"[0-9]", passwort):  # Ziffern vorhanden?
        pool += 10  # 10 Ziffern addieren
    if re.search(r"[^a-zA-Z0-9]", passwort):  # Sonderzeichen?
        pool += 32  # ca. 32 Sonderzeichen annehmen
    return max(pool, 1)  # Division durch Null vermeiden


def bewerte(passwort: str) -> tuple[int, list[str]]:
    """Berechnet Score (0-100) und sammelt Verbesserungs-Tipps."""
    tipps = []  # Liste fuer Hinweise an den Nutzer
    score = 0  # Startpunktzahl
    laenge = len(passwort)  # Passwortlaenge bestimmen
    # Laenge bewerten (max. 40 Punkte)
    score += min(laenge * 4, 40)  # 4 Punkte je Zeichen, gedeckelt
    if laenge < 12:  # Mindestlaenge unterschritten?
        tipps.append("Nutze mindestens 12 Zeichen (besser 16+).")
    # Zeichenklassen zaehlen (max. 30 Punkte)
    klassen = sum(bool(re.search(p, passwort)) for p in
                  [r"[a-z]", r"[A-Z]", r"[0-9]", r"[^a-zA-Z0-9]"])
    score += klassen * 7 + (2 if klassen == 4 else 0)  # Bonus bei allen 4
    if klassen < 3:  # Zu wenige Klassen?
        tipps.append("Kombiniere Gross-/Kleinbuchstaben, Zahlen, Sonderzeichen.")
    # Entropie schaetzen (max. 30 Punkte)
    pool = berechne_pool(passwort)  # Zeichenvorrat ermitteln
    entropie = laenge * math.log2(pool)  # Entropie = L * log2(Pool)
    score += min(int(entropie / 4), 30)  # Entropie-Anteil deckeln
    if entropie < 60:  # Schwellenwert fuer starke Passwoerter
        tipps.append(f"Entropie nur {entropie:.1f} Bit - laenger/zufaelliger waehlen.")
    # Top-Liste pruefen (harter Abzug)
    if passwort.lower() in TOP_PASSWOERTER:  # Sehr haeufiges Passwort?
        score = min(score, 10)  # Score stark begrenzen
        tipps.append("Passwort steht in Top-Liste - unbedingt vermeiden!")
    return min(score, 100), tipps  # Score auf 100 deckeln


def main() -> None:
    """Einstiegspunkt: Argumente parsen und Bewertung ausgeben."""
    parser = argparse.ArgumentParser(description="Prueft Staerke eigener Passwoerter.")
    parser.add_argument("--passwort", required=True, help="Eigenes Passwort zum Pruefen")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("15_passwort_staerke_checker.py", args)
    except Exception:
        pass  # Argumente auswerten
    score, tipps = bewerte(args.passwort)  # Bewertung durchfuehren
    pool = berechne_pool(args.passwort)  # Pool fuer Anzeige berechnen
    entropie = len(args.passwort) * math.log2(pool)  # Entropie erneut berechnen
    print(f"Laenge: {len(args.passwort)} | Pool: {pool} | Entropie: {entropie:.1f} Bit")
    print(f"Score: {score}/100")  # Ergebnis ausgeben
    if score >= 80:  # Bewertung einordnen
        print("Einschaetzung: stark")  # Starkes Passwort
    elif score >= 50:  # Mittlerer Bereich
        print("Einschaetzung: mittel")  # Mittelmaessig
    else:  # Niedriger Score
        print("Einschaetzung: schwach")  # Schwach
    for tipp in tipps:  # Alle Tipps ausgeben
        print(f"- Tipp: {tipp}")  # Einzelnen Tipp zeigen
    report = {
        "tool": "15_passwort_staerke_checker",
        "target": "local-password-check",
        "zeit": datetime.now().isoformat(),
        "score": score,
        "entropie_bit": round(entropie, 1),
        "laenge": len(args.passwort),
        "einschaetzung": ("stark" if score >= 80 else "mittel" if score >= 50 else "schwach"),
        "tipps": tipps,
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
                    _zeilen = [f"# {report['tool']}", f"Score: {score}/100 ({report['einschaetzung']})",
                               f"Entropie: {report['entropie_bit']} Bit, Laenge: {report['laenge']}", ""]
                    _zeilen += [f"- {t}" for t in tipps] or ["- Keine Tipps."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()  # Skript nur bei direktem Aufruf starten
