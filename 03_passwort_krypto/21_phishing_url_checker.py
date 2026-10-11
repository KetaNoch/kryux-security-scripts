#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 21_phishing_url_checker.py
"""21 - Phishing-URL-Checker (defensiv/edukativ).
Bewertet nur die URL-Form (Heuristik, keine Garantie). Links nicht oeffnen,
sondern bei Verdacht direkt beim Anbieter pruefen. Bildet niemanden an.
Verwendung: python3 21_phishing_url_checker.py --url "http://beispiel.de"
"""
import argparse  # Argumente parsen
import json
import re  # Muster fuer IP, @, Punycode suchen
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse  # URL in Bestandteile zerlegen

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


# Verdaechtige TLDs (Heuristik - auch legitime Seiten koennen sie nutzen)
VERDAECHTIGE_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov", ".ru"}


def pruefe_url(url: str) -> tuple[int, list[str]]:
    """Vergibt Risiko-Score (0-100) plus Gruende fuer die Einschaetzung."""
    gruende, score = [], 0  # Sammellisten initialisieren
    if not url.startswith(("http://", "https://")):  # Schema fehlt?
        url = "http://" + url  # Schema zum Parsen ergaenzen
    teile = urlparse(url)  # URL zerlegen (Schema, Host, Pfad ...)
    host = teile.hostname or ""  # Hostnamen holen (klein, ohne Port)
    # 1. Verschluesselung pruefen (+20 bei http)
    if teile.scheme == "http":  # Unverschluesseltes HTTP?
        score += 20  # Risiko erhoehen
        gruende.append("http statt https (unverschluesselt).")
    # 2. @-Zeichen deutet auf getarnte URL hin (+25)
    if "@" in url:  # Klammeraffe in URL?
        score += 25  # Deutlicher Risiko-Zuschlag
        gruende.append("'@' in URL lenkt oft auf fremden Host um.")
    # 3. IP statt Domain (+25)
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):  # IPv4-Muster?
        score += 25  # Risiko erhoehen
        gruende.append("IP-Adresse statt Domainname verwendet.")
    # 4. Punycode / IDN-Trick (+20)
    if "xn--" in host:  # Punycode-Praefix gefunden?
        score += 20  # Aehnlichkeits-Angriff moeglich
        gruende.append("Punycode (xn--) kann Zeichen vortaeuschen.")
    # 5. Zu viele Subdomains (+15 ab 4 Punkten)
    if host.count(".") >= 3:  # Viele Ebenen?
        score += 15  # Tarnung durch Subdomains moeglich
        gruende.append("Auffaellig viele Subdomain-Ebenen.")
    # 6. Verdaechtige TLD (+15)
    if any(host.endswith(tld) for tld in VERDAECHTIGE_TLDS):  # TLD-Check
        score += 15  # Risiko erhoehen
        gruende.append("TLD wird haeufig fuer Missbrauch genutzt.")
    # 7. Sehr lange URL (+10)
    if len(url) > 100:  # Ueberlange URL?
        score += 10  # Leichter Zuschlag
        gruende.append("Sehr lange URL (Verschleierung moeglich).")
    return min(score, 100), gruende  # Score auf 100 deckeln


def main() -> None:
    """Einstiegspunkt: URL pruefen und Ampel-Einschaetzung ausgeben."""
    parser = argparse.ArgumentParser(description="URL-Heuristik gegen Phishing.")
    parser.add_argument("--url", required=True, help="Zu pruefende URL (Textform)")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("21_phishing_url_checker.py", args)
    except Exception:
        pass  # Argumente auswerten
    score, gruende = pruefe_url(args.url)  # Pruefung durchfuehren
    print(f"URL: {args.url}")  # Gepruefte URL zeigen
    print(f"Risiko-Score: {score}/100")  # Score ausgeben
    if score >= 50:  # Hoher Wert
        print("Einschaetzung: HOCH - nicht oeffnen, getrennt verifizieren!")
    elif score >= 25:  # Mittlerer Wert
        print("Einschaetzung: MITTEL - vorsichtig, Absender pruefen.")
    else:  # Niedriger Wert
        print("Einschaetzung: NIEDRIG - trotzdem wachsam bleiben.")
    for grund in gruende or ["Keine Auffaelligkeiten gefunden."]:  # Gruende
        print(f"- {grund}")  # Jeden Grund ausgeben
    report = {
        "tool": "21_phishing_url_checker",
        "target": args.url,
        "zeit": datetime.now().isoformat(),
        "score": score,
        "einschaetzung": ("HOCH" if score >= 50 else "MITTEL" if score >= 25 else "NIEDRIG"),
        "befunde": gruende,
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
                    _zeilen = [f"# {report['tool']}", f"URL: {args.url}",
                               f"Risiko-Score: {score}/100 ({report['einschaetzung']})", ""]
                    _zeilen += [f"- {g}" for g in gruende] or ["- Keine Auffaelligkeiten."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()  # Skript nur bei direktem Aufruf starten
