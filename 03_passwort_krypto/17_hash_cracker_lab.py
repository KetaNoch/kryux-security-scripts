#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 17_hash_cracker_lab.py
"""KRYUX // SECURITY SUITE v3.0 – 17_hash_cracker_lab.py
Hash-Audit NUR fuer eigene Hashes / mit schriftlicher Erlaubnis (defensiv).
Unterstuetzte Algos: md5, sha1, sha256, sha512, ntlm. Dictionary-Angriff mit
Tempo-Messung (H/s), pipelining-faehig via --yes, Report via --out/--format.
Verwendung: python3 17_hash_cracker_lab.py --hash <hex> --algo sha256 --wordlist liste.txt --yes
"""
import argparse
import hashlib
import json
import sys
import time
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

ALGOS = ("md5", "sha1", "sha256", "sha512", "ntlm")


def hash_wort(wort: str, algo: str) -> str:
    """Hasht ein Wort mit dem gewaehlten Algo (ntlm = MD4/UTF-16LE)."""
    if algo == "ntlm":
        try:
            return hashlib.new("md4", wort.encode("utf-16le")).hexdigest()
        except Exception:
            raise SystemExit("[KRYUX] NTLM braucht OpenSSL-MD4 (auf diesem System fehlt md4).")
    return hashlib.new(algo, wort.encode("utf-8")).hexdigest()


def cracke(ziel: str, algo: str, wortliste: Path, limit: int = 5_000_000):
    """Stromt die Wortliste, gibt (treffer|None, versuche, dauer_s) zurueck."""
    ziel_norm = ziel.strip().lower()
    versuche = 0
    start = time.perf_counter()
    with open(wortliste, encoding="utf-8", errors="ignore") as datei:
        for zeile in datei:
            wort = zeile.strip()
            if not wort:
                continue
            versuche += 1
            if versuche > limit:
                break
            if hash_wort(wort, algo) == ziel_norm:
                return wort, versuche, time.perf_counter() - start
    return None, versuche, time.perf_counter() - start


def main() -> None:
    """Einstiegspunkt: Consent-Flag, Woerterbuchlauf, Tempo + Report."""
    parser = argparse.ArgumentParser(description="KRYUX Dictionary-Audit nur am eigenen Hash.")
    parser.add_argument("--hash", required=True, help="Eigener Hash (Hex)")
    parser.add_argument("--wordlist", required=True, help="Pfad zur Wortliste (.txt)")
    parser.add_argument("--algo", default="sha256", choices=list(ALGOS), help="Hash-Algorithmus")
    parser.add_argument("--limit", type=int, default=5_000_000, help="Max. Kandidaten")
    parser.add_argument("--yes", action="store_true",
                        help="PFLICHT: bestaetigt eigenen Hash / schriftliche Erlaubnis (piping-faehig)")
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("17_hash_cracker_lab.py", args)
    except Exception:
        pass
    if not args.yes:
        print("[KRYUX] BLOCKIERT: --yes fehlt. Nur eigener Hash / mit Erlaubnis.", file=sys.stderr)
        raise SystemExit(2)
    wl = Path(args.wordlist)
    if not wl.exists():
        print(f"[KRYUX] Wortliste fehlt: {wl}", file=sys.stderr)
        raise SystemExit(2)
    treffer, versuche, dauer = cracke(args.hash, args.algo, wl, args.limit)
    tempo = versuche / dauer if dauer > 0 else 0
    report = {"tool": "17_hash_cracker_lab", "kryux": "v3.0", "algo": args.algo,
              "zeit": datetime.now(timezone.utc).isoformat(), "versuche": versuche,
              "dauer_s": round(dauer, 2), "h_s": round(tempo),
              "treffer": bool(treffer), "limit": args.limit}
    if treffer is None:
        print(f"[KRYUX] Kein Treffer nach {versuche} Versuchen in {dauer:.2f}s ({tempo:.0f} H/s).")
    else:
        print(f"[KRYUX] Treffer: '{treffer}' nach {versuche} Versuchen in {dauer:.2f}s.")
        report["klartext_laenge"] = len(treffer)
    print("[KRYUX] Lernziel: lange, einzigartige Passwoerter + Argon2/scrypt widerstehen Listen.")
    if getattr(args, "format", "text") == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    if getattr(args, "out", ""):
        try:
            Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[KRYUX] Report -> {args.out}", file=sys.stderr)
        except OSError as e:
            print(f"[KRYUX] Report fehlgeschlagen: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
