#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 19_aes_file_encryptor.py
"""KRYUX // SECURITY SUITE v3.0 – 19_aes_file_encryptor.py
Datei-Verschluessler mit PBKDF2-HMAC-SHA256 (600k Runden) + Fernet/AES-128-CBC+HMAC.
Erfordert 'cryptography' (kein unsicherer Fallback!): pip install cryptography.
Chunked-Streaming fuer grosse Dateien, Salt+Iterationen im Header, Meta-Report.
Nur eigene Dateien! Backup behalten. Falsches Passwort -> klare Fehlermeldung.
Verwendung: python3 19_aes_file_encryptor.py encrypt --in a.txt --out a.enc --passwort <pw>
"""
import argparse
import base64
import getpass
import hashlib
import json
import secrets
import sys
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

try:
    from cryptography.fernet import Fernet, InvalidToken
    HAT_FERNET = True
except ImportError:
    HAT_FERNET = False

ITERATIONEN = 600_000
CHUNK = 64 * 1024 * 1024  # 64 MiB Bloecke (RAM-schonend)


def leite_schluessel(passwort: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 -> Fernet-kompatibler Key (-base64)."""
    roh = hashlib.pbkdf2_hmac("sha256", passwort.encode(), salt, ITERATIONEN)
    return base64.urlsafe_b64encode(roh)


def _passwort(args) -> str:
    pw = getattr(args, "passwort", "")
    if pw:
        return pw
    try:
        return getpass.getpass("KRYUX Passwort: ")
    except Exception:
        raise SystemExit("[KRYUX] Kein Passwort (Tipp: --passwort oder interaktiv).")


def verschluesseln(quelle: str, ziel: str, passwort: str) -> dict:
    """Liest chunkweise, verschluesselt pro Chunk, Header KRYUX1+salt+iter."""
    if not HAT_FERNET:
        raise SystemExit("[KRYUX] Paket 'cryptography' fehlt: pip install cryptography "
                         "(kein Fallback - unsichere Modi werden verweigert).")
    salt = secrets.token_bytes(16)
    fernet = Fernet(leite_schluessel(passwort, salt))
    q, z = Path(quelle), Path(ziel)
    if not q.exists():
        raise SystemExit(f"[KRYUX] Quelle fehlt: {q}")
    header = b"KRYUX1" + salt + ITERATIONEN.to_bytes(4, "big")
    bloecke, groesse = 0, 0
    with open(q, "rb") as fin, open(z, "wb") as fout:
        fout.write(base64.b64encode(header) + b"\n")
        while True:
            daten = fin.read(CHUNK)
            if not daten:
                break
            fout.write(base64.b64encode(fernet.encrypt(daten)) + b"\n")
            bloecke += 1
            groesse += len(daten)
    return {"modus": "encrypt", "quelle": str(q), "ziel": str(z), "bytes": groesse,
            "bloecke": bloecke, "iterationen": ITERATIONEN}


def entschluesseln(quelle: str, ziel: str, passwort: str) -> dict:
    """Prueft Header, leitet Key ab, entschluesselt chunkweise (Token je Zeile)."""
    if not HAT_FERNET:
        raise SystemExit("[KRYUX] Paket 'cryptography' fehlt: pip install cryptography.")
    q, z = Path(quelle), Path(ziel)
    with open(q, "rb") as fin:
        try:
            header = base64.b64decode(fin.readline().strip())
        except Exception:
            raise SystemExit("[KRYUX] Unbekanntes Dateiformat (kein KRYUX-Header).")
        if header[:6] == b"FERNET1":  # Legacy-Format aus v2 lesen
            rest = fin.read()
            salt = header[6:22]
            fernet = Fernet(leite_schluessel(passwort, salt))
            try:
                klar = fernet.decrypt(base64.b64decode(rest))
            except InvalidToken:
                raise SystemExit("[KRYUX] Falsches Passwort oder Datei manipuliert.")
            z.write_bytes(klar)
            return {"modus": "decrypt", "format": "legacy-FERNET1", "bytes": len(klar)}
        if header[:6] != b"KRYUX1":
            raise SystemExit("[KRYUX] Unbekanntes Dateiformat (erwartet KRYUX1).")
        salt, it = header[6:22], int.from_bytes(header[22:26], "big")
        fernet = Fernet(base64.urlsafe_b64encode(
            hashlib.pbkdf2_hmac("sha256", passwort.encode(), salt, it)))
        groesse, bloecke = 0, 0
        with open(z, "wb") as fout:
            for zeile in fin:
                zeile = zeile.strip()
                if not zeile:
                    continue
                try:
                    klar = fernet.decrypt(base64.b64decode(zeile))
                except InvalidToken:
                    try:
                        z.unlink()
                    except OSError:
                        pass
                    raise SystemExit("[KRYUX] Falsches Passwort oder Datei manipuliert (Teildatei entfernt).")
                fout.write(klar)
                groesse += len(klar)
                bloecke += 1
    return {"modus": "decrypt", "quelle": str(q), "ziel": str(z), "bytes": groesse,
            "bloecke": bloecke, "iterationen": it}


def main() -> None:
    """Einstiegspunkt: encrypt/decrypt. Meta-Report via Haupt---out (vor Subcommand),
    z.B. --out meta.json encrypt --in a --out a.enc. Datei-Output via Sub---out."""
    parser = argparse.ArgumentParser(description="KRYUX Dateien sicher verschluesseln (AES/Fernet).")
    sub = parser.add_subparsers(dest="modus", required=True)
    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name, help=f"{name}-Modus")
        p.add_argument("--in", dest="quelle", required=True, help="Quelldatei (eigene!)")
        p.add_argument("--out", dest="ziel", required=True, help="Zieldatei")
        p.add_argument("--passwort", default="", help="Passwort (sonst sichere Abfrage)")
        _kryux_apply(p)  # --format/--no-banner auch nach Subcommand
    parser = _kryux_apply(parser)
    args = parser.parse_args()
    try:
        _kryux_banner("19_aes_file_encryptor.py", args)
    except Exception:
        pass
    pw = _passwort(args)
    if len(pw) < 8:
        print("[KRYUX] Warnung: kurzes Passwort (<8 Zeichen).", file=sys.stderr)
    erg = verschluesseln(args.quelle, args.ziel, pw) if args.modus == "encrypt" \
        else entschluesseln(args.quelle, args.ziel, pw)
    erg.update({"tool": "19_aes_encryptor", "kryux": "v3.0",
                "zeit": datetime.now(timezone.utc).isoformat()})
    print(f"[KRYUX] {'Verschluesselt' if args.modus == 'encrypt' else 'Entschluesselt'}: "
          f"{args.quelle} -> {args.ziel} ({erg['bytes']} B, {erg.get('bloecke', '?')} Bloecke)")
    if getattr(args, "format", "text") == "json":
        print(json.dumps(erg, indent=2, ensure_ascii=False))
    if getattr(args, "out", ""):
        try:
            Path(args.out).write_text(json.dumps(erg, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[KRYUX] Meta-Report -> {args.out}", file=sys.stderr)
        except OSError as e:
            print(f"[KRYUX] Report fehlgeschlagen: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
