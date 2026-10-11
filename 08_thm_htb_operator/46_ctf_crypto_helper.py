#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 46_ctf_crypto_helper.py
"""46_ctf_crypto_helper.py - CTF/Pruefungs-Helfer: Hash-ID, Crack, Decoder, JWT.

Rein defensiv/analytisch, Stdlib-only. Fuer eigene CTF-Hashes / Lab-Daten.
  ID:    --identify <hash>
  Crack: --crack <hash> --wordlist rockyou.txt [--algo auto|md5|sha1|sha256|sha512|ntlm]
  Decode:--decode <text> --art auto|b64|hex|url|rot13|caesar|xor
  JWT:   --jwt <token>  (dekodiert Header/Payload, verifiziert NICHT)
  Datei: --file <pfad>  (Magic-Bytes + Strings-Stichprobe)

Beispiele:
  python3 46_ctf_crypto_helper.py --identify 5d41402abc4b2a76b9719d911017c592
  python3 46_ctf_crypto_helper.py --crack 5d41402abc4b2a76b9719d911017c592 --wordlist /usr/share/wordlists/rockyou.txt
  python3 46_ctf_crypto_helper.py --decode aGFsbG8= --art b64
  python3 46_ctf_crypto_helper.py --jwt eyJhbGciOi...
"""
import argparse
import base64
import binascii
import hashlib
import json
import re
import urllib.parse
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



def identify(h: str):
    h = h.strip()
    out = []
    if re.fullmatch(r"[a-fA-F0-9]{32}", h):
        out += ["md5 (32 hex)", "ntlm (32 hex, upper -> NTLM prüfen)", "md4"]
    if re.fullmatch(r"[a-fA-F0-9]{40}", h):
        out += ["sha1 (40 hex)"]
    if re.fullmatch(r"[a-fA-F0-9]{64}", h):
        out += ["sha256 (64 hex)"]
    if re.fullmatch(r"[a-fA-F0-9]{128}", h):
        out += ["sha512 (128 hex)"]
    if h.startswith("$2") and len(h) >= 53:
        out += ["bcrypt"]
    if h.startswith("$6$"):
        out += ["sha512crypt (/etc/shadow)"]
    if h.startswith("$1$"):
        out += ["md5crypt (/etc/shadow)"]
    if re.fullmatch(r"[A-Za-z0-9+/=]{20,}", h):
        out += ["evtl. base64-codiert (nicht Hash, decodieren versuchen)"]
    return out or ["unbekannt - Länge/Zeichen prüfen"]


def hash_pw(pw: str, algo: str):
    b = pw.encode()
    if algo == "md5":
        return hashlib.md5(b).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(b).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(b).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(b).hexdigest()
    if algo == "ntlm":
        return hashlib.new("md4", pw.encode("utf-16le")).hexdigest()
    raise ValueError(algo)


def crack(ziel: str, wortliste: Path, algo: str):
    ziel = ziel.strip().lower()
    algos = ["md5", "sha1", "sha256", "sha512", "ntlm"] if algo == "auto" else [algo]
    n = 0
    with open(wortliste, errors="ignore") as f:
        for zeile in f:
            pw = zeile.rstrip("\n").rstrip("\r")
            if not pw:
                continue
            n += 1
            if n > 5_000_000:
                break
            for al in algos:
                try:
                    if hash_pw(pw, al) == ziel:
                        return pw, al, n
                except Exception:
                    continue
            if n % 500000 == 0:
                print(f"[*] {n} getestet ...")
    return None, "", n


def rot(s, n):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def english_score(t: str):
    t = t.lower()
    return sum(t.count(w) for w in (" the ", " and ", " flag", "thm", "htb", "password", "admin", "e", "a"))


def decode(text: str, art: str):
    erg = {}
    def versuch(name, fn):
        try:
            erg[name] = fn()
        except Exception as e:
            erg[name] = f"(fehlgeschlagen: {e})"
    if art in ("auto", "b64"):
        versuch("base64", lambda: base64.b64decode(text.strip() + "===" ).decode("utf-8", errors="replace"))
    if art in ("auto", "hex"):
        versuch("hex", lambda: bytes.fromhex("".join(text.split())).decode("utf-8", errors="replace"))
    if art in ("auto", "url"):
        versuch("url", lambda: urllib.parse.unquote_plus(text))
    if art in ("auto", "rot13"):
        versuch("rot13", lambda: rot(text, 13))
    if art == "caesar":
        for i in range(1, 26):
            versuch(f"caesar_{i}", lambda i=i: rot(text, i))
    if art == "xor":
        best = []
        for k in range(1, 256):
            dec = "".join(chr(ord(c) ^ k) for c in text[:200])
            if all(32 <= ord(c) < 127 or c in "\n\r\t" for c in dec):
                best.append((english_score(dec), k, dec[:200]))
        best.sort(reverse=True)
        erg["xor_top3"] = [{"key": k, "text": t} for _, k, t in best[:3]] or ["kein druckbarer XOR-Fund"]
    if art == "auto":
        # kurze Caesar-Vorschau
        cands = sorted(((english_score(rot(text, i)), i) for i in range(1, 26)), reverse=True)[:1]
        erg["caesar_best"] = f"rot{cands[0][1]}: {rot(text, cands[0][1])[:200]}"
    return erg


def jwt_decode(tok: str):
    teile = tok.strip().split(".")
    if len(teile) < 2:
        return {"fehler": "kein JWT-Format"}
    def pad(s):
        return s + "=" * (-len(s) % 4)
    out = {}
    for name, part in (("header", teile[0]), ("payload", teile[1])):
        try:
            out[name] = json.loads(base64.urlsafe_b64decode(pad(part)).decode("utf-8", errors="replace"))
        except Exception as e:
            out[name] = f"(decode-fehler: {e})"
    out["hinweis"] = "NUR dekodiert, NICHT verifiziert. alg=none / schwacher Secret = typische CTF-Falle."
    return out


def file_check(pfad: Path):
    data = pfad.read_bytes()[:8000]
    magic = data[:8]
    typ = "unbekannt"
    if data.startswith(b"\xff\xd8\xff"):
        typ = "JPEG (evtl. Stego: strings/exiftool pruefen)"
    elif data.startswith(b"\x89PNG"):
        typ = "PNG (evtl. Stego: zsteg/steghide im Lab)"
    elif data.startswith(b"PK"):
        typ = "ZIP/Office/OpenXML (unzip -l versuchen)"
    elif data.startswith(b"%PDF"):
        typ = "PDF"
    elif data.startswith(b"\x7fELF"):
        typ = "ELF-Binary"
    strings = re.findall(rb"[ -~]{4,}", data)
    top = [s.decode()[:120] for s in strings[:30]]
    return {"typ": typ, "magic": magic.hex(), "strings_stichprobe": top}


def main() -> None:
    ap = argparse.ArgumentParser(description="CTF-Crypto-Helfer (Hash/Decode/JWT/File)")
    ap.add_argument("--identify", default="")
    ap.add_argument("--crack", default="")
    ap.add_argument("--wordlist", default="")
    ap.add_argument("--algo", default="auto", choices=["auto", "md5", "sha1", "sha256", "sha512", "ntlm"])
    ap.add_argument("--decode", default="")
    ap.add_argument("--art", default="auto", choices=["auto", "b64", "hex", "url", "rot13", "caesar", "xor"])
    ap.add_argument("--jwt", default="")
    ap.add_argument("--file", default="")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("46_ctf_crypto_helper.py", a)
    except Exception:
        pass
    if a.identify:
        print("ID:", "; ".join(identify(a.identify)))
    if a.crack:
        if not a.wordlist or not Path(a.wordlist).exists():
            print("[!] --wordlist fehlt/gueltige Datei angeben")
        else:
            pw, al, n = crack(a.crack, Path(a.wordlist), a.algo)
            print(f"[+] GEFUNDEN: '{pw}' ({al}, {n} getestet)" if pw else f"[-] nichts nach {n} Woertern")
    if a.decode:
        for k, v in decode(a.decode, a.art).items():
            print(f"{k}: {v if not isinstance(v, list) else json.dumps(v, ensure_ascii=False)[:800]}")
    if a.jwt:
        print(json.dumps(jwt_decode(a.jwt), indent=2, ensure_ascii=False))
    if a.file:
        p = Path(a.file)
        print(json.dumps(file_check(p), indent=2, ensure_ascii=False) if p.exists() else "[!] Datei fehlt")
    if not any([a.identify, a.crack, a.decode, a.jwt, a.file]):
        ap.print_help()


if __name__ == "__main__":
    main()
