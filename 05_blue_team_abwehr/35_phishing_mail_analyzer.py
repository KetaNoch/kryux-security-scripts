#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 35_phishing_mail_analyzer.py
"""35_phishing_mail_analyzer.py - Analysiert .eml-Datei (defensiv).

Prüft: From vs Return-Path/Reply-To-Mismatch, SPF/DKIM-Header,
Links (http), Anhänge mit gefährlicher Extension. Keine Links öffnen!
"""
import argparse
import email
import json
import re
from datetime import datetime
from email import policy
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


ETHIK = "Defensiv: verdächtige Mails nicht öffnen/weiterleiten, nur analysieren."
GEFAEHRlich = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1",
               ".jar", ".lnk", ".iso", ".docm", ".xlsm"}
URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def analyse(eml: Path) -> dict:
    """Parst eml, liefert Befunde."""
    msg = email.message_from_bytes(eml.read_bytes(), policy=policy.default)
    frm = str(msg.get("From", ""))
    rp = str(msg.get("Return-Path", ""))
    reply = str(msg.get("Reply-To", ""))
    spf = str(msg.get("Received-SPF", "")) + str(msg.get("Authentication-Results", ""))
    body = msg.get_body(preferencelist=("plain", "html"))
    text = body.get_content() if body else ""
    urls = URL_RE.findall(text + frm)
    anhaenge = []
    for part in msg.iter_attachments():
        fn = part.get_filename() or "unbenannt"
        ext = Path(fn).suffix.lower()
        anhaenge.append((fn, ext in GEFAEHRlich))
    mismatch = bool(rp and rp not in frm) or bool(reply and reply not in frm)
    spf_fail = "fail" in spf.lower()
    dkim_fail = "dkim=fail" in spf.lower()
    return {"from": frm, "return": rp, "reply": reply, "spf": spf[:200],
            "urls": urls[:20], "anhaenge": anhaenge, "mismatch": mismatch,
            "spf_fail": spf_fail, "dkim_fail": dkim_fail}


def main() -> None:
    ap = argparse.ArgumentParser(description="Phishing-Mail-Analyzer (.eml, defensiv)")
    ap.add_argument("eml", help="Pfad zur .eml-Datei")
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("35_phishing_mail_analyzer.py", a)
    except Exception:
        pass
    pfad = Path(a.eml)
    if not pfad.is_file():
        print(f"[!] Datei fehlt: {pfad}")
        return
    print(ETHIK)
    b = analyse(pfad)
    score = sum([b["mismatch"], b["spf_fail"], b["dkim_fail"],
                 any(g for _, g in b["anhaenge"]), len(b["urls"]) > 3])
    print(f"From: {b['from']}\nReturn-Path: {b['return']}\nReply-To: {b['reply']}")
    print(f"Mismatch: {b['mismatch']}, SPF-Fail: {b['spf_fail']}, DKIM-Fail: {b['dkim_fail']}")
    print(f"Links ({len(b['urls'])}):")
    for u in b["urls"]:
        print(f"  {u[:100]}")
    print("Anhänge:")
    for fn, gef in b["anhaenge"] or [("(keine)", False)]:
        print(f"  {'[!] GEFÄHRLICH' if gef else '[+]'} {fn}")
    print(f"Risiko-Score: {score}/5 -> {'HOCH' if score >= 3 else 'MITTEL' if score else 'NIEDRIG'}")
    report = {
        "tool": "35_phishing_mail_analyzer",
        "target": str(pfad),
        "zeit": datetime.now().isoformat(),
        "score": score,
        "einschaetzung": ("HOCH" if score >= 3 else "MITTEL" if score >= 1 else "NIEDRIG"),
        "from": b["from"],
        "mismatch": b["mismatch"],
        "spf_fail": b["spf_fail"],
        "dkim_fail": b["dkim_fail"],
        "anzahl_urls": len(b["urls"]),
        "urls": b["urls"],
        "anhaenge": [{"datei": fn, "gefaehrlich": gef} for fn, gef in b["anhaenge"]],
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
                    _zeilen = [f"# {report['tool']}", f"Datei: {pfad}", f"Risiko-Score: {score}/5 ({report['einschaetzung']})", ""]
                    _zeilen += [f"- URL: {u[:100]}" for u in b["urls"]] or ["- Keine URLs."]
                    _zeilen += [f"- Anhang: {fn} {'[GEFAEHRLICH]' if gef else ''}" for fn, gef in b["anhaenge"]] or ["- Keine Anhaenge."]
                    _p.write_text("\n".join(_zeilen) + "\n", encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    main()
