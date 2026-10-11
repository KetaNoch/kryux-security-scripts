#!/usr/bin/env python3
# ⬢ KRYUX // SECURITY SUITE v3.0 – 43_incident_collector.py
"""43_incident_collector.py - Triage-Sammler fuer Incident Response (lesend).

Sammelt in ein Fall-Verzeichnis: Prozesse, Netzwerkverbindungen, Autostarts
(cron/systemd/bashrc), Benutzer/logins, sensitive Bin-Hashes, juengste Dateien
(Timeline-Stichprobe), USB/dmesg-Hinweise. Packt alles als .tar.gz.
Keine Aenderungen am System, keine Memory-Dumps (dafuer Volatility/LiME nutzen).

  python3 43_incident_collector.py --out ./ir_fall_2026_001
"""
import argparse
import hashlib
import json
import subprocess
import tarfile
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



def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr)[:30000]
    except Exception as e:
        return f"n/a: {e}"


def sha256(pfad: Path):
    try:
        h = hashlib.sha256()
        with open(pfad, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"n/a: {e}"


def timeline(root: str, tiefe: int, limit: int):
    out = []
    try:
        r = subprocess.run(["find", root, "-maxdepth", str(tiefe), "-type", "f",
                            "-printf", "%T@ %TY-%Tm-%Td %TH:%TM %p\\n"],
                           capture_output=True, text=True, timeout=25)
        zeilen = sorted(r.stdout.splitlines(), reverse=True)[:limit]
        for z in zeilen:
            out.append(z.strip())
    except Exception as e:
        out.append(f"n/a: {e}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Incident-Triage-Collector (lesend)")
    ap.add_argument("--out", default="./ir_fall", help="Fall-Verzeichnis")
    ap.add_argument("--timeline-root", default="/tmp", help="Root fuer Timeline-Stichprobe")
    ap.add_argument("--timeline-tiefe", type=int, default=3)
    ap.add_argument("--timeline-limit", type=int, default=200)
    ap = _kryux_apply(ap)
    a = ap.parse_args()
    try:
        _kryux_banner("43_incident_collector.py", a)
    except Exception:
        pass
    out = Path(a.out)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    manifest = {"start": datetime.now(timezone.utc).isoformat(), "dateien": []}

    def speichere(name, inhalt):
        p = out / "raw" / name
        p.write_text(inhalt if isinstance(inhalt, str) else json.dumps(inhalt, indent=2, ensure_ascii=False),
                     encoding="utf-8", errors="ignore")
        manifest["dateien"].append(name)

    speichere("prozesse_ps_aux.txt", run(["ps", "aux"]))
    speichere("net_ss.txt", run(["ss", "-tulpen"]) or run(["netstat", "-tulpen"]))
    speichere("net_proc_tcp.txt", run(["cat", "/proc/net/tcp"])[:8000])
    speichere("benutzer_w.txt", run(["w"]) + "\n---\n" + run(["last", "-n", "30"]))
    speichere("autorun_cron.txt", run(["cat", "/etc/crontab"]) + "\n---\n" + run(["ls", "-la", "/etc/cron.d/"]))
    speichere("autorun_systemd.txt", run(["systemctl", "list-unit-files", "--state=enabled"]))
    speichere("autorun_bashrc.txt", run(["ls", "-la", "/home"]) + "\n" + run(["cat", "/etc/rc.local"]))
    speichere("usb_dmesg.txt", run(["dmesg"]) [-8000:] + "\n---\n" + run(["lsusb"]))
    speichere("timeline.txt", "\n".join(timeline(a.timeline_root, a.timeline_tiefe, a.timeline_limit)))
    hashes = {}
    for b in ("/bin/bash", "/bin/sh", "/usr/bin/sudo", "/usr/bin/ssh", "/bin/systemctl"):
        if Path(b).exists():
            hashes[b] = sha256(Path(b))
    speichere("bin_hashes.json", hashes)
    manifest["ende"] = datetime.now(timezone.utc).isoformat()
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    archiv = str(out) + ".tar.gz"
    with tarfile.open(archiv, "w:gz") as tar:
        tar.add(str(out), arcname=out.name)
    print(f"[+] Fall: {out} ({len(manifest['dateien'])} Artefakte) -> {archiv}")
    print("[*] Naechste Schritte: Hashes mit 31er-Check, Logs mit 42er-Hunter, Timeline sichten.")


if __name__ == "__main__":
    main()
