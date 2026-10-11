# ⬢ KRYUX // SECURITY SUITE – Python Skripte (46 Profi-Tools, v3.0)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![KRYUX v3.0](https://img.shields.io/badge/KRYUX-v3.0-00ffa3.svg)]

> **Wichtig – nur ethisch & legal nutzen:** Alle Skripte sind für **eigene Systeme, eigenes Labor (z.B. VMs, TryHackMe, HackTheBox, DVWA, Metasploitable)** und Kunden-Systeme **nur mit schriftlicher Freigabe** gedacht. Keine fremden Systeme ohne Erlaubnis testen. Bei `10_directory_enum`, `11_sqli_tester_lab`, `12_xss_tester_lab`, `17_hash_cracker_lab (--yes)`, `39_web_audit_pro`, `44_htb_thm_recon` ist eine explizite Consent-Bestätigung eingebaut. `37_scope_guard` blockt Out-of-Scope-Ziele.

## KRYUX-Standard (v3.0, alle 46 Skripte)

- **Branding:** `⬢ KRYUX // SECURITY SUITE v3.0`-Header + Banner nach stderr (JSON-stdout bleibt sauber), abschaltbar mit `--no-banner`.
- **Reports:** jedes Tool kann `--format json` (stdout) und `--out datei.json` (bei Text-Tools auch `.md`/`.txt`). Gemeinsamer Kern: `kryux_common.py` (mit Fallback – jedes Skript läuft auch standalone).
- **Echt statt Demo:** keine Dummy-/XOR-/input()-Demos mehr. `18` ist ein echter Login-Hardening-Auditor (PAM/SSH/fail2ban, Score), `19` verweigert ohne `cryptography` (AES/Fernet, PBKDF2 600k, Chunked-Streaming, Legacy-Read), `17` ist piping-fähig mit 5 Algos + H/s-Benchmark, `20` hat Caesar-Cracker (Chi-Quadrat + Wort-Bonus) + Datei-Modus.

## Struktur

```
Cybersecurity_Ethical_Hacking_Scripts/
├── 01_netzwerk_scanning/       01-07: Port-Scanner, Ping-Sweep, Banner-Grabber, ARP-Scanner, DNS-Enum, Packet-Sniffer, Traceroute
├── 02_web_sicherheit/          08-14: Header-Analyzer, SSL-Checker, Directory-Enum (Lab), SQLi-Tester (Lab), XSS-Tester (Lab), Clickjacking-Test, robots/sitemap
├── 03_passwort_krypto/         15-21: Passwort-Stärke, Hash-Generator, Hash-Cracker (eigener Hash), Bruteforce-Simulator, AES-Encryptor, Caesar/Vigenere, Phishing-URL-Check
├── 04_forensik_system/         22-28: System-Info, File-Integrity-Monitor, Log-Analyzer, Metadata-Extractor, Prozess-Monitor, USB-Detector, Permission-Auditor
├── 05_blue_team_abwehr/        29-36: Bruteforce-Detector, Firewall-Parser, Malware-Hash-Check, YARA-Simple-Scanner, Backup-Verifier, Keylogger-Detector (defensiv!), Phishing-Mail-Analyzer, Sicherheits-Audit
├── 06_kunden_pentest/           37-40 PROFI: Scope-Guard (Gatekeeper), Nmap-XML-Parser (JSON/MD/CSV), Web-Audit-Pro, Finding-Report-Generator (MD+HTML)
├── 07_blue_team_pro/            41-43 PROFI: Linux-Hardening-Audit (Score+JSON), Log-Threat-Hunter (Bruteforce/SQLi/XSS/Scanner), Incident-Collector (Triage-Bundle .tar.gz)
├── 08_thm_htb_operator/         44-46 PROFI: HTB/THM-Recon (Scan+Banner+Dir+VHost+notes.md), PrivEsc-Checker (nur Hints, kein Exploit), CTF-Crypto-Helper (Hash-ID/Crack/Decode/JWT/File)
├── kryux_common.py            Gemeinsamer Kern (Banner, --out/--format/--no-banner)
├── requirements.txt
└── README.md
```

## Standard-Flags (jedes Tool)

```bash
python3 01_netzwerk_scanning/01_port_scanner.py --host 127.0.0.1 --ports 22,80 --format json --out report.json
python3 05_blue_team_abwehr/29_bruteforce_detector.py --log /var/log/auth.log --out hunt.json --no-banner
```

## Echte Krypto-/Audit-Beispiele (v3.0)

```bash
# Hash-Audit (eigener Hash, piping-fähig, 5 Algos)
python3 03_passwort_krypto/17_hash_cracker_lab.py --hash <hex> --algo sha256 --wordlist liste.txt --yes --format json
# Login-Hardening (echt, lesend) + optional Lern-Simulation
python3 03_passwort_krypto/18_bruteforce_simulator.py --out hardening.json
python3 03_passwort_krypto/18_bruteforce_simulator.py --simulate --versuche 20
# AES (braucht: pip install cryptography) – ohne Paket kein Fallback, Abbruch mit Hinweis
python3 03_passwort_krypto/19_aes_file_encryptor.py encrypt --in a.txt --out a.enc --passwort <pw>
python3 03_passwort_krypto/19_aes_file_encryptor.py decrypt --in a.enc --out a.txt --passwort <pw>
# Klassik + Cracker (nur Lernen/CTF!)
python3 03_passwort_krypto/20_caesar_vigenere_tool.py crack --text "WKH TXLFN ..." --top 3
```

## Profi-Workflows (Kunde / THM / HTB)

```bash
# --- Kunden-Pentest (nur mit Freigabe!) ---
python3 06_kunden_pentest/37_scope_guard.py --init-template   # scope.txt + freigabe.txt anlegen/anpassen
python3 06_kunden_pentest/37_scope_guard.py --target 192.168.10.5 --scope 06_kunden_pentest/scope.txt --auth-file 06_kunden_pentest/freigabe.txt
nmap -sV -O -oX scan.xml 192.168.10.5                          # erst nach FREIGABE-OK!
python3 06_kunden_pentest/38_nmap_report_parser.py --xml scan.xml --out-dir ./nmap_report
python3 06_kunden_pentest/39_web_audit_pro.py --url https://app.kunde.de --i-have-authorization --out audit.json
python3 06_kunden_pentest/40_finding_report_generator.py --findings nmap_report/findings.json --kunde "Beispiel GmbH" --auftrag 2026-014 --out-dir ./bericht

# --- Blue Team beim Kunden ---
python3 07_blue_team_pro/41_linux_hardening_audit_pro.py --out-dir ./audit_server01
python3 07_blue_team_pro/42_log_threat_hunter.py --log /var/log/auth.log --out ./hunt
python3 07_blue_team_pro/43_incident_collector.py --out ./ir_fall_2026_001

# --- THM / HTB Lab ---
python3 08_thm_htb_operator/44_htb_thm_recon.py --target 10.10.10.5 --i-have-authorization --ports top100 --out ./lab_maschine
python3 08_thm_htb_operator/45_linenum_privesc_checker.py --out ./privesc   # erst nach Shell im Lab
python3 08_thm_htb_operator/46_ctf_crypto_helper.py --identify 5d41402abc4b2a76b9719d911017c592
python3 08_thm_htb_operator/46_ctf_crypto_helper.py --crack <hash> --wordlist /usr/share/wordlists/rockyou.txt --algo auto
```

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Alle Skripte laufen mit Standardlib. Optional: `scapy`, `cryptography`, `psutil` für mehr Funktionen.

## Beispiele

```bash
# Netzwerk
python3 01_netzwerk_scanning/01_port_scanner.py --host 127.0.0.1 --ports 1-1024
python3 01_netzwerk_scanning/03_banner_grabber.py --host 127.0.0.1 --ports 80,443
python3 01_netzwerk_scanning/05_dns_enum.py --domain example.com

# Web (nur eigene Domain!)
python3 02_web_sicherheit/08_http_header_analyzer.py --url https://example.com
python3 02_web_sicherheit/09_ssl_tls_checker.py --host example.com

# Passwort & Krypto
python3 03_passwort_krypto/15_passwort_staerke_checker.py
python3 03_passwort_krypto/16_hash_generator.py --text hallo --algo sha256
python3 03_passwort_krypto/21_phishing_url_checker.py --url http://beispiel.test

# Forensik
python3 04_forensik_system/22_system_info_collector.py --out report.json
python3 04_forensik_system/23_file_integrity_monitor.py --init --pfad ./wichtig --db baseline.json
python3 04_forensik_system/23_file_integrity_monitor.py --check --pfad ./wichtig --db baseline.json

# Blue Team
python3 05_blue_team_abwehr/36_sicherheits_audit.py
python3 05_blue_team_abwehr/29_bruteforce_detector.py --log /var/log/auth.log
```

Jedes Skript hat `--help` für alle Optionen.

## Lernpfad-Empfehlung
1. Starte mit `15, 21, 22, 36` (ungefährlich, kein Root nötig)
2. Dann `01, 03, 08, 09, 23, 24` (Netzwerk/Web Grundlagen im Heim-Labor)
3. Für Fortgeschrittene mit eigener VM: `06, 04, 10-12` (brauchen ggf. Root / Consent-Flag)

Erstellt für Lernzwecke – viel Erfolg beim defensiven Security-Lernen!

## Lizenz & Security

- Lizenz: [MIT](LICENSE)
- [Security Policy](SECURITY.md) – nur autorisierte Nutzung, Schwachstellen bitte privat melden.
