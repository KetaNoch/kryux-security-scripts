# Security Policy

## Authorized use only

These tools are **defensive security and audit utilities** for:

- your own systems and home lab,
- customer systems **only with prior written authorization** (see `06_kunden_pentest/37_scope_guard.py`),
- learning platforms such as TryHackMe / HackTheBox (your own lab machines).

Active checks (`10_directory_enum`, `11_sqli_tester_lab`, `12_xss_tester_lab`,
`39_web_audit_pro`, `44_htb_thm_recon`) require an explicit consent flag and
refuse to run without it. Never test systems you do not own or that are not
covered by a written engagement.

## Reporting a vulnerability

If you find a security issue **in these tools themselves**, please do **not**
open a public issue. Instead use
**GitHub → Security → Report a vulnerability** (private Security Advisory).
We aim to acknowledge reports within 7 days.

## Scope notes

- No exploit payloads, no credential attacks against third parties.
- Hash auditing (`17`, `46`) is for your own hashes / lab data only.
- Encryption (`19`) requires the `cryptography` package; no insecure fallback.
