# Changelog

## 1.0.0 - 2026-10-28

- First release.
- Inventories AD CS certification authorities (including offline roots from the Certification Authorities container) and every published certificate template: key algorithm and size, request hash, provider (CSP or KSP), schema version, validity, key archival and purpose.
- Probes LDAPS, RDP (with the X.224 negotiation), IIS and WSUS endpoints for protocol, cipher suite, key exchange and certificate, and maps each host's Windows release to what it can do: TLS 1.3, hybrid ML-KEM, an ML-DSA CA.
- Kerberos: RC4 and DES on SPN accounts and trusts, accounts with no AES keys, KDC events 201-209, krbtgt age, and PKINIT exposure.
- Ranks every quantum-vulnerable asset by Mosca's inequality: shelf life of the data (from classification) plus migration time against a configurable quantum year (default 2030).
- Five-phase roadmap; CycloneDX 1.6 CBOM; HTML report; inventory CSV; Markdown roadmap; JSON findings.
