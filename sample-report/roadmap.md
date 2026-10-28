# Quantum-readiness roadmap: Contoso (fictional demo estate)

Assessed 2026-10-27. Planning year for a cryptographically relevant quantum computer: **2030** (3.2 years away).

- **14** systems protect data that must stay secret past 2030 with classical key exchange or encryption.
- **22** of 32 quantum-vulnerable assets should already have started migrating (Mosca's inequality); 5 more must start within a year.
- **2** classical CAs stay trusted after 2030.
- **18** assets have weaknesses that ordinary computers exploit today.
- Hybrid ML-KEM: on for 2 of 17 endpoints, available but off on 1, needs an OS upgrade on 12.

## Ranked by when migration must start

| # | Asset | Type | Protects | Shelf life | Start by | Status |
|---|---|---|---|---|---|---|
| 1 | IIS hr.contoso.com:443 | Endpoint | Both | 25 y (Regulated) | 2003-07-03 | Overdue by 23.3 y |
| 2 | Contoso-SMIME | Template | Confidentiality | 25 y (Regulated) | 2004-01-02 | Overdue by 22.8 y |
| 3 | Contoso-EFS-Recovery | Template | Confidentiality | 15 y (Restricted) | 2013-07-02 | Overdue by 13.3 y |
| 4 | Contoso-User | Template | Confidentiality | 15 y (Restricted) | 2013-07-02 | Overdue by 13.3 y |
| 5 | IIS legal-dms.contoso.com:443 | Endpoint | Both | 15 y (Restricted) | 2013-07-02 | Overdue by 13.3 y |
| 6 | RDP BR-DC01:3389 | Endpoint | Both | 15 y (Restricted) | 2013-07-02 | Overdue by 13.3 y |
| 7 | RDP CORP-DC01:3389 | Endpoint | Both | 15 y (Restricted) | 2013-07-02 | Overdue by 13.3 y |
| 8 | RDP CORP-DC03:3389 | Endpoint | Both | 15 y (Restricted) | 2013-07-02 | Overdue by 13.3 y |
| 9 | RDP CORP-PAW-JMP01:3389 | Endpoint | Both | 15 y (Restricted) | 2014-10-02 | Overdue by 12.1 y |
| 10 | PKINIT (smart cards and Windows Hello) | Kerberos | Both | 7 y (Confidential) | 2021-01-01 | Overdue by 5.8 y |
| 11 | LDAPS BR-DC01:636 | Endpoint | Both | 7 y (Confidential) | 2021-07-02 | Overdue by 5.3 y |
| 12 | LDAPS CORP-DC01:636 | Endpoint | Both | 7 y (Confidential) | 2021-07-02 | Overdue by 5.3 y |
| 13 | LDAPS CORP-DC02:636 | Endpoint | Both | 7 y (Confidential) | 2021-07-02 | Overdue by 5.3 y |
| 14 | LDAPS CORP-DC03:636 | Endpoint | Both | 7 y (Confidential) | 2021-07-02 | Overdue by 5.3 y |
| 15 | Contoso-CodeSigning | Template | Authenticity | - | 2025-07-02 | Overdue by 1.3 y |
| 16 | Contoso-SmartCard | Template | Authenticity | - | 2025-07-02 | Overdue by 1.3 y |
| 17 | Contoso-WSUS-Legacy | Template | Authenticity | - | 2025-07-02 | Overdue by 1.3 y |
| 18 | IIS intranet.contoso.com:443 | Endpoint | Both | 2 y (Internal) | 2026-07-03 | Overdue by 0.3 y |
| 19 | WSUS corp-wsus-old.contoso.com:8531 | Endpoint | Both | 2 y (Internal) | 2026-07-03 | Overdue by 0.3 y |
| 20 | WSUS CORP-WSUS01:8531 | Endpoint | Both | 2 y (Internal) | 2026-07-03 | Overdue by 0.3 y |
| 21 | Contoso-WebServer | Template | Authenticity | - | 2026-07-03 | Overdue by 0.3 y |
| 22 | WebServer | Template | Authenticity | - | 2026-07-03 | Overdue by 0.3 y |
| 23 | Contoso Issuing CA 01 | CA | Authenticity | - | 2027-01-01 | Now |
| 24 | Contoso Legacy CA | CA | Authenticity | - | 2027-01-01 | Now |
| 25 | Contoso Root CA | CA | Authenticity | - | 2027-01-01 | Now |
| 26 | Contoso-Computer | Template | Authenticity | - | 2027-07-03 | Now |
| 27 | Contoso-KDC | Template | Authenticity | - | 2027-07-03 | Now |
| 28 | Contoso-WebServer-v4 | Template | Authenticity | - | 2027-11-30 | Next |
| 29 | IIS claims.contoso.com:443 | Endpoint | Authenticity | 25 y (Regulated) | 2028-01-02 | Next |
| 30 | Contoso-RDP | Template | Authenticity | - | 2028-01-02 | Next |
| 31 | IIS pki.contoso.com:443 | Endpoint | Authenticity | - | 2028-01-02 | Next |
| 32 | Contoso-OCSP | Template | Authenticity | - | 2028-12-17 | Next |

## Phase 0: Fix what is broken today

Classical weaknesses an attacker can use with ordinary computers: SHA-1, short RSA keys, RC4 and DES, TLS 1.0/1.1, RSA key transport, cleartext WSUS. Every later phase depends on these being gone.

- **IIS legal-dms.contoso.com:443** (High, QR-11): Still accepts TLS 1.0, TLS 1.1. Disable TLS 1.0 and 1.1 in Schannel (SCHANNEL\Protocols registry keys or your baseline GPO).
- **RDP BR-DC01:3389** (High, QR-27): Certificate expired on 2026-10-02. Renew it; clients are either failing or ignoring validation.
- **RDP CORP-DC03:3389** (High, QR-27): Certificate expired on 2026-10-02. Renew it; clients are either failing or ignoring validation.
- **RDP BR-DC01:3389** (Medium, QR-15): Self-signed certificate. Clients can't tell this RDP server from an impostor, so users learn to click through warnings. Issue it from the enterprise CA (auto-enrolment for RDP).
- **RDP CORP-DC03:3389** (Medium, QR-15): Self-signed certificate. Clients can't tell this RDP server from an impostor, so users learn to click through warnings. Issue it from the enterprise CA (auto-enrolment for RDP).
- **LDAPS BR-DC01:636** (High, QR-10): Negotiates TLS_RSA_WITH_AES_256_CBC_SHA256 (no forward secrecy). With RSA key transport, whoever gets the server's private key - today by theft, later by quantum - decrypts every recorded session. Prefer ECDHE suites and remove TLS_RSA_* from the cipher suite order.
- **Contoso-WSUS-Legacy** (Critical, QR-01): Requests signed with SHA1. Set the request hash to SHA-256 or better (schema v3+ template).
- **WebServer** (Critical, QR-02): Minimum key size RSA 1024. Raise the minimum key size to 2048 or more (3072 for anything issued past 2030) and supersede the template.
- **WebServer** (Critical, QR-01): Requests signed with SHA1. Set the request hash to SHA-256 or better (schema v3+ template).
- **WSUS corp-wsus-old.contoso.com:8531** (Critical, QR-01): Certificate signed with sha1RSA. Reissue from a SHA-256 CA.
- **WSUS corp-wsus-old.contoso.com:8531** (Critical, QR-02): Certificate key is RSA 1024. Reissue with RSA 3072+ or ECDSA P-384.
- **WSUS corp-wsus-old.contoso.com:8531** (High, QR-10): Negotiates TLS_RSA_WITH_AES_128_CBC_SHA (no forward secrecy). With RSA key transport, whoever gets the server's private key - today by theft, later by quantum - decrypts every recorded session. Prefer ECDHE suites and remove TLS_RSA_* from the cipher suite order.
- **WSUS corp-wsus-old.contoso.com:8531** (High, QR-27): Certificate expired on 2026-05-01. Renew it; clients are either failing or ignoring validation.
- **WSUS corp-wsus-old.contoso.com:8531** (High, QR-25): Windows Server 2012 R2 is out of support. Replace the server; it gets no security updates and none of the post-quantum work.
- **Contoso Legacy CA** (Critical, QR-01): CA certificate signed with sha1RSA. SHA-1 collisions are practical today. Re-key the CA with SHA-256 or better, or retire it and move its templates.
- **Contoso Legacy CA** (High, QR-25): Windows Server 2012 R2 is out of support. Replace the server; it gets no security updates and none of the post-quantum work.
- **svc-scan** (Critical, QR-19): DES enabled. DES is removed from Windows Server 2025 and broken for decades. Clear "Use only Kerberos DES encryption types" and set msDS-SupportedEncryptionTypes to 0x18; replace the device if it only speaks DES.
- **WSUS BR-WSUS02:8530** (Critical, QR-16): WSUS over HTTP on port 8530. Clients that take updates over HTTP can be served malicious updates by anyone on the network path (WSUSpect-style attacks). Bind an HTTPS certificate, use port 8531 and set the GPO server URL to https://.
- **Domain Kerberos policy** (High, QR-21): Trust to fabrikam.local uses RC4 only. Enable AES on both sides of the trust (Active Directory Domains and Trusts, "The other domain supports Kerberos AES Encryption") and test cross-domain access.
- **gmsa-sqlprod$** (High, QR-17): RC4 explicitly enabled (msDS-SupportedEncryptionTypes 0x1C). RC4 service tickets can be cracked offline (Kerberoasting) and stay exposed to CVE-2026-20833. Fix the client, set 0x18 and reset the password.
- **NAS01$** (High, QR-17): RC4 explicitly enabled (msDS-SupportedEncryptionTypes 0x4). RC4 service tickets can be cracked offline (Kerberoasting) and stay exposed to CVE-2026-20833. Fix the client, set 0x18 and reset the password.
- **svc-backup** (High, QR-18): No AES keys: password last set 2010-03-22, before AES keys existed in this domain. Since the April 2026 Kerberos update the KDC defaults to AES only, so this account fails (events 204/209) unless RC4 is kept. Reset the password twice and test the service.
- **svc-crm** (High, QR-17): RC4 explicitly enabled (msDS-SupportedEncryptionTypes 0x1C). RC4 service tickets can be cracked offline (Kerberoasting) and stay exposed to CVE-2026-20833. Fix the client, set 0x18 and reset the password.
- **svc-oracle-kt** (High, QR-17): RC4 explicitly enabled (msDS-SupportedEncryptionTypes 0x4). RC4 service tickets can be cracked offline (Kerberoasting) and stay exposed to CVE-2026-20833. The KDC has already refused 58 requests (events 203/204). Fix the client, set 0x18 and reset the password.
- **svc-sapbw** (High, QR-17): RC4 explicitly enabled (msDS-SupportedEncryptionTypes 0x24). RC4 service tickets can be cracked offline (Kerberoasting) and stay exposed to CVE-2026-20833. Fix the client, set 0x18 and reset the password.
- **svc-sql-legacy** (High, QR-17): RC4 explicitly enabled (msDS-SupportedEncryptionTypes 0x4). RC4 service tickets can be cracked offline (Kerberoasting) and stay exposed to CVE-2026-20833. The KDC has already refused 112 requests (events 203/204). Fix the client, set 0x18 and reset the password.
- **svc-sql-legacy** (High, QR-18): No AES keys: password last set 2009-11-03, before AES keys existed in this domain. Since the April 2026 Kerberos update the KDC defaults to AES only, so this account fails (events 204/209) unless RC4 is kept. Reset the password twice and test the service.
- **WSUS BR-WSUS02:8530** (High, QR-25): Windows Server 2012 R2 is out of support. Replace the server; it gets no security updates and none of the post-quantum work.
- **Domain Kerberos policy** (Medium, QR-23): krbtgt password last set 2019-08-14. Rotate krbtgt (twice, with replication in between) so old ticket-signing keys, including any RC4 keys, are gone.

## Phase 1: Make the estate crypto-agile

Post-quantum algorithms on Windows live only in CNG and on current releases. Move templates to Key Storage Providers and schema v3+, and move TLS hosts to Windows Server 2025.

- **IIS hr.contoso.com:443** (High, QR-12): Windows Server 2019 has no TLS 1.3 in Schannel. Move IIS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 25 years of shelf life.
- **IIS legal-dms.contoso.com:443** (High, QR-12): Windows Server 2016 has no TLS 1.3 in Schannel. Move IIS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 15 years of shelf life.
- **RDP BR-DC01:3389** (High, QR-12): Windows Server 2016 has no TLS 1.3 in Schannel. Move RDP to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 15 years of shelf life.
- **RDP CORP-DC01:3389** (High, QR-12): Windows Server 2022 supports TLS 1.3 but not ML-KEM. Move RDP to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 15 years of shelf life.
- **RDP CORP-DC03:3389** (High, QR-12): Windows Server 2019 has no TLS 1.3 in Schannel. Move RDP to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 15 years of shelf life.
- **Contoso-EFS-Recovery** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **Contoso-User** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **IIS legal-dms.contoso.com:443** (Low, QR-25): Windows Server 2016 extended support ends 12 January 2027. Plan the upgrade to Windows Server 2025 with the TLS work below.
- **RDP BR-DC01:3389** (Low, QR-25): Windows Server 2016 extended support ends 12 January 2027. Plan the upgrade to Windows Server 2025 with the TLS work below.
- **LDAPS BR-DC01:636** (High, QR-12): Windows Server 2016 has no TLS 1.3 in Schannel. Move LDAPS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 7 years of shelf life.
- **LDAPS CORP-DC01:636** (High, QR-12): Windows Server 2022 supports TLS 1.3 but not ML-KEM. Move LDAPS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 7 years of shelf life.
- **LDAPS CORP-DC02:636** (High, QR-12): Windows Server 2022 supports TLS 1.3 but not ML-KEM. Move LDAPS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 7 years of shelf life.
- **LDAPS CORP-DC03:636** (High, QR-12): Windows Server 2019 has no TLS 1.3 in Schannel. Move LDAPS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 7 years of shelf life.
- **LDAPS BR-DC01:636** (Low, QR-25): Windows Server 2016 extended support ends 12 January 2027. Plan the upgrade to Windows Server 2025 with the TLS work below.
- **Contoso-CodeSigning** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **Contoso-SmartCard** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **Contoso-WSUS-Legacy** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **IIS intranet.contoso.com:443** (High, QR-12): Windows Server 2022 supports TLS 1.3 but not ML-KEM. Move IIS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 2 years of shelf life.
- **WSUS corp-wsus-old.contoso.com:8531** (High, QR-12): Windows Server 2012 R2 has no TLS 1.3 in Schannel. Move WSUS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 2 years of shelf life.
- **WSUS CORP-WSUS01:8531** (High, QR-12): Windows Server 2019 has no TLS 1.3 in Schannel. Move WSUS to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for 2 years of shelf life.
- **Contoso-WebServer** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **WebServer** (Medium, QR-06): Schema v1 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **Contoso Root CA** (Low, QR-25): Windows Server 2016 extended support ends 12 January 2027. Plan the upgrade to Windows Server 2025 with the TLS work below.
- **Contoso-Computer** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.
- **Contoso-KDC** (Medium, QR-06): Schema v2 template using a legacy CryptoAPI provider. ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.

## Phase 2: Stop harvest-now, decrypt-later

Traffic recorded today can be decrypted once a quantum computer exists. Turn on hybrid ML-KEM key exchange for TLS 1.3 where Windows supports it, most sensitive data first.

- **Contoso-SMIME** (High, QR-07): Encryption certificates (Secure Email) protect 25-year data with RSA 2048. Mail and files encrypted to these keys can be recorded now and opened later. AD CS's ML-DSA support is signature-only, so there is no post-quantum encryption template yet: use RSA 3072+, shorten validity, protect the CA database and archived keys, and track hybrid S/MIME. Archived private keys mean the CA database can decrypt every old message too.
- **Contoso-EFS-Recovery** (High, QR-07): Encryption certificates (File Recovery) protect 15-year data with RSA 2048. Mail and files encrypted to these keys can be recorded now and opened later. AD CS's ML-DSA support is signature-only, so there is no post-quantum encryption template yet: use RSA 3072+, shorten validity, protect the CA database and archived keys, and track hybrid S/MIME. Archived private keys mean the CA database can decrypt every old message too.
- **Contoso-User** (High, QR-07): Encryption certificates (Client Authentication, Secure Email, Encrypting File System) protect 15-year data with RSA 2048. Mail and files encrypted to these keys can be recorded now and opened later. AD CS's ML-DSA support is signature-only, so there is no post-quantum encryption template yet: use RSA 3072+, shorten validity, protect the CA database and archived keys, and track hybrid S/MIME. Archived private keys mean the CA database can decrypt every old message too.
- **RDP CORP-PAW-JMP01:3389** (High, QR-13): Hybrid ML-KEM available on Windows Server 2025 but not in use. Enable the post-quantum TLS 1.3 groups (off by default since the July 2026 update) and confirm clients negotiate them. This is the quickest win in the report.

## Phase 3: Build the post-quantum PKI

Stand up a parallel ML-DSA hierarchy on Windows Server 2025 (AD CS cannot convert an existing CA), pilot ML-DSA templates and reissue as clients support them.

- **IIS hr.contoso.com:443** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **IIS legal-dms.contoso.com:443** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **RDP BR-DC01:3389** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **RDP CORP-DC01:3389** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **RDP CORP-DC03:3389** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **RDP CORP-PAW-JMP01:3389** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **PKINIT (smart cards and Windows Hello)** (High, QR-22): PKINIT relies on RSA 2048 for 4490 users. A recorded PKINIT exchange can reveal the session key for the TGT once RSA or Diffie-Hellman falls. Windows has no post-quantum PKINIT yet: keep KDC certificates short-lived and RSA 3072+, prefer Windows Hello key trust or cloud Kerberos trust, and track Microsoft's plans.
- **LDAPS BR-DC01:636** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **LDAPS CORP-DC01:636** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **LDAPS CORP-DC02:636** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **LDAPS CORP-DC03:636** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **Contoso-CodeSigning** (Low, QR-09): Certificates issued today are valid for 1095 days. Shorter validity shrinks the window in which a 2030 quantum computer could abuse a classical certificate.
- **Contoso-SmartCard** (Low, QR-09): Certificates issued today are valid for 1095 days. Shorter validity shrinks the window in which a 2030 quantum computer could abuse a classical certificate.
- **Contoso-WSUS-Legacy** (Low, QR-09): Certificates issued today are valid for 1095 days. Shorter validity shrinks the window in which a 2030 quantum computer could abuse a classical certificate.
- **IIS intranet.contoso.com:443** (Low, QR-24): ECDSA P-256 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **WSUS corp-wsus-old.contoso.com:8531** (Low, QR-24): RSA 1024 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **WSUS CORP-WSUS01:8531** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **Contoso Issuing CA 01** (High, QR-04): RSA 2048 CA trusted until 2031-05-10, after 2030. Anyone with a quantum computer could forge certificates from this CA's public key. Build the ML-DSA hierarchy in parallel and move templates to it.
- **Contoso Root CA** (High, QR-04): RSA 4096 CA trusted until 2036-03-01, after 2030 and past 2035, when NIST disallows RSA and ECC. Anyone with a quantum computer could forge certificates from this CA's public key. Build the ML-DSA hierarchy in parallel and move templates to it.
- **Contoso Issuing CA 01** (Medium, QR-03): RSA 2048 gives 112-bit security, which NIST deprecates after 2030. Do not renew at RSA 2048. Any interim classical CA should be RSA 3072+ or ECDSA P-384.
- **Contoso Legacy CA** (Medium, QR-04): RSA 2048 CA expires 2029-02-01. Do not renew it with an RSA key. Move its templates to the post-quantum hierarchy before it expires.
- **IIS claims.contoso.com:443** (Low, QR-24): RSA 3072 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.
- **IIS pki.contoso.com:443** (Low, QR-24): RSA 2048 server certificate. Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.

## Phase 4: Retire classical trust before 2035

NIST disallows RSA and ECC signatures from 2035. Remove the classical roots from trust stores and NTAuth once the post-quantum hierarchy carries the load.

- **Contoso Issuing CA 01** (Medium, QR-26): Classical CA in trust stores. Once its replacement is live, remove it from NTAuth, the Trusted Root / Intermediate GPOs and Intune trusted-certificate profiles, no later than 2035-01-01.
- **Contoso Legacy CA** (Medium, QR-26): Classical CA in trust stores. Once its replacement is live, remove it from NTAuth, the Trusted Root / Intermediate GPOs and Intune trusted-certificate profiles, no later than 2035-01-01.
- **Contoso Root CA** (Medium, QR-26): Classical CA in trust stores. Once its replacement is live, remove it from NTAuth, the Trusted Root / Intermediate GPOs and Intune trusted-certificate profiles, no later than 2035-01-01.

---
Generated by Quantum-Ready Windows PKI v1.0.0. Read-only assessment; verify each change in a test environment first.

