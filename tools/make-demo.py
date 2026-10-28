#!/usr/bin/env python3
"""Regenerates demo/sample-estate.json: a fictional Contoso Windows estate (AD CS, TLS endpoints, Kerberos)."""
import json, os, random

random.seed(5)
OID = {
    'serverAuth': '1.3.6.1.5.5.7.3.1', 'clientAuth': '1.3.6.1.5.5.7.3.2', 'codeSigning': '1.3.6.1.5.5.7.3.3',
    'secureEmail': '1.3.6.1.5.5.7.3.4', 'efs': '1.3.6.1.4.1.311.10.3.4', 'efsRecovery': '1.3.6.1.4.1.311.10.3.4.1',
    'smartcardLogon': '1.3.6.1.4.1.311.20.2.2', 'kdcAuth': '1.3.6.1.5.2.3.5', 'ocspSigning': '1.3.6.1.5.5.7.3.9',
    'rdpAuth': '1.3.6.1.4.1.311.54.1.2',
}

def cert(subject, issuer, alg, size, sig, nb, na, self_signed=False, template=None):
    tp = ''.join(random.choice('0123456789ABCDEF') for _ in range(40))
    c = {'subject': subject, 'issuer': issuer, 'keyAlgorithm': alg, 'keySize': size, 'signatureAlgorithm': sig,
         'notBefore': nb, 'notAfter': na, 'thumbprint': tp, 'selfSigned': self_signed}
    if template: c['template'] = template
    return c

cas = [
    {'name': 'Contoso Root CA', 'host': 'CORP-ROOTCA', 'os': 'Windows Server 2016', 'type': 'Root', 'offline': True,
     'cert': cert('CN=Contoso Root CA', 'CN=Contoso Root CA', 'RSA', 4096, 'sha256RSA', '2016-03-01', '2036-03-01', True), 'publishedTemplates': []},
    {'name': 'Contoso Issuing CA 01', 'host': 'CORP-CA01', 'os': 'Windows Server 2019', 'type': 'Issuing', 'offline': False,
     'cert': cert('CN=Contoso Issuing CA 01', 'CN=Contoso Root CA', 'RSA', 2048, 'sha256RSA', '2021-05-10', '2031-05-10'),
     'publishedTemplates': ['Contoso-WebServer', 'Contoso-WebServer-v4', 'Contoso-KDC', 'Contoso-Computer', 'Contoso-User', 'Contoso-EFS-Recovery',
                            'Contoso-SMIME', 'Contoso-CodeSigning', 'Contoso-SmartCard', 'Contoso-RDP', 'Contoso-OCSP']},
    {'name': 'Contoso Legacy CA', 'host': 'CORP-CA-OLD', 'os': 'Windows Server 2012 R2', 'type': 'Issuing', 'offline': False,
     'cert': cert('CN=Contoso Legacy CA', 'CN=Contoso Legacy CA', 'RSA', 2048, 'sha1RSA', '2014-02-01', '2029-02-01', True),
     'publishedTemplates': ['WebServer', 'Contoso-WSUS-Legacy']},
    {'name': 'Contoso PQC Pilot CA', 'host': 'CORP-PQCA01', 'os': 'Windows Server 2025', 'type': 'Root', 'offline': False,
     'cert': cert('CN=Contoso PQC Pilot CA', 'CN=Contoso PQC Pilot CA', 'ML-DSA-65', 0, 'ML-DSA-65', '2026-06-15', '2041-06-15', True),
     'publishedTemplates': ['PQC-WebServer-MLDSA']},
]

def tpl(name, ver, alg, size, hash_, provider, ekus, ku, days, issued, archival=False, classification=None, display=None):
    t = {'name': name, 'displayName': display or name.replace('-', ' '), 'schemaVersion': ver, 'keyAlgorithm': alg, 'minKeySize': size,
         'hashAlgorithm': hash_, 'provider': provider, 'ekus': [OID[e] for e in ekus], 'keyUsage': ku, 'validityDays': days,
         'archival': archival, 'issuedLast90Days': issued}
    if classification: t['classification'] = classification
    return t

DS, KE = 'DigitalSignature', 'KeyEncipherment'
templates = [
    tpl('Contoso-WebServer', 2, 'RSA', 2048, 'SHA256', 'CSP', ['serverAuth'], [DS, KE], 730, 140),
    tpl('Contoso-WebServer-v4', 4, 'RSA', 3072, 'SHA256', 'KSP', ['serverAuth'], [DS], 397, 85),
    tpl('Contoso-KDC', 2, 'RSA', 2048, 'SHA256', 'CSP', ['clientAuth', 'serverAuth', 'smartcardLogon', 'kdcAuth'], [DS, KE], 365, 6, display='Contoso Kerberos Authentication'),
    tpl('Contoso-Computer', 2, 'RSA', 2048, 'SHA256', 'CSP', ['clientAuth', 'serverAuth'], [DS, KE], 365, 2410),
    tpl('Contoso-User', 2, 'RSA', 2048, 'SHA256', 'CSP', ['clientAuth', 'secureEmail', 'efs'], [DS, KE], 365, 3120, archival=True, classification='Restricted'),
    tpl('Contoso-EFS-Recovery', 2, 'RSA', 2048, 'SHA256', 'CSP', ['efsRecovery'], [KE], 1825, 2, archival=True, classification='Restricted'),
    tpl('Contoso-SMIME', 3, 'RSA', 2048, 'SHA256', 'KSP', ['secureEmail'], [DS, KE], 730, 905, archival=True, classification='Regulated', display='Contoso Legal & Finance S/MIME'),
    tpl('Contoso-CodeSigning', 2, 'RSA', 3072, 'SHA256', 'CSP', ['codeSigning'], [DS], 1095, 12),
    tpl('Contoso-SmartCard', 2, 'RSA', 2048, 'SHA256', 'CSP', ['smartcardLogon', 'clientAuth'], [DS, KE], 1095, 410),
    tpl('Contoso-RDP', 3, 'RSA', 2048, 'SHA256', 'KSP', ['rdpAuth'], [DS, KE], 365, 262),
    tpl('Contoso-OCSP', 3, 'RSA', 2048, 'SHA256', 'KSP', ['ocspSigning'], [DS], 14, 52),
    tpl('WebServer', 1, 'RSA', 1024, 'SHA1', 'CSP', ['serverAuth'], [DS, KE], 730, 9, display='Web Server (built-in v1)'),
    tpl('Contoso-WSUS-Legacy', 2, 'RSA', 2048, 'SHA1', 'CSP', ['serverAuth'], [DS, KE], 1095, 3),
    tpl('PQC-WebServer-MLDSA', 4, 'ML-DSA-65', 0, 'ML-DSA-65', 'KSP', ['serverAuth'], [DS], 365, 4, display='PQC Web Server (ML-DSA-65 pilot)'),
]

ISS = 'CN=Contoso Issuing CA 01'
def ep(host, service, port, os_, proto, suite, kex, c, classification=None, site=None, also=None):
    e = {'host': host, 'service': service, 'port': port, 'os': os_, 'protocol': proto, 'cipherSuite': suite, 'keyExchange': kex, 'cert': c}
    if classification: e['classification'] = classification
    if site: e['site'] = site
    if also: e['alsoAccepts'] = also
    return e

T13 = 'TLS_AES_256_GCM_SHA384'
EC12 = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
def kdc(dc, nb='2026-02-11', na='2027-02-11'): return cert(f'CN={dc}.contoso.com', ISS, 'RSA', 2048, 'sha256RSA', nb, na, template='Contoso-KDC')
def rdp_self(h): return cert(f'CN={h}.contoso.com', f'CN={h}.contoso.com', 'RSA', 2048, 'sha256RSA', '2026-04-02', '2026-10-02', True)
def rdp_ca(h): return cert(f'CN={h}.contoso.com', ISS, 'RSA', 2048, 'sha256RSA', '2026-03-01', '2027-03-01', template='Contoso-RDP')
def web(h, alg='RSA', size=2048, sig='sha256RSA', nb='2025-09-01', na='2027-09-01', iss=ISS, t='Contoso-WebServer'):
    return cert(f'CN={h}', iss, alg, size, sig, nb, na, template=t)

endpoints = [
    ep('CORP-DC01', 'LDAPS', 636, 'Windows Server 2022', 'TLS 1.3', T13, 'x25519', kdc('CORP-DC01')),
    ep('CORP-DC02', 'LDAPS', 636, 'Windows Server 2022', 'TLS 1.3', T13, 'x25519', kdc('CORP-DC02')),
    ep('CORP-DC03', 'LDAPS', 636, 'Windows Server 2019', 'TLS 1.2', EC12, 'secp384r1', kdc('CORP-DC03', '2025-12-01', '2026-12-01')),
    ep('BR-DC01', 'LDAPS', 636, 'Windows Server 2016', 'TLS 1.2', 'TLS_RSA_WITH_AES_256_CBC_SHA256', 'RSA', kdc('BR-DC01', '2026-01-20', '2027-01-20'), site='Branch-Denver'),
    ep('CORP-DC01', 'RDP', 3389, 'Windows Server 2022', 'TLS 1.3', T13, 'x25519', rdp_ca('CORP-DC01'), classification='Restricted'),
    ep('CORP-DC03', 'RDP', 3389, 'Windows Server 2019', 'TLS 1.2', EC12, 'secp384r1', rdp_self('CORP-DC03'), classification='Restricted'),
    ep('BR-DC01', 'RDP', 3389, 'Windows Server 2016', 'TLS 1.2', EC12, 'secp256r1', rdp_self('BR-DC01'), classification='Restricted', site='Branch-Denver'),
    ep('CORP-PAW-JMP01', 'RDP', 3389, 'Windows Server 2025', 'TLS 1.3', T13, 'x25519', rdp_ca('CORP-PAW-JMP01'), classification='Restricted'),
    ep('hr.contoso.com', 'IIS', 443, 'Windows Server 2019', 'TLS 1.2', EC12, 'secp256r1', web('hr.contoso.com'), classification='Regulated', site='HR and payroll portal'),
    ep('legal-dms.contoso.com', 'IIS', 443, 'Windows Server 2016', 'TLS 1.2', EC12, 'secp256r1', web('legal-dms.contoso.com', nb='2025-03-15', na='2027-03-15'),
       classification='Restricted', site='Legal document management', also=['TLS 1.0', 'TLS 1.1']),
    ep('claims.contoso.com', 'IIS', 443, 'Windows Server 2025', 'TLS 1.3', T13, 'X25519MLKEM768', web('claims.contoso.com', size=3072, nb='2026-07-20', na='2027-08-20', t='Contoso-WebServer-v4'),
       classification='Regulated', site='Insurance claims'),
    ep('intranet.contoso.com', 'IIS', 443, 'Windows Server 2022', 'TLS 1.3', T13, 'x25519', web('intranet.contoso.com', alg='ECDSA', size=256, sig='sha256ECDSA'), classification='Internal', site='Intranet'),
    ep('pki.contoso.com', 'IIS', 443, 'Windows Server 2019', 'TLS 1.2', EC12, 'secp256r1', web('pki.contoso.com', nb='2024-11-01', na='2026-12-15'), classification='Public', site='CRL and AIA distribution'),
    ep('pqc-lab.contoso.com', 'IIS', 443, 'Windows Server 2025', 'TLS 1.3', T13, 'X25519MLKEM768',
       web('pqc-lab.contoso.com', alg='ML-DSA-65', size=0, sig='ML-DSA-65', nb='2026-09-01', na='2027-09-01', iss='CN=Contoso PQC Pilot CA', t='PQC-WebServer-MLDSA'), classification='Internal', site='PQC pilot'),
    ep('CORP-WSUS01', 'WSUS', 8531, 'Windows Server 2019', 'TLS 1.2', EC12, 'secp256r1', web('corp-wsus01.contoso.com', nb='2026-01-05', na='2028-01-05')),
    ep('BR-WSUS02', 'WSUS', 8530, 'Windows Server 2012 R2', 'HTTP', None, None, None, site='Branch-Denver'),
    ep('corp-wsus-old.contoso.com', 'WSUS', 8531, 'Windows Server 2012 R2', 'TLS 1.2', 'TLS_RSA_WITH_AES_128_CBC_SHA', 'RSA',
       web('corp-wsus-old.contoso.com', size=1024, sig='sha1RSA', nb='2023-05-01', na='2026-05-01', iss='CN=Contoso Legacy CA', t='WebServer')),
]

def acct(sam, typ, enc, pwd, des=False, events=None, note=None):
    a = {'samAccountName': sam, 'type': typ, 'spn': True, 'supportedEncTypes': enc, 'pwdLastSet': pwd, 'useDesKeyOnly': des, 'kdcEvents': events or {}}
    if note: a['note'] = note
    return a

accounts = [
    acct('svc-sql-legacy', 'user', 0x4, '2009-11-03', events={'203': 112}, note='SQL Server 2008 R2 reporting'),
    acct('svc-backup', 'user', None, '2010-03-22', events={'204': 37}, note='Backup agent'),
    acct('svc-oracle-kt', 'user', 0x4, '2015-06-30', events={'203': 58}, note='Linux keytab for Oracle SSO'),
    acct('svc-sapbw', 'user', 0x24, '2019-04-11', events={'201': 0}, note='SAP BW (RC4 kept as a workaround)'),
    acct('svc-crm', 'user', 0x1C, '2022-02-14'),
    acct('svc-scan', 'user', 0x3, '2012-08-09', des=True, note='Multifunction printer scan-to-folder'),
    acct('NAS01$', 'computer', 0x4, '2026-09-30', events={'201': 14}, note='Linux NAS joined with Samba'),
    acct('svc-web-hr', 'user', 0x18, '2024-05-02'),
    acct('svc-iis-intranet', 'user', None, '2023-01-18'),
    acct('gmsa-sqlprod$', 'gmsa', 0x1C, '2026-10-01'),
]
# Healthy background accounts
for i in range(1, 54):
    accounts.append(acct(f'svc-app{i:02d}', 'user', random.choice([None, 0x18, 0x18, 0x10]), f'20{random.randint(18, 26)}-{random.randint(1, 9):02d}-{random.randint(10, 28)}'))

estate = {
    'label': 'Contoso (fictional demo estate)', 'now': '2026-10-27', 'forest': 'contoso.com', 'domain': 'contoso.com',
    'cas': cas, 'templates': templates, 'endpoints': endpoints,
    'kerberos': {
        'domainFunctionalLevel': 'Windows Server 2016', 'aesKeysSince': '2011-06-14', 'defaultDomainSupportedEncTypes': None,
        'krbtgtPwdLastSet': '2019-08-14', 'accounts': accounts,
        'trusts': [{'name': 'fabrikam.local', 'type': 'External', 'direction': 'Bidirectional', 'supportedEncTypes': 0x4},
                   {'name': 'tailspin.com', 'type': 'Forest', 'direction': 'Outbound', 'supportedEncTypes': 0x18}],
        'pkinit': {'kdcTemplate': 'Contoso-KDC', 'smartCardUsers': 410, 'whfbCertTrustUsers': 1250, 'whfbKeyTrustUsers': 2830},
    },
}
out = os.path.join(os.path.dirname(__file__), '..', 'demo', 'sample-estate.json')
with open(out, 'w', encoding='utf-8') as f: json.dump(estate, f, indent=1)
print('wrote', out, len(endpoints), 'endpoints', len(templates), 'templates', len(accounts), 'accounts')
