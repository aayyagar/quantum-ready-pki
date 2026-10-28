<#
.SYNOPSIS
    Quantum-Ready Windows PKI - inventories the classical cryptography across a Windows and Active
    Directory estate that a future quantum computer could break, and ranks it by how long the data it
    protects has to stay secret.

.DESCRIPTION
    General quantum-readiness scanners look at code and network traffic. This tool looks at the places
    Windows estates actually keep their keys:
      * AD CS certification authorities (root and issuing) and the certificate templates they publish,
      * TLS on LDAPS, RDP, IIS and WSUS - certificate, protocol, key exchange, and whether the host's
        Windows version can do hybrid ML-KEM key exchange,
      * Kerberos: RC4 and DES on service accounts and trusts, accounts with no AES keys, KDC events
        201-209, krbtgt age, and PKINIT (smart cards and Windows Hello for Business).

    Each quantum-vulnerable asset gets a "start by" date using Mosca's inequality: data that must stay
    secret for X years, behind a migration that takes Y years, is already at risk if X + Y is more than
    the years left until a cryptographically relevant quantum computer (-QuantumYear). Signatures (CAs,
    templates, certificates) are dated by how long they will still be trusted.

    Outputs: an HTML report, a CycloneDX 1.6 cryptography bill of materials (CBOM), an inventory CSV,
    a phased migration roadmap (Markdown) and the full findings as JSON.

    It is READ-ONLY. It reads Active Directory over LDAP and opens TLS handshakes; it changes nothing.

.PARAMETER Demo
    Assess the bundled fictional Contoso estate. Needs no connections.

.PARAMETER InputPath
    Assess an offline snapshot (same format as demo/sample-estate.json).

.PARAMETER QuantumYear
    The year you plan for a cryptographically relevant quantum computer. Default 2030, the year NIST's
    transition timeline (IR 8547) deprecates 112-bit RSA and ECC. Use 2035, when they are disallowed,
    for a less conservative plan.

.PARAMETER ShelfLife
    Hashtable of classification -> years the data must stay secret. Defaults:
    Public 0, Internal 2, Confidential 7, Restricted 15, Regulated 25.

.PARAMETER MigrationYears
    Hashtable overriding migration-time estimates: CaHierarchy 3, Template 1, OsUpgrade 1.5,
    TlsConfig 0.25, CertReissue 1, Pkinit 2.

.PARAMETER Endpoints
    Extra endpoints to probe in live mode, as host:port[:service][:classification], for example
    'hr.contoso.com:443:IIS:Regulated'. Domain controllers (LDAPS, RDP) are found automatically.

.PARAMETER OutputPath
    Report folder. Default .\QuantumReadiness_<timestamp>

.EXAMPLE
    .\Invoke-QuantumReadyPki.ps1 -Demo

.EXAMPLE
    .\Invoke-QuantumReadyPki.ps1 -Endpoints 'hr.contoso.com:443:IIS:Regulated','wsus01:8531:WSUS' -QuantumYear 2032

.NOTES
    Version : 1.0.0
    Requires: PowerShell 7+. Live mode: Windows, domain-joined, a domain account (no admin rights needed).
    License : MIT
    Author  : Akhilesh Ayyagari
#>
#Requires -Version 7.0
[CmdletBinding()]
param(
    [switch]$Demo,
    [string]$InputPath,
    [ValidateRange(2026, 2050)][int]$QuantumYear = 2030,
    [hashtable]$ShelfLife = @{},
    [hashtable]$MigrationYears = @{},
    [string[]]$Endpoints = @(),
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$script:QrVersion = '1.0.0'

$script:DefaultShelfLife = [ordered]@{ Public = 0; Internal = 2; Confidential = 7; Restricted = 15; Regulated = 25 }
$script:DefaultMigration = [ordered]@{ CaHierarchy = 3; Template = 1; OsUpgrade = 1.5; TlsConfig = 0.25; CertReissue = 1; Pkinit = 2 }
$script:ServiceClassification = @{ LDAPS = 'Confidential'; RDP = 'Confidential'; IIS = 'Internal'; WSUS = 'Internal' }
$script:NistDisallowed = [datetime]'2035-01-01'
$script:Eku = @{
    '1.3.6.1.5.5.7.3.1' = 'Server Authentication'; '1.3.6.1.5.5.7.3.2' = 'Client Authentication'; '1.3.6.1.5.5.7.3.3' = 'Code Signing'
    '1.3.6.1.5.5.7.3.4' = 'Secure Email'; '1.3.6.1.4.1.311.10.3.4' = 'Encrypting File System'; '1.3.6.1.4.1.311.10.3.4.1' = 'File Recovery'
    '1.3.6.1.4.1.311.20.2.2' = 'Smart Card Logon'; '1.3.6.1.5.2.3.5' = 'KDC Authentication'; '1.3.6.1.5.5.7.3.9' = 'OCSP Signing'
    '1.3.6.1.4.1.311.54.1.2' = 'Remote Desktop Authentication'
}
$script:EncryptionEkus = @('1.3.6.1.5.5.7.3.4', '1.3.6.1.4.1.311.10.3.4', '1.3.6.1.4.1.311.10.3.4.1')
$script:PkinitEkus = @('1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.5')
$script:EncTypeBits = @(@(0x1, 'DES-CBC-CRC'), @(0x2, 'DES-CBC-MD5'), @(0x4, 'RC4-HMAC'), @(0x8, 'AES128'), @(0x10, 'AES256'), @(0x20, 'AES256-SK'))
$script:PhaseNames = [ordered]@{
    0 = 'Fix what is broken today'
    1 = 'Make the estate crypto-agile'
    2 = 'Stop harvest-now, decrypt-later'
    3 = 'Build the post-quantum PKI'
    4 = 'Retire classical trust before 2035'
}
$script:PhaseText = @{
    0 = 'Classical weaknesses an attacker can use with ordinary computers: SHA-1, short RSA keys, RC4 and DES, TLS 1.0/1.1, RSA key transport, cleartext WSUS. Every later phase depends on these being gone.'
    1 = 'Post-quantum algorithms on Windows live only in CNG and on current releases. Move templates to Key Storage Providers and schema v3+, and move TLS hosts to Windows Server 2025.'
    2 = 'Traffic recorded today can be decrypted once a quantum computer exists. Turn on hybrid ML-KEM key exchange for TLS 1.3 where Windows supports it, most sensitive data first.'
    3 = 'Stand up a parallel ML-DSA hierarchy on Windows Server 2025 (AD CS cannot convert an existing CA), pilot ML-DSA templates and reissue as clients support them.'
    4 = 'NIST disallows RSA and ECC signatures from 2035. Remove the classical roots from trust stores and NTAuth once the post-quantum hierarchy carries the load.'
}

function Get-Prop {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $Default } }
    $p = $Object.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return $p.Value } else { return $Default }
}

# ---------------------------------------------------------------------------------------
# Algorithms, operating systems and encodings
# ---------------------------------------------------------------------------------------
function Get-QrKeyClass {
    <# Classifies a public key: family, display label, quantum safety and classical strength. #>
    param([string]$Algorithm, [int]$Size = 0)
    $a = "$Algorithm".ToUpperInvariant()
    switch -Regex ($a) {
        '^ML-DSA' { return [pscustomobject]@{ Family = 'ML-DSA'; Label = $Algorithm; QuantumSafe = $true; Classical = 'OK'; Bits = 0 } }
        '^ML-KEM' { return [pscustomobject]@{ Family = 'ML-KEM'; Label = $Algorithm; QuantumSafe = $true; Classical = 'OK'; Bits = 0 } }
        '^RSA' {
            $c = if ($Size -lt 2048) { 'Broken' } elseif ($Size -lt 3072) { 'Until2030' } else { 'OK' }
            return [pscustomobject]@{ Family = 'RSA'; Label = "RSA $Size"; QuantumSafe = $false; Classical = $c; Bits = $Size }
        }
        '^(EC|ECDSA|ECDH)' {
            $curve = switch ($Size) { 256 { 'P-256' } 384 { 'P-384' } 521 { 'P-521' } default { "$Size-bit" } }
            $c = if ($Size -lt 224) { 'Broken' } else { 'OK' }
            return [pscustomobject]@{ Family = 'ECC'; Label = "ECDSA $curve"; QuantumSafe = $false; Classical = $c; Bits = $Size }
        }
        default { return [pscustomobject]@{ Family = 'Unknown'; Label = ($Algorithm ? $Algorithm : 'Unknown'); QuantumSafe = $false; Classical = 'Unknown'; Bits = $Size } }
    }
}

function Test-QrWeakHash { param([string]$SignatureAlgorithm) return ("$SignatureAlgorithm" -match '(?i)sha-?1|md5|md2') }

function Get-QrOsPqc {
    <# What a Windows release can do: TLS 1.3 in Schannel, hybrid ML-KEM key exchange, an ML-DSA CA. #>
    param([string]$OperatingSystem)
    $o = "$OperatingSystem"
    $r = [ordered]@{ Os = $o; Tls13 = $false; HybridMlKem = $false; MlDsaCa = $false; Support = 'Supported'; Note = '' }
    switch -Regex ($o) {
        'Server 2025' { $r.Tls13 = $true; $r.HybridMlKem = $true; $r.MlDsaCa = $true; $r.Note = 'Hybrid ML-KEM for TLS 1.3 since the July 2026 update (off by default); ML-DSA CA since KB5087539 (May 2026)'; break }
        'Windows 11' { $r.Tls13 = $true; $r.HybridMlKem = $true; $r.Note = 'Hybrid ML-KEM for TLS 1.3 since the July 2026 update (off by default)'; break }
        'Server 2022' { $r.Tls13 = $true; $r.Note = 'TLS 1.3, but no ML-KEM key exchange'; break }
        'Server 2019|Windows 10' { $r.Note = 'No TLS 1.3 in Schannel'; break }
        'Server 2016' { $r.Note = 'No TLS 1.3; extended support ends 12 January 2027'; $r.Support = 'EndingSoon'; break }
        'Server 20(12|08)|Server 2003' { $r.Note = 'Out of support'; $r.Support = 'Unsupported'; break }
        default { $r.Note = 'Not a Windows release this tool knows'; $r.Support = 'Unknown' }
    }
    [pscustomobject]$r
}

function ConvertFrom-QrEncTypes {
    <# Decodes msDS-SupportedEncryptionTypes into names. #>
    param($Value)
    if ($null -eq $Value) { return @() }
    $v = [int]$Value
    @($script:EncTypeBits | Where-Object { $v -band $_[0] } | ForEach-Object { $_[1] })
}

function ConvertFrom-QrPkiPeriod {
    <# Decodes pKIExpirationPeriod / pKIOverlapPeriod (8-byte negative FILETIME interval) into days. #>
    param([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -ne 8) { return $null }
    $ticks = - [BitConverter]::ToInt64($Bytes, 0)
    [math]::Round($ticks / 864000000000, 0)
}

function ConvertFrom-QrTemplatePolicy {
    <# Parses msPKI-RA-Application-Policies on schema v3+ templates (name`type`value triplets) into
       the key algorithm and hash algorithm, for example RSA / SHA256 or ML-DSA-65. #>
    param([string]$Value)
    $r = @{}
    if (-not $Value) { return [pscustomobject]@{ KeyAlgorithm = $null; HashAlgorithm = $null } }
    $parts = $Value.Trim('`') -split '`'
    for ($i = 0; $i + 2 -lt $parts.Count + 1 -and $i + 2 -le $parts.Count - 1; $i += 3) { $r[$parts[$i]] = $parts[$i + 2] }
    [pscustomobject]@{ KeyAlgorithm = $r['msPKI-Asymmetric-Algorithm']; HashAlgorithm = $r['msPKI-Hash-Algorithm'] }
}

# ---------------------------------------------------------------------------------------
# Time: Mosca's inequality and urgency
# ---------------------------------------------------------------------------------------
function Get-QrYears { param([datetime]$From, [datetime]$To) [math]::Round(($To - $From).TotalDays / 365.25, 1) }

function Get-QrShelfYears {
    param([string]$Classification, [hashtable]$Map)
    if ($Map.Contains($Classification)) { return [double]$Map[$Classification] }
    return [double]$Map['Internal']
}

function Get-QrStartBy {
    <# Latest date the migration can start and still finish in time.
       Confidentiality (harvest now, decrypt later): Q - migration - shelf life.
       Authenticity (forgery once Q arrives): Q - migration - remaining trust (validity of certificates
       still to be issued). Returns $null when there is nothing to protect. #>
    param([ValidateSet('Confidentiality', 'Authenticity')][string]$Kind, [datetime]$QuantumDate, [double]$MigrationYears, [double]$ShelfYears = 0, [double]$ValidityYears = 0)
    $lead = $MigrationYears + $(if ($Kind -eq 'Confidentiality') { $ShelfYears } else { $ValidityYears })
    if ($Kind -eq 'Confidentiality' -and $ShelfYears -le 0) { return $null }
    $QuantumDate.AddDays(-[math]::Round($lead * 365.25))
}

function Get-QrUrgency {
    param($StartBy, [datetime]$Now)
    if ($null -eq $StartBy) { return 'None' }
    $s = [datetime]$StartBy
    if ($s -lt $Now) { 'Overdue' } elseif ($s -lt $Now.AddYears(1)) { 'Now' } elseif ($s -lt $Now.AddYears(3)) { 'Next' } else { 'Later' }
}

# ---------------------------------------------------------------------------------------
# Asset assessment
# ---------------------------------------------------------------------------------------
function New-QrIssue {
    param([string]$Code, [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity, [int]$Phase, [string]$Title, [string]$Fix, [switch]$Classical)
    [pscustomobject]@{ Code = $Code; Severity = $Severity; Phase = $Phase; Title = $Title; Fix = $Fix; Classical = [bool]$Classical }
}

function New-QrAsset {
    param([string]$Category, [string]$Name, [string]$Host_, [string]$Detail)
    [pscustomobject][ordered]@{
        Id = "$Category|$Name"; Category = $Category; Name = $Name; Host = $Host_; Detail = $Detail; Os = $null
        Algorithm = $null; Signature = $null; KeyExchange = $null; QuantumVulnerable = $false; QuantumSafeParts = @()
        Classification = $null; ShelfLifeYears = 0; ProtectedUntil = $null; TrustUntil = $null
        Exposure = 'None'; MigrationYears = 0; ConfidentialityStartBy = $null; AuthenticityStartBy = $null
        StartBy = $null; Urgency = 'None'; YearsLate = 0; PqcPath = ''; Issues = [System.Collections.Generic.List[object]]::new(); Extra = @{}
    }
}

function Complete-QrAsset {
    param($Asset, [datetime]$Now)
    $dates = @($Asset.ConfidentialityStartBy, $Asset.AuthenticityStartBy | Where-Object { $_ })
    if ($dates.Count) { $Asset.StartBy = ($dates | Sort-Object | Select-Object -First 1) }
    $Asset.Urgency = Get-QrUrgency -StartBy $Asset.StartBy -Now $Now
    if ($Asset.Urgency -eq 'Overdue') { $Asset.YearsLate = Get-QrYears -From ([datetime]$Asset.StartBy) -To $Now }
    $e = @()
    if ($Asset.ConfidentialityStartBy) { $e += 'Confidentiality' }
    if ($Asset.AuthenticityStartBy) { $e += 'Authenticity' }
    $Asset.Exposure = if ($e.Count -eq 2) { 'Both' } elseif ($e.Count) { $e[0] } else { 'None' }
    foreach ($k in 'ConfidentialityStartBy', 'AuthenticityStartBy', 'StartBy', 'ProtectedUntil', 'TrustUntil') {
        if ($Asset.$k -is [datetime]) { $Asset.$k = $Asset.$k.ToString('yyyy-MM-dd') }
    }
    $Asset
}

function Add-QrOsIssues {
    param($Asset, $OsInfo)
    if ($OsInfo.Support -eq 'Unsupported') { $Asset.Issues.Add((New-QrIssue 'QR-25' 'High' 0 "$($OsInfo.Os) is out of support" 'Replace the server; it gets no security updates and none of the post-quantum work.' -Classical)) }
    elseif ($OsInfo.Support -eq 'EndingSoon') { $Asset.Issues.Add((New-QrIssue 'QR-25' 'Low' 1 "$($OsInfo.Os) extended support ends 12 January 2027" 'Plan the upgrade to Windows Server 2025 with the TLS work below.' -Classical)) }
}

function Test-QrCa {
    param($Ca, [datetime]$Now, [datetime]$QuantumDate, [hashtable]$Migration)
    $c = Get-Prop $Ca 'cert'
    $a = New-QrAsset -Category 'CA' -Name (Get-Prop $Ca 'name') -Host_ (Get-Prop $Ca 'host') -Detail ("$(Get-Prop $Ca 'type' 'Issuing') CA" + $(if (Get-Prop $Ca 'offline' $false) { ' (offline)' } else { '' }))
    $os = Get-QrOsPqc (Get-Prop $Ca 'os'); $a.Os = $os.Os
    $k = Get-QrKeyClass (Get-Prop $c 'keyAlgorithm') ([int](Get-Prop $c 'keySize' 0))
    $a.Algorithm = $k.Label; $a.Signature = Get-Prop $c 'signatureAlgorithm'
    $na = [datetime](Get-Prop $c 'notAfter'); $a.TrustUntil = $na
    $a.Extra = @{ PublishedTemplates = @(Get-Prop $Ca 'publishedTemplates' @()); NotBefore = Get-Prop $c 'notBefore'; Subject = Get-Prop $c 'subject'; Thumbprint = Get-Prop $c 'thumbprint' }
    Add-QrOsIssues $a $os
    if (Test-QrWeakHash $a.Signature) { $a.Issues.Add((New-QrIssue 'QR-01' 'Critical' 0 "CA certificate signed with $($a.Signature)" 'SHA-1 collisions are practical today. Re-key the CA with SHA-256 or better, or retire it and move its templates.' -Classical)) }
    if ($k.Classical -eq 'Broken') { $a.Issues.Add((New-QrIssue 'QR-02' 'Critical' 0 "CA key is $($k.Label)" 'Keys below RSA 2048 can be factored with ordinary computers. Retire this CA.' -Classical)) }
    if ($k.QuantumSafe) {
        $a.QuantumSafeParts = @('Signature')
        $a.PqcPath = 'Already post-quantum (ML-DSA). Keep it in a pilot until clients and relying parties recognise ML-DSA certificates.'
        return Complete-QrAsset $a $Now
    }
    $a.QuantumVulnerable = $true
    $a.MigrationYears = $Migration.CaHierarchy
    $a.AuthenticityStartBy = Get-QrStartBy -Kind Authenticity -QuantumDate $QuantumDate -MigrationYears $Migration.CaHierarchy
    if ($na -gt $QuantumDate) {
        $past = if ($na -gt $script:NistDisallowed) { " and past 2035, when NIST disallows RSA and ECC" } else { '' }
        $a.Issues.Add((New-QrIssue 'QR-04' 'High' 3 "$($k.Label) CA trusted until $($na.ToString('yyyy-MM-dd')), after $($QuantumDate.Year)$past" 'Anyone with a quantum computer could forge certificates from this CA''s public key. Build the ML-DSA hierarchy in parallel and move templates to it.'))
    }
    else { $a.Issues.Add((New-QrIssue 'QR-04' 'Medium' 3 "$($k.Label) CA expires $($na.ToString('yyyy-MM-dd'))" 'Do not renew it with an RSA key. Move its templates to the post-quantum hierarchy before it expires.')) }
    if ($k.Classical -eq 'Until2030' -and $na -gt [datetime]'2031-01-01') { $a.Issues.Add((New-QrIssue 'QR-03' 'Medium' 3 "$($k.Label) gives 112-bit security, which NIST deprecates after 2030" 'Do not renew at RSA 2048. Any interim classical CA should be RSA 3072+ or ECDSA P-384.' -Classical)) }
    $a.Issues.Add((New-QrIssue 'QR-26' 'Medium' 4 'Classical CA in trust stores' 'Once its replacement is live, remove it from NTAuth, the Trusted Root / Intermediate GPOs and Intune trusted-certificate profiles, no later than 2035-01-01.'))
    $a.PqcPath = if ($os.MlDsaCa) { 'Install a new ML-DSA CA on Windows Server 2025 (KB5087539 or later). AD CS cannot convert this CA in place.' } else { "This host runs $($os.Os). Build the ML-DSA CA on a new Windows Server 2025 server (KB5087539 or later); AD CS has no in-place migration." }
    Complete-QrAsset $a $Now
}

function Test-QrTemplate {
    param($Template, [object[]]$Cas, [datetime]$Now, [datetime]$QuantumDate, [hashtable]$Migration, [hashtable]$Shelf)
    $name = Get-Prop $Template 'name'
    $ekus = @(Get-Prop $Template 'ekus' @())
    $issuers = @($Cas | Where-Object { @(Get-Prop $_ 'publishedTemplates' @()) -contains $name } | ForEach-Object { Get-Prop $_ 'name' })
    $purpose = @($ekus | ForEach-Object { if ($script:Eku.ContainsKey($_)) { $script:Eku[$_] } else { $_ } }) -join ', '
    $a = New-QrAsset -Category 'Template' -Name $name -Host_ ($issuers -join ', ') -Detail $purpose
    $ver = [int](Get-Prop $Template 'schemaVersion' 1)
    $k = Get-QrKeyClass (Get-Prop $Template 'keyAlgorithm' 'RSA') ([int](Get-Prop $Template 'minKeySize' 0))
    $a.Algorithm = $k.Label; $a.Signature = Get-Prop $Template 'hashAlgorithm'
    $days = [int](Get-Prop $Template 'validityDays' 365)
    $a.Extra = @{ DisplayName = Get-Prop $Template 'displayName' $name; SchemaVersion = $ver; Provider = Get-Prop $Template 'provider' 'CSP'; ValidityDays = $days
        Issued90 = [int](Get-Prop $Template 'issuedLast90Days' 0); Archival = [bool](Get-Prop $Template 'archival' $false); Ekus = $ekus; Published = [bool]$issuers.Count }
    if (-not $issuers.Count) { $a.Extra.Published = $false; return $null }
    $encryption = [bool](@($ekus | Where-Object { $script:EncryptionEkus -contains $_ }).Count)
    if ($k.Classical -eq 'Broken') { $a.Issues.Add((New-QrIssue 'QR-02' 'Critical' 0 "Minimum key size $($k.Label)" 'Raise the minimum key size to 2048 or more (3072 for anything issued past 2030) and supersede the template.' -Classical)) }
    if (Test-QrWeakHash $a.Signature) { $a.Issues.Add((New-QrIssue 'QR-01' 'Critical' 0 "Requests signed with $($a.Signature)" 'Set the request hash to SHA-256 or better (schema v3+ template).' -Classical)) }
    if ($k.QuantumSafe) {
        $a.QuantumSafeParts = @('Signature')
        $a.PqcPath = 'ML-DSA template. Expand it once relying parties accept ML-DSA certificates.'
        return Complete-QrAsset $a $Now
    }
    $a.QuantumVulnerable = $true
    $legacy = ($ver -lt 3 -or (Get-Prop $Template 'provider' 'CSP') -ne 'KSP')
    if ($legacy) { $a.Issues.Add((New-QrIssue 'QR-06' 'Medium' 1 "Schema v$ver template using a legacy CryptoAPI provider" 'ML-DSA needs a CNG Key Storage Provider. Duplicate the template with compatibility set to Windows Server 2008 or later for both the CA and the recipient, and choose a KSP.')) }
    $mig = $Migration.Template + $(if ($legacy) { 0.5 } else { 0 })
    $a.MigrationYears = $mig
    $validity = [math]::Round($days / 365.25, 2)
    if ($encryption) {
        $cls = Get-Prop $Template 'classification' 'Restricted'
        $a.Classification = $cls; $a.ShelfLifeYears = Get-QrShelfYears $cls $Shelf
        $a.ProtectedUntil = $Now.AddYears([int]$a.ShelfLifeYears)
        $a.ConfidentialityStartBy = Get-QrStartBy -Kind Confidentiality -QuantumDate $QuantumDate -MigrationYears $mig -ShelfYears $a.ShelfLifeYears
        $arch = if ($a.Extra.Archival) { ' Archived private keys mean the CA database can decrypt every old message too.' } else { '' }
        $a.Issues.Add((New-QrIssue 'QR-07' 'High' 2 "Encryption certificates ($purpose) protect $($a.ShelfLifeYears)-year data with $($k.Label)" "Mail and files encrypted to these keys can be recorded now and opened later. AD CS's ML-DSA support is signature-only, so there is no post-quantum encryption template yet: use RSA 3072+, shorten validity, protect the CA database and archived keys, and track hybrid S/MIME.$arch"))
        $a.PqcPath = 'No post-quantum option yet: ML-DSA is signature-only and AD CS cannot issue ML-KEM certificates. Reduce exposure and track Microsoft''s roadmap.'
    }
    else {
        $a.AuthenticityStartBy = Get-QrStartBy -Kind Authenticity -QuantumDate $QuantumDate -MigrationYears $mig -ValidityYears $validity
        $a.TrustUntil = $Now.AddDays($days)
        if ($Now.AddDays($days) -gt $QuantumDate.AddYears(-1)) { $a.Issues.Add((New-QrIssue 'QR-09' 'Low' 3 "Certificates issued today are valid for $days days" "Shorter validity shrinks the window in which a $($QuantumDate.Year) quantum computer could abuse a classical certificate.")) }
        $pk = [bool](@($ekus | Where-Object { $script:PkinitEkus -contains $_ }).Count)
        $a.PqcPath = if ($pk) { 'Used for Kerberos PKINIT. Windows has no post-quantum PKINIT yet, so keep this classical (RSA 3072+) and watch for Microsoft''s plans.' }
        elseif ($ekus -contains '1.3.6.1.5.5.7.3.3') { 'Issue an ML-DSA code-signing template from the new hierarchy once your signing tools and verifiers accept ML-DSA.' }
        else { 'Create an ML-DSA version (schema v4, CNG KSP, signature-only key usage) on the post-quantum CA and pilot it.' }
    }
    Complete-QrAsset $a $Now
}

function Test-QrEndpoint {
    param($Endpoint, [datetime]$Now, [datetime]$QuantumDate, [hashtable]$Migration, [hashtable]$Shelf)
    $svc = Get-Prop $Endpoint 'service' 'IIS'; $h = Get-Prop $Endpoint 'host'; $port = Get-Prop $Endpoint 'port' 443
    $a = New-QrAsset -Category 'Endpoint' -Name "$svc $($h):$port" -Host_ $h -Detail (Get-Prop $Endpoint 'site' $svc)
    $os = Get-QrOsPqc (Get-Prop $Endpoint 'os'); $a.Os = $os.Os
    $proto = Get-Prop $Endpoint 'protocol' 'TLS 1.2'; $suite = Get-Prop $Endpoint 'cipherSuite'; $kex = Get-Prop $Endpoint 'keyExchange'
    $cls = Get-Prop $Endpoint 'classification' $script:ServiceClassification[$svc]
    if (-not $cls) { $cls = 'Internal' }
    $a.Classification = $cls; $a.ShelfLifeYears = Get-QrShelfYears $cls $Shelf
    $a.Extra = @{ Service = $svc; Port = $port; Protocol = $proto; CipherSuite = $suite; AlsoAccepts = @(Get-Prop $Endpoint 'alsoAccepts' @()); Hybrid = $false; OsNote = $os.Note }
    Add-QrOsIssues $a $os
    if ($proto -eq 'HTTP') {
        $a.KeyExchange = 'None (cleartext)'
        $a.Issues.Add((New-QrIssue 'QR-16' 'Critical' 0 "$svc over HTTP on port $port" 'Clients that take updates over HTTP can be served malicious updates by anyone on the network path (WSUSpect-style attacks). Bind an HTTPS certificate, use port 8531 and set the GPO server URL to https://.' -Classical))
        $a.PqcPath = 'Turn on TLS first.'
        return Complete-QrAsset $a $Now
    }
    $old = @(@($proto) + $a.Extra.AlsoAccepts | Where-Object { $_ -match 'TLS 1\.[01]|SSL' })
    if ($old.Count) { $a.Issues.Add((New-QrIssue 'QR-11' 'High' 0 "Still accepts $($old -join ', ')" 'Disable TLS 1.0 and 1.1 in Schannel (SCHANNEL\Protocols registry keys or your baseline GPO).' -Classical)) }
    $rsaKt = "$suite" -match '^TLS_RSA_'
    $hybrid = "$kex" -match 'MLKEM'
    $a.Extra.Hybrid = $hybrid
    $a.KeyExchange = if ($hybrid) { "$kex (hybrid ML-KEM)" } elseif ($rsaKt) { 'RSA key transport' } elseif ($kex) { "ECDHE $kex" } else { 'ECDHE' }
    if ($rsaKt) { $a.Issues.Add((New-QrIssue 'QR-10' 'High' 0 "Negotiates $suite (no forward secrecy)" 'With RSA key transport, whoever gets the server''s private key - today by theft, later by quantum - decrypts every recorded session. Prefer ECDHE suites and remove TLS_RSA_* from the cipher suite order.' -Classical)) }
    # Confidentiality: key exchange
    if ($hybrid) {
        $a.QuantumSafeParts = @('KeyExchange')
        $a.PqcPath = 'Key exchange is hybrid ML-KEM: recorded traffic stays private. Replace the certificate from the ML-DSA hierarchy later.'
    }
    elseif ($a.ShelfLifeYears -gt 0) {
        $a.QuantumVulnerable = $true
        $a.ProtectedUntil = $Now.AddYears([int]$a.ShelfLifeYears)
        if ($os.HybridMlKem) {
            $a.MigrationYears = $Migration.TlsConfig
            $a.Issues.Add((New-QrIssue 'QR-13' 'High' 2 "Hybrid ML-KEM available on $($os.Os) but not in use" 'Enable the post-quantum TLS 1.3 groups (off by default since the July 2026 update) and confirm clients negotiate them. This is the quickest win in the report.'))
            $a.PqcPath = 'Configuration change: enable hybrid ML-KEM groups for TLS 1.3. Clients need Windows 11 / Server 2025 with the same update, or a TLS stack with ML-KEM.'
        }
        else {
            $a.MigrationYears = $Migration.OsUpgrade
            $why = if ($os.Tls13) { 'supports TLS 1.3 but not ML-KEM' } else { 'has no TLS 1.3 in Schannel' }
            $a.Issues.Add((New-QrIssue 'QR-12' 'High' 1 "$($os.Os) $why" "Move $svc to Windows Server 2025, then enable hybrid ML-KEM. Traffic recorded until then stays exposed for $($a.ShelfLifeYears) years of shelf life."))
            $a.PqcPath = "OS upgrade to Windows Server 2025, then hybrid ML-KEM. $($os.Note)."
        }
        $a.ConfidentialityStartBy = Get-QrStartBy -Kind Confidentiality -QuantumDate $QuantumDate -MigrationYears $a.MigrationYears -ShelfYears $a.ShelfLifeYears
    }
    # Authenticity: certificate
    $c = Get-Prop $Endpoint 'cert'
    if ($c) {
        $k = Get-QrKeyClass (Get-Prop $c 'keyAlgorithm') ([int](Get-Prop $c 'keySize' 0))
        $a.Algorithm = $k.Label; $a.Signature = Get-Prop $c 'signatureAlgorithm'
        $a.Extra.Issuer = Get-Prop $c 'issuer'; $a.Extra.NotAfter = Get-Prop $c 'notAfter'; $a.Extra.Template = Get-Prop $c 'template'; $a.Extra.Thumbprint = Get-Prop $c 'thumbprint'; $a.Extra.Subject = Get-Prop $c 'subject'
        if ($k.Classical -eq 'Broken') { $a.Issues.Add((New-QrIssue 'QR-02' 'Critical' 0 "Certificate key is $($k.Label)" 'Reissue with RSA 3072+ or ECDSA P-384.' -Classical)) }
        if (Test-QrWeakHash $a.Signature) { $a.Issues.Add((New-QrIssue 'QR-01' 'Critical' 0 "Certificate signed with $($a.Signature)" 'Reissue from a SHA-256 CA.' -Classical)) }
        if ([bool](Get-Prop $c 'selfSigned' $false)) { $a.Issues.Add((New-QrIssue 'QR-15' 'Medium' 0 'Self-signed certificate' "Clients can't tell this $svc server from an impostor, so users learn to click through warnings. Issue it from the enterprise CA (auto-enrolment for RDP)." -Classical)) }
        if ([datetime](Get-Prop $c 'notAfter') -lt $Now) { $a.Issues.Add((New-QrIssue 'QR-27' 'High' 0 "Certificate expired on $(Get-Prop $c 'notAfter')" 'Renew it; clients are either failing or ignoring validation.' -Classical)) }
        if ($k.QuantumSafe) { $a.QuantumSafeParts = @($a.QuantumSafeParts + 'Signature') }
        else {
            $a.QuantumVulnerable = $true
            $a.AuthenticityStartBy = Get-QrStartBy -Kind Authenticity -QuantumDate $QuantumDate -MigrationYears $Migration.CertReissue -ValidityYears 1
            $a.Issues.Add((New-QrIssue 'QR-24' 'Low' 3 "$($k.Label) server certificate" 'Reissue from the ML-DSA hierarchy once the clients of this service accept ML-DSA certificates. Not urgent: a forged certificate only matters once a quantum computer exists.'))
        }
    }
    if (-not $a.PqcPath) { $a.PqcPath = 'Nothing to protect for confidentiality (public data); certificate follows the PKI migration.' }
    Complete-QrAsset $a $Now
}

function Test-QrKerberos {
    <# Kerberos uses symmetric keys: AES is not meaningfully weakened by quantum computers, but RC4 and
       DES are broken today and Microsoft's RC4 changes (CVE-2026-20833) now block them. PKINIT, which
       starts Kerberos from a certificate or Windows Hello key, is classical public-key crypto. #>
    param($Kerberos, [object[]]$Templates, [datetime]$Now, [datetime]$QuantumDate, [hashtable]$Migration, [hashtable]$Shelf)
    $assets = [System.Collections.Generic.List[object]]::new()
    $aesSince = [datetime](Get-Prop $Kerberos 'aesKeysSince' '2008-01-01')
    $dd = Get-Prop $Kerberos 'defaultDomainSupportedEncTypes'
    $default = if ($null -ne $dd) { [int]$dd } else { 0x18 }
    $stats = [ordered]@{ Accounts = 0; Rc4 = 0; Des = 0; NoAesKeys = 0; Healthy = 0; Events = [ordered]@{}; Blocked = 0 }
    foreach ($acc in @(Get-Prop $Kerberos 'accounts' @())) {
        $stats.Accounts++
        $sam = Get-Prop $acc 'samAccountName'
        $set = Get-Prop $acc 'supportedEncTypes'
        $eff = if ($null -ne $set) { [int]$set } else { $default }
        $names = ConvertFrom-QrEncTypes $eff
        $pwd = [datetime](Get-Prop $acc 'pwdLastSet' '2000-01-01')
        $ev = Get-Prop $acc 'kdcEvents' @{}
        $evMap = [ordered]@{}
        $pairs = if ($ev -is [System.Collections.IDictionary]) { @($ev.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Name = "$($_.Key)"; Value = $_.Value } }) } else { @($ev.PSObject.Properties | Select-Object Name, Value) }
        foreach ($p in $pairs) { if ([int]$p.Value -gt 0) { $evMap[$p.Name] = [int]$p.Value; $stats.Events[$p.Name] = [int](Get-Prop $stats.Events $p.Name 0) + [int]$p.Value } }
        $a = New-QrAsset -Category 'Kerberos' -Name $sam -Host_ (Get-Prop $Kerberos 'domain') -Detail (Get-Prop $acc 'note' "$((Get-Prop $acc 'type' 'user')) with SPN")
        $a.Algorithm = ($names -join ', '); $a.KeyExchange = 'Symmetric (Kerberos)'
        $a.Extra = @{ Type = Get-Prop $acc 'type' 'user'; SupportedEncTypes = $set; Effective = $names; PwdLastSet = $pwd.ToString('yyyy-MM-dd'); Events = $evMap; ExplicitSetting = ($null -ne $set) }
        if ([bool](Get-Prop $acc 'useDesKeyOnly' $false) -or ($eff -band 0x3)) { $stats.Des++; $a.Issues.Add((New-QrIssue 'QR-19' 'Critical' 0 'DES enabled' 'DES is removed from Windows Server 2025 and broken for decades. Clear "Use only Kerberos DES encryption types" and set msDS-SupportedEncryptionTypes to 0x18; replace the device if it only speaks DES.' -Classical)) }
        if ($null -ne $set -and ($eff -band 0x4)) {
            $stats.Rc4++
            $blk = if ($evMap.Contains('203') -or $evMap.Contains('204')) { " The KDC has already refused $([int](Get-Prop $evMap '203' 0) + [int](Get-Prop $evMap '204' 0)) requests (events 203/204)." } else { '' }
            $a.Issues.Add((New-QrIssue 'QR-17' 'High' 0 "RC4 explicitly enabled (msDS-SupportedEncryptionTypes 0x$('{0:X}' -f $eff))" "RC4 service tickets can be cracked offline (Kerberoasting) and stay exposed to CVE-2026-20833.$blk Fix the client, set 0x18 and reset the password." -Classical))
        }
        if ($pwd -lt $aesSince) {
            $stats.NoAesKeys++
            $a.Issues.Add((New-QrIssue 'QR-18' 'High' 0 "No AES keys: password last set $($pwd.ToString('yyyy-MM-dd')), before AES keys existed in this domain" 'Since the April 2026 Kerberos update the KDC defaults to AES only, so this account fails (events 204/209) unless RC4 is kept. Reset the password twice and test the service.' -Classical))
        }
        if ($evMap.Contains('203') -or $evMap.Contains('204') -or $evMap.Contains('208') -or $evMap.Contains('209')) { $stats.Blocked++ }
        if ($a.Issues.Count) { $assets.Add((Complete-QrAsset $a $Now)) } else { $stats.Healthy++ }
    }
    # Domain-level settings
    $dom = New-QrAsset -Category 'Kerberos' -Name 'Domain Kerberos policy' -Host_ (Get-Prop $Kerberos 'domain') -Detail "Functional level $(Get-Prop $Kerberos 'domainFunctionalLevel' 'unknown')"
    $dom.Algorithm = (ConvertFrom-QrEncTypes $default) -join ', '; $dom.KeyExchange = 'Symmetric (Kerberos)'
    $dom.Extra = @{ DefaultDomainSupportedEncTypes = $dd; Effective = @(ConvertFrom-QrEncTypes $default) }
    if ($null -ne $dd -and ($default -band 0x7)) { $dom.Issues.Add((New-QrIssue 'QR-20' 'High' 0 "DefaultDomainSupportedEncTypes is set to 0x$('{0:X}' -f $default) and includes RC4 or DES" 'This explicit value overrides the AES-only default (event 205). Remove it or set it to 0x18 on every DC.' -Classical)) }
    $kt = Get-Prop $Kerberos 'krbtgtPwdLastSet'
    if ($kt -and ([datetime]$kt) -lt $Now.AddDays(-180)) { $dom.Issues.Add((New-QrIssue 'QR-23' 'Medium' 0 "krbtgt password last set $kt" 'Rotate krbtgt (twice, with replication in between) so old ticket-signing keys, including any RC4 keys, are gone.' -Classical)) }
    foreach ($t in @(Get-Prop $Kerberos 'trusts' @())) {
        $te = Get-Prop $t 'supportedEncTypes'
        if ($null -eq $te -or ([int]$te -band 0x4) -and -not ([int]$te -band 0x18)) {
            $dom.Issues.Add((New-QrIssue 'QR-21' 'High' 0 "Trust to $(Get-Prop $t 'name') uses RC4 only" 'Enable AES on both sides of the trust (Active Directory Domains and Trusts, "The other domain supports Kerberos AES Encryption") and test cross-domain access.' -Classical))
        }
    }
    if ($dom.Issues.Count) { $assets.Add((Complete-QrAsset $dom $Now)) }
    # PKINIT
    $pk = Get-Prop $Kerberos 'pkinit'
    if ($pk) {
        $users = [int](Get-Prop $pk 'smartCardUsers' 0) + [int](Get-Prop $pk 'whfbCertTrustUsers' 0) + [int](Get-Prop $pk 'whfbKeyTrustUsers' 0)
        $kdcT = $Templates | Where-Object { (Get-Prop $_ 'name') -eq (Get-Prop $pk 'kdcTemplate') } | Select-Object -First 1
        $k = Get-QrKeyClass (Get-Prop $kdcT 'keyAlgorithm' 'RSA') ([int](Get-Prop $kdcT 'minKeySize' 2048))
        $a = New-QrAsset -Category 'Kerberos' -Name 'PKINIT (smart cards and Windows Hello)' -Host_ (Get-Prop $Kerberos 'domain') -Detail "$users users start Kerberos from a certificate or Windows Hello key"
        $a.Algorithm = $k.Label; $a.KeyExchange = 'RSA / Diffie-Hellman'
        $a.Extra = @{ SmartCard = [int](Get-Prop $pk 'smartCardUsers' 0); CertTrust = [int](Get-Prop $pk 'whfbCertTrustUsers' 0); KeyTrust = [int](Get-Prop $pk 'whfbKeyTrustUsers' 0); KdcTemplate = Get-Prop $pk 'kdcTemplate' }
        if (-not $k.QuantumSafe) {
            $a.QuantumVulnerable = $true
            $a.Classification = 'Confidential'; $a.ShelfLifeYears = Get-QrShelfYears 'Confidential' $Shelf
            $a.ProtectedUntil = $Now.AddYears([int]$a.ShelfLifeYears)
            $a.MigrationYears = $Migration.Pkinit
            $a.ConfidentialityStartBy = Get-QrStartBy -Kind Confidentiality -QuantumDate $QuantumDate -MigrationYears $Migration.Pkinit -ShelfYears $a.ShelfLifeYears
            $a.AuthenticityStartBy = Get-QrStartBy -Kind Authenticity -QuantumDate $QuantumDate -MigrationYears $Migration.Pkinit -ValidityYears 1
            $a.Issues.Add((New-QrIssue 'QR-22' 'High' 3 "PKINIT relies on $($k.Label) for $users users" 'A recorded PKINIT exchange can reveal the session key for the TGT once RSA or Diffie-Hellman falls. Windows has no post-quantum PKINIT yet: keep KDC certificates short-lived and RSA 3072+, prefer Windows Hello key trust or cloud Kerberos trust, and track Microsoft''s plans.'))
            $a.PqcPath = 'No post-quantum PKINIT in Windows yet. Reduce exposure; move it when Microsoft ships it.'
        }
        $assets.Add((Complete-QrAsset $a $Now))
    }
    [pscustomobject]@{ Assets = $assets; Stats = [pscustomobject]$stats; DefaultEncTypes = @(ConvertFrom-QrEncTypes $default); ExplicitDefault = ($null -ne $dd) }
}

# ---------------------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------------------
function Invoke-QrAnalysis {
    param($Snapshot, [int]$QuantumYear = 2030, [hashtable]$ShelfLife = @{}, [hashtable]$MigrationYears = @{})
    $now = if (Get-Prop $Snapshot 'now') { ([datetime](Get-Prop $Snapshot 'now')).Date } else { (Get-Date).Date }
    $q = [datetime]"$QuantumYear-01-01"
    $shelf = @{}; foreach ($k in $script:DefaultShelfLife.Keys) { $shelf[$k] = $script:DefaultShelfLife[$k] }; foreach ($k in $ShelfLife.Keys) { $shelf[$k] = [double]$ShelfLife[$k] }
    $mig = @{}; foreach ($k in $script:DefaultMigration.Keys) { $mig[$k] = $script:DefaultMigration[$k] }; foreach ($k in $MigrationYears.Keys) { $mig[$k] = [double]$MigrationYears[$k] }
    $cas = @(Get-Prop $Snapshot 'cas' @()); $tpls = @(Get-Prop $Snapshot 'templates' @())
    $assets = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $cas) { $assets.Add((Test-QrCa -Ca $c -Now $now -QuantumDate $q -Migration $mig)) }
    $unpublished = 0
    foreach ($t in $tpls) { $r = Test-QrTemplate -Template $t -Cas $cas -Now $now -QuantumDate $q -Migration $mig -Shelf $shelf; if ($r) { $assets.Add($r) } else { $unpublished++ } }
    foreach ($e in @(Get-Prop $Snapshot 'endpoints' @())) { $assets.Add((Test-QrEndpoint -Endpoint $e -Now $now -QuantumDate $q -Migration $mig -Shelf $shelf)) }
    $kerb = $null
    if (Get-Prop $Snapshot 'kerberos') { $kerb = Test-QrKerberos -Kerberos (Get-Prop $Snapshot 'kerberos') -Templates $tpls -Now $now -QuantumDate $q -Migration $mig -Shelf $shelf; foreach ($a in $kerb.Assets) { $assets.Add($a) } }

    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $urgRank = @{ Overdue = 0; Now = 1; Next = 2; Later = 3; None = 4 }
    $ranked = @($assets | Where-Object QuantumVulnerable | Sort-Object @{ e = { if ($_.StartBy) { [datetime]$_.StartBy } else { [datetime]::MaxValue } } }, @{ e = { $_.ShelfLifeYears }; Descending = $true }, Name)
    $i = 0; foreach ($r in $ranked) { $i++; $r | Add-Member -NotePropertyName Rank -NotePropertyValue $i -Force }

    $fixFirst = @($assets | ForEach-Object { $as = $_; $as.Issues | Where-Object { $_.Classical -and $_.Severity -in 'Critical', 'High' } | ForEach-Object {
                [pscustomobject]@{ Asset = $as.Name; Category = $as.Category; Code = $_.Code; Severity = $_.Severity; Title = $_.Title; Fix = $_.Fix } } } |
        Sort-Object @{ e = { $sevRank[$_.Severity] } }, Category, Asset)

    $phases = foreach ($p in $script:PhaseNames.Keys) {
        $items = @($assets | ForEach-Object { $as = $_; $as.Issues | Where-Object Phase -eq $p | ForEach-Object {
                    [pscustomobject]@{ Asset = $as.Name; Category = $as.Category; Code = $_.Code; Severity = $_.Severity; Title = $_.Title; Fix = $_.Fix; StartBy = $as.StartBy; Urgency = $as.Urgency } } } |
            Sort-Object @{ e = { if ($_.StartBy) { [datetime]$_.StartBy } else { [datetime]::MaxValue } } }, @{ e = { $sevRank[$_.Severity] } }, Asset)
        $earliest = @($items | Where-Object StartBy | ForEach-Object { [datetime]$_.StartBy } | Sort-Object | Select-Object -First 1)
        [pscustomobject]@{ Number = $p; Name = $script:PhaseNames[$p]; Text = $script:PhaseText[$p]; Items = $items; Count = $items.Count
            StartBy = $(if ($p -eq 0) { $now.ToString('yyyy-MM-dd') } elseif ($earliest.Count) { $earliest[0].ToString('yyyy-MM-dd') } else { $null }) }
    }

    $eps = @($assets | Where-Object Category -eq 'Endpoint')
    $tlsEps = @($eps | Where-Object { $_.Extra.Protocol -ne 'HTTP' })
    $harvest = @($assets | Where-Object { $_.ConfidentialityStartBy -and $_.ProtectedUntil -and ([datetime]$_.ProtectedUntil) -gt $q })
    $summary = [pscustomobject][ordered]@{
        Now = $now.ToString('yyyy-MM-dd'); QuantumYear = $QuantumYear; YearsToQuantum = Get-QrYears $now $q
        Assets = $assets.Count; QuantumVulnerable = $ranked.Count
        QuantumSafe = @($assets | Where-Object { $_.QuantumSafeParts.Count }).Count
        HarvestExposed = $harvest.Count
        HarvestRegulated = @($harvest | Where-Object { $_.ShelfLifeYears -ge 15 }).Count
        Overdue = @($ranked | Where-Object Urgency -eq 'Overdue').Count
        StartWithinYear = @($ranked | Where-Object Urgency -eq 'Now').Count
        TrustedPastQuantum = @($assets | Where-Object { $_.Category -eq 'CA' -and $_.QuantumVulnerable -and ([datetime]$_.TrustUntil) -gt $q }).Count
        BrokenToday = @($assets | Where-Object { @($_.Issues | Where-Object { $_.Classical -and $_.Severity -in 'Critical', 'High' }).Count }).Count
        CriticalIssues = @($assets | ForEach-Object { $_.Issues } | Where-Object Severity -eq 'Critical').Count
        Cas = @($assets | Where-Object Category -eq 'CA').Count
        Templates = @($assets | Where-Object Category -eq 'Template').Count; TemplatesUnpublished = $unpublished
        TemplatesLegacyProvider = @($assets | Where-Object { $_.Category -eq 'Template' -and @($_.Issues | Where-Object Code -eq 'QR-06').Count }).Count
        EncryptionTemplates = @($assets | Where-Object { $_.Category -eq 'Template' -and @($_.Issues | Where-Object Code -eq 'QR-07').Count }).Count
        Endpoints = $eps.Count
        HybridOn = @($tlsEps | Where-Object { $_.Extra.Hybrid }).Count
        HybridAvailableOff = @($eps | Where-Object { @($_.Issues | Where-Object Code -eq 'QR-13').Count }).Count
        NeedOsUpgrade = @($eps | Where-Object { @($_.Issues | Where-Object Code -eq 'QR-12').Count }).Count
        Tls13 = @($tlsEps | Where-Object { $_.Extra.Protocol -eq 'TLS 1.3' }).Count
        KerberosAccounts = $(if ($kerb) { $kerb.Stats.Accounts } else { 0 })
        KerberosFlagged = $(if ($kerb) { @($kerb.Assets | Where-Object { $_.Extra.ContainsKey('PwdLastSet') }).Count } else { 0 })
        Shelf = $shelf; Migration = $mig
    }
    [pscustomobject]@{ Summary = $summary; Assets = $assets; Ranked = $ranked; FixFirst = $fixFirst; Phases = @($phases); Kerberos = $kerb; Now = $now; QuantumDate = $q }
}

# ---------------------------------------------------------------------------------------
# CycloneDX 1.6 cryptography bill of materials
# ---------------------------------------------------------------------------------------
function ConvertTo-QrCbom {
    param($Analysis, [string]$Label)
    $components = [System.Collections.Generic.List[object]]::new(); $algs = @{}
    function Add-Alg([string]$Name, [string]$Primitive, [int]$Level, [string]$Param) {
        $ref = 'crypto/algorithm/' + ($Name.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
        if (-not $algs.ContainsKey($ref)) {
            $p = [ordered]@{ primitive = $Primitive; nistQuantumSecurityLevel = $Level }
            if ($Param) { $p.parameterSetIdentifier = $Param }
            $algs[$ref] = [ordered]@{ type = 'cryptographic-asset'; 'bom-ref' = $ref; name = $Name; cryptoProperties = [ordered]@{ assetType = 'algorithm'; algorithmProperties = $p } }
        }
        $ref
    }
    function Get-KeyRef($Label) {
        if ($Label -match '^ML-DSA-(\d+)') { return Add-Alg $Label 'signature' $(switch ($Matches[1]) { '44' { 2 } '65' { 3 } default { 5 } }) $Matches[1] }
        if ($Label -match '^RSA (\d+)') { return Add-Alg $Label 'pke' 0 $Matches[1] }
        if ($Label -match '^ECDSA (.+)') { return Add-Alg $Label 'signature' 0 $Matches[1] }
        Add-Alg ($Label ? $Label : 'unknown') 'other' 0 $null
    }
    foreach ($a in $Analysis.Assets) {
        $ref = 'crypto/' + $a.Category.ToLowerInvariant() + '/' + ($a.Name.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
        $props = @(
            [ordered]@{ name = 'qr:category'; value = $a.Category }, [ordered]@{ name = 'qr:quantumVulnerable'; value = "$($a.QuantumVulnerable)".ToLowerInvariant() },
            [ordered]@{ name = 'qr:urgency'; value = $a.Urgency }, [ordered]@{ name = 'qr:startBy'; value = "$($a.StartBy)" }, [ordered]@{ name = 'qr:shelfLifeYears'; value = "$($a.ShelfLifeYears)" }
        )
        switch ($a.Category) {
            'CA' {
                $cp = [ordered]@{ assetType = 'certificate'; certificateProperties = [ordered]@{ subjectName = $a.Extra.Subject; notValidBefore = $a.Extra.NotBefore; notValidAfter = $a.TrustUntil
                        signatureAlgorithmRef = (Get-KeyRef $a.Algorithm); subjectPublicKeyRef = (Get-KeyRef $a.Algorithm); certificateFormat = 'X.509' } }
            }
            'Endpoint' {
                if ($a.Extra.Protocol -eq 'HTTP') { $cp = [ordered]@{ assetType = 'protocol'; protocolProperties = [ordered]@{ type = 'other'; version = 'HTTP' } } }
                else {
                    $pp = [ordered]@{ type = 'tls'; version = ($a.Extra.Protocol -replace 'TLS ', '') }
                    if ($a.Extra.CipherSuite) { $pp.cipherSuites = @([ordered]@{ name = $a.Extra.CipherSuite }) }
                    $cp = [ordered]@{ assetType = 'protocol'; protocolProperties = $pp }
                    if ($a.Algorithm) { $cp.protocolProperties.cryptoRefArray = @(Get-KeyRef $a.Algorithm) }
                    if ($a.Extra.Hybrid) { $cp.protocolProperties.cryptoRefArray = @(@($cp.protocolProperties.cryptoRefArray) + (Add-Alg 'X25519MLKEM768' 'kem' 3 'ML-KEM-768')) }
                }
            }
            'Template' { $cp = [ordered]@{ assetType = 'related-crypto-material'; relatedCryptoMaterialProperties = [ordered]@{ type = 'private-key'; algorithmRef = (Get-KeyRef $a.Algorithm); size = [int]($a.Algorithm -replace '\D', '0') } } }
            default { $cp = [ordered]@{ assetType = 'protocol'; protocolProperties = [ordered]@{ type = 'other'; version = 'Kerberos 5' } } }
        }
        $components.Add([ordered]@{ type = 'cryptographic-asset'; 'bom-ref' = $ref; name = $a.Name; description = $a.Detail; cryptoProperties = $cp; properties = $props })
    }
    [ordered]@{
        bomFormat = 'CycloneDX'; specVersion = '1.6'; serialNumber = "urn:uuid:$([guid]::NewGuid())"; version = 1
        metadata = [ordered]@{ timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); tools = [ordered]@{ components = @([ordered]@{ type = 'application'; name = 'Quantum-Ready Windows PKI'; version = $script:QrVersion }) }
            component = [ordered]@{ type = 'platform'; name = $Label } }
        components = @($components) + @($algs.Values)
    }
}

# ---------------------------------------------------------------------------------------
# Markdown roadmap
# ---------------------------------------------------------------------------------------
function ConvertTo-QrMarkdown {
    param($Report)
    $s = $Report.Summary; $sb = [Text.StringBuilder]::new()
    $null = $sb.AppendLine("# Quantum-readiness roadmap: $($Report.Scope.Label)").AppendLine()
    $null = $sb.AppendLine("Assessed $($s.Now). Planning year for a cryptographically relevant quantum computer: **$($s.QuantumYear)** ($($s.YearsToQuantum) years away).").AppendLine()
    $null = $sb.AppendLine("- **$($s.HarvestExposed)** systems protect data that must stay secret past $($s.QuantumYear) with classical key exchange or encryption.")
    $null = $sb.AppendLine("- **$($s.Overdue)** of $($s.QuantumVulnerable) quantum-vulnerable assets should already have started migrating (Mosca's inequality); $($s.StartWithinYear) more must start within a year.")
    $null = $sb.AppendLine("- **$($s.TrustedPastQuantum)** classical CAs stay trusted after $($s.QuantumYear).")
    $null = $sb.AppendLine("- **$($s.BrokenToday)** assets have weaknesses that ordinary computers exploit today.")
    $null = $sb.AppendLine("- Hybrid ML-KEM: on for $($s.HybridOn) of $($s.Endpoints) endpoints, available but off on $($s.HybridAvailableOff), needs an OS upgrade on $($s.NeedOsUpgrade).").AppendLine()
    $null = $sb.AppendLine('## Ranked by when migration must start').AppendLine()
    $null = $sb.AppendLine('| # | Asset | Type | Protects | Shelf life | Start by | Status |').AppendLine('|---|---|---|---|---|---|---|')
    foreach ($r in $Report.Ranked) {
        $st = if ($r.Urgency -eq 'Overdue') { "Overdue by $($r.YearsLate) y" } else { $r.Urgency }
        $shelfTxt = if ($r.ShelfLifeYears) { "$($r.ShelfLifeYears) y ($($r.Classification))" } else { '-' }
        $null = $sb.AppendLine("| $($r.Rank) | $($r.Name) | $($r.Category) | $($r.Exposure) | $shelfTxt | $($r.StartBy) | $st |")
    }
    foreach ($p in $Report.Phases) {
        $null = $sb.AppendLine().AppendLine("## Phase $($p.Number): $($p.Name)").AppendLine().AppendLine($p.Text).AppendLine()
        if (-not $p.Count) { $null = $sb.AppendLine('Nothing to do in this phase.'); continue }
        foreach ($i in $p.Items) { $null = $sb.AppendLine("- **$($i.Asset)** ($($i.Severity), $($i.Code)): $($i.Title). $($i.Fix)") }
    }
    $null = $sb.AppendLine().AppendLine('---').AppendLine("Generated by Quantum-Ready Windows PKI v$($Report.Version). Read-only assessment; verify each change in a test environment first.")
    $sb.ToString()
}

# ---------------------------------------------------------------------------------------
# Live collection (Windows, domain-joined)
# ---------------------------------------------------------------------------------------
function Get-QrTlsProbe {
    <# Opens a TLS handshake (with the RDP X.224 negotiation for port 3389) and reads the certificate,
       protocol and cipher suite. .NET does not expose the key-exchange group, so hybrid ML-KEM shows as
       unknown in live mode unless the host reports it. #>
    param([string]$HostName, [int]$Port, [string]$Service)
    $tcp = [Net.Sockets.TcpClient]::new()
    try {
        $iar = $tcp.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(4000)) { throw "timeout connecting to $($HostName):$Port" }
        $tcp.EndConnect($iar)
        $stream = $tcp.GetStream(); $stream.ReadTimeout = 5000
        if ($Service -eq 'WSUS' -and $Port -eq 8530) { return [pscustomobject]@{ protocol = 'HTTP'; cipherSuite = $null; keyExchange = $null; cert = $null } }
        if ($Service -eq 'RDP') {
            [byte[]]$req = 0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00
            $stream.Write($req, 0, $req.Length); $buf = [byte[]]::new(19); $null = $stream.Read($buf, 0, 19)
        }
        $ssl = [Net.Security.SslStream]::new($stream, $false, { $true })
        $ssl.AuthenticateAsClient($HostName)
        $x = [Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        $alg = switch ($x.PublicKey.Oid.Value) { '1.2.840.113549.1.1.1' { 'RSA' } '1.2.840.10045.2.1' { 'ECDSA' } default { $x.PublicKey.Oid.FriendlyName } }
        $size = if ($alg -eq 'RSA') { $x.PublicKey.GetRSAPublicKey().KeySize } elseif ($alg -eq 'ECDSA') { $x.PublicKey.GetECDsaPublicKey().KeySize } else { 0 }
        $tmpl = ($x.Extensions | Where-Object { $_.Oid.Value -in '1.3.6.1.4.1.311.21.7', '1.3.6.1.4.1.311.20.2' } | Select-Object -First 1)
        [pscustomobject]@{
            protocol = ($ssl.SslProtocol.ToString() -replace 'Tls13', 'TLS 1.3' -replace 'Tls12', 'TLS 1.2' -replace 'Tls11', 'TLS 1.1' -replace '^Tls$', 'TLS 1.0')
            cipherSuite = "$($ssl.NegotiatedCipherSuite)"; keyExchange = $null
            cert = [pscustomobject]@{ subject = $x.Subject; issuer = $x.Issuer; keyAlgorithm = $alg; keySize = $size; signatureAlgorithm = $x.SignatureAlgorithm.FriendlyName
                notBefore = $x.NotBefore.ToString('yyyy-MM-dd'); notAfter = $x.NotAfter.ToString('yyyy-MM-dd'); thumbprint = $x.Thumbprint; selfSigned = ($x.Subject -eq $x.Issuer)
                template = $(if ($tmpl) { $tmpl.Format($false) } else { $null }) }
        }
    }
    finally { $tcp.Dispose() }
}

function Get-QrLiveSnapshot {
    param([string[]]$Endpoints = @())
    if (-not $IsWindows) { throw 'Live mode needs Windows on a domain-joined machine. Use -Demo or -InputPath elsewhere.' }
    $root = [ADSI]'LDAP://RootDSE'
    $cfg = "$($root.configurationNamingContext)"; $dn = "$($root.defaultNamingContext)"
    $domain = ($dn -replace 'DC=', '' -replace ',', '.')
    function Find-Qr([string]$Base, [string]$Filter, [string[]]$Props) {
        $s = [DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://$Base", $Filter, $Props); $s.PageSize = 500; $s.FindAll()
    }
    Write-Host '  Reading AD CS from the configuration partition...'
    $osBy = @{}
    foreach ($c in (Find-Qr $dn '(objectCategory=computer)' @('dnshostname', 'name', 'operatingsystem'))) {
        $os = "$($c.Properties['operatingsystem'])"; $osBy["$($c.Properties['name'])".ToUpper()] = $os; $osBy["$($c.Properties['dnshostname'])".ToUpper()] = $os
    }
    $cas = foreach ($e in (Find-Qr "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg" '(objectClass=pKIEnrollmentService)' @('cn', 'dnshostname', 'cacertificate', 'certificatetemplates'))) {
        $x = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$e.Properties['cacertificate'][0])
        $alg = switch ($x.PublicKey.Oid.Value) { '1.2.840.113549.1.1.1' { 'RSA' } '1.2.840.10045.2.1' { 'ECDSA' } default { $x.PublicKey.Oid.FriendlyName } }
        $size = if ($alg -eq 'RSA') { $x.PublicKey.GetRSAPublicKey().KeySize } elseif ($alg -eq 'ECDSA') { $x.PublicKey.GetECDsaPublicKey().KeySize } else { 0 }
        $h = "$($e.Properties['dnshostname'])"
        [pscustomobject]@{ name = "$($e.Properties['cn'])"; host = $h; os = $osBy[$h.ToUpper()]; type = $(if ($x.Subject -eq $x.Issuer) { 'Root' } else { 'Issuing' })
            cert = [pscustomobject]@{ subject = $x.Subject; issuer = $x.Issuer; keyAlgorithm = $alg; keySize = $size; signatureAlgorithm = $x.SignatureAlgorithm.FriendlyName; notBefore = $x.NotBefore.ToString('yyyy-MM-dd'); notAfter = $x.NotAfter.ToString('yyyy-MM-dd'); thumbprint = $x.Thumbprint }
            publishedTemplates = @($e.Properties['certificatetemplates']) }
    }
    # Offline roots appear only in the AIA / Certification Authorities containers.
    foreach ($r in (Find-Qr "CN=Certification Authorities,CN=Public Key Services,CN=Services,$cfg" '(objectClass=certificationAuthority)' @('cn', 'cacertificate'))) {
        foreach ($raw in $r.Properties['cacertificate']) {
            $x = [Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$raw)
            if (@($cas | Where-Object { $_.cert.thumbprint -eq $x.Thumbprint }).Count) { continue }
            $size = if ($x.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') { $x.PublicKey.GetRSAPublicKey().KeySize } else { 0 }
            $cas = @($cas) + [pscustomobject]@{ name = "$($r.Properties['cn'])"; host = '(offline)'; os = ''; type = 'Root'; offline = $true
                cert = [pscustomobject]@{ subject = $x.Subject; issuer = $x.Issuer; keyAlgorithm = $(if ($size) { 'RSA' } else { $x.PublicKey.Oid.FriendlyName }); keySize = $size; signatureAlgorithm = $x.SignatureAlgorithm.FriendlyName; notBefore = $x.NotBefore.ToString('yyyy-MM-dd'); notAfter = $x.NotAfter.ToString('yyyy-MM-dd'); thumbprint = $x.Thumbprint }
                publishedTemplates = @() }
        }
    }
    $templates = foreach ($t in (Find-Qr "CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg" '(objectClass=pKICertificateTemplate)' @('cn', 'displayname', 'mspki-template-schema-version', 'mspki-minimal-key-size', 'pkiextendedkeyusage', 'pkiexpirationperiod', 'pkidefaultcsps', 'mspki-ra-application-policies', 'mspki-private-key-flag', 'pkikeyusage'))) {
        $p = $t.Properties; $ver = [int]"$($p['mspki-template-schema-version'])"
        $pol = ConvertFrom-QrTemplatePolicy "$($p['mspki-ra-application-policies'])"
        $csps = @($p['pkidefaultcsps'] | ForEach-Object { "$_" })
        $ku = @(); if ($p['pkikeyusage'].Count) { $b = ([byte[]]$p['pkikeyusage'][0])[0]; if ($b -band 0x80) { $ku += 'DigitalSignature' }; if ($b -band 0x20) { $ku += 'KeyEncipherment' }; if ($b -band 0x08) { $ku += 'KeyAgreement' } }
        [pscustomobject]@{ name = "$($p['cn'])"; displayName = "$($p['displayname'])"; schemaVersion = $ver
            keyAlgorithm = $(if ($pol.KeyAlgorithm) { $pol.KeyAlgorithm } else { 'RSA' }); minKeySize = [int]"$($p['mspki-minimal-key-size'])"
            hashAlgorithm = $(if ($pol.HashAlgorithm) { $pol.HashAlgorithm } else { 'SHA1' })
            provider = $(if ($ver -ge 3 -and -not ($csps -match 'Cryptographic Provider')) { 'KSP' } else { 'CSP' })
            ekus = @($p['pkiextendedkeyusage'] | ForEach-Object { "$_" }); keyUsage = $ku
            validityDays = ConvertFrom-QrPkiPeriod ([byte[]]$p['pkiexpirationperiod'][0]); archival = [bool]([int]"$($p['mspki-private-key-flag'])" -band 1) }
    }
    Write-Host '  Reading Kerberos settings...'
    $accounts = foreach ($u in (Find-Qr $dn '(&(servicePrincipalName=*)(!(objectClass=computer))(!(samAccountName=krbtgt)))' @('samaccountname', 'msds-supportedencryptiontypes', 'pwdlastset', 'useraccountcontrol', 'objectclass'))) {
        $p = $u.Properties
        [pscustomobject]@{ samAccountName = "$($p['samaccountname'])"; type = $(if ($p['objectclass'] -contains 'msDS-GroupManagedServiceAccount') { 'gmsa' } else { 'user' }); spn = $true
            supportedEncTypes = $(if ($p['msds-supportedencryptiontypes'].Count) { [int]"$($p['msds-supportedencryptiontypes'])" } else { $null })
            pwdLastSet = [datetime]::FromFileTimeUtc([int64]"$($p['pwdlastset'])").ToString('yyyy-MM-dd'); useDesKeyOnly = [bool]([int]"$($p['useraccountcontrol'])" -band 0x200000); kdcEvents = @{} }
    }
    $krb = Find-Qr $dn '(samAccountName=krbtgt)' @('pwdlastset') | Select-Object -First 1
    $trusts = foreach ($t in (Find-Qr "CN=System,$dn" '(objectClass=trustedDomain)' @('name', 'msds-supportedencryptiontypes', 'trustdirection'))) {
        [pscustomobject]@{ name = "$($t.Properties['name'])"; supportedEncTypes = $(if ($t.Properties['msds-supportedencryptiontypes'].Count) { [int]"$($t.Properties['msds-supportedencryptiontypes'])" } else { $null }) }
    }
    $dcs = @(Find-Qr $dn '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dnshostname', 'operatingsystem'))
    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($d in $dcs) { $h = "$($d.Properties['dnshostname'])"; $targets.Add(@($h, 636, 'LDAPS', $null)); $targets.Add(@($h, 3389, 'RDP', 'Restricted')) }
    foreach ($e in $Endpoints) { $x = $e -split ':'; $targets.Add(@($x[0], [int]$x[1], $(if ($x.Count -gt 2) { $x[2] } else { 'IIS' }), $(if ($x.Count -gt 3) { $x[3] } else { $null }))) }
    Write-Host "  Probing $($targets.Count) TLS endpoints..."
    $eps = foreach ($t in $targets) {
        try { $pr = Get-QrTlsProbe -HostName $t[0] -Port $t[1] -Service $t[2] } catch { Write-Warning "  $($t[0]):$($t[1]) - $($_.Exception.Message)"; continue }
        $o = [ordered]@{ host = $t[0]; service = $t[2]; port = $t[1]; os = $osBy["$($t[0])".ToUpper()]; protocol = $pr.protocol; cipherSuite = $pr.cipherSuite; keyExchange = $pr.keyExchange; cert = $pr.cert }
        if ($t[3]) { $o.classification = $t[3] }
        [pscustomobject]$o
    }
    [pscustomobject]@{ label = $domain; now = (Get-Date).ToString('yyyy-MM-dd'); forest = $domain; domain = $domain; cas = @($cas); templates = @($templates); endpoints = @($eps)
        kerberos = [pscustomobject]@{ domainFunctionalLevel = "$($root.domainFunctionality)"; aesKeysSince = '2008-01-01'; defaultDomainSupportedEncTypes = $null
            krbtgtPwdLastSet = $(if ($krb) { [datetime]::FromFileTimeUtc([int64]"$($krb.Properties['pwdlastset'])").ToString('yyyy-MM-dd') } else { $null }); accounts = @($accounts); trusts = @($trusts); pkinit = $null } }
}

# ---------------------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------------------
function Invoke-QuantumReadyPki {
    [CmdletBinding()]
    param($Demo, $InputPath, [int]$QuantumYear = 2030, [hashtable]$ShelfLife = @{}, [hashtable]$MigrationYears = @{}, [string[]]$Endpoints = @(), $OutputPath)
    $root = $PSScriptRoot; if (-not $root) { $root = (Get-Location).Path }
    if ($Demo -or $InputPath) {
        $file = if ($Demo) { Join-Path $root 'demo/sample-estate.json' } else { $InputPath }
        $snap = Get-Content $file -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    else { $snap = Get-QrLiveSnapshot -Endpoints $Endpoints }
    $a = Invoke-QrAnalysis -Snapshot $snap -QuantumYear $QuantumYear -ShelfLife $ShelfLife -MigrationYears $MigrationYears
    $label = Get-Prop $snap 'label' 'Windows estate'
    $view = { param($x) $x | Select-Object Rank, Id, Category, Name, Host, Detail, Os, Algorithm, Signature, KeyExchange, QuantumVulnerable, QuantumSafeParts, Classification, ShelfLifeYears, ProtectedUntil, TrustUntil, Exposure, MigrationYears, ConfidentialityStartBy, AuthenticityStartBy, StartBy, Urgency, YearsLate, PqcPath, Issues, Extra -ErrorAction SilentlyContinue }
    $report = [pscustomobject][ordered]@{
        Tool = 'Quantum-Ready Windows PKI'; Version = $script:QrVersion; GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Scope = [pscustomobject]@{ Label = $label; Forest = Get-Prop $snap 'forest'; Demo = [bool]$Demo }
        Summary = $a.Summary; Ranked = @(& $view $a.Ranked); FixFirst = $a.FixFirst; Phases = $a.Phases
        Assets = @(& $view $a.Assets)
        Kerberos = $(if ($a.Kerberos) { [pscustomobject]@{ Stats = $a.Kerberos.Stats; DefaultEncTypes = $a.Kerberos.DefaultEncTypes; ExplicitDefault = $a.Kerberos.ExplicitDefault } } else { $null })
        Capabilities = @(
            [pscustomobject]@{ Feature = 'ML-KEM and ML-DSA in CNG'; Where = 'Windows 11, Windows Server 2025'; Since = 'November 2025'; Note = 'CNG only; legacy CryptoAPI providers cannot use them' }
            [pscustomobject]@{ Feature = 'ML-DSA certification authorities'; Where = 'Windows Server 2025 AD CS'; Since = 'May 2026 (KB5087539)'; Note = 'New CA only; no in-place migration; signature-only; CNG KSP templates; no NDES' }
            [pscustomobject]@{ Feature = 'Hybrid ML-KEM key exchange in TLS 1.3'; Where = 'Windows 11, Windows Server 2025'; Since = 'July 2026 update'; Note = 'Off by default; both ends must support the group' }
            [pscustomobject]@{ Feature = 'Kerberos AES-only by default'; Where = 'All supported DCs'; Since = 'April 2026; rollback removed July 2026'; Note = 'CVE-2026-20833; events 201-209 show what breaks' }
            [pscustomobject]@{ Feature = 'Post-quantum PKINIT or encryption certificates'; Where = '-'; Since = 'Not available'; Note = 'S/MIME, EFS and PKINIT stay classical for now' }
        )
    }

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) ('QuantumReadiness_' + (Get-Date -Format 'yyyyMMdd_HHmmss')) }
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $report | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $OutputPath 'findings.json') -Encoding UTF8
    ConvertTo-QrCbom -Analysis $a -Label $label | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $OutputPath 'cbom.cdx.json') -Encoding UTF8
    Set-Content (Join-Path $OutputPath 'roadmap.md') -Value (ConvertTo-QrMarkdown -Report $report) -Encoding UTF8
    $a.Assets | Select-Object @{ n = 'Rank'; e = { Get-Prop $_ 'Rank' } }, Category, Name, Host, Detail, Os, Algorithm, Signature, KeyExchange, QuantumVulnerable, Classification, ShelfLifeYears, ProtectedUntil, TrustUntil, Exposure, MigrationYears, StartBy, Urgency, YearsLate,
    @{ n = 'Issues'; e = { ($_.Issues | ForEach-Object { "$($_.Code) $($_.Severity): $($_.Title)" }) -join ' | ' } }, PqcPath |
        Sort-Object @{ e = { if ($_.Rank) { $_.Rank } else { 9999 } } }, Category, Name | Export-Csv (Join-Path $OutputPath 'inventory.csv') -NoTypeInformation -Encoding UTF8
    $tpl = Join-Path $root 'report/template.html'
    if (Test-Path $tpl) {
        $json = ($report | ConvertTo-Json -Depth 10 -Compress) -replace '</', '<\/'
        Set-Content (Join-Path $OutputPath 'index.html') -Value ((Get-Content $tpl -Raw -Encoding UTF8).Replace('/*__QR_DATA__*/null', $json)) -Encoding UTF8
    }
    $s = $a.Summary
    Write-Host ''
    Write-Host "  $($s.HarvestExposed) systems protect data that must stay secret past $($s.QuantumYear)  ·  $($s.Overdue) migrations overdue  ·  $($s.BrokenToday) broken today"
    Write-Host "  $($s.QuantumVulnerable) of $($s.Assets) assets quantum-vulnerable  ·  hybrid ML-KEM on $($s.HybridOn), available but off on $($s.HybridAvailableOff)"
    Write-Host "  Output: $OutputPath"
    [pscustomobject]@{ Report = $report; Analysis = $a; OutputPath = $OutputPath }
}

if ($MyInvocation.InvocationName -ne '.') {
    Write-Host ''
    Write-Host "  Quantum-Ready Windows PKI v$script:QrVersion"
    $null = Invoke-QuantumReadyPki -Demo:$Demo -InputPath $InputPath -QuantumYear $QuantumYear -ShelfLife $ShelfLife -MigrationYears $MigrationYears -Endpoints $Endpoints -OutputPath $OutputPath
}
