#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
# Run: Invoke-Pester ./tests

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-QuantumReadyPki.ps1')
    $script:Now = [datetime]'2026-10-27'; $script:Q = [datetime]'2030-01-01'
    $script:Mig = @{ CaHierarchy = 3; Template = 1; OsUpgrade = 1.5; TlsConfig = 0.25; CertReissue = 1; Pkinit = 2 }
    $script:Shelf = @{ Public = 0; Internal = 2; Confidential = 7; Restricted = 15; Regulated = 25 }
    function New-Cert { param([string]$Alg = 'RSA', [int]$Size = 2048, [string]$Sig = 'sha256RSA', [string]$NotAfter = '2027-06-01', [bool]$Self = $false)
        [pscustomobject]@{ subject = 'CN=x'; issuer = 'CN=ca'; keyAlgorithm = $Alg; keySize = $Size; signatureAlgorithm = $Sig; notBefore = '2025-01-01'; notAfter = $NotAfter; selfSigned = $Self } }
    function New-Ep { param([string]$Os = 'Windows Server 2022', [string]$Proto = 'TLS 1.3', [string]$Suite = 'TLS_AES_256_GCM_SHA384', [string]$Kex = 'x25519', [string]$Svc = 'LDAPS', [string]$Cls, $Cert = (New-Cert))
        $e = [pscustomobject]@{ host = 'h1'; service = $Svc; port = 636; os = $Os; protocol = $Proto; cipherSuite = $Suite; keyExchange = $Kex; cert = $Cert }
        if ($Cls) { $e | Add-Member -NotePropertyName classification -NotePropertyValue $Cls }
        $e }
}

Describe 'Algorithms, operating systems and encodings' {
    It 'classifies keys by quantum safety and classical strength' {
        (Get-QrKeyClass 'RSA' 1024).Classical | Should -Be 'Broken'
        (Get-QrKeyClass 'RSA' 2048).Classical | Should -Be 'Until2030'
        (Get-QrKeyClass 'RSA' 4096).QuantumSafe | Should -BeFalse
        (Get-QrKeyClass 'ECDSA' 384).Label | Should -Be 'ECDSA P-384'
        (Get-QrKeyClass 'ML-DSA-65').QuantumSafe | Should -BeTrue
        Test-QrWeakHash 'sha1RSA' | Should -BeTrue
        Test-QrWeakHash 'sha256RSA' | Should -BeFalse
    }
    It 'knows which Windows releases can do TLS 1.3, hybrid ML-KEM and ML-DSA CAs' {
        $s25 = Get-QrOsPqc 'Windows Server 2025 Datacenter'
        $s25.HybridMlKem | Should -BeTrue; $s25.MlDsaCa | Should -BeTrue
        $s22 = Get-QrOsPqc 'Windows Server 2022 Standard'
        $s22.Tls13 | Should -BeTrue; $s22.HybridMlKem | Should -BeFalse
        (Get-QrOsPqc 'Windows Server 2019 Standard').Tls13 | Should -BeFalse
        (Get-QrOsPqc 'Windows Server 2012 R2 Standard').Support | Should -Be 'Unsupported'
    }
    It 'decodes msDS-SupportedEncryptionTypes, pKIExpirationPeriod and v3+ template policies' {
        (ConvertFrom-QrEncTypes 0x1C) -join ',' | Should -Be 'RC4-HMAC,AES128,AES256'
        ConvertFrom-QrEncTypes $null | Should -BeNullOrEmpty
        # One year as a negative FILETIME interval
        ConvertFrom-QrPkiPeriod ([BitConverter]::GetBytes([int64](-365 * 864000000000))) | Should -Be 365
        $p = ConvertFrom-QrTemplatePolicy 'msPKI-Asymmetric-Algorithm`PZPWSTR`ML-DSA-65`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`'
        $p.KeyAlgorithm | Should -Be 'ML-DSA-65'
        $p.HashAlgorithm | Should -Be 'SHA512'
    }
}

Describe "Mosca's inequality" {
    It 'dates confidentiality from shelf life plus migration time' {
        $d = Get-QrStartBy -Kind Confidentiality -QuantumDate $script:Q -MigrationYears 1 -ShelfYears 7
        $d.Year | Should -Be 2022
        Get-QrUrgency -StartBy $d -Now $script:Now | Should -Be 'Overdue'
        Get-QrStartBy -Kind Confidentiality -QuantumDate $script:Q -MigrationYears 1 -ShelfYears 0 | Should -BeNullOrEmpty
    }
    It 'dates signatures from migration time plus the validity of certificates still to be issued' {
        $d = Get-QrStartBy -Kind Authenticity -QuantumDate $script:Q -MigrationYears 3
        $d.Year | Should -Be 2027
        Get-QrUrgency -StartBy $d -Now $script:Now | Should -Be 'Now'
        Get-QrUrgency -StartBy ([datetime]'2028-06-01') -Now $script:Now | Should -Be 'Next'
        Get-QrUrgency -StartBy ([datetime]'2032-01-01') -Now $script:Now | Should -Be 'Later'
    }
}

Describe 'Endpoints' {
    It 'calls hybrid ML-KEM a quick win where Windows supports it but it is off' {
        $a = Test-QrEndpoint -Endpoint (New-Ep -Os 'Windows Server 2025') -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        @($a.Issues.Code) | Should -Contain 'QR-13'
        $a.MigrationYears | Should -Be 0.25
    }
    It 'needs an OS upgrade on Windows Server 2022 and older' {
        $a = Test-QrEndpoint -Endpoint (New-Ep) -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        @($a.Issues.Code) | Should -Contain 'QR-12'
        $a.ShelfLifeYears | Should -Be 7
        $a.Urgency | Should -Be 'Overdue'
    }
    It 'treats hybrid key exchange as safe for confidentiality, leaving only the certificate' {
        $a = Test-QrEndpoint -Endpoint (New-Ep -Os 'Windows Server 2025' -Kex 'X25519MLKEM768' -Cls 'Regulated') -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        $a.ConfidentialityStartBy | Should -BeNullOrEmpty
        $a.Exposure | Should -Be 'Authenticity'
        $a.QuantumSafeParts | Should -Contain 'KeyExchange'
    }
    It 'flags classical problems: RSA key transport, old TLS, self-signed, SHA-1, cleartext WSUS' {
        $a = Test-QrEndpoint -Endpoint (New-Ep -Os 'Windows Server 2016' -Proto 'TLS 1.0' -Suite 'TLS_RSA_WITH_AES_128_CBC_SHA' -Kex 'RSA' -Cert (New-Cert -Sig 'sha1RSA' -Self $true)) -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        foreach ($c in 'QR-10', 'QR-11', 'QR-15', 'QR-01') { @($a.Issues.Code) | Should -Contain $c }
        $w = Test-QrEndpoint -Endpoint (New-Ep -Svc 'WSUS' -Proto 'HTTP' -Cert $null) -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        $w.Issues[0].Code | Should -Be 'QR-16'
        $w.Issues[0].Severity | Should -Be 'Critical'
    }
}

Describe 'AD CS' {
    It 'needs a parallel ML-DSA hierarchy for a classical CA trusted past the quantum year' {
        $ca = [pscustomobject]@{ name = 'Root'; host = 'ca'; os = 'Windows Server 2019'; type = 'Root'; cert = (New-Cert -Size 4096 -NotAfter '2036-01-01'); publishedTemplates = @() }
        $a = Test-QrCa -Ca $ca -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig
        ($a.Issues | Where-Object Code -eq 'QR-04').Severity | Should -Be 'High'
        $a.PqcPath | Should -Match 'new Windows Server 2025'
        @($a.Issues.Code) | Should -Contain 'QR-26'
    }
    It 'recognises an ML-DSA CA as already post-quantum' {
        $ca = [pscustomobject]@{ name = 'PQC'; host = 'pq'; os = 'Windows Server 2025'; type = 'Root'; cert = (New-Cert -Alg 'ML-DSA-65' -Size 0 -Sig 'ML-DSA-65' -NotAfter '2041-01-01'); publishedTemplates = @() }
        $a = Test-QrCa -Ca $ca -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig
        $a.QuantumVulnerable | Should -BeFalse
        $a.Urgency | Should -Be 'None'
    }
    It 'separates encryption templates (no PQC path) from signing templates on legacy providers' {
        $cas = @([pscustomobject]@{ name = 'CA'; publishedTemplates = @('Mail', 'Web') })
        $mail = [pscustomobject]@{ name = 'Mail'; schemaVersion = 3; keyAlgorithm = 'RSA'; minKeySize = 2048; hashAlgorithm = 'SHA256'; provider = 'KSP'; ekus = @('1.3.6.1.5.5.7.3.4'); validityDays = 730; archival = $true; classification = 'Regulated' }
        $web = [pscustomobject]@{ name = 'Web'; schemaVersion = 2; keyAlgorithm = 'RSA'; minKeySize = 2048; hashAlgorithm = 'SHA256'; provider = 'CSP'; ekus = @('1.3.6.1.5.5.7.3.1'); validityDays = 365 }
        $m = Test-QrTemplate -Template $mail -Cas $cas -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        @($m.Issues.Code) | Should -Contain 'QR-07'
        $m.ShelfLifeYears | Should -Be 25
        $m.PqcPath | Should -Match 'signature-only'
        $w = Test-QrTemplate -Template $web -Cas $cas -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        @($w.Issues.Code) | Should -Contain 'QR-06'
        $w.Exposure | Should -Be 'Authenticity'
        Test-QrTemplate -Template ([pscustomobject]@{ name = 'Unpublished' }) -Cas $cas -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf | Should -BeNullOrEmpty
    }
}

Describe 'Kerberos' {
    It 'finds RC4, DES, missing AES keys, RC4 trusts and an old krbtgt, and leaves AES accounts alone' {
        $k = [pscustomobject]@{ domain = 'contoso.com'; aesKeysSince = '2011-01-01'; krbtgtPwdLastSet = '2019-01-01'
            accounts = @(
                [pscustomobject]@{ samAccountName = 'rc4'; supportedEncTypes = 4; pwdLastSet = '2015-01-01'; kdcEvents = [pscustomobject]@{ '203' = 5 } }
                [pscustomobject]@{ samAccountName = 'old'; supportedEncTypes = $null; pwdLastSet = '2009-01-01' }
                [pscustomobject]@{ samAccountName = 'des'; supportedEncTypes = 3; pwdLastSet = '2020-01-01'; useDesKeyOnly = $true }
                [pscustomobject]@{ samAccountName = 'ok'; supportedEncTypes = 24; pwdLastSet = '2024-01-01' })
            trusts = @([pscustomobject]@{ name = 'legacy.local'; supportedEncTypes = 4 }) }
        $r = Test-QrKerberos -Kerberos $k -Templates @() -Now $script:Now -QuantumDate $script:Q -Migration $script:Mig -Shelf $script:Shelf
        $r.Stats.Rc4 | Should -Be 1; $r.Stats.NoAesKeys | Should -Be 1; $r.Stats.Des | Should -Be 1; $r.Stats.Healthy | Should -Be 1
        $r.Stats.Events['203'] | Should -Be 5
        $dom = $r.Assets | Where-Object Name -eq 'Domain Kerberos policy'
        @($dom.Issues.Code) | Should -Contain 'QR-21'
        @($dom.Issues.Code) | Should -Contain 'QR-23'
        @($r.Assets | Where-Object Name -eq 'ok').Count | Should -Be 0
    }
}

Describe 'Demo estate' {
    It 'ranks, phases and writes every output' {
        $out = Join-Path ([IO.Path]::GetTempPath()) ("qr-test-" + [guid]::NewGuid())
        $run = Invoke-QuantumReadyPki -Demo $true -OutputPath $out
        $s = $run.Report.Summary
        $s.Assets | Should -Be 45
        $s.QuantumVulnerable | Should -Be 32
        $s.HarvestExposed | Should -Be 14
        $s.HybridOn | Should -Be 2
        $s.HybridAvailableOff | Should -Be 1
        $r = @($run.Report.Ranked)
        $r[0].Name | Should -Be 'IIS hr.contoso.com:443'
        for ($i = 1; $i -lt $r.Count; $i++) { [datetime]$r[$i].StartBy | Should -BeGreaterOrEqual ([datetime]$r[$i - 1].StartBy) }
        @($run.Report.Phases).Count | Should -Be 5
        foreach ($f in 'index.html', 'findings.json', 'cbom.cdx.json', 'inventory.csv', 'roadmap.md') { Join-Path $out $f | Should -Exist }
        $cbom = Get-Content (Join-Path $out 'cbom.cdx.json') -Raw | ConvertFrom-Json
        $cbom.bomFormat | Should -Be 'CycloneDX'
        $cbom.specVersion | Should -Be '1.6'
        @($cbom.components | Where-Object { $_.cryptoProperties.assetType -eq 'algorithm' -and $_.name -eq 'ML-DSA-65' }).Count | Should -Be 1
        Remove-Item $out -Recurse -Force
    }
    It 'moves the plan later with a later quantum year' {
        $out = Join-Path ([IO.Path]::GetTempPath()) ("qr-test-" + [guid]::NewGuid())
        $run = Invoke-QuantumReadyPki -Demo $true -OutputPath $out -QuantumYear 2035
        $run.Report.Summary.Overdue | Should -BeLessOrEqual 22
        Remove-Item $out -Recurse -Force
    }
}
