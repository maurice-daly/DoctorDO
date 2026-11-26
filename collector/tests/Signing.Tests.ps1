#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Signed-request protocol v1 (contract C1) against the golden vector contracts/signing/signing-v1.vector.json, and the
# selection of the Entra device certificate. Real cryptography throughout; certificates are built in memory and never
# added to a store.
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:Vector = Get-SigningVector
    $script:Rsa = $script:Vector.cases | Where-Object { $_.name -eq 'rsa-entra-device-key' }
    $script:Ec = $script:Vector.cases | Where-Object { $_.name -eq 'ecdsa-tenant-ca-key' }
    $script:Body = [Convert]::FromBase64String($script:Rsa.request.bodyBase64)
    $script:Sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    function Get-CaseCanonical {
        param($Case)
        $h = $Case.request.headers
        InModuleScope DoctorDO.Collector -Parameters @{ C = $Case; H = $h } {
            param($C, $H)
            Get-DDCanonicalString -Method $C.request.method -Path $C.request.path -HostName $C.request.host -Kind $H.'x-doctordo-kind' `
                -CollectedAt $H.'x-doctordo-collected-at' -SignedAt $H.'x-doctordo-signed-at' -Nonce $H.'x-doctordo-nonce' -Body ([Convert]::FromBase64String($C.request.bodyBase64))
        }
    }
}

Describe 'Canonical string (golden vector)' {
    It 'equals the vector canonical string for <name>' -ForEach @(@{ name = 'rsa-entra-device-key' }, @{ name = 'ecdsa-tenant-ca-key' }) {
        $case = $script:Vector.cases | Where-Object { $_.name -eq $name }
        $s = Get-CaseCanonical -Case $case
        $s | Should -BeExactly $case.canonicalString
        $s | Should -Not -Match "`r" -Because 'LF only, also on Windows'
        $s.EndsWith("`n") | Should -BeFalse -Because 'no trailing newline'
    }

    It 'hashes the body bytes as sent (base64 SHA-256 of the gzip bytes)' {
        InModuleScope DoctorDO.Collector -Parameters @{ B = $script:Body } { param($B) Get-DDBodyHash -Body $B } | Should -BeExactly $script:Rsa.bodySha256Base64
    }
}

Describe 'RSA signature (golden vector, byte for byte)' {
    BeforeAll { $script:RsaCert = New-VectorCertificate -Case $script:Rsa }

    It 'the test certificate carries the vector key and thumbprint' {
        $script:RsaCert.HasPrivateKey | Should -BeTrue
        $script:RsaCert.Thumbprint | Should -Be $script:Rsa.certificateSha1Thumbprint
    }

    It 'New-DDSignature reproduces the vector signature exactly' {
        $sig = InModuleScope DoctorDO.Collector -Parameters @{ C = $script:RsaCert; S = $script:Rsa.canonicalString } {
            param($C, $S) New-DDSignature -Certificate $C -Data ([System.Text.Encoding]::UTF8.GetBytes($S))
        }
        $sig | Should -BeExactly $script:Rsa.request.headers.'x-doctordo-signature'
    }

    It 'New-DDSignedHeaders produces the four vector headers from the canonical inputs' {
        $h = $script:Rsa.request.headers
        $out = InModuleScope DoctorDO.Collector -Parameters @{ C = $script:RsaCert; H = $h; B = $script:Body; U = [uri]"https://$($script:Rsa.request.host)$($script:Rsa.request.path)" } {
            param($C, $H, $B, $U)
            New-DDSignedHeaders -Certificate $C -Uri $U -Kind $H.'x-doctordo-kind' -CollectedAt $H.'x-doctordo-collected-at' -Body $B -SignedAt $H.'x-doctordo-signed-at' -Nonce $H.'x-doctordo-nonce'
        }
        @($out.Keys) | Should -Be @('X-DoctorDO-Device-Cert', 'X-DoctorDO-Signed-At', 'X-DoctorDO-Nonce', 'X-DoctorDO-Signature')
        $out['X-DoctorDO-Device-Cert'] | Should -BeExactly $h.'x-doctordo-device-cert'
        $out['X-DoctorDO-Signed-At'] | Should -BeExactly $h.'x-doctordo-signed-at'
        $out['X-DoctorDO-Nonce'] | Should -BeExactly $h.'x-doctordo-nonce'
        $out['X-DoctorDO-Signature'] | Should -BeExactly $h.'x-doctordo-signature'
    }

    It 'signs over the host in lower case without the port' {
        $h = $script:Rsa.request.headers
        $out = InModuleScope DoctorDO.Collector -Parameters @{ C = $script:RsaCert; H = $h; B = $script:Body; U = [uri]"https://$($script:Rsa.request.host.ToUpperInvariant()):8443/v1/ingest" } {
            param($C, $H, $B, $U)
            New-DDSignedHeaders -Certificate $C -Uri $U -Kind $H.'x-doctordo-kind' -CollectedAt $H.'x-doctordo-collected-at' -Body $B -SignedAt $H.'x-doctordo-signed-at' -Nonce $H.'x-doctordo-nonce'
        }
        $out['X-DoctorDO-Signature'] | Should -BeExactly $h.'x-doctordo-signature'
    }

    It 'a one-byte change in the body changes the signature (the body hash is signed)' {
        $h = $script:Rsa.request.headers
        $b2 = [byte[]]$script:Body.Clone(); $b2[$b2.Length - 1] = $b2[$b2.Length - 1] -bxor 1
        $out = InModuleScope DoctorDO.Collector -Parameters @{ C = $script:RsaCert; H = $h; B = $b2; U = [uri]"https://$($script:Rsa.request.host)/v1/ingest" } {
            param($C, $H, $B, $U)
            New-DDSignedHeaders -Certificate $C -Uri $U -Kind $H.'x-doctordo-kind' -CollectedAt $H.'x-doctordo-collected-at' -Body $B -SignedAt $H.'x-doctordo-signed-at' -Nonce $H.'x-doctordo-nonce'
        }
        $out['X-DoctorDO-Signature'] | Should -Not -Be $h.'x-doctordo-signature'
    }
}

Describe 'ECDSA P-256 signature (verify only)' {
    BeforeAll {
        $script:EcCert = New-VectorCertificate -Case $script:Ec
        $script:EcPub = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]](Get-TestPemBytes -Pem $script:Ec.certificatePem))
    }

    It 'the vector''s own signature verifies (sanity check of the verifier used below)' {
        $pk = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($script:EcPub)
        $pk.VerifyData([System.Text.Encoding]::UTF8.GetBytes($script:Ec.canonicalString), [Convert]::FromBase64String($script:Ec.request.headers.'x-doctordo-signature'), $script:Sha256) | Should -BeTrue
    }

    It 'a signature produced by the collector verifies with the vector certificate''s public key, in P1363 form' {
        $h = $script:Ec.request.headers
        $out = InModuleScope DoctorDO.Collector -Parameters @{ C = $script:EcCert; H = $h; B = $script:Body; U = [uri]"https://$($script:Ec.request.host)/v1/ingest" } {
            param($C, $H, $B, $U)
            New-DDSignedHeaders -Certificate $C -Uri $U -Kind $H.'x-doctordo-kind' -CollectedAt $H.'x-doctordo-collected-at' -Body $B -SignedAt $H.'x-doctordo-signed-at' -Nonce $H.'x-doctordo-nonce'
        }
        $sig = [Convert]::FromBase64String($out['X-DoctorDO-Signature'])
        $sig.Length | Should -Be 64 -Because 'IEEE P1363 r||s for P-256, not DER'
        $pk = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($script:EcPub)
        $pk.VerifyData([System.Text.Encoding]::UTF8.GetBytes($script:Ec.canonicalString), $sig, $script:Sha256) | Should -BeTrue
        $out['X-DoctorDO-Device-Cert'] | Should -BeExactly $h.'x-doctordo-device-cert'
    }

    It 'refuses an EC key that is not P-256' {
        $p384 = New-EntraTestCertificate -KeyType ecdsa-p384
        { InModuleScope DoctorDO.Collector -Parameters @{ C = $p384 } { param($C) New-DDSignature -Certificate $C -Data ([byte[]](1, 2, 3)) } } | Should -Throw '*P-256*'
    }
}

Describe 'RSA key fallback: the device key opened by container name' {
    BeforeAll {
        # A certificate whose private key the certificate object cannot reach (public part only), and the matching
        # key, which the mocked Open-DDMachineRsaKey hands out as a fresh object each time (the signer disposes it).
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $full = $req.CreateSelfSigned([System.DateTimeOffset]::UtcNow.AddDays(-1), [System.DateTimeOffset]::UtcNow.AddDays(1))
        $script:PubOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $full.RawData)
        $global:DDKeyParams = $rsa.ExportParameters($true)
        $global:DDOtherParams = ([System.Security.Cryptography.RSA]::Create(2048)).ExportParameters($true)
        $script:Data = [System.Text.Encoding]::UTF8.GetBytes($script:Rsa.canonicalString)
    }
    BeforeEach {
        $global:DDOpened = $null
        Mock -ModuleName DoctorDO.Collector Open-DDMachineRsaKey { $global:DDOpened = @{ C = $KeyContainer; P = $KeyProvider }; $k = [System.Security.Cryptography.RSA]::Create(); $k.ImportParameters($global:DDKeyParams); $k }
    }

    It 'signs with the key named by dsregcmd KeyContainerId / KeyProvider when the certificate cannot give its key' {
        $sig = InModuleScope DoctorDO.Collector -Parameters @{ C = $script:PubOnly; D = $script:Data } {
            param($C, $D) New-DDSignature -Certificate $C -Data $D -KeyContainer '374d6ad5-6fe4-49e1-810b-e8ae65df8641' -KeyProvider 'Microsoft Platform Crypto Provider'
        }
        $global:DDOpened.C | Should -Be '374d6ad5-6fe4-49e1-810b-e8ae65df8641'
        $global:DDOpened.P | Should -Be 'Microsoft Platform Crypto Provider'
        $pk = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($script:PubOnly)
        $pk.VerifyData($script:Data, [Convert]::FromBase64String($sig), $script:Sha256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) | Should -BeTrue
    }

    It 'refuses a key from the container that is not the certificate''s key' {
        Mock -ModuleName DoctorDO.Collector Open-DDMachineRsaKey { $k = [System.Security.Cryptography.RSA]::Create(); $k.ImportParameters($global:DDOtherParams); $k }
        { InModuleScope DoctorDO.Collector -Parameters @{ C = $script:PubOnly; D = $script:Data } { param($C, $D) New-DDSignature -Certificate $C -Data $D -KeyContainer 'x' -KeyProvider 'y' } } | Should -Throw '*different key*'
    }

    It 'without a container name it fails with the reason, and never opens anything' {
        { InModuleScope DoctorDO.Collector -Parameters @{ C = $script:PubOnly; D = $script:Data } { param($C, $D) New-DDSignature -Certificate $C -Data $D } } | Should -Throw
        Should -Invoke -ModuleName DoctorDO.Collector Open-DDMachineRsaKey -Times 0
    }

    It 'is not used when the certificate''s own key works' {
        $c = New-EntraTestCertificate
        $null = InModuleScope DoctorDO.Collector -Parameters @{ C = $c; D = $script:Data } { param($C, $D) New-DDSignature -Certificate $C -Data $D -KeyContainer 'x' -KeyProvider 'y' }
        Should -Invoke -ModuleName DoctorDO.Collector Open-DDMachineRsaKey -Times 0
    }
}

Describe 'Nonce, signed-at and ingest URI' {
    It 'nonce is 16 random bytes as 22 base64url characters without padding, fresh every time' {
        $n = InModuleScope DoctorDO.Collector { @(1..50 | ForEach-Object { New-DDNonce }) }
        foreach ($x in $n) { $x | Should -MatchExactly '^[A-Za-z0-9_-]{22}$' }
        @($n | Select-Object -Unique).Count | Should -Be 50
    }

    It 'signed-at defaults to the clock in RFC 3339 UTC with whole seconds' {
        Mock -ModuleName DoctorDO.Collector Get-DDNowUtc { [datetime]::new(2026, 10, 12, 14, 3, 22, 640, [System.DateTimeKind]::Utc) }
        $c = New-EntraTestCertificate
        $h = InModuleScope DoctorDO.Collector -Parameters @{ C = $c } { param($C) New-DDSignedHeaders -Certificate $C -Uri ([uri]'https://h.example/v1/ingest') -Kind 'telemetry' -CollectedAt '2026-10-12T14:00:00Z' -Body ([byte[]](1)) }
        $h['X-DoctorDO-Signed-At'] | Should -BeExactly '2026-10-12T14:03:22Z'
    }

    It 'normalises the ingest URI to https://<host>/v1/ingest and refuses anything else' -ForEach @(
        @{ In = 'https://func-x.azurewebsites.net/v1/ingest'; Out = 'https://func-x.azurewebsites.net/v1/ingest' }
        @{ In = 'https://func-x.azurewebsites.net'; Out = 'https://func-x.azurewebsites.net/v1/ingest' }
        @{ In = 'https://func-x.azurewebsites.net/'; Out = 'https://func-x.azurewebsites.net/v1/ingest' }
        @{ In = 'https://localhost:8443/v1/ingest'; Out = 'https://localhost:8443/v1/ingest' }
        @{ In = 'http://func-x.azurewebsites.net/v1/ingest'; Out = $null }
        @{ In = 'https://func-x.azurewebsites.net/api/v1/ingest'; Out = $null }
        @{ In = 'https://func-x.azurewebsites.net/v1/ingest?code=abc'; Out = $null }
        @{ In = 'https://func-x.azurewebsites.net/V1/Ingest'; Out = $null }
    ) {
        $r = InModuleScope DoctorDO.Collector -Parameters @{ U = [uri]$In } { param($U) Resolve-DDIngestUri -Uri $U }
        if ($null -eq $Out) { $r | Should -BeNullOrEmpty } else { $r.AbsoluteUri | Should -BeExactly $Out }
    }
}

Describe 'Entra device certificate selection (entra-device)' {
    BeforeAll {
        $script:Id = '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20'
        $script:Good = New-EntraTestCertificate -DeviceId $script:Id
        $script:Decoys = @(
            (New-EntraTestCertificate -DeviceId $script:Id -IssuerDn 'CN=MS-Organization-P2P-Access [2025]' -SubjectDn "CN=$($script:Id), DC=9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10"),
            (New-EntraTestCertificate -DeviceId '99999999-2222-4333-8444-555555555555'),
            (New-EntraTestCertificate -DeviceId $script:Id -IssuerDn 'CN=Contoso Issuing CA'),
            (New-EntraTestCertificate -DeviceId $script:Id -NotBefore ([datetime]::UtcNow.AddYears(-11)) -NotAfter ([datetime]::UtcNow.AddDays(-1))),
            (New-EntraTestCertificate -DeviceId $script:Id -NoPrivateKey),
            (New-TestCertificate -DeviceId $script:Id),
            (New-EntraTestCertificate -DeviceId $script:Id -IssuerDn 'CN=Not-MS-Organization-Access')
        )
        function Invoke-Select { param($Certs, [string] $DsregThumbprint, [string] $Thumbprint, [string] $Id = $script:Id)
            InModuleScope DoctorDO.Collector -Parameters @{ L = $Certs; Id = $Id; D = $DsregThumbprint; T = $Thumbprint } { param($L, $Id, $D, $T) Select-DDEntraDeviceCertificate -Certificates $L -EntraDeviceId $Id -DsregThumbprint $D -Thumbprint $T }
        }
    }

    It 'picks the MS-Organization-Access certificate for this device among decoys (P2P, other device, other issuer, expired, no key, SCEP)' {
        $r = Invoke-Select -Certs (@($script:Decoys) + $script:Good)
        $r.Reason | Should -BeNullOrEmpty
        $r.Certificate.Thumbprint | Should -Be $script:Good.Thumbprint
    }

    It 'requires the thumbprint dsregcmd reports, compared case-insensitively' {
        (Invoke-Select -Certs (@($script:Decoys) + $script:Good) -DsregThumbprint $script:Good.Thumbprint.ToLowerInvariant()).Certificate.Thumbprint | Should -Be $script:Good.Thumbprint
        $r = Invoke-Select -Certs @($script:Good) -DsregThumbprint ('A' * 40)
        $r.Certificate | Should -BeNullOrEmpty
        $r.Reason | Should -Match 'thumbprint dsregcmd reports'
    }

    It 'matches the subject CN to the device ID case-insensitively' {
        $upper = New-EntraTestCertificate -DeviceId $script:Id.ToUpperInvariant()
        (Invoke-Select -Certs @($upper)).Certificate.Thumbprint | Should -Be $upper.Thumbprint
    }

    It 'fails rather than guess when two qualify and dsregcmd gives no thumbprint, and resolves with one' {
        $second = New-EntraTestCertificate -DeviceId $script:Id
        $r = Invoke-Select -Certs @($script:Good, $second)
        $r.Certificate | Should -BeNullOrEmpty
        $r.Reason | Should -Match '2 certificates qualify'
        (Invoke-Select -Certs @($script:Good, $second) -DsregThumbprint $second.Thumbprint).Certificate.Thumbprint | Should -Be $second.Thumbprint
    }

    It 'says why nothing qualified' -ForEach @(
        @{ Which = 'none'; Pattern = 'no certificate issued by MS-Organization-Access' }
        @{ Which = 'expired'; Pattern = 'validity period' }
        @{ Which = 'nokey'; Pattern = 'no private key' }
    ) {
        $certs = switch ($Which) {
            'none' { @($script:Decoys[0], $script:Decoys[1], $script:Decoys[2]) }
            'expired' { @($script:Decoys[3]) }
            'nokey' { @($script:Decoys[4]) }
        }
        $r = Invoke-Select -Certs $certs
        $r.Certificate | Should -BeNullOrEmpty
        $r.Reason | Should -Match $Pattern
    }

    It 'honours an explicit -CertificateThumbprint as well' {
        $r = Invoke-Select -Certs @($script:Good) -Thumbprint ('B' * 40)
        $r.Certificate | Should -BeNullOrEmpty
        $r.Reason | Should -Match 'CertificateThumbprint'
    }

    It 'reads the issuer CN from a multi-valued RDN, as seen on a real device (DC=net + DC=windows + CN=MS-Organization-Access + OU=...)' {
        $multi = $null
        try { $multi = New-EntraTestCertificate -DeviceId $script:Id -IssuerDn 'DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97' } catch { $multi = $null }
        if ($null -eq $multi) { Set-ItResult -Skipped -Because 'this platform cannot encode a multi-valued RDN from a string'; return }
        # Linux .NET accepts the string but does not encode it as one multi-valued RDN, so the issuer CN never reads
        # as MS-Organization-Access there. Devices are Windows; Windows PowerShell 5.1 and 7 on Windows run this test.
        if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { Set-ItResult -Skipped -Because 'only Windows encodes a multi-valued RDN from this string the way a real device certificate carries it'; return }
        (Invoke-Select -Certs @($multi)).Certificate.Thumbprint | Should -Be $multi.Thumbprint
    }
}

Describe 'Tenant CA certificate selection keeps Entra certificates out' {
    It 'never picks an MS-Organization-* certificate, even though it carries the device ID and the client-auth EKU' {
        $id = '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20'
        $entra = New-EntraTestCertificate -DeviceId $id
        $p2p = New-EntraTestCertificate -DeviceId $id -IssuerDn 'CN=MS-Organization-P2P-Access [2025]'
        $scep = New-TestCertificate -DeviceId $id -NotAfter ([datetime]::UtcNow.AddDays(200))
        $r = InModuleScope DoctorDO.Collector -Parameters @{ L = @($entra, $p2p, $scep); Id = $id } { param($L, $Id) Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id }
        $r.Thumbprint | Should -Be $scep.Thumbprint
        $none = InModuleScope DoctorDO.Collector -Parameters @{ L = @($entra, $p2p); Id = $id } { param($L, $Id) Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id }
        $none | Should -BeNullOrEmpty
    }

    It 'restricts to the registered issuer when -Issuer is given (DN or CN)' {
        $id = '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20'
        $scep = New-TestCertificate -DeviceId $id    # self-signed: issuer = CN=<id>
        $r = InModuleScope DoctorDO.Collector -Parameters @{ L = @($scep); Id = $id } {
            param($L, $Id)
            @{ Dn = (Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id -Issuer "CN=$Id"); Cn = (Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id -Issuer $Id.ToUpperInvariant()); Other = (Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id -Issuer 'CN=Contoso Issuing CA') }
        }
        $r.Dn.Thumbprint | Should -Be $scep.Thumbprint
        $r.Cn.Thumbprint | Should -Be $scep.Thumbprint
        $r.Other | Should -BeNullOrEmpty
    }
}

Describe 'dsregcmd /status: device certificate fields' {
    It 'parses the Device Details Thumbprint and KeyProvider' {
        $tp = 'FE35E8C1C7BEDFA9D2C20E80069FC6022C4F0047'
        $d = InModuleScope DoctorDO.Collector -Parameters @{ L = (New-DsregText -Thumbprint $tp.ToLowerInvariant()) } { param($L) ConvertFrom-DDDsregStatus -Lines $L }
        $d.DeviceCertificateThumbprint | Should -BeExactly $tp
        $d.KeyProvider | Should -Be 'Microsoft Platform Crypto Provider'
        $d.AzureAdJoined | Should -BeTrue
    }
    It 'accepts the blank lines real dsregcmd output contains (they used to fail parameter binding)' {
        $lines = New-DsregText -Thumbprint ('D' * 40)
        @($lines | Where-Object { $_ -eq '' }).Count | Should -BeGreaterThan 0
        $d = InModuleScope DoctorDO.Collector -Parameters @{ L = $lines } { param($L) ConvertFrom-DDDsregStatus -Lines $L }
        $d.Parsed | Should -BeTrue
        $d.DeviceId | Should -Be '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20'
    }

    It 'leaves the thumbprint empty when dsregcmd prints none or something that is not a thumbprint' {
        (InModuleScope DoctorDO.Collector -Parameters @{ L = (New-DsregText) } { param($L) ConvertFrom-DDDsregStatus -Lines $L }).DeviceCertificateThumbprint | Should -BeNullOrEmpty
        (InModuleScope DoctorDO.Collector -Parameters @{ L = (New-DsregText -Thumbprint 'not-a-thumbprint') } { param($L) ConvertFrom-DDDsregStatus -Lines $L }).DeviceCertificateThumbprint | Should -BeNullOrEmpty
    }
}
