#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:DeviceId = '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20'    # the fake device's dsregcmd DeviceId
    $script:Cert = New-TestCertificate -DeviceId $script:DeviceId    # tenant-ca: SCEP-style, SAN carries the device ID
    $script:EntraCert = New-EntraTestCertificate -DeviceId $script:DeviceId
    $script:P2P = New-EntraTestCertificate -DeviceId $script:DeviceId -IssuerDn 'CN=MS-Organization-P2P-Access [2025]'
    $script:Telemetry = InModuleScope DoctorDO.Collector -Parameters @{ Fix = (Join-Path $PSScriptRoot 'fixtures') } {
        param($Fix)
        $raw = Read-DDJsonFile -Path (Join-Path $Fix 'few-files.raw.json')
        $ctx = Read-DDJsonFile -Path (Join-Path $Fix 'few-files.context.json')
        ConvertTo-DDTelemetry -Raw $raw -Seq 3 -InventoryHash $ctx['inventoryHash'] -PeriodFrom $ctx['period']['from'] -PeriodTo $ctx['period']['to']
    }
    $script:Inventory = InModuleScope DoctorDO.Collector -Parameters @{ Fix = (Join-Path $PSScriptRoot 'fixtures') } { param($Fix) Read-DDJsonFile -Path (Join-Path $Fix 'inventory.sample.json') }
    $script:Uri = [uri]'https://ingest.contoso.example/v1/ingest'
    $script:SignedNames = @('X-DoctorDO-Device-Cert', 'X-DoctorDO-Signed-At', 'X-DoctorDO-Nonce', 'X-DoctorDO-Signature')
    $script:PlainNames = @('Content-Type', 'Content-Encoding', 'X-DoctorDO-Schema', 'X-DoctorDO-Kind', 'X-DoctorDO-Collected-At')

    function Test-SignedRequest {
        # Verify a request the way ingest does (C1): certificate from the header, canonical string rebuilt from the
        # headers as received and the configured host, signature checked with the certificate's public key.
        param([Parameter(Mandatory)] $Headers, [Parameter(Mandatory)][byte[]] $Body, [Parameter(Mandatory)][string] $HostName)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String([string]$Headers['X-DoctorDO-Device-Cert']))
        $canonical = InModuleScope DoctorDO.Collector -Parameters @{ H = $Headers; B = $Body; N = $HostName } {
            param($H, $B, $N)
            Get-DDCanonicalString -Method 'POST' -Path '/v1/ingest' -HostName $N -Kind ([string]$H['X-DoctorDO-Kind']) -CollectedAt ([string]$H['X-DoctorDO-Collected-At']) `
                -SignedAt ([string]$H['X-DoctorDO-Signed-At']) -Nonce ([string]$H['X-DoctorDO-Nonce']) -Body $B
        }
        $data = [System.Text.Encoding]::UTF8.GetBytes($canonical)
        $sig = [Convert]::FromBase64String([string]$Headers['X-DoctorDO-Signature'])
        $sha = [System.Security.Cryptography.HashAlgorithmName]::SHA256
        if ($cert.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') {
            return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert).VerifyData($data, $sig, $sha, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert).VerifyData($data, $sig, $sha)
    }

    function Initialize-SendMocks {
        param([string[]] $Dsreg, $Certificates, [switch] $RealTransport)
        Initialize-FakeDevice
        $global:DDDsregText = $Dsreg
        $global:DDFakeCerts = $Certificates
        Mock -ModuleName DoctorDO.Collector Get-DDDsregStatusText { $global:DDDsregText }
        Mock -ModuleName DoctorDO.Collector Get-DDMachineCertificates { @($global:DDFakeCerts) }
        $global:DDPosted = $null
        if (-not $RealTransport) {
            Mock -ModuleName DoctorDO.Collector Invoke-DDHttpPost {
                $global:DDPosted = @{ Uri = $Uri; Body = $Body; Headers = $Headers; Bound = @($PSBoundParameters.Keys); Proxy = (Get-Variable -Name Proxy -ValueOnly -ErrorAction SilentlyContinue); NoProxy = [bool](Get-Variable -Name NoProxy -ValueOnly -ErrorAction SilentlyContinue) }
                [pscustomobject]@{ StatusCode = 202; RetryAfter = $null; Error = $null }
            }
        }
    }
}

Describe 'Certificate selection (tenant-ca)' {
    It 'picks the valid client-authentication certificate whose SAN contains the Entra device id' {
        $other = New-TestCertificate -DeviceId '99999999-2222-4333-8444-555555555555'
        $c = InModuleScope DoctorDO.Collector -Parameters @{ A = $script:Cert; B = $other; Id = $script:DeviceId } { param($A, $B, $Id) Select-DDDeviceCertificate -Certificates @($B, $A) -EntraDeviceId $Id }
        $c.Thumbprint | Should -Be $script:Cert.Thumbprint
    }

    It 'matches a SAN written as a plain URI containing the id as well (SCEP profile variants)' {
        $c2 = New-TestCertificate -DeviceId 'cccccccc-2222-4333-8444-555555555555' -SanText 'https://device.example/cccccccc-2222-4333-8444-555555555555'
        $c = InModuleScope DoctorDO.Collector -Parameters @{ A = $c2 } { param($A) Select-DDDeviceCertificate -Certificates @($A) -EntraDeviceId 'cccccccc-2222-4333-8444-555555555555' }
        $c | Should -Not -BeNullOrEmpty
    }

    It 'rejects expired, not-yet-valid, wrong-EKU, no-private-key and other devices'' certificates' {
        $expired = New-TestCertificate -DeviceId $script:DeviceId -NotBefore ([datetime]::UtcNow.AddDays(-30)) -NotAfter ([datetime]::UtcNow.AddDays(-1))
        $future = New-TestCertificate -DeviceId $script:DeviceId -NotBefore ([datetime]::UtcNow.AddDays(2)) -NotAfter ([datetime]::UtcNow.AddDays(20))
        $server = New-TestCertificate -DeviceId $script:DeviceId -NoClientAuth
        $pubOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $script:Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        $none = InModuleScope DoctorDO.Collector -Parameters @{ L = @($expired, $future, $server, $pubOnly); Id = $script:DeviceId } { param($L, $Id) Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id }
        $none | Should -BeNullOrEmpty
    }

    It 'prefers the certificate that expires last and honours an explicit thumbprint' {
        $older = New-TestCertificate -DeviceId $script:DeviceId -NotAfter ([datetime]::UtcNow.AddDays(30))
        $r = InModuleScope DoctorDO.Collector -Parameters @{ L = @($older, $script:Cert); Id = $script:DeviceId; T = $older.Thumbprint } {
            param($L, $Id, $T)
            @{ Newest = (Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id).Thumbprint; Pinned = (Select-DDDeviceCertificate -Certificates $L -EntraDeviceId $Id -Thumbprint $T).Thumbprint }
        }
        $r.Newest | Should -Be $script:Cert.Thumbprint
        $r.Pinned | Should -Be $older.Thumbprint
    }
}

Describe 'Send-DoctorDOReport, entra-device anchor (transport mocked)' {
    BeforeEach {
        Initialize-SendMocks -Dsreg (New-DsregText -DeviceId $script:DeviceId -Thumbprint $script:EntraCert.Thumbprint) -Certificates @($script:P2P, $script:Cert, $script:EntraCert)
    }

    It 'is the default: signs with the MS-Organization-Access certificate and sends the nine headers, and no client certificate' {
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $r.Outcome | Should -Be 'Accepted' -Because $r.Message
        $r.ExitCode | Should -Be 0; $r.StatusCode | Should -Be 202
        $h = $global:DDPosted.Headers
        @($h.Keys) | Should -Be (@($script:PlainNames) + @($script:SignedNames)) -Because 'exactly the C1 headers, in a stable order'
        $h['Content-Type'] | Should -BeExactly 'application/vnd.doctordo.report+json'
        $h['Content-Encoding'] | Should -BeExactly 'gzip'
        $h['X-DoctorDO-Schema'] | Should -BeExactly '1'
        $h['X-DoctorDO-Kind'] | Should -BeExactly 'telemetry'
        $h['X-DoctorDO-Collected-At'] | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
        $h['X-DoctorDO-Signed-At'] | Should -BeExactly '2026-10-12T08:00:00Z' -Because 'the module clock, whole seconds, UTC'
        $h['X-DoctorDO-Nonce'] | Should -MatchExactly '^[A-Za-z0-9_-]{22}$'
        $h['X-DoctorDO-Device-Cert'] | Should -BeExactly ([Convert]::ToBase64String($script:EntraCert.RawData))
        ($h.Keys | Where-Object { $_ -match 'key|auth|token|tenant|secret|password' }) | Should -BeNullOrEmpty
        Test-SignedRequest -Headers $h -Body $global:DDPosted.Body -HostName 'ingest.contoso.example' | Should -BeTrue
        $global:DDPosted.Bound | Should -Not -Contain 'Certificate'
        $global:DDPosted.Uri.AbsoluteUri | Should -BeExactly 'https://ingest.contoso.example/v1/ingest'
        $ms = New-Object System.IO.MemoryStream (, [byte[]]$global:DDPosted.Body)
        $text = (New-Object System.IO.StreamReader((New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)))).ReadToEnd()
        $text | Should -Not -Match "`n|  " -Because 'compact JSON'
        ($text | ConvertFrom-Json).kind | Should -Be 'telemetry'
        $r.CompressedBytes | Should -Be $global:DDPosted.Body.Length
    }

    It 'the transport has no client-certificate parameter at all (no mutual TLS)' {
        (InModuleScope DoctorDO.Collector { (Get-Command Invoke-DDHttpPost).Parameters.Keys }) | Should -Not -Contain 'Certificate'
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../DoctorDO.Collector/Private/Http.ps1') -Raw
        $src | Should -Not -Match 'ClientCertificates'
    }

    It 'sends an inventory with kind inventory, signed over that kind' {
        $null = Send-DoctorDOReport -Report $script:Inventory -IngestUri $script:Uri
        $global:DDPosted.Headers['X-DoctorDO-Kind'] | Should -Be 'inventory'
        Test-SignedRequest -Headers $global:DDPosted.Headers -Body $global:DDPosted.Body -HostName 'ingest.contoso.example' | Should -BeTrue
    }

    It 'uses a fresh nonce for every request' {
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $n1 = $global:DDPosted.Headers['X-DoctorDO-Nonce']
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $global:DDPosted.Headers['X-DoctorDO-Nonce'] | Should -Not -Be $n1
    }

    It 'completes a bare host with /v1/ingest and refuses any other path, query or http' {
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri ([uri]'https://ingest.contoso.example')
        $global:DDPosted.Uri.AbsoluteUri | Should -BeExactly 'https://ingest.contoso.example/v1/ingest'
        foreach ($bad in 'https://ingest.contoso.example/api/ingest', 'https://ingest.contoso.example/v1/ingest?code=x', 'http://ingest.contoso.example/v1/ingest') {
            $global:DDPosted = $null
            $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri ([uri]$bad)
            $r.Outcome | Should -Be 'InvalidReport' -Because $bad
            $r.ExitCode | Should -Be 5
            $global:DDPosted | Should -BeNullOrEmpty
        }
    }

    It 'exit 6 (<Name>) without a network call' -ForEach @(
        @{ Name = 'domain joined only'; Dsreg = { New-DsregText -AzureAdJoined 'NO' -DomainJoined 'YES' }; Certs = 'entra'; Outcome = 'NotJoined'; Pattern = "dsregcmd /status reports join state 'domain'" }
        @{ Name = 'not joined'; Dsreg = { New-DsregText -AzureAdJoined 'NO' -DomainJoined 'NO' }; Certs = 'entra'; Outcome = 'NotJoined'; Pattern = "join state 'none'" }
        @{ Name = 'dsregcmd unreadable'; Dsreg = { @('garbage') }; Certs = 'entra'; Outcome = 'NotJoined'; Pattern = 'dsregcmd /status' }
        @{ Name = 'joined, no device certificate'; Dsreg = { New-DsregText -Thumbprint $script:EntraCert.Thumbprint }; Certs = 'none'; Outcome = 'NoCertificate'; Pattern = 'No usable Entra device certificate.*dsregcmd /status' }
        @{ Name = 'only decoys (P2P and SCEP)'; Dsreg = { New-DsregText }; Certs = 'decoys'; Outcome = 'NoCertificate'; Pattern = 'MS-Organization-Access' }
        @{ Name = 'thumbprint differs from dsregcmd'; Dsreg = { New-DsregText -Thumbprint ('C' * 40) }; Certs = 'entra'; Outcome = 'NoCertificate'; Pattern = 'thumbprint dsregcmd reports' }
    ) {
        $global:DDDsregText = & $Dsreg
        $global:DDFakeCerts = switch ($Certs) { 'entra' { @($script:EntraCert) } 'none' { @() } 'decoys' { @($script:P2P, $script:Cert) } }
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $r.ExitCode | Should -Be 6
        $r.Outcome | Should -Be $Outcome
        $r.Message | Should -Match $Pattern
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDHttpPost -Times 0
    }

    It 'exit 6 when dsregcmd cannot run at all' {
        Mock -ModuleName DoctorDO.Collector Get-DDDsregStatusText { throw 'dsregcmd.exe not found' }
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $r.ExitCode | Should -Be 6; $r.Outcome | Should -Be 'NotJoined'
    }

    It 'exit 6 when -EntraDeviceId disagrees with dsregcmd (the certificate is chosen for the dsregcmd device)' {
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -EntraDeviceId '99999999-2222-4333-8444-555555555555'
        $r.ExitCode | Should -Be 6
        $r.Message | Should -Match 'does not match'
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -EntraDeviceId $script:DeviceId.ToUpperInvariant()).Outcome | Should -Be 'Accepted'
    }

    It 'exit 6 when the device key cannot sign (for example not running as SYSTEM)' {
        Mock -ModuleName DoctorDO.Collector New-DDSignature { throw [System.Security.Cryptography.CryptographicException]::new('Keyset does not exist') }
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $r.Outcome | Should -Be 'SigningFailed'; $r.ExitCode | Should -Be 6
        $r.Message | Should -Match 'SYSTEM'
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDHttpPost -Times 0
    }

    It 'hands dsregcmd''s KeyContainerId and KeyProvider to the signer for its fallback (entra-device only)' {
        $global:DDSignArgs = $null
        Mock -ModuleName DoctorDO.Collector New-DDSignature { $global:DDSignArgs = @{ C = $KeyContainer; P = $KeyProvider }; 'c2ln' }
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $global:DDSignArgs.C | Should -Be '00aa00aa-bb11-cc22-dd33-44ee44ee44ee'
        $global:DDSignArgs.P | Should -Be 'Microsoft Platform Crypto Provider'
        $global:DDFakeCerts = @($script:Cert)
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca
        $global:DDSignArgs.C | Should -BeNullOrEmpty
    }

    It 'uses a dsregcmd result it is given instead of running dsregcmd again' {
        $d = InModuleScope DoctorDO.Collector -Parameters @{ L = (New-DsregText -Thumbprint $script:EntraCert.Thumbprint) } { param($L) ConvertFrom-DDDsregStatus -Lines $L }
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DsregStatus $d).Outcome | Should -Be 'Accepted'
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDDsregStatusText -Times 0
    }

    It 'rejects something that is not a report' {
        (Send-DoctorDOReport -Report 'hello' -IngestUri $script:Uri).Outcome | Should -Be 'InvalidReport'
        (Send-DoctorDOReport -Report ([ordered]@{ schemaVersion = 1; kind = 'bundle' }) -IngestUri $script:Uri).Outcome | Should -Be 'InvalidReport'
    }

    It 'does not send a report over the 64 KB hard cap' {
        $big = [ordered]@{ schemaVersion = 1; kind = 'telemetry'; collectedAt = '2026-10-12T08:00:00Z'; junk = (New-RandomText -Bytes 120000) }
        $r = Send-DoctorDOReport -Report $big -IngestUri $script:Uri
        $r.Outcome | Should -Be 'TooLarge'
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDHttpPost -Times 0
    }

    It 'treats the response as opaque: only the status code decides (<Code>: <Outcome>)' -ForEach @(
        @{ Code = 202; Outcome = 'Accepted'; Exit = 0; Says = '^Accepted\.$' }
        @{ Code = 429; Outcome = 'RateLimited'; Exit = 5; Says = 'Retry-After' }
        # A device clock more than five minutes behind gets 401 (the signed-at window); ahead, 422 (collected in the future).
        @{ Code = 401; Outcome = 'BackOff'; Exit = 5; Says = 'check the device clock' }
        @{ Code = 422; Outcome = 'Rejected'; Exit = 5; Says = 'Check the device clock' }
        @{ Code = 503; Outcome = 'BackOff'; Exit = 5; Says = 'unavailable; backing off' }
        @{ Code = 500; Outcome = 'BackOff'; Exit = 5; Says = 'unavailable; backing off' }
        @{ Code = 502; Outcome = 'BackOff'; Exit = 5; Says = 'a gateway' }
        @{ Code = 504; Outcome = 'BackOff'; Exit = 5; Says = 'a gateway' }
        @{ Code = 408; Outcome = 'BackOff'; Exit = 5; Says = 'backing off' }
        @{ Code = 407; Outcome = 'Rejected'; Exit = 5; Says = 'the proxy asked for credentials' }
        @{ Code = 404; Outcome = 'Rejected'; Exit = 5; Says = '^HTTP 404\.$' }
        @{ Code = 400; Outcome = 'Rejected'; Exit = 5; Says = '^HTTP 400\.$' }
        @{ Code = 0; Outcome = 'NetworkError'; Exit = 5; Says = 'Network error \(ConnectFailure\) reaching the ingest host' }
    ) {
        $global:DDCode = $Code
        Mock -ModuleName DoctorDO.Collector Invoke-DDHttpPost { [pscustomobject]@{ StatusCode = $global:DDCode; RetryAfter = '90'; Error = $(if ($global:DDCode -eq 0) { 'ConnectFailure' } else { $null }) } }
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $r.Outcome | Should -Be $Outcome
        $r.ExitCode | Should -Be $Exit
        $r.Message | Should -Match $Says
    }

    It 'uploads through the proxy the endpoint probes would use for the ingest host, directly where WinHTTP bypasses it, and through the default proxy otherwise' {
        Mock -ModuleName DoctorDO.Collector Resolve-DDUrlProxy { [pscustomobject]@{ Source = 'netsh'; Proxy = 'proxy.contoso.example:8080'; Error = $null } }
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $global:DDPosted.Proxy | Should -Be 'proxy.contoso.example:8080'
        $global:DDPosted.NoProxy | Should -BeFalse
        Should -Invoke -ModuleName DoctorDO.Collector Resolve-DDUrlProxy -ParameterFilter { $Uri -eq 'https://ingest.contoso.example/v1/ingest' }
        Mock -ModuleName DoctorDO.Collector Resolve-DDUrlProxy { [pscustomobject]@{ Source = 'pac'; Proxy = $null; Error = $null } }
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $global:DDPosted.Proxy | Should -BeNullOrEmpty
        $global:DDPosted.NoProxy | Should -BeTrue
        foreach ($d in @([pscustomobject]@{ Source = 'none'; Proxy = $null; Error = $null }, [pscustomobject]@{ Source = 'unresolved'; Proxy = $null; Error = 'PAC evaluation failed (12167)' })) {
            $global:DDNextProxy = $d
            Mock -ModuleName DoctorDO.Collector Resolve-DDUrlProxy { $global:DDNextProxy }
            $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
            $global:DDPosted.Proxy | Should -BeNullOrEmpty
            $global:DDPosted.NoProxy | Should -BeFalse -Because "$($d.Source): the runtime's default proxy stays in place"
        }
        # A failure names the path by the proxy's source, never its address.
        Mock -ModuleName DoctorDO.Collector Resolve-DDUrlProxy { [pscustomobject]@{ Source = 'wpad'; Proxy = 'proxy.contoso.example:8080'; Error = $null } }
        Mock -ModuleName DoctorDO.Collector Invoke-DDHttpPost { [pscustomobject]@{ StatusCode = 0; RetryAfter = $null; Error = 'ProxyNameResolutionFailure' } }
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        $r.Message | Should -Match 'through the proxy WinHTTP chooses for the ingest host \(from wpad\)'
        $r.Message | Should -Not -Match 'contoso'
    }

    It 'signs for, and sends to, the host without a trailing dot' {
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri ([uri]'https://Ingest.Contoso.Example./v1/ingest')
        $global:DDPosted.Uri.AbsoluteUri | Should -BeExactly 'https://ingest.contoso.example/v1/ingest'
        Test-SignedRequest -Headers $global:DDPosted.Headers -Body $global:DDPosted.Body -HostName 'ingest.contoso.example' | Should -BeTrue
        InModuleScope DoctorDO.Collector { Get-DDIngestHost -Uri 'https://host.example./v1/ingest' } | Should -BeExactly 'host.example'
    }

    It 'honours Retry-After on 429 and 503' {
        Mock -ModuleName DoctorDO.Collector Invoke-DDHttpPost { [pscustomobject]@{ StatusCode = 429; RetryAfter = '120'; Error = $null } }
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri).RetryAfterSeconds | Should -Be 120
    }

    It 'the result object has no field that could carry a response body' {
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri
        ($r.PSObject.Properties.Name | Sort-Object) | Should -Be @('BudgetResult', 'CompressedBytes', 'ExitCode', 'Kind', 'Message', 'Outcome', 'RetryAfterSeconds', 'StatusCode')
    }
}

Describe 'Transport TLS setting (D-15)' {
    It 'leaves SystemDefault and an explicit TLS 1.2-or-later setting alone, and replaces anything older with TLS 1.2 and 1.3' {
        InModuleScope DoctorDO.Collector {
            Get-DDUploadTlsProtocol -Current 0 | Should -BeNullOrEmpty -Because 'SystemDefault: the operating system chooses (.NET Framework 4.7+ and .NET)'
            Get-DDUploadTlsProtocol -Current 3072 | Should -BeNullOrEmpty
            Get-DDUploadTlsProtocol -Current (3072 -bor 12288) | Should -BeNullOrEmpty
            Get-DDUploadTlsProtocol -Current (48 -bor 192) | Should -Be (3072 -bor 12288) -Because 'Windows PowerShell 5.1 can start with Ssl3, Tls'
            Get-DDUploadTlsProtocol -Current (192 -bor 768 -bor 3072) | Should -Be (3072 -bor 12288) -Because 'TLS 1.0 and 1.1 are dropped'
        }
    }

    It 'falls back to TLS 1.2 alone where the runtime refuses TLS 1.3''s value, and restores the setting afterwards' {
        InModuleScope DoctorDO.Collector {
            $global:DDProtoSets = New-Object System.Collections.Generic.List[int]
            $prev = [int][System.Net.ServicePointManager]::SecurityProtocol
            Mock Get-DDUploadTlsProtocol { 3072 -bor 12288 }
            Mock Set-DDSecurityProtocol { $global:DDProtoSets.Add($Value); if ($Value -band 12288) { throw [System.NotSupportedException]::new('The requested security protocol is not supported.') } }
            # Nothing listens on this port: the request fails after the TLS setting was chosen.
            $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop()
            $r = Invoke-DDHttpPost -Uri "https://127.0.0.1:$p/v1/ingest" -Body ([byte[]]@(1)) -Headers @{ 'Content-Type' = 'application/octet-stream' } -TimeoutSec 5 -NoProxy
            $r.StatusCode | Should -Be 0
            $r.Error | Should -Not -Be 'NotSupportedException' -Because 'the TLS fallback, not the setter, decides the outcome'
            @($global:DDProtoSets) | Should -Be @((3072 -bor 12288), 3072, $prev)
        }
    }
}

Describe 'Send-DoctorDOReport, tenant-ca anchor (transport mocked)' {
    BeforeEach {
        Initialize-SendMocks -Dsreg (New-DsregText -DeviceId $script:DeviceId -Thumbprint $script:EntraCert.Thumbprint) -Certificates @($script:EntraCert, $script:P2P, $script:Cert)
    }

    It 'signs with the SCEP/PKCS certificate, never the Entra one, with the same headers' {
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca
        $r.Outcome | Should -Be 'Accepted' -Because $r.Message
        $h = $global:DDPosted.Headers
        @($h.Keys) | Should -Be (@($script:PlainNames) + @($script:SignedNames))
        $h['X-DoctorDO-Device-Cert'] | Should -BeExactly ([Convert]::ToBase64String($script:Cert.RawData))
        Test-SignedRequest -Headers $h -Body $global:DDPosted.Body -HostName 'ingest.contoso.example' | Should -BeTrue
    }

    It 'keeps exit 6 meaning "certificate profile not deployed", and makes no network call' {
        $global:DDFakeCerts = @($script:EntraCert, $script:P2P)
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca -EntraDeviceId $script:DeviceId
        $r.Outcome | Should -Be 'NoCertificate'; $r.ExitCode | Should -Be 6
        $r.Message | Should -Match 'SCEP or PKCS certificate profile'
        Should -Invoke -ModuleName DoctorDO.Collector Invoke-DDHttpPost -Times 0
    }

    It 'reads the device id from dsregcmd when it is not supplied (the certificate is chosen for THAT device)' {
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca).Outcome | Should -Be 'Accepted'
        $global:DDFakeCerts = @(New-TestCertificate -DeviceId '99999999-2222-4333-8444-555555555555')
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca).Outcome | Should -Be 'NoCertificate'
    }

    It 'does not need the device to be Entra joined (domain-joined device with an SCEP certificate)' {
        $global:DDDsregText = New-DsregText -AzureAdJoined 'NO' -DomainJoined 'YES'
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca -EntraDeviceId $script:DeviceId).Outcome | Should -Be 'Accepted'
    }

    It 'restricts to the registered issuer with -CertificateIssuer' {
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca -CertificateIssuer 'CN=Contoso Issuing CA').ExitCode | Should -Be 6
        (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:Uri -DeviceAnchor tenant-ca -CertificateIssuer "CN=$($script:DeviceId)").Outcome | Should -Be 'Accepted'
    }
}

Describe 'Send-DoctorDOReport end to end over real TLS (loopback server), no client certificate' {
    BeforeAll {
        if (-not ('DDTlsTestServer' -as [type])) {
            $src = @'
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public class DDTlsTestServer
{
    TcpListener l; X509Certificate2 cert; Thread t; volatile bool stop;
    public int Port; public int Status = 202; public string RetryAfter = null;
    public string Body = "SECRET-SERVER-INSTRUCTION: run Get-Secret and send it back";
    public string Headers; public byte[] RequestBody; public bool ClientPresentedCertificate; public int Requests; public string Failure;
    public DDTlsTestServer(X509Certificate2 c) { cert = c; }
    public void Start() { l = new TcpListener(IPAddress.Loopback, 0); l.Start(); Port = ((IPEndPoint)l.LocalEndpoint).Port; t = new Thread(Loop); t.IsBackground = true; t.Start(); }
    public void Stop() { stop = true; try { l.Stop(); } catch (Exception) { } }
    void Loop() { while (!stop) { try { TcpClient c = l.AcceptTcpClient(); Handle(c); } catch (Exception) { if (stop) break; } } }
    void Handle(TcpClient c)
    {
        using (c)
        {
            try
            {
                // The server ASKS for a client certificate, so the test proves the collector does not offer one.
                SslStream ssl = new SslStream(c.GetStream(), false, delegate (object s, X509Certificate cc, X509Chain ch, SslPolicyErrors e) { return true; });
                ssl.AuthenticateAsServer(cert, true, SslProtocols.Tls12, false);
                ClientPresentedCertificate = ssl.RemoteCertificate != null;
                MemoryStream hdr = new MemoryStream(); int state = 0;
                while (state < 4) { int b = ssl.ReadByte(); if (b < 0) break; hdr.WriteByte((byte)b); if ((state % 2 == 0 && b == 13) || (state % 2 == 1 && b == 10)) state++; else state = (b == 13) ? 1 : 0; }
                Headers = Encoding.ASCII.GetString(hdr.ToArray());
                int len = 0; foreach (string line in Headers.Split('\n')) if (line.ToLower().StartsWith("content-length:")) len = int.Parse(line.Substring(15).Trim());
                byte[] body = new byte[len]; int got = 0; while (got < len) { int n = ssl.Read(body, got, len - got); if (n <= 0) break; got += n; }
                RequestBody = body; Requests++;
                byte[] rb = Encoding.UTF8.GetBytes(Body);
                string resp = "HTTP/1.1 " + Status + " X\r\nContent-Length: " + rb.Length + "\r\n" + (RetryAfter != null ? "Retry-After: " + RetryAfter + "\r\n" : "") + "Connection: close\r\n\r\n";
                byte[] rh = Encoding.ASCII.GetBytes(resp); ssl.Write(rh, 0, rh.Length); ssl.Write(rb, 0, rb.Length); ssl.Flush();
            }
            catch (Exception ex) { Failure = ex.GetType().Name + ": " + ex.Message; }
        }
    }
}

public static class DDTrustAll
{
    public static readonly System.Net.Security.RemoteCertificateValidationCallback Callback = delegate (object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; };
}
'@
            if ($PSVersionTable.PSEdition -eq 'Core') {
                Add-Type -ReferencedAssemblies 'System.Net.Primitives', 'System.Net.Sockets', 'System.Net.Security', 'System.Security.Cryptography', 'System.Security.Cryptography.X509Certificates', 'System.Collections', 'System.Threading', 'System.Threading.Thread', 'System.Runtime', 'System.Linq', 'System.Memory', 'netstandard' -TypeDefinition $src
            } else {
                # Windows PowerShell 5.1: everything used is in System.dll, which Add-Type references by default.
                Add-Type -TypeDefinition $src
            }
        }
        $script:ServerCert = New-TestCertificate -DeviceId 'server' -SanText 'https://localhost/'
        # Server validation is overridden for the loopback test only; production uses normal validation.
        $script:Srv = New-Object DDTlsTestServer($script:ServerCert)
        $script:Srv.Start()
        $script:PrevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DDTrustAll]::Callback
        function ConvertFrom-RawHeaders {
            param([string] $Raw)
            $h = @{}
            foreach ($line in ($Raw -split "`r`n")) { $m = [regex]::Match($line, '^([A-Za-z0-9-]+):\s?(.*)$'); if ($m.Success) { $h[$m.Groups[1].Value] = $m.Groups[2].Value } }
            $h
        }
    }
    AfterAll {
        $script:Srv.Stop()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $script:PrevCb
    }
    BeforeEach {
        Initialize-SendMocks -Dsreg (New-DsregText -DeviceId $script:DeviceId -Thumbprint $script:EntraCert.Thumbprint) -Certificates @($script:P2P, $script:EntraCert) -RealTransport
        $script:Srv.Status = 202; $script:Srv.RetryAfter = $null; $script:Srv.ClientPresentedCertificate = $false
        $script:E2eUri = [uri]"https://localhost:$($script:Srv.Port)/v1/ingest"
    }

    It 'presents no client certificate although the server asks, and delivers headers and a signature that verify' {
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:E2eUri
        $script:Srv.Failure | Should -BeNullOrEmpty
        $r.Outcome | Should -Be 'Accepted' -Because $r.Message
        $script:Srv.ClientPresentedCertificate | Should -BeFalse
        $hdr = $script:Srv.Headers
        $hdr | Should -Match '(?im)^POST /v1/ingest HTTP/1\.1'
        $hdr | Should -Not -Match '(?im)^Authorization:'
        $h = ConvertFrom-RawHeaders -Raw $hdr
        $h['Content-Type'] | Should -BeExactly 'application/vnd.doctordo.report+json'
        $h['Content-Encoding'] | Should -BeExactly 'gzip'
        $h['X-DoctorDO-Schema'] | Should -BeExactly '1'
        $h['X-DoctorDO-Kind'] | Should -BeExactly 'telemetry'
        $h['X-DoctorDO-Collected-At'] | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
        foreach ($n in $script:SignedNames) { $h.ContainsKey($n) | Should -BeTrue -Because $n }
        $h['X-DoctorDO-Device-Cert'] | Should -BeExactly ([Convert]::ToBase64String($script:EntraCert.RawData))
        Test-SignedRequest -Headers $h -Body $script:Srv.RequestBody -HostName 'localhost' | Should -BeTrue -Because 'the host is signed without the port'
        $ms = New-Object System.IO.MemoryStream (, [byte[]]$script:Srv.RequestBody)
        $json = (New-Object System.IO.StreamReader((New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)))).ReadToEnd()
        (ConvertFrom-Json $json).seq | Should -Be 3
    }

    It 'never reads or surfaces the response body, even when the server sends an instruction' {
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:E2eUri
        (ConvertTo-Json -InputObject $r -Depth 4) | Should -Not -Match 'SECRET-SERVER-INSTRUCTION|Get-Secret'
        ($r | Out-String) | Should -Not -Match 'SECRET-SERVER-INSTRUCTION'
    }

    It 'reads the status code and Retry-After of a 429 and nothing else' {
        $script:Srv.Status = 429; $script:Srv.RetryAfter = '45'
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:E2eUri
        $r.Outcome | Should -Be 'RateLimited'; $r.RetryAfterSeconds | Should -Be 45
    }

    It 'maps 401 and 503 to back-off' {
        foreach ($code in 401, 503) {
            $script:Srv.Status = $code
            (Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:E2eUri).Outcome | Should -Be 'BackOff'
        }
    }

    It 'reports a network error when nothing is listening' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop()
        $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri ([uri]"https://localhost:$p/v1/ingest") -TimeoutSec 5
        $r.Outcome | Should -Be 'NetworkError'; $r.ExitCode | Should -Be 5
    }

    It 'names itself in a User-Agent and sends no Expect: 100-continue' {
        $null = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:E2eUri
        $h = ConvertFrom-RawHeaders -Raw $script:Srv.Headers
        $h['User-Agent'] | Should -Match '^DoctorDO-Collector/\d+\.\d+\.\d+$'
        $h.ContainsKey('Expect') | Should -BeFalse
    }
}

Describe 'Send-DoctorDOReport through a proxy (real transport, loopback CONNECT proxy; Windows PowerShell 5.1 and PowerShell 7)' -Skip:([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
    # The upload goes through the proxy WinHTTP would choose for the ingest host, as the endpoint probes do (D-06). The
    # proxy is a loopback CONNECT tunnel to the TLS test server; the ingest host's name never resolves and is never used
    # directly (a loopback name would bypass any proxy).
    BeforeAll {
        . (Join-Path $PSScriptRoot 'NetStubs.ps1')
        function ConvertFrom-RawHeaders {
            param([string] $Raw)
            $h = @{}
            foreach ($line in ($Raw -split "`r`n")) { $m = [regex]::Match($line, '^([A-Za-z0-9-]+):\s?(.*)$'); if ($m.Success) { $h[$m.Groups[1].Value] = $m.Groups[2].Value } }
            $h
        }
        $script:PxCert = New-TestCertificate -DeviceId 'server' -SanText 'https://doctordo-ingest.invalid/'
        $script:PxSrv = New-Object DDTlsTestServer($script:PxCert)
        $script:PxSrv.Start()
        $script:PxPrevCb = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [DDTrustAll]::Callback
        $script:PxUri = [uri]"https://doctordo-ingest.invalid:$($script:PxSrv.Port)/v1/ingest"
    }
    AfterAll {
        $script:PxSrv.Stop()
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $script:PxPrevCb
    }
    BeforeEach {
        Initialize-SendMocks -Dsreg (New-DsregText -DeviceId $script:DeviceId -Thumbprint $script:EntraCert.Thumbprint) -Certificates @($script:P2P, $script:EntraCert) -RealTransport
        $script:PxSrv.Status = 202
    }

    It 'tunnels the signed upload through the proxy WinHTTP chooses for the ingest host' {
        $tunnel = New-NetStub -Mode 'tunnel' -TargetPort $script:PxSrv.Port
        try {
            $global:DDTunnel = "127.0.0.1:$($tunnel.Port)"
            Mock -ModuleName DoctorDO.Collector Resolve-DDUrlProxy { [pscustomobject]@{ Source = 'netsh'; Proxy = $global:DDTunnel; Error = $null } }
            $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:PxUri -TimeoutSec 15
            $r.Outcome | Should -Be 'Accepted' -Because "$($r.Message) $($tunnel.Failure) $($script:PxSrv.Failure)"
            @($tunnel.Lines()) | Should -Contain "CONNECT doctordo-ingest.invalid:$($script:PxSrv.Port) HTTP/1.1"
            $h = ConvertFrom-RawHeaders -Raw $script:PxSrv.Headers
            Test-SignedRequest -Headers $h -Body $script:PxSrv.RequestBody -HostName 'doctordo-ingest.invalid' | Should -BeTrue
            $h['User-Agent'] | Should -Match '^DoctorDO-Collector/'
            $h.ContainsKey('Expect') | Should -BeFalse
        } finally { $tunnel.Stop() }
    }

    It 'a proxy that wants credentials the device cannot give is a failed upload (exit 5), not a hang or a crash' {
        $px = New-NetStub -Mode 'proxy407'
        try {
            $global:DDTunnel = "127.0.0.1:$($px.Port)"
            Mock -ModuleName DoctorDO.Collector Resolve-DDUrlProxy { [pscustomobject]@{ Source = 'pac'; Proxy = $global:DDTunnel; Error = $null } }
            $r = Send-DoctorDOReport -Report $script:Telemetry -IngestUri $script:PxUri -TimeoutSec 10
            $r.ExitCode | Should -Be 5
            $r.Outcome | Should -BeIn @('Rejected', 'NetworkError')
            if ($r.Outcome -eq 'Rejected') { $r.StatusCode | Should -Be 407; $r.Message | Should -Match 'proxy asked for credentials' }
            $r.Message | Should -Match 'from pac'
            @($px.Lines()) | Should -Contain "CONNECT doctordo-ingest.invalid:$($script:PxSrv.Port) HTTP/1.1"
        } finally { $px.Stop() }
    }
}
