# Shared test helpers. Every Windows-only wrapper in Private/Platform.ps1 is mocked here, so the whole
# collector runs under Pester on Linux with a believable fake device.

function Import-DDModule {
    Get-Module DoctorDO.Collector | Remove-Module -Force
    Import-Module (Join-Path $PSScriptRoot '../DoctorDO.Collector/DoctorDO.Collector.psd1') -Force -DisableNameChecking
}

function Get-FixturePath { param([string] $Name) Join-Path $PSScriptRoot "fixtures/$Name" }

function New-TestCertificate {
    <#
      A self-signed device-style certificate: client-auth EKU, SAN URI + DNS carrying the device id.
      NotBefore defaults to a fixed date before Initialize-FakeDevice's clock (2026-10-12 08:00 UTC): "a day before
      now" made the certificate not yet valid on that clock from the day after it was written.
    #>
    param([string] $DeviceId = '11111111-2222-4333-8444-555555555555', [datetime] $NotBefore = ([datetime]::new(2026, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)), [datetime] $NotAfter = ([datetime]::UtcNow.AddDays(300)), [switch] $NoClientAuth, [string] $SanText)
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest("CN=$DeviceId", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
    if (-not $SanText) { $SanText = "urn:doctordo:device:$DeviceId" }
    $san.AddUri([uri]$SanText)
    $req.CertificateExtensions.Add($san.Build())
    $oids = New-Object System.Security.Cryptography.OidCollection
    if ($NoClientAuth) { [void]$oids.Add((New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.1'))) } else { [void]$oids.Add((New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.2'))) }
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids, $false)))
    $cert = $req.CreateSelfSigned([System.DateTimeOffset]$NotBefore, [System.DateTimeOffset]$NotAfter)
    # Round-trip through PFX so the private key is usable by SslStream on every platform.
    New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'x'), 'x', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
}

# ---- signed requests (contract C1) --------------------------------------------------------------------------------


function Get-SigningVector {
    # contracts/signing/signing-v1.vector.json, the golden vector shared with packages/device-auth. Its keys are
    # throwaway test keys generated for that file and nothing else.
    # Read with the module's date-safe parser: PowerShell 7's ConvertFrom-Json turns the timestamp headers into
    # [datetime], which would then be signed in the local culture's format.
    $path = (Resolve-Path (Join-Path $PSScriptRoot '../../contracts/signing/signing-v1.vector.json')).Path
    InModuleScope DoctorDO.Collector -Parameters @{ P = $path } { param($P) Read-DDJsonFile -Path $P }
}

function Get-TestPemBytes {
    param([string] $Pem)
    $b64 = ($Pem -split "`r?`n" | Where-Object { $_ -and $_ -notmatch '^-----' }) -join ''
    , [Convert]::FromBase64String($b64)
}

function Read-TestDer {
    # Minimal DER reader for the vector's test keys: the element at $Offset as @{ Tag; Value; Next }.
    param([byte[]] $Bytes, [int] $Offset = 0)
    $len = [int]$Bytes[$Offset + 1]
    $hdr = 2
    if ($len -band 0x80) {
        $n = $len -band 0x7f
        $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len -shl 8) -bor $Bytes[$Offset + 2 + $i] }
        $hdr = 2 + $n
    }
    $val = New-Object byte[] $len
    [Array]::Copy($Bytes, $Offset + $hdr, $val, 0, $len)
    @{ Tag = $Bytes[$Offset]; Value = $val; Next = $Offset + $hdr + $len }
}

function Read-TestDerChildren {
    param([byte[]] $Bytes)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $o = 0
    while ($o -lt $Bytes.Length) { $e = Read-TestDer -Bytes $Bytes -Offset $o; $out.Add($e); $o = $e.Next }
    , $out.ToArray()
}

function ConvertTo-TestUnsigned {
    # DER INTEGER -> big-endian unsigned of exactly $Length bytes (the Windows providers insist on exact lengths).
    param([byte[]] $Bytes, [int] $Length)
    $start = 0
    while ($start -lt $Bytes.Length - 1 -and $Bytes[$start] -eq 0) { $start++ }
    $n = $Bytes.Length - $start
    $out = New-Object byte[] $Length
    [Array]::Copy($Bytes, $start, $out, $Length - $n, $n)
    , $out
}

function ConvertFrom-TestPkcs8 {
    <#
      PKCS#8 PrivateKeyInfo (PEM) -> RSAParameters, or ECParameters for P-256. Parsed by hand because Windows
      PowerShell 5.1 (.NET Framework) has no PKCS#8 import that yields a key a certificate can be paired with:
      CngKey.Import gives an ephemeral, non-exportable key that CopyWithPrivateKey refuses.
    #>
    param([string] $Pem)
    [byte[]] $der = Get-TestPemBytes -Pem $Pem
    $pki = Read-TestDerChildren -Bytes (Read-TestDer -Bytes $der).Value
    $algOid = (Read-TestDerChildren -Bytes $pki[1].Value)[0].Value
    $f = Read-TestDerChildren -Bytes (Read-TestDer -Bytes $pki[2].Value).Value
    if ([BitConverter]::ToString($algOid) -eq '2A-86-48-86-F7-0D-01-01-01') {
        # RSAPrivateKey: version, n, e, d, p, q, dp, dq, qinv
        $s = 0; while ($f[1].Value[$s] -eq 0) { $s++ }
        $nLen = $f[1].Value.Length - $s
        $half = [int]($nLen / 2)
        $eS = 0; while ($f[2].Value[$eS] -eq 0) { $eS++ }
        $p = New-Object System.Security.Cryptography.RSAParameters
        $p.Modulus = ConvertTo-TestUnsigned -Bytes $f[1].Value -Length $nLen
        $p.Exponent = ConvertTo-TestUnsigned -Bytes $f[2].Value -Length ($f[2].Value.Length - $eS)
        $p.D = ConvertTo-TestUnsigned -Bytes $f[3].Value -Length $nLen
        $p.P = ConvertTo-TestUnsigned -Bytes $f[4].Value -Length $half
        $p.Q = ConvertTo-TestUnsigned -Bytes $f[5].Value -Length $half
        $p.DP = ConvertTo-TestUnsigned -Bytes $f[6].Value -Length $half
        $p.DQ = ConvertTo-TestUnsigned -Bytes $f[7].Value -Length $half
        $p.InverseQ = ConvertTo-TestUnsigned -Bytes $f[8].Value -Length $half
        return $p
    }
    # ECPrivateKey: version, privateKey, [0] parameters (optional), [1] publicKey BIT STRING (00 04 X Y)
    $bits = (Read-TestDer -Bytes ($f | Where-Object { $_.Tag -eq 0xA1 } | Select-Object -First 1).Value).Value
    $x = New-Object byte[] 32; $y = New-Object byte[] 32
    [Array]::Copy($bits, 2, $x, 0, 32); [Array]::Copy($bits, 34, $y, 0, 32)
    $q = New-Object System.Security.Cryptography.ECPoint
    $q.X = $x; $q.Y = $y
    $e = New-Object System.Security.Cryptography.ECParameters
    $e.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256
    $e.D = ConvertTo-TestUnsigned -Bytes $f[1].Value -Length 32
    $e.Q = $q
    $e
}

function New-VectorCertificate {
    # The vector case's certificate paired with its private key, held in memory only (nothing is added to a store).
    param([Parameter(Mandatory)] $Case)
    $pub = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]](Get-TestPemBytes -Pem $Case.certificatePem))
    $params = ConvertFrom-TestPkcs8 -Pem $Case.privateKeyPkcs8Pem
    if ($Case.algorithm -like 'rsa*') {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportParameters($params)
        return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($pub, $rsa)
    }
    [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($pub, [System.Security.Cryptography.ECDsa]::Create($params))
}

function New-EntraTestCertificate {
    <#
      A certificate shaped like the Entra device certificate: subject CN = device ID, issued (by a throwaway test key)
      under an MS-Organization-Access issuer name, client-authentication EKU. In memory only, never in a store.
    #>
    param(
        [string] $DeviceId = '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20',
        [string] $IssuerDn = 'CN=MS-Organization-Access, OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97, DC=windows, DC=net',
        [string] $SubjectDn,
        [datetime] $NotBefore = ([datetime]::UtcNow.AddYears(-1)),
        [datetime] $NotAfter = ([datetime]::UtcNow.AddYears(9)),
        [ValidateSet('rsa', 'ecdsa-p256', 'ecdsa-p384')][string] $KeyType = 'rsa',
        [switch] $NoPrivateKey
    )
    if (-not (Test-Path -Path variable:script:TestIssuerKey)) { $script:TestIssuerKey = [System.Security.Cryptography.RSA]::Create(2048) }
    if (-not $SubjectDn) { $SubjectDn = "CN=$DeviceId" }
    $subject = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($SubjectDn)
    $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    if ($KeyType -eq 'rsa') {
        $key = [System.Security.Cryptography.RSA]::Create(2048)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($subject, $key, $sha256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } else {
        $curve = $(if ($KeyType -eq 'ecdsa-p256') { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256 } else { [System.Security.Cryptography.ECCurve+NamedCurves]::nistP384 })
        $key = [System.Security.Cryptography.ECDsa]::Create($curve)
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($subject, $key, $sha256)
    }
    $oids = New-Object System.Security.Cryptography.OidCollection
    [void]$oids.Add((New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.2')))
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids, $false)))
    $gen = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($script:TestIssuerKey, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $serial = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($serial)
    $serial[0] = $serial[0] -band 0x7f
    $issuer = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($IssuerDn)
    $pub = $req.Create($issuer, $gen, [System.DateTimeOffset]$NotBefore, [System.DateTimeOffset]$NotAfter, $serial)
    if ($NoPrivateKey) { return $pub }
    if ($KeyType -eq 'rsa') { return [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($pub, $key) }
    [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($pub, $key)
}

function New-DsregText {
    # dsregcmd /status text in the documented layout (Device State, Device Details, Tenant Details), including the
    # blank lines real output has between a section's header box and its fields.
    param(
        [string] $AzureAdJoined = 'YES',
        [string] $DomainJoined = 'NO',
        [string] $DeviceId = '3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20',
        [string] $Thumbprint
    )
    $l = New-Object 'System.Collections.Generic.List[string]'
    $l.AddRange([string[]]@('', '+----------------------------------------------------------------------+', '| Device State                                                         |', '+----------------------------------------------------------------------+', '',
            "             AzureAdJoined : $AzureAdJoined", '          EnterpriseJoined : NO', "              DomainJoined : $DomainJoined", '               Device Name : CONTOSO-LT-0042', ''))
    if ($AzureAdJoined -eq 'YES') {
        $l.AddRange([string[]]@('+----------------------------------------------------------------------+', '| Device Details                                                       |', '+----------------------------------------------------------------------+', '',
                "                  DeviceId : $DeviceId"))
        if ($Thumbprint) { $l.Add("                Thumbprint : $Thumbprint") }
        $l.AddRange([string[]]@(' DeviceCertificateValidity : [ 2026-06-02 09:22:03.000 UTC -- 2036-06-02 09:52:03.000 UTC ]', '            KeyContainerId : 00aa00aa-bb11-cc22-dd33-44ee44ee44ee', '               KeyProvider : Microsoft Platform Crypto Provider',
                '              TpmProtected : YES', '          DeviceAuthStatus : SUCCESS', '', '+----------------------------------------------------------------------+', '| Tenant Details                                                       |', '+----------------------------------------------------------------------+', '',
                '                TenantName : Contoso', '                  TenantId : 9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10', ''))
    }
    , $l.ToArray()
}

function Initialize-FakeDevice {
    <#
      Mocks every platform wrapper with a fixed, schema-plausible device.
      Options let a test vary one thing without re-declaring the rest.
    #>
    param(
        [string] $TempState,
        [int] $FileCount = 30,
        [string] $Hostname = 'CONTOSO-LT-0042',
        [switch] $Dhcp235,
        [switch] $NoDoModule,
        [string] $DownloadMode = 'Group',
        [string] $CacheHost,
        [switch] $ProbeFailures,
        # 'ok' (default) or 'captive': what the DO geo service answers.
        [string] $Geo = 'ok',
        # Proxy auto-config: 'none' (default); 'device' (per-machine policy, one PAC naming DO, DIRECT for DO); 'users' (two
        # signed-in users with different PACs); 'proxied' (device-wide, sends DO through a proxy).
        [ValidateSet('none', 'device', 'users', 'proxied')][string] $Pac = 'none'
    )
    $global:DDFake = @{ Hostname = $Hostname; NoDoModule = [bool]$NoDoModule; DownloadMode = $DownloadMode; CacheHost = $CacheHost; FileCount = $FileCount; ProbeFailures = [bool]$ProbeFailures; Dhcp235 = [bool]$Dhcp235; Geo = $Geo; Pac = $Pac }
    $mod = 'DoctorDO.Collector'
    Mock -ModuleName $mod Test-DDWindows { $true }
    Mock -ModuleName $mod Test-DDElevated { $true }
    Mock -ModuleName $mod Test-DDSystemContext { $true }
    # Nothing a test runs opens a window or starts a browser: a report test that wants either mocks it itself.
    Mock -ModuleName $mod Get-DDNonInteractiveReason { 'a test run' }
    Mock -ModuleName $mod Find-DDPdfBrowser { $null }
    Mock -ModuleName $mod Invoke-DDHeadlessPrint { throw 'Invoke-DDHeadlessPrint is not expected on the fake device' }
    Mock -ModuleName $mod Get-DDNowUtc { [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc) }
    Mock -ModuleName $mod Get-DDHostName { $global:DDFake.Hostname }
    Mock -ModuleName $mod Get-DDMachineGuid { 'a1b2c3d4-0000-4000-8000-000000000001' }
    Mock -ModuleName $mod Protect-DDPath { }
    # The state folder is judged as off Windows (no ACLs: trusted); State.Tests-style cases mock their own raw facts.
    Mock -ModuleName $mod Get-DDDirectorySecurityRaw { $null }
    Mock -ModuleName $mod Reset-DDStateDirectory { throw 'Reset-DDStateDirectory is not expected on the fake device' }
    Mock -ModuleName $mod Set-DDLastSuccess { }

    Mock -ModuleName $mod Get-DDDsregStatusText {
        @('+----------------------------------------------------------------------+', '| Device State                                                         |', '+----------------------------------------------------------------------+',
            '             AzureAdJoined : YES', '          EnterpriseJoined : NO', '              DomainJoined : YES', '                DomainName : CONTOSO',
            '+----------------------------------------------------------------------+', '| Device Details                                                       |',
            '                  DeviceId : 3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20', '+----------------------------------------------------------------------+', '| Tenant Details                                                       |',
            '                TenantName : Contoso', '                  TenantId : 9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10')
    }
    Mock -ModuleName $mod Get-DDEnrollmentRecords {
        @([pscustomobject]@{ EnrollmentId = 'E0000000-0000-4000-8000-000000000001'; ProviderId = 'MS DM Server'; EnrollmentType = 6; EnrollmentState = 1
                DiscoveryUrl = 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc'; EntDmId = 'c0a8e1d2-77b4-4f09-b3a1-5e2d9c4f6a88' })
    }
    Mock -ModuleName $mod Get-DDIntuneDeviceIdFromCertificate { $null }
    Mock -ModuleName $mod Get-DDDevDetail { [pscustomobject]@{ OEM = 'Contoso Devices'; DevTyp = 'Contoso Laptop 14' } }
    Mock -ModuleName $mod Get-DDConfigMgrRaw { [pscustomobject]@{ Client = $false; SiteCode = $null } }
    # No Enrollment Status Page tracking unless a test supplies one (a Windows runner may carry a real key).
    Mock -ModuleName $mod Get-DDEspTrackingRaw { $null }

    Mock -ModuleName $mod Get-DDRegistryValue {
        $cv = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        if ($Path -eq $cv) {
            switch ($Name) {
                'CurrentMajorVersionNumber' { 10 } 'CurrentMinorVersionNumber' { 0 } 'CurrentBuild' { '26100' } 'UBR' { 4061 }
                'EditionID' { 'Enterprise' } 'ProductName' { 'Windows 10 Enterprise' } 'DisplayVersion' { '24H2' } 'InstallDate' { 1773446400 } default { $null }
            }
        } elseif ($Name -eq 'BIOSVersion') { @('1.8.2') } else { $null }
    }
    Mock -ModuleName $mod Get-DDRegistrySubKeyNames { @() }
    Mock -ModuleName $mod Get-DDRegistryValues {
        if ($Path -match 'Policies\\Microsoft\\Windows\\DeliveryOptimization$') {
            $v = @(
                [ordered]@{ name = 'DODownloadMode'; type = 'REG_DWORD'; data = '2' },
                [ordered]@{ name = 'DOGroupId'; type = 'REG_SZ'; data = 'a1b2c3d4-aaaa-bbbb-cccc-0123456789ab' },
                [ordered]@{ name = 'DOMadeUpFutureSetting'; type = 'REG_DWORD'; data = '7' })
            if ($global:DDFake.Dhcp235) { $v += [ordered]@{ name = 'DOCacheHostSource'; type = 'REG_DWORD'; data = '1' } }
            @{ Present = $true; Values = $v }
        } elseif ($Path -match 'DoSvc$') {
            @{ Present = $true; Values = @([ordered]@{ name = 'Start'; type = 'REG_DWORD'; data = '3' }, [ordered]@{ name = 'DelayedAutoStart'; type = 'REG_DWORD'; data = '0' }) }
        } else { @{ Present = $false; Values = @() } }
    }
    Mock -ModuleName $mod Get-DDCim {
        switch ($ClassName) {
            'Win32_ComputerSystem' { @([pscustomobject]@{ Model = 'Contoso Laptop 14'; Manufacturer = 'Contoso Devices'; TotalPhysicalMemory = [double](16GB); HypervisorPresent = $false }) }
            'Win32_SystemEnclosure' { @([pscustomobject]@{ ChassisTypes = @(10) }) }
            'Win32_BaseBoard' { @([pscustomobject]@{ SerialNumber = 'SN-ABC-12345' }) }
            'Win32_Processor' { @([pscustomobject]@{ Name = 'Contoso Core 7 '; NumberOfLogicalProcessors = 12 }) }
            default { @() }
        }
    }
    Mock -ModuleName $mod Get-DDLocalDisks { @([pscustomobject]@{ DeviceId = 'C:'; Size = [long](476GB); FreeSpace = [long](210GB) }) }
    Mock -ModuleName $mod Get-DDPhysicalDisks { @([pscustomobject]@{ MediaType = 4; BusType = 17; Size = [long](476GB) }) }
    Mock -ModuleName $mod Get-DDTpmRaw { [pscustomobject]@{ SpecVersion = '2.0, 0, 1.38' } }
    Mock -ModuleName $mod Get-DDBatteryRaw { @([pscustomobject]@{ BatteryStatus = 2; EstimatedChargeRemaining = 87 }) }
    Mock -ModuleName $mod Get-DDDirectorySize { [long]1073741824 }
    Mock -ModuleName $mod Get-DDDoSvcState { [pscustomobject]@{ Status = 'Running'; StartType = 'Manual' } }
    # Diagnosis signals (Diag.ps1): DoSvc ended unexpectedly twice in the week, and one 6-hour session at the start of the week, with nothing since (6 hours over the 6 days of history is 1 hour a day).
    Mock -ModuleName $mod Get-DDDoSvcDisplayName { 'Delivery Optimization' }
    Mock -ModuleName $mod Get-DDServiceTerminationEventsRaw {
        $n = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)   # the fake clock above
        @([pscustomobject]@{ Id = 7034; Provider = 'Service Control Manager'; TimeCreated = $n.AddDays(-1); Name = 'Delivery Optimization' },
            [pscustomobject]@{ Id = 7031; Provider = 'Service Control Manager'; TimeCreated = $n.AddDays(-2); Name = 'Delivery Optimization' },
            [pscustomobject]@{ Id = 7034; Provider = 'Service Control Manager'; TimeCreated = $n.AddDays(-2); Name = 'Some Other Service' })
    }
    # The device is old (installed and logging long before the window), so the powered-on mean is over the full 7 days.
    Mock -ModuleName $mod Get-DDDeviceHistoryStartRaw { [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc).AddDays(-400) }
    Mock -ModuleName $mod Get-DDKernelGeneralEventsRaw {
        $n = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)   # the fake clock above
        @([pscustomobject]@{ Id = 12; Provider = 'Microsoft-Windows-Kernel-General'; TimeCreated = $n.AddDays(-6); Name = $null },
            [pscustomobject]@{ Id = 13; Provider = 'Microsoft-Windows-Kernel-General'; TimeCreated = $n.AddDays(-6).AddHours(6); Name = $null })
    }

    Mock -ModuleName $mod Get-DDNetworkRaw {
        [pscustomobject]@{ DefaultInterfaceIndex = 7; Gateway = '10.20.4.1'; IPv4 = '10.20.4.71'; PrefixLength = 22
            Adapters = @([pscustomobject]@{ Name = 'Ethernet'; Description = 'Intel(R) Ethernet Connection'; Status = 'Up'; MediaType = '802.3'; PhysicalMediaType = '802.3'; IfIndex = 7; IfType = 6 },
                [pscustomobject]@{ Name = 'Teredo Tunneling Pseudo-Interface'; Description = 'Teredo Tunneling Pseudo-Interface'; Status = 'Up'; MediaType = 'Tunnel'; PhysicalMediaType = 'Unspecified'; IfIndex = 9; IfType = 131 }) }
    }
    Mock -ModuleName $mod Get-DDInternetSettings {
        [pscustomobject]@{ User = @{ Present = $true; Values = @() }; Machine = @{ Present = $false; Values = @() }; ProxySettingsPerUser = $null; DefaultConnectionSettings = $null }
    }
    Mock -ModuleName $mod Get-DDNetshWinHttpProxy { @('Current WinHTTP proxy settings:', '', '    Direct access (no proxy server).') }
    Mock -ModuleName $mod Get-DDPacSourcesRaw {
        $e = { param($scope, $url) [pscustomobject]@{ Scope = $scope; AutoConfigUrl = $url; Connections = $null } }
        switch ($global:DDFake.Pac) {
            # The machine store and the policy key name the same script under two URLs; the user's own PAC is not in force.
            'device' { [pscustomobject]@{ PerMachine = $true; Entries = @((& $e 'device' 'http://pac.contoso.example/proxy.pac'), (& $e 'device' 'http://wpad.contoso.example/proxy.pac'), (& $e 'user' 'http://alice.contoso.example/own.pac')); UsersRead = 1; UsersUnreadable = 0 } }
            'proxied' { [pscustomobject]@{ PerMachine = $true; Entries = @((& $e 'device' 'http://pac.contoso.example/all-via-proxy.pac')); UsersRead = 1; UsersUnreadable = 0 } }
            'users' { [pscustomobject]@{ PerMachine = $false; Entries = @((& $e 'user' 'http://pac.contoso.example/proxy.pac'), (& $e 'user' 'http://pac.contoso.example/old.pac'), (& $e 'service' $null)); UsersRead = 2; UsersUnreadable = 0 } }
            default { [pscustomobject]@{ PerMachine = $false; Entries = @((& $e 'user' $null)); UsersRead = 1; UsersUnreadable = 0 } }
        }
    }
    Mock -ModuleName $mod Resolve-DDPacProxy { [pscustomobject]@{ Proxy = $(if ($PacUrl -like '*all-via-proxy*') { 'proxy.contoso.example:8080' } else { $null }); Error = $null } }
    Mock -ModuleName $mod Get-DDConnectionCost { 'Unrestricted' }
    Mock -ModuleName $mod Get-DDAdSiteName { 'MAN-01' }
    Mock -ModuleName $mod Get-DDFirewallProfilesRaw { @([pscustomobject]@{ Name = 'Domain'; AllowLocalFirewallRules = 'True' }, [pscustomobject]@{ Name = 'Public'; AllowLocalFirewallRules = 'NotConfigured' }) }
    Mock -ModuleName $mod Get-DDFirewallRulesRaw {
        , @([pscustomobject]@{ DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'; Program = '%SystemRoot%\system32\svchost.exe'; Service = 'dosvc' },
            [pscustomobject]@{ DisplayName = 'Delivery Optimization (UDP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Domain, Private'; Protocol = 'UDP'; LocalPort = '7680'; Program = '%SystemRoot%\system32\svchost.exe'; Service = 'dosvc' })
    }
    # Delivery Optimization health (Health.ps1). -Dhcp235: DOCacheHostSource = 1 is set and the DHCP server offers 235.
    Mock -ModuleName $mod Get-DDAdapterCandidatesRaw {
        , @([pscustomobject]@{ Order = 0; Id = '{8A63F27C-0000-4000-8000-000000000007}'; Name = 'Ethernet'; Description = 'Intel(R) Ethernet Connection'; Up = $true; IfType = 6; IfIndex = 7; ConnectorPresent = $true
                IPv4 = @([pscustomobject]@{ Address = '10.20.4.71'; PrefixLength = 22 }) },
            [pscustomobject]@{ Order = 1; Id = '{8A63F27C-0000-4000-8000-000000000009}'; Name = 'Teredo Tunneling Pseudo-Interface'; Description = 'Teredo'; Up = $true; IfType = 131; IfIndex = 9; ConnectorPresent = $false; IPv4 = @() })
    }
    Mock -ModuleName $mod Get-DDDhcpOptionsRaw {
        $opts = @(foreach ($id in $OptionIds) {
                $data = $(if ($id -eq 1) { [byte[]](255, 255, 252, 0) } elseif ($id -eq 235 -and $global:DDFake.Dhcp235) { [System.Text.Encoding]::ASCII.GetBytes('10.20.9.15') } else { $null })
                [pscustomobject]@{ OptionId = $id; Present = ($null -ne $data); Data = $data }
            })
        [pscustomobject]@{ Attempted = $true; TimedOut = $false; Win32Error = 0; Error = $null; Options = $opts }
    }
    Mock -ModuleName $mod Resolve-DDUrlProxy { [pscustomobject]@{ Source = 'none'; Proxy = $null; Error = $null } }
    Mock -ModuleName $mod Invoke-DDHttpFetch -ParameterFilter { $Uri -like '*.pac' } {
        $pacs = @{
            'proxy.pac'         = 'function FindProxyForURL(url, host) { if (dnsDomainIs(host, ".do.dsp.mp.microsoft.com") || shExpMatch(host, "*.dl.delivery.mp.microsoft.com")) return "DIRECT"; return "PROXY proxy.contoso.example:8080"; }'
            'old.pac'           = 'function FindProxyForURL(url, host) { return "PROXY proxy.contoso.example:8080"; }'
            'all-via-proxy.pac' = 'function FindProxyForURL(url, host) { if (shExpMatch(host, "*.windowsupdate.com")) return "PROXY wsus.contoso.example:8530"; return "PROXY proxy.contoso.example:8080"; }'
        }
        $body = $pacs[($Uri -split '/')[-1]]
        [pscustomobject]@{ Attempted = $true; TimedOut = $false; Error = $null; Ms = 12.0; Status = 200; ContentType = 'application/x-ns-proxy-autoconfig'; ContentLength = $body.Length; Redirected = $false
            CertSeen = $false; ChainOk = $false; NameOk = $false; ChainMicrosoft = $false; Issuer = $null; ProxyUsed = $false; ProxyStatus = 0
            Body = [System.Text.Encoding]::UTF8.GetBytes($body); BodyTruncated = $false }
    }
    Mock -ModuleName $mod Invoke-DDHttpFetch {
        $captive = $global:DDFake.Geo -eq 'captive'
        $body = '{"ExternalIpAddress":"203.0.113.7","CountryCode":"GB","KeyValue_EndpointFullUri":"https://kv801.prod.do.dsp.mp.microsoft.com/all","Version":"26A6D4D6","CacheHost":"203.0.113.42","CacheId":7}'
        [pscustomobject]@{ Attempted = $true; TimedOut = $false; Error = $null; Ms = 41.2; Status = 200; ContentType = $(if ($captive) { 'text/html; charset=utf-8' } else { 'text/json' }); ContentLength = 200; Redirected = $false
            CertSeen = $true; ChainOk = $true; NameOk = $true; ChainMicrosoft = $true; Issuer = 'CN=Microsoft Azure RSA TLS Issuing CA 04'; ProxyUsed = $false; ProxyStatus = 0
            Body = $(if ($captive) { $null } else { [System.Text.Encoding]::UTF8.GetBytes($body) }); BodyTruncated = $false }
    }
    Mock -ModuleName $mod Get-DDCacheFolderAclRaw {
        [pscustomobject]@{ Exists = $true; DoSvcSid = 'S-1-5-80-3055155277-3816794035-3994065555-2874236192-2193176987'; Entries = @(
                [pscustomobject]@{ Sid = 'S-1-5-20'; Type = 'Allow'; Rights = 2032127; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' },
                [pscustomobject]@{ Sid = 'S-1-5-18'; Type = 'Allow'; Rights = 2032127; Inheritance = 'ContainerInherit, ObjectInherit'; Propagation = 'None' }) }
    }
    Mock -ModuleName $mod Test-DDDoStateFile { $true }
    Mock -ModuleName $mod Get-DDUusVersionRaw { '1510.2610.1012.0' }
    Mock -ModuleName $mod Get-DDActivePowerPlan { 'Balanced' }
    Mock -ModuleName $mod Get-DDNlmCostText { @('INetworkCostManager connectivity state:', '  Cost : unrestricted', '  Data Limit (MB) : not set') }

    Mock -ModuleName $mod Test-DDDeliveryOptimizationModule { -not $global:DDFake.NoDoModule }
    Mock -ModuleName $mod Get-DDDOConfigRaw {
        # Property names and the verbose text follow "Monitor Delivery Optimization" (Get-DOConfig -Verbose).
        $cfg = [pscustomobject]@{ DownloadMode = $global:DDFake.DownloadMode; MinTotalRAM = 4; BatteryPctToSeed = 60; WorkingDirectory = 'C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache'
            VpnKeywords = 'vpn,tunnel'; DownBackLimitBps = 0; DOGroupId = 'a1b2c3d4-aaaa-bbbb-cccc-0123456789ab' }
        if ($global:DDFake.CacheHost) { $cfg | Add-Member -NotePropertyName DOCacheHost -NotePropertyValue $global:DDFake.CacheHost }
        [pscustomobject]@{ Config = $cfg; Verbose = @("DownloadMode:$($global:DDFake.DownloadMode) DownloadModeProvider:GroupPolicy Provider", 'MinTotalRAM:4 MinTotalRAMProvider:Default Provider', 'BatteryPctToSeed:60 BatteryPctToSeedProvider:Mdm Provider', 'DOGroupId:a1b2c3d4 DOGroupIdProvider:Mdm Provider', 'DownBackLimitBps:0 DownBackLimitBpsProvider:Default Provider') }
    }
    Mock -ModuleName $mod Get-DDDOStatusRaw {
        $callers = 'Windows Update', 'Office Click-to-Run', 'Microsoft Store'
        @(1..$global:DDFake.FileCount | ForEach-Object {
                $size = [long]($_ * 1MB * 7)
                [pscustomobject]@{ FileId = ('{0:x40}' -f $_); FileSize = $size; BytesToLanPeers = 1000; BytesToInternetPeers = 0; TotalBytesDownloaded = $size; BytesFromHttp = [long]($size * 0.5); BytesFromLanPeers = [long]($size * 0.4)
                    BytesFromGroupPeers = [long]($size * 0.1); BytesFromInternetPeers = 0; BytesFromCacheServer = 0; DownloadMode = 2; Status = 'Caching'; Priority = 'Background'
                    NumPeers = 3; PredefinedCallerApplication = $callers[$_ % 3]; SourceURL = "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/$('{0:x8}' -f $_)-aaaa-bbbb-cccc-dddddddddddd?P1=1&P2=secret"
                    ExpireOn = [datetime]::new(2026, 10, 20, 0, 0, 0, [System.DateTimeKind]::Utc); CacheHost = $null; DownloadDuration = [timespan]::FromMilliseconds($_ * 1500) }
            })
    }
    Mock -ModuleName $mod Get-DDDOPeerInfoRaw {
        @([pscustomobject]@{ FileId = ('{0:x40}' -f 1); Peers = @(
                    [pscustomobject]@{ IP = '10.20.4.55'; PeerType = 'LAN'; ConnectionEstablished = $true; BytesSent = 1000; BytesReceived = 5000 },
                    [pscustomobject]@{ IP = '10.20.9.12'; PeerType = 'Group'; ConnectionEstablished = $true; BytesSent = 10; BytesReceived = 20 }) })
    }
    Mock -ModuleName $mod Get-DDDOPerfSnapRaw {
        # -ThisMonth: Get-DeliveryOptimizationPerfSnapThisMonth's shape on Windows 11 26H2 (read 19 Oct 2026; no group counter).
        if ($PesterBoundParameters.ContainsKey('ThisMonth') -and $PesterBoundParameters['ThisMonth']) {
            return [pscustomobject]@{ Snap = [pscustomobject]@{ UploadLanBytes = 6022418944; UploadInternetBytes = 0; DownloadHttpBytes = 18440031483; DownloadCacheHostBytes = 2628549676
                    DownloadLanBytes = 9214877102; DownloadInternetBytes = 0; DownloadFgRateKbps = 62115; DownloadBgRateKbps = 27588; UploadLimitReached = $false
                    MonthStartDate = [datetime]::new(2026, 10, 1) }; Verbose = @() }
        }
        [pscustomobject]@{ Snap = [pscustomobject]@{ FilesDownloaded = 12; NumberOfPeers = 38; CacheHostConnections = 2; DownlinkUsageBps = 5242880 }
            Verbose = @('Bytes from CDN: 41234567890', 'Bytes from LAN peers: 30123456789', 'Bytes from Group peers: 5123456789', 'Bytes from Internet peers: 0', 'Bytes from Connected Cache: 7', 'Average peer connections per download: 3') }
    }
    Mock -ModuleName $mod Get-DDDOLogEntries {
        $t = [datetime]::new(2026, 10, 12, 7, 50, 0, [System.DateTimeKind]::Utc)
        @(
            [pscustomobject]@{ TimeCreated = $t; Function = 'DownloadManager'; Message = "Download $('{0:x40}' -f 1) failed: 0x80d02002 for C:\Users\alice\AppData http://x.dl.delivery.mp.microsoft.com/a/b/c?token=zzz from 10.20.4.55 on CONTOSO-LT-0042" },
            [pscustomobject]@{ TimeCreated = $t.AddMinutes(1); Function = 'DownloadManager'; Message = 'retry later 0x80D02002' },
            [pscustomobject]@{ TimeCreated = $t.AddMinutes(2); Function = 'Misc'; Message = 'plain information line' },
            [pscustomobject]@{ TimeCreated = $t.AddMinutes(3); Function = 'GroupIdResolver'; Message = 'resolve failed 0x80072EE2 alice@contoso.com' })
    }
    Mock -ModuleName $mod Get-DDDOLogConnections {
        @([pscustomobject]@{ FileId = ('{0:x40}' -f 1); DestinationIP = '10.20.4.55'; PeerType = 'LAN'; StatusCode = '200'; Connected = $true; BytesSent = 10; BytesReceived = 20 },
            [pscustomobject]@{ FileId = ('{0:x40}' -f 1); DestinationIP = '10.20.4.56'; PeerType = 'LAN'; StatusCode = '0x80072EFD'; Connected = $false; BytesSent = 0; BytesReceived = 0 })
    }
    Mock -ModuleName $mod Get-DDListeningTcpPorts { @(7680) }
    Mock -ModuleName $mod Get-DDDoSvcTcpConnections { @() }
    # Teredo qualified with DO's server: the classes behind Get-NetTeredoState first, netsh as the fallback.
    Mock -ModuleName $mod Get-DDTeredoStateRaw { [pscustomobject]@{ Type = 2; ServerName = 'win1910.ipv6.microsoft.com.'; StatePresent = $true; State = 'qualified'; Error = 'none' } }
    Mock -ModuleName $mod Get-DDTeredoStateText { @('Type : client', 'Server Name : win1910.ipv6.microsoft.com', 'State : qualified', 'Error : none') }

    Mock -ModuleName $mod Invoke-DDNetProbeBatch {
        foreach ($s in @($Specs)) {
            $ok = -not ($global:DDFake.ProbeFailures -and $s.Tag -like 'cdn:*')
            [pscustomobject]@{ Kind = $s.Kind; Target = $s.Target; Port = $s.Port; Tag = $s.Tag; Ok = $ok; TimedOut = (-not $ok); Ms = 12.5; Error = $(if ($ok) { $null } else { 'timeout' })
                Addresses = '20.1.1.1,20.1.1.2'; Issuer = 'CN=Microsoft Azure RSA TLS Issuer 04, O=Microsoft Corporation, C=US'; Protocol = 'Tls12'; HttpStatus = 206
                Evidence = 'issuer=CN=Microsoft Azure RSA TLS Issuer 04, O=Microsoft Corporation; subject=CN=*.do.dsp.mp.microsoft.com; policyErrors=None'; Detail = 'None' }
        }
    }
    # Endpoint health: no proxy, and every probe healthy unless -ProbeFailures black-holes the content CDN. A test that
    # wants something else mocks Invoke-DDEndpointProbeBatch itself, with New-FakeEndpointOutcome.
    Mock -ModuleName $mod Resolve-DDProbeProxy { @{} }
    Mock -ModuleName $mod Invoke-DDEndpointProbeBatch {
        foreach ($s in @($Specs)) {
            if ($global:DDFake.ProbeFailures -and $s.Host -like '*.dl.delivery.mp.microsoft.com') { New-FakeEndpointOutcome -Spec $s -TcpTimeout }
            else { New-FakeEndpointOutcome -Spec $s }
        }
    }
}

function global:New-FakeEndpointOutcome {
    <#
      An outcome shaped like DoctorDO.Net.EndpointOutcome for one spec. Healthy by default; switches break one stage.
    #>
    param(
        [Parameter(Mandatory)] $Spec,
        [switch] $DnsFail, [string] $DnsError = 'SocketException TryAgain', [switch] $TcpTimeout, [int] $ProxyStatus = 0,
        [string] $Issuer = 'CN=Microsoft Azure RSA TLS Issuing CA 04, O=Microsoft Corporation, C=US', [switch] $NotMicrosoft, [switch] $Untrusted, [switch] $NameMismatch,
        [int] $HttpStatus = 400, [int] $RangeStatus = 206, [switch] $ViaProxy, [switch] $DirectBlocked,
        [string] $ContentRange, [int] $VerifyStatus = 200, [string] $VerifyContentType = 'application/octet-stream', [long] $VerifyContentLength = 302341
    )
    $ports = @(for ($i = 0; $i -lt @($Spec.Ports).Count; $i++) {
            if (@($Spec.Protocols)[$i] -eq 'udp') { continue }
            [pscustomobject]@{ Port = @($Spec.Ports)[$i]; Ok = (-not $TcpTimeout -and $ProxyStatus -eq 0); TimedOut = [bool]$TcpTimeout; Ms = 12.5
                Error = $(if ($TcpTimeout) { 'timeout' } elseif ($ProxyStatus) { "proxy answered $ProxyStatus to CONNECT" } else { $null }); ViaProxy = [bool]$ViaProxy; ProxyStatus = $ProxyStatus }
        })
    $anyOk = @($ports | Where-Object { $_.Ok }).Count -gt 0
    $https = @($Spec.Protocols) -contains 'https'
    $tls = [bool]$Spec.Tls -and $https -and $anyOk -and -not $DnsFail
    $iss = $(if ($NotMicrosoft) { 'CN=Contoso SSL Inspection CA, O=Contoso' } else { $Issuer })
    [pscustomobject]@{
        Tag = $Spec.Tag; Host = $Spec.Host
        DnsAttempted = $true; DnsOk = (-not $DnsFail); DnsMs = 3.1; DnsError = $(if ($DnsFail) { $DnsError } else { $null }); DnsTypes = $(if ($DnsFail) { '' } else { 'A,AAAA' }); Addresses = $(if ($Spec.WantAddresses -and -not $DnsFail) { '150.171.109.244,2620:1ec:bdf::44' } else { '' })
        Ports = $(if ($DnsFail -and -not $ViaProxy) { @() } else { $ports })
        TlsAttempted = $tls; TlsHandshake = $tls; TlsMs = 20; TlsError = $null; TlsProtocol = 'Tls12'
        CertSeen = $tls; Issuer = $iss; ChainMicrosoft = ($tls -and -not $NotMicrosoft -and $iss -match 'Microsoft'); NameOk = -not $NameMismatch; ChainOk = -not $Untrusted; PolicyErrors = 'None'
        HttpAttempted = ([bool]$Spec.Http -and $anyOk -and -not $DnsFail); HttpStatus = $HttpStatus; HttpMs = 15; HttpError = $null; HttpVia = [bool]$ViaProxy
        RangeAttempted = ([bool]$Spec.RangeUrl -and $anyOk -and -not $DnsFail); RangeStatus = $RangeStatus; RangeMs = 18; RangeError = $null
        ContentRange = $(if ($ContentRange) { $ContentRange } elseif ($RangeStatus -eq 206) { 'bytes 0-0/{0}' -f $(if ($null -ne $Spec.PSObject.Properties['RangeSize'] -and $Spec.RangeSize) { $Spec.RangeSize } else { 1048576 }) } else { $null })
        AcceptRanges = $(if ($RangeStatus -eq 206) { 'bytes' } else { $null }); RangeContentLength = $(if ($RangeStatus -eq 206) { 1 } else { -1 })
        VerifyAttempted = ($null -ne $Spec.PSObject.Properties['VerifyUrl'] -and [bool]$Spec.VerifyUrl -and $anyOk -and -not $DnsFail); VerifyStatus = $VerifyStatus; VerifyMs = 9; VerifyError = $null
        VerifyContentType = $VerifyContentType; VerifyContentLength = $VerifyContentLength
        ProxyUsed = [bool]$ViaProxy; ProxyStatus = $ProxyStatus; ProxyError = $null
        DirectAttempted = [bool]$ViaProxy; DirectOk = ([bool]$ViaProxy -and -not $DirectBlocked); DirectMs = 9; DirectError = $(if ($DirectBlocked) { 'timeout' } else { $null })
        TimedOut = $false
    }
}

function Assert-ValidAgainstSchema {
    # Test-Json emits one non-terminating error per failing sub-schema (including anyOf branches), so collect them and fail with all.
    param([Parameter(Mandatory)] $Object, [Parameter(Mandatory)][string] $SchemaFile)
    # Test-Json is PowerShell 6.1+. Under Windows PowerShell 5.1 the contract checks are reported as skipped rather than
    # silently passed; the same tests run them under PowerShell 7.
    if (-not (Get-Command -Name Test-Json -ErrorAction SilentlyContinue)) { Set-ItResult -Skipped -Because 'Test-Json (schema validation) needs PowerShell 7'; return }
    $json =if ($Object -is [string]) { $Object } else { ConvertTo-Json -InputObject $Object -Depth 32 -Compress }
    # The contracts are generated by the engine stream (pnpm contract:emit). Until a contract declares a field this collector
    # now sends (TelemetryV1.diag, Vitals.cacheDriveFreeGB), that field is removed before the check so the rest of the report is
    # still validated; once the contract has it the field is validated like any other.
    $schemaText = Get-Content -LiteralPath $SchemaFile -Raw
    if ($schemaText -notmatch '"cacheDriveFreeGB"' -or $schemaText -notmatch '"diag"') {
        $node = [System.Text.Json.Nodes.JsonNode]::Parse($json)
        if ($node -is [System.Text.Json.Nodes.JsonObject]) {
            if ($schemaText -notmatch '"diag"') { [void]$node.Remove('diag') }
            if ($schemaText -notmatch '"cacheDriveFreeGB"') {
                foreach ($section in 'vitals', 'device') {
                    $sub = $node[$section]
                    if ($sub -is [System.Text.Json.Nodes.JsonObject]) { [void]$sub.Remove('cacheDriveFreeGB') }
                }
            }
            $json = $node.ToJsonString()
        }
    }
    $errs = $null
    $ok = Test-Json -Json $json -SchemaFile $SchemaFile -ErrorVariable errs -ErrorAction SilentlyContinue
    if (-not $ok) { throw ("Schema validation failed: " + (($errs | ForEach-Object { $_.Exception.Message }) -join ' | ')) }
}

function Get-ContractPath { param([string] $Name) (Resolve-Path (Join-Path $PSScriptRoot "../../contracts/$Name")).Path }

function New-RandomText {
    param([int] $Bytes)
    $b = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    [Convert]::ToBase64String($b)
}
