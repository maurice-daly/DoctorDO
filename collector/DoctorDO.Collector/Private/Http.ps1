#Requires -Version 5.1
# Transport for fleet reports. One-way (ADR-0024): the service answers with a status code and nothing else is
# read. The response BODY IS NEVER READ, LOGGED OR ACTED ON, and no response header except Retry-After is looked
# at. TLS 1.2 or later with normal server validation, and NO client certificate: the device proves its identity by
# signing the request with its device key (Signing.ps1, ADR-0029), not in the TLS handshake. Through the proxy the
# endpoint probes would use for the ingest host (Resolve-DDUploadProxy), with the default credentials of the account
# running the collector if the proxy asks for them.

Set-StrictMode -Version Latest

$script:DDClientAuthOid = '1.3.6.1.5.5.7.3.2'
# Issuer CN of the Entra device certificate (Microsoft Entra device management FAQ). The well-known OU GUID and DC
# components vary in order and grouping between devices (a multi-valued RDN has been observed), so only the CN is used.
$script:DDEntraIssuerCn = 'MS-Organization-Access'
# HTTP statuses that mean "try again later": the service or a gateway in front of it is unavailable, or the device's identity
# was refused (401, which a clock more than five minutes behind also gives). Invoke-DoctorDOCollector backs off after them,
# and after a network error, exponentially; 429 waits for its Retry-After.
$script:DDBackOffStatuses = @(401, 408, 500, 502, 503, 504)
# After this many failed runs in a row, a run that skips because of the back-off exits 5, not 0, so Intune shows the device
# as failing while it cannot report.
$script:DDBackoffExitAfter = 3

function Compress-DDGzip {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]] $Bytes)
    $ms = New-Object System.IO.MemoryStream
    try {
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionLevel]::Optimal, $true)
        try { $gz.Write($Bytes, 0, $Bytes.Length) } finally { $gz.Dispose() }
        , $ms.ToArray()
    } finally { $ms.Dispose() }
}

function ConvertTo-DDReportBytes {
    # ConvertTo-Json -Compress (docs/08), then gzip. Depth is explicit: the default of 2 truncates silently.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Report)
    $json = ConvertTo-Json -InputObject $Report -Compress -Depth 32
    $utf8 = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    [pscustomobject]@{ Json = $json; RawBytes = $utf8.Length; Gzip = (Compress-DDGzip -Bytes $utf8) }
}

function Get-DDReportBudget {
    # Mirrors packages/wire budgets.ts (compressed bytes).
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateSet('inventory', 'telemetry')][string] $Kind, [Parameter(Mandatory)][int] $CompressedBytes)
    $typical = $(if ($Kind -eq 'inventory') { 10 * 1024 } else { 4 * 1024 })
    $hard = 64 * 1024
    if ($CompressedBytes -gt $hard) { return 'over-hard' }
    if ($CompressedBytes -gt $typical) { return 'over-typical' }
    'within'
}

function Get-DDCertificateSanText {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Certificate)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in $Certificate.Extensions) {
        if ($e.Oid.Value -eq '2.5.29.17') { $parts.Add($e.Format($true)) }
    }
    ($parts -join "`n")
}

function Test-DDEntraIssuedCertificate {
    # True for certificates issued by Entra device registration (MS-Organization-Access and its siblings such as
    # MS-Organization-P2P-Access). Used to keep them out of the tenant-ca selection.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Certificate)
    $cn = [string]$Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    $cn.StartsWith('MS-Organization-', [System.StringComparison]::OrdinalIgnoreCase)
}

function Select-DDEntraDeviceCertificate {
    <#
    .SYNOPSIS
        Pick the Entra device certificate (anchor entra-device): exactly one certificate or a reason why not.
    .DESCRIPTION
        From LocalMachine\My: issuer CN exactly MS-Organization-Access, subject CN equal to the dsregcmd DeviceId
        (case-insensitive GUID), valid now, with a private key, and, when dsregcmd reports the device certificate's
        Thumbprint, that thumbprint. Exactly one must remain. The issuer CN is compared for equality, not containment:
        an Entra joined device also holds an MS-Organization-P2P-Access certificate with the same subject CN.
        Returns @{ Certificate; Reason } where Reason is $null on success.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] $Certificates = @(),
        [Parameter(Mandatory)][string] $EntraDeviceId,
        [string] $DsregThumbprint,
        [string] $Thumbprint,
        [datetime] $Now = (Get-DDNowUtc)
    )
    $simple = [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName
    $id = $EntraDeviceId.Trim()
    $shaped = @(@($Certificates) | Where-Object {
            $null -ne $_ -and
            [string]::Equals([string]$_.GetNameInfo($simple, $true), $script:DDEntraIssuerCn, [System.StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals([string]$_.GetNameInfo($simple, $false), $id, [System.StringComparison]::OrdinalIgnoreCase)
        })
    $fail = { param($reason) [pscustomobject]@{ Certificate = $null; Reason = $reason } }
    if ($shaped.Count -eq 0) { return (& $fail "no certificate issued by $($script:DDEntraIssuerCn) with subject CN $id") }
    $valid = @($shaped | Where-Object { $_.NotBefore.ToUniversalTime() -le $Now -and $_.NotAfter.ToUniversalTime() -ge $Now })
    if ($valid.Count -eq 0) { return (& $fail 'the device certificate is outside its validity period') }
    $keyed = @($valid | Where-Object { $_.HasPrivateKey })
    if ($keyed.Count -eq 0) { return (& $fail 'the device certificate has no private key in this store') }
    if ($DsregThumbprint) {
        $keyed = @($keyed | Where-Object { [string]::Equals($_.Thumbprint, $DsregThumbprint.Trim(), [System.StringComparison]::OrdinalIgnoreCase) })
        if ($keyed.Count -eq 0) { return (& $fail "no device certificate matches the thumbprint dsregcmd reports ($($DsregThumbprint.Trim()))") }
    }
    if ($Thumbprint) {
        $keyed = @($keyed | Where-Object { [string]::Equals($_.Thumbprint, $Thumbprint.Trim(), [System.StringComparison]::OrdinalIgnoreCase) })
        if ($keyed.Count -eq 0) { return (& $fail "no device certificate matches -CertificateThumbprint $($Thumbprint.Trim())") }
    }
    # Never guess between two: the server binds one key per device, so a wrong pick would be a 401 on every run.
    if ($keyed.Count -gt 1) { return (& $fail "$($keyed.Count) certificates qualify and dsregcmd reports no thumbprint to choose between them") }
    [pscustomobject]@{ Certificate = $keyed[0]; Reason = $null }
}

function Select-DDDeviceCertificate {
    <#
    .SYNOPSIS
        Pick the Intune-deployed device certificate (anchor tenant-ca): valid now, has a private key,
        client-authentication EKU, and a SAN (or CN) that contains the Entra device ID. Newest expiry wins. Returns
        $null when none qualifies.
    .DESCRIPTION
        Certificates issued by Entra device registration (MS-Organization-*) are excluded: they carry the device ID as
        their CN and the client-authentication EKU, and with a ten-year lifetime they would otherwise always win
        "newest expiry". -Issuer, when given, restricts the choice to the CA registered with DoctorDO (matched against
        the issuer distinguished name or its CN, case-insensitive).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] $Certificates = @(),
        [Parameter(Mandatory)][string] $EntraDeviceId,
        [datetime] $Now = (Get-DDNowUtc),
        [string] $Thumbprint,
        [string] $Issuer
    )
    $id = $EntraDeviceId.Trim().ToLowerInvariant()
    $ok = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in @($Certificates)) {
        if ($Thumbprint -and $c.Thumbprint -ne $Thumbprint) { continue }
        if (Test-DDEntraIssuedCertificate -Certificate $c) { continue }
        if ($Issuer) {
            $issuerCn = [string]$c.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
            if (-not ([string]::Equals($c.Issuer, $Issuer.Trim(), [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($issuerCn, $Issuer.Trim(), [System.StringComparison]::OrdinalIgnoreCase))) { continue }
        }
        if (-not $c.HasPrivateKey) { continue }
        if ($c.NotBefore.ToUniversalTime() -gt $Now -or $c.NotAfter.ToUniversalTime() -lt $Now) { continue }
        $eku = @($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
        if ($eku.Count -gt 0) {
            $has = $false
            foreach ($e in $eku) { foreach ($o in $e.EnhancedKeyUsages) { if ($o.Value -eq $script:DDClientAuthOid) { $has = $true } } }
            if (-not $has) { continue }
        }
        $san = (Get-DDCertificateSanText -Certificate $c).ToLowerInvariant()
        if ($san.Contains($id) -or $c.Subject.ToLowerInvariant().Contains($id)) { $ok.Add($c) }
    }
    if ($ok.Count -eq 0) { return $null }
    @($ok | Sort-Object -Property NotAfter -Descending)[0]
}

function ConvertTo-DDRetryAfterSeconds {
    [CmdletBinding()]
    param([AllowNull()][string] $Value, [datetime] $Now = (Get-DDNowUtc))
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $n = 0
    if ([int]::TryParse($Value.Trim(), [ref]$n)) { return [math]::Min(86400, [math]::Max(0, $n)) }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) {
        return [int][math]::Min(86400, [math]::Max(0, ($d - $Now).TotalSeconds))
    }
    $null
}

function Get-DDUploadTlsProtocol {
    <#
    .SYNOPSIS
        The value to give ServicePointManager.SecurityProtocol for the upload, or $null to leave it. SystemDefault (the
        .NET Framework 4.7+ and .NET default) is left: the operating system chooses, with TLS 1.2 or later on every
        supported Windows, as Microsoft recommends ("TLS best practices with .NET Framework"). An explicit value that
        offers only TLS 1.2 and later is left too. Anything else (Windows PowerShell 5.1 can start with Ssl3, Tls) becomes
        TLS 1.2 and 1.3. Pure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int] $Current)
    $tls12 = [int][System.Net.SecurityProtocolType]::Tls12
    $tls13 = 12288
    if ($Current -eq 0) { return $null }
    if (($Current -band $tls12) -and -not ($Current -band (-bnot ($tls12 -bor $tls13)))) { return $null }
    $tls12 -bor $tls13
}

function Set-DDSecurityProtocol {
    # The process-wide TLS protocol setting. Mockable seam: whether a value is accepted depends on the runtime (.NET
    # Framework before 4.8 has no TLS 1.3 value and may refuse 12288 with NotSupportedException).
    [CmdletBinding()]
    param([Parameter(Mandatory)][int] $Value)
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]$Value
}

function Resolve-DDUploadProxy {
    <#
    .SYNOPSIS
        The proxy for the report upload, chosen as the endpoint probes choose theirs (Resolve-DDUrlProxy: WinHTTP for
        DoSvc's background context, a netsh winhttp proxy first, then the WinINET configuration with its WPAD, PAC, static
        proxy and bypass list). Returns @{ Mode; Proxy; Source }: Mode 'proxy' (Proxy is host:port), 'direct' (WinHTTP
        would bypass the proxy for this host, or the PAC answers DIRECT), or 'default' when no proxy is configured or the
        resolution failed, which leaves the runtime's own default proxy in place.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][uri] $Uri, [int] $TimeoutMs = 4000)
    $d = $null
    try { $d = Resolve-DDUrlProxy -Uri $Uri.AbsoluteUri -TimeoutMs $TimeoutMs } catch { Write-Verbose "upload proxy not resolved ($($_.Exception.GetType().Name))" }
    $source = $(if ($null -ne $d -and $d.Source) { [string]$d.Source } else { 'none' })
    if ($source -in 'none', 'unresolved') { return [pscustomobject]@{ Mode = 'default'; Proxy = $null; Source = $source } }
    if ($d.Proxy) { return [pscustomobject]@{ Mode = 'proxy'; Proxy = [string]$d.Proxy; Source = $source } }
    [pscustomobject]@{ Mode = 'direct'; Proxy = $null; Source = $source }
}

function Invoke-DDHttpPost {
    <#
    .SYNOPSIS
        POST bytes with the given headers. Returns ONLY the status code and the Retry-After header value.
        The response stream is never opened.
    .DESCRIPTION
        No TLS client certificate is attached (ADR-0029 decision 1): identity travels in the signed X-DoctorDO-*
        headers. Content-Type goes through the property HttpWebRequest requires; every other header is set as given, plus
        a User-Agent naming the collector. No Expect: 100-continue: the body follows the headers at once.
    .PARAMETER Proxy
        host:port of the proxy to use (Resolve-DDUploadProxy), with the default credentials of the account running the
        collector (under SYSTEM, the computer account), which the proxy is offered only if it asks (HTTP 407).
    .PARAMETER NoProxy
        Connect directly. Without -Proxy or -NoProxy the runtime's default proxy is used, also with default credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][uri] $Uri,
        [Parameter(Mandatory)][byte[]] $Body,
        [Parameter(Mandatory)][System.Collections.IDictionary] $Headers,
        [int] $TimeoutSec = 30,
        [string] $Proxy,
        [switch] $NoProxy
    )
    $prevProto = [int][System.Net.ServicePointManager]::SecurityProtocol
    $protoSet = $false
    try {
        # TLS 1.2 minimum (ingest requires it). In its own try: a runtime that refuses TLS 1.3's value gets TLS 1.2 alone,
        # instead of every upload failing.
        $want = Get-DDUploadTlsProtocol -Current $prevProto
        if ($null -ne $want) {
            try { Set-DDSecurityProtocol -Value $want }
            catch {
                Write-Verbose "TLS 1.3 not accepted by this runtime ($($_.Exception.GetType().Name)); TLS 1.2 only"
                Set-DDSecurityProtocol -Value ([int][System.Net.SecurityProtocolType]::Tls12)
            }
            $protoSet = $true
        }
        $req = [System.Net.HttpWebRequest]::Create($Uri)
        $req.Method = 'POST'
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $false
        $req.KeepAlive = $false
        $req.UserAgent = "DoctorDO-Collector/$(Get-DDCollectorVersion)"
        if ($Proxy) {
            $wp = New-Object System.Net.WebProxy("http://$Proxy")
            $wp.UseDefaultCredentials = $true
            $req.Proxy = $wp
        } elseif ($NoProxy) {
            $req.Proxy = $null
        } else {
            # The default proxy, evaluated for this URL, with default credentials on a copy (the shared object is not
            # changed). If it cannot be evaluated the request keeps the default proxy as it is.
            try {
                $def = [System.Net.WebRequest]::DefaultWebProxy
                if ($null -ne $def -and -not $def.IsBypassed($Uri)) {
                    $p = $def.GetProxy($Uri)
                    if ($null -ne $p -and $p.Authority -ne $Uri.Authority) {
                        $wp = New-Object System.Net.WebProxy($p)
                        $wp.UseDefaultCredentials = $true
                        $req.Proxy = $wp
                    }
                }
            } catch { Write-Verbose "default proxy not evaluated ($($_.Exception.GetType().Name))" }
        }
        # After the proxy is chosen: through a proxy, .NET Framework uses the proxy's service point, not the host's.
        $req.ServicePoint.Expect100Continue = $false
        foreach ($k in @($Headers.Keys)) {
            if ($k -eq 'Content-Type') { $req.ContentType = [string]$Headers[$k] } else { $req.Headers[[string]$k] = [string]$Headers[$k] }
        }
        $req.ContentLength = $Body.Length
        $rs = $req.GetRequestStream()
        try { $rs.Write($Body, 0, $Body.Length) } finally { $rs.Dispose() }
        $resp = $null
        try {
            $resp = $req.GetResponse()
        } catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($null -eq $resp) { return [pscustomobject]@{ StatusCode = 0; RetryAfter = $null; Error = $_.Exception.Status.ToString() } }
        }
        try {
            [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; RetryAfter = [string]$resp.Headers['Retry-After']; Error = $null }
        } finally { $resp.Close() }
    } catch {
        # A failure inside GetRequestStream or GetResponse arrives wrapped (MethodInvocationException): its WebException
        # status says more than the wrapper's type name.
        $ex = $_.Exception
        while ($null -ne $ex.InnerException -and $ex -isnot [System.Net.WebException]) { $ex = $ex.InnerException }
        [pscustomobject]@{ StatusCode = 0; RetryAfter = $null; Error = $(if ($ex -is [System.Net.WebException]) { $ex.Status.ToString() } else { $ex.GetType().Name }) }
    } finally { if ($protoSet) { Set-DDSecurityProtocol -Value $prevProto } }
}
