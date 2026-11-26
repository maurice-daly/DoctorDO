#Requires -Version 5.1
# Signed-request protocol v1 (ADR-0029, contract C1 in docs/25). The device signs a canonical string with the private
# key of its device certificate, and ingest verifies it against the certificate it is sent. This replaces mutual TLS:
# no TLS client certificate is presented. The golden vector is contracts/signing/signing-v1.vector.json; the Pester
# suite reproduces its RSA signature byte for byte, so any change here that alters a byte of the canonical string
# fails the tests.
#
# Everything here runs on Windows PowerShell 5.1 (.NET Framework 4.7.2+) and PowerShell 7: only the
# RSACertificateExtensions / ECDsaCertificateExtensions accessors and HashAlgorithmName overloads are used, which both
# runtimes have and which work with the TPM (Microsoft Platform Crypto Provider) and software key storage providers.

Set-StrictMode -Version Latest

$script:DDSignatureVersion = 'DOCTORDO-SIG-1'
$script:DDIngestPath = '/v1/ingest'
$script:DDRsaOid = '1.2.840.113549.1.1.1'
$script:DDEcOid = '1.2.840.10045.2.1'

function Get-DDBodyHash {
    # Base64 SHA-256 of the body bytes exactly as sent (the gzip bytes, not the JSON).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]] $Body)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { [Convert]::ToBase64String($sha.ComputeHash($Body)) } finally { $sha.Dispose() }
}

function Get-DDCanonicalString {
    <#
    .SYNOPSIS
        The C1 canonical string: nine lines joined by a single LF, no trailing newline. Header values are used exactly
        as they are sent, so the caller passes the same strings it puts in the headers.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $Method,
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $HostName,
        [Parameter(Mandatory)][string] $Kind,
        [Parameter(Mandatory)][string] $CollectedAt,
        [Parameter(Mandatory)][string] $SignedAt,
        [Parameter(Mandatory)][string] $Nonce,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]] $Body
    )
    # Explicit "`n": a here-string or -join [Environment]::NewLine would put CRLF in on Windows.
    (@($script:DDSignatureVersion, $Method, $Path, $HostName, $Kind, $CollectedAt, $SignedAt, $Nonce, (Get-DDBodyHash -Body $Body)) -join "`n")
}

function New-DDNonce {
    # 16 random bytes, base64url without padding (22 characters). RNGCryptoServiceProvider exists on both runtimes.
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $b = New-Object byte[] 16
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-DDIngestHost {
    # The verifier signs over its configured public host (lower case, no port), so the collector uses the host of the
    # URI it was configured with, never anything a proxy or redirect might substitute. IdnHost gives the ASCII form; a
    # trailing dot (an absolute DNS name, "host.") is not part of the host the verifier is configured with.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][uri] $Uri)
    $Uri.IdnHost.ToLowerInvariant().TrimEnd('.')
}

function Resolve-DDIngestUri {
    <#
    .SYNOPSIS
        Normalise the configured ingest URI to https://<host>/v1/ingest. Returns $null for anything else.
    .DESCRIPTION
        The path is part of the signed string, so a URI whose path is not /v1/ingest would be refused by every
        verifier: it is better refused here, with a message, than sent and answered with a bare 401. A bare host
        (https://<host> or https://<host>/) is completed with /v1/ingest, and a trailing dot on the host (https://<host>./)
        is removed, so the request goes to, and is signed for, the host the service is configured with.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][uri] $Uri)
    if (-not $Uri.IsAbsoluteUri -or $Uri.Scheme -ne 'https') { return $null }
    if ($Uri.Query -or $Uri.Fragment -or $Uri.UserInfo) { return $null }
    $path = $Uri.AbsolutePath
    if ($path -eq '/' -or $path -eq '') { $path = $script:DDIngestPath }
    if ($path -cne $script:DDIngestPath) { return $null }
    $b = New-Object System.UriBuilder($Uri)
    $b.Path = $path
    if ($b.Host.EndsWith('.')) { $b.Host = $b.Host.TrimEnd('.') }
    if (-not $b.Host) { return $null }
    $b.Uri
}

function Get-DDSigningAlgorithm {
    # The algorithm follows the certificate's key type (C1). RSA covers the Entra device key, which Microsoft documents
    # as RSA 2048; EC P-256 is for a tenant-ca certificate profile with an ECDSA key.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Certificate)
    $oid = $Certificate.PublicKey.Oid.Value
    if ($oid -eq $script:DDRsaOid) { return 'rsa-pkcs1-sha256' }
    if ($oid -eq $script:DDEcOid) {
        $pub = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate)
        try { $size = $pub.KeySize } finally { $pub.Dispose() }
        if ($size -eq 256) { return 'ecdsa-p256-sha256' }
        throw [System.NotSupportedException]::new("EC key of $size bits: only P-256 is defined by the signing protocol.")
    }
    throw [System.NotSupportedException]::new("Key algorithm $oid is not supported by the signing protocol (RSA or EC P-256 only).")
}

function Test-DDSameRsaPublicKey {
    # A key opened by name is only trusted for signing when it is the certificate's key: a wrong key would be a 401 on
    # every run, with nothing on the device saying why.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Certificate, [Parameter(Mandatory)] $Key)
    $pub = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
    try {
        $a = $pub.ExportParameters($false); $b = $Key.ExportParameters($false)
        ([Convert]::ToBase64String($a.Modulus) -eq [Convert]::ToBase64String($b.Modulus)) -and ([Convert]::ToBase64String($a.Exponent) -eq [Convert]::ToBase64String($b.Exponent))
    } finally { $pub.Dispose() }
}

function New-DDSignature {
    <#
    .SYNOPSIS
        Sign bytes with the certificate's private key. Returns standard base64 with padding.
    .DESCRIPTION
        RSA: RSASSA-PKCS1-v1_5 with SHA-256 (deterministic). EC P-256: ECDSA with SHA-256; .NET returns the IEEE P1363
        (r||s) form, which is what the verifier expects. The key object is disposed after use; for a persisted key
        (CNG or TPM) that closes the handle and does not delete the key.

        RSA fallback: when GetRSAPrivateKey() fails and KeyContainer and KeyProvider are given (dsregcmd's
        KeyContainerId and KeyProvider for the Entra device key), the machine CNG key is opened by name instead. On a
        lab device both values equal the certificate's own key provider information (certutil), and .NET Framework has
        been seen to report "Invalid provider type specified" for such a key where .NET reports "Keyset does not
        exist" (both unelevated). The opened key is used only if its public key matches the certificate's.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Certificate, [Parameter(Mandatory)][byte[]] $Data, [string] $KeyContainer, [string] $KeyProvider)
    $alg = Get-DDSigningAlgorithm -Certificate $Certificate
    $sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    if ($alg -eq 'rsa-pkcs1-sha256') {
        $key = $null
        $why = 'the certificate has no accessible RSA private key'
        try { $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) }
        catch { $why = ([string]$(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message })).Trim() }
        if ($null -eq $key -and $KeyContainer -and $KeyProvider) {
            try {
                $key = Open-DDMachineRsaKey -KeyContainer $KeyContainer -KeyProvider $KeyProvider
                if (-not (Test-DDSameRsaPublicKey -Certificate $Certificate -Key $key)) {
                    $key.Dispose(); $key = $null
                    $why += "; the key container $KeyContainer holds a different key"
                }
            } catch {
                $key = $null
                $why += "; opening key container $KeyContainer in '$KeyProvider' also failed: $(([string]$(if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message })).Trim())"
            }
        }
        if ($null -eq $key) { throw [System.Security.Cryptography.CryptographicException]::new($why.Trim()) }
        try { return [Convert]::ToBase64String($key.SignData($Data, $sha256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) } finally { $key.Dispose() }
    }
    $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
    if ($null -eq $key) { throw [System.Security.Cryptography.CryptographicException]::new('The certificate has no accessible ECDSA private key.') }
    try { [Convert]::ToBase64String($key.SignData($Data, $sha256)) } finally { $key.Dispose() }
}

function New-DDSignedHeaders {
    <#
    .SYNOPSIS
        The four C1 headers for one request: device certificate, signed-at, nonce and signature.
    .DESCRIPTION
        Kind and CollectedAt must be the exact strings sent in X-DoctorDO-Kind and X-DoctorDO-Collected-At, and Body the
        exact bytes sent. SignedAt and Nonce are generated unless given (the tests pin them to the golden vector).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] $Certificate,
        [Parameter(Mandatory)][uri] $Uri,
        [Parameter(Mandatory)][string] $Kind,
        [Parameter(Mandatory)][string] $CollectedAt,
        [Parameter(Mandatory)][byte[]] $Body,
        [string] $SignedAt,
        [string] $Nonce,
        [string] $KeyContainer,
        [string] $KeyProvider
    )
    if (-not $SignedAt) { $SignedAt = Format-DDIso -Value (Get-DDNowUtc) }
    if (-not $Nonce) { $Nonce = New-DDNonce }
    $canonical = Get-DDCanonicalString -Method 'POST' -Path $Uri.AbsolutePath -HostName (Get-DDIngestHost -Uri $Uri) -Kind $Kind `
        -CollectedAt $CollectedAt -SignedAt $SignedAt -Nonce $Nonce -Body $Body
    $signature = New-DDSignature -Certificate $Certificate -Data ((New-Object System.Text.UTF8Encoding($false)).GetBytes($canonical)) -KeyContainer $KeyContainer -KeyProvider $KeyProvider
    [ordered]@{
        'X-DoctorDO-Device-Cert' = [Convert]::ToBase64String($Certificate.RawData)
        'X-DoctorDO-Signed-At'   = $SignedAt
        'X-DoctorDO-Nonce'       = $Nonce
        'X-DoctorDO-Signature'   = $signature
    }
}
