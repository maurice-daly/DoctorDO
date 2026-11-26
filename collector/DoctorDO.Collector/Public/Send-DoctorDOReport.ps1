function Send-DoctorDOReport {
    <#
    .SYNOPSIS
        Sends one inventory or telemetry report to your DoctorDO ingest service as a request signed with the device
        certificate's key, and returns what happened.
    .DESCRIPTION
        Send-DoctorDOReport is the transport that Invoke-DoctorDOCollector -Fleet uses; you can call it yourself to
        test a device's identity and its path to the ingest service. It serialises the report (ConvertTo-Json
        -Compress), compresses it with gzip and POSTs it over TLS 1.2 or later to https://<host>/v1/ingest, with the
        request signed by the device key (signed-request protocol v1). There is no key, token or password, and no TLS
        client certificate is presented: the device certificate travels in the X-DoctorDO-Device-Cert header and the
        signature in X-DoctorDO-Signature, with X-DoctorDO-Signed-At and a random X-DoctorDO-Nonce.

        -DeviceAnchor entra-device (default) signs with the Entra device certificate in LocalMachine\My: issuer
        MS-Organization-Access, subject CN equal to the DeviceId that dsregcmd /status reports, and the thumbprint
        dsregcmd reports. The device must be Microsoft Entra joined or hybrid joined. -DeviceAnchor tenant-ca signs
        with the tenant's Intune SCEP or PKCS certificate whose subject alternative name (or subject) contains the
        Entra device ID and which has the client authentication EKU.

        The exchange is one way: only the HTTP status code (and Retry-After) is used, and the response body is never
        read, logged or acted on. 202 means accepted; 429 means rate limited; 401 and 503 mean back off; anything
        else is a rejection. Reports over the 64 KB compressed hard limit are not sent. This command never retries
        and keeps no state: Invoke-DoctorDOCollector handles back-off and the state file.
    .PARAMETER Report
        The report to send: an inventory or telemetry dictionary with schemaVersion 1 and kind 'inventory' or
        'telemetry', as returned by Get-DOInventory or Get-DOTelemetry.
    .PARAMETER IngestUri
        The ingest URL of your DoctorDO deployment, https://<host>/v1/ingest. A bare https://<host> is completed with
        /v1/ingest. Plain http, other paths and query strings are refused, because the path is part of the signed
        request.
    .PARAMETER DeviceAnchor
        Which certificate identifies the device and signs the request: entra-device (default) or tenant-ca. It must
        match the anchor your DoctorDO deployment was set up with.
    .PARAMETER EntraDeviceId
        tenant-ca: the Microsoft Entra device ID used to choose the certificate (read from dsregcmd /status when
        omitted). entra-device: an optional cross-check that must equal the DeviceId dsregcmd reports.
    .PARAMETER CertificateThumbprint
        Use only the certificate with this thumbprint in LocalMachine\My.
    .PARAMETER CertificateIssuer
        tenant-ca only: accept only certificates from this issuer (distinguished name or common name), the
        certification authority registered with your DoctorDO deployment.
    .PARAMETER DsregStatus
        Internal: an already parsed dsregcmd /status result, so dsregcmd does not run twice. Invoke-DoctorDOCollector
        passes the one it collected. Leave it out when calling the command yourself.
    .PARAMETER TimeoutSec
        How long to wait for the ingest service, 5 to 300 seconds. Default 30.
    .EXAMPLE
        $r = Send-DoctorDOReport -Report (Get-DOTelemetry) -IngestUri https://ingest.contoso.example/v1/ingest
        $r | Format-List Outcome, StatusCode, ExitCode, Message

        Sends one telemetry report and shows the outcome. Run it as SYSTEM (for example with psexec -s), because the
        device key is a machine key. Accepted with StatusCode 202 means the device's identity and network path work.
        This report does not update the collector's state, so the next fleet run reports the same period again.
    .EXAMPLE
        Send-DoctorDOReport -Report (Get-DOInventory -Anonymise) -IngestUri https://ingest.contoso.example -DeviceAnchor tenant-ca -CertificateIssuer 'CN=Contoso Issuing CA'

        Sends an anonymised inventory signed with the Intune SCEP or PKCS certificate from Contoso Issuing CA. The
        bare host is completed with /v1/ingest. NoCertificate (exit code 6) means the certificate profile has not
        reached the device yet.
    .EXAMPLE
        $r = Send-DoctorDOReport -Report (Get-DOTelemetry -SkipConnectivityChecks) -IngestUri https://ingest.contoso.example/v1/ingest
        if ($r.ExitCode -eq 6) { $r.Message; dsregcmd /status | Select-String 'AzureAdJoined|DeviceId|Thumbprint|DeviceAuthStatus' }

        Checks a device's identity before you deploy the remediation to it: when the device cannot identify itself
        (exit code 6), prints the reason and the dsregcmd /status lines the collector depends on.
    .INPUTS
        None. You cannot pipe objects to Send-DoctorDOReport; pass the report with -Report.
    .OUTPUTS
        System.Management.Automation.PSCustomObject with Outcome, StatusCode, RetryAfterSeconds, Kind,
        CompressedBytes, BudgetResult, ExitCode and Message. Outcome is one of Accepted, RateLimited, BackOff,
        Rejected, NotJoined, NoCertificate, SigningFailed, NetworkError, TooLarge or InvalidReport.
    .NOTES
        Run as SYSTEM: the private key of the Entra device certificate (and usually of a SCEP certificate) is a
        machine key that a user session cannot use (SigningFailed). The device clock must be within five minutes of
        the service's.

        What is sent: the report you pass, plus the device certificate (public part only). With entra-device the
        certificate's subject is the Entra device ID, so the service learns that ID from every request. Nothing is
        sent anywhere but -IngestUri, and nothing on the device is changed.

        ExitCode on the result: 0 accepted; 3 the report is not a valid inventory or telemetry dictionary; 5 not
        accepted (network error, HTTP error, rate limited or back-off, too large, or an IngestUri that is not
        https://<host>/v1/ingest); 6 the device cannot identify itself (NotJoined, NoCertificate, SigningFailed).
    .LINK
        https://www.doctor-do.com/get-started/
    .LINK
        about_DoctorDO.Collector
    .LINK
        Invoke-DoctorDOCollector
    .LINK
        https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] $Report,
        [Parameter(Mandatory)][uri] $IngestUri,
        [ValidateSet('entra-device', 'tenant-ca')][string] $DeviceAnchor = 'entra-device',
        [string] $EntraDeviceId,
        [string] $CertificateThumbprint,
        [string] $CertificateIssuer,
        [Parameter(DontShow)] $DsregStatus,
        [ValidateRange(5, 300)][int] $TimeoutSec = 30
    )

    $result = {
        param($outcome, $code, $retry, $kind, $bytes, $budget, $exit, $msg)
        [pscustomobject]@{ Outcome = $outcome; StatusCode = $code; RetryAfterSeconds = $retry; Kind = $kind; CompressedBytes = $bytes; BudgetResult = $budget; ExitCode = $exit; Message = $msg }
    }

    $kind = $null
    if ($Report -is [System.Collections.IDictionary]) { $kind = [string]$Report['kind'] }
    if ($Report -isnot [System.Collections.IDictionary] -or $kind -notin 'inventory', 'telemetry' -or $Report['schemaVersion'] -ne 1) {
        return (& $result 'InvalidReport' 0 $null $kind 0 $null 3 'Report must be a schemaVersion 1 inventory or telemetry dictionary.')
    }
    if ($IngestUri.IsAbsoluteUri -and $IngestUri.Scheme -ne 'https') {
        return (& $result 'InvalidReport' 0 $null $kind 0 $null 5 'IngestUri must be https: reports are only ever sent over TLS.')
    }
    $uri = Resolve-DDIngestUri -Uri $IngestUri
    if ($null -eq $uri) {
        return (& $result 'InvalidReport' 0 $null $kind 0 $null 5 "IngestUri must be https://<host>/v1/ingest (the path is part of the signed request); got '$IngestUri'.")
    }

    # ---- identity: the certificate whose key signs the request ------------------------------------------------
    $dsreg = $DsregStatus
    if ($null -eq $dsreg) {
        $dsreg = Invoke-DDStep -Context (New-DDContext) -Field 'dsreg' -Script { ConvertFrom-DDDsregStatus -Lines (Get-DDDsregStatusText) }
    }
    $cert = $null
    if ($DeviceAnchor -eq 'entra-device') {
        if ($null -eq $dsreg -or -not $dsreg.Parsed) {
            return (& $result 'NotJoined' 0 $null $kind 0 $null 6 'Could not read the join state from dsregcmd /status, so the Entra device certificate cannot be identified. The entra-device anchor needs a Microsoft Entra joined or hybrid joined device; run dsregcmd /status as SYSTEM to check.')
        }
        if (-not $dsreg.AzureAdJoined -or -not $dsreg.DeviceId) {
            return (& $result 'NotJoined' 0 $null $kind 0 $null 6 "dsregcmd /status reports join state '$($dsreg.JoinType)' (AzureAdJoined: $(if ($dsreg.AzureAdJoined) { 'YES' } else { 'NO' })). The entra-device anchor needs a Microsoft Entra joined or hybrid joined device with an Entra device ID; Entra registered and domain-only devices cannot report.")
        }
        if ($EntraDeviceId -and -not [string]::Equals($EntraDeviceId.Trim(), $dsreg.DeviceId, [System.StringComparison]::OrdinalIgnoreCase)) {
            return (& $result 'NoCertificate' 0 $null $kind 0 $null 6 "-EntraDeviceId $EntraDeviceId does not match the DeviceId dsregcmd /status reports ($($dsreg.DeviceId)); the device certificate is chosen for the dsregcmd device.")
        }
        $pick = Select-DDEntraDeviceCertificate -Certificates @(Get-DDMachineCertificates) -EntraDeviceId $dsreg.DeviceId -DsregThumbprint $dsreg.DeviceCertificateThumbprint -Thumbprint $CertificateThumbprint
        if ($null -eq $pick.Certificate) {
            return (& $result 'NoCertificate' 0 $null $kind 0 $null 6 "No usable Entra device certificate in LocalMachine\My: $($pick.Reason). dsregcmd /status reports join state '$($dsreg.JoinType)' and DeviceId $($dsreg.DeviceId); check its Device Details (Thumbprint, DeviceCertificateValidity, DeviceAuthStatus) as SYSTEM.")
        }
        $cert = $pick.Certificate
    } else {
        if (-not $EntraDeviceId -and $dsreg) { $EntraDeviceId = $dsreg.DeviceId }
        if ($EntraDeviceId) {
            $cert = Select-DDDeviceCertificate -Certificates @(Get-DDMachineCertificates) -EntraDeviceId $EntraDeviceId -Thumbprint $CertificateThumbprint -Issuer $CertificateIssuer
        }
        if ($null -eq $cert) {
            return (& $result 'NoCertificate' 0 $null $kind 0 $null 6 'No usable device certificate in LocalMachine\My. Deploy the Intune SCEP or PKCS certificate profile (client authentication, SAN containing {{AAD_Device_ID}}) to this device.')
        }
    }

    $payload = ConvertTo-DDReportBytes -Report $Report
    $gz = $payload.Gzip
    $budget = Get-DDReportBudget -Kind $kind -CompressedBytes $gz.Length
    if ($budget -eq 'over-hard') {
        return (& $result 'TooLarge' 0 $null $kind $gz.Length $budget 5 "Report is $($gz.Length) bytes compressed, over the 64 KB hard cap; not sent.")
    }
    if ($budget -eq 'over-typical') { Write-Warning "Report is $($gz.Length) bytes compressed, over the typical budget for $kind." }

    $collectedAt = [string]$Report['collectedAt']
    $headers = [ordered]@{
        'Content-Type'            = 'application/vnd.doctordo.report+json'
        'Content-Encoding'        = 'gzip'
        'X-DoctorDO-Schema'       = '1'
        'X-DoctorDO-Kind'         = $kind
        'X-DoctorDO-Collected-At' = $collectedAt
    }
    $keyArgs = @{}
    if ($DeviceAnchor -eq 'entra-device' -and $null -ne $dsreg.PSObject.Properties['KeyContainerId'] -and $dsreg.KeyContainerId -and $dsreg.KeyProvider) { $keyArgs = @{ KeyContainer = $dsreg.KeyContainerId; KeyProvider = $dsreg.KeyProvider } }
    try {
        # Signed as late as possible: signed-at must be within five minutes of the verifier's clock.
        $signed = New-DDSignedHeaders -Certificate $cert -Uri $uri -Kind $kind -CollectedAt $collectedAt -Body $gz @keyArgs
    } catch {
        return (& $result 'SigningFailed' 0 $null $kind $gz.Length $budget 6 "The device key could not sign the request ($($_.Exception.GetType().Name): $($_.Exception.Message)). The collector must run as SYSTEM to use the device key; certificate $($cert.Thumbprint).")
    }
    foreach ($k in $signed.Keys) { $headers[$k] = $signed[$k] }

    # The same proxy the endpoint probes would use for the ingest host (Resolve-DDUploadProxy); named in a failure's
    # message by its source only, never its address.
    $px = Resolve-DDUploadProxy -Uri $uri
    $postArgs = @{}
    if ($px.Mode -eq 'proxy') { $postArgs.Proxy = $px.Proxy } elseif ($px.Mode -eq 'direct') { $postArgs.NoProxy = $true }
    $path = $(switch ($px.Mode) { 'proxy' { " through the proxy WinHTTP chooses for the ingest host (from $($px.Source))" } 'direct' { " directly (WinHTTP bypasses the $($px.Source) proxy for the ingest host)" } default { '' } })
    $resp = Invoke-DDHttpPost -Uri $uri -Body $gz -Headers $headers -TimeoutSec $TimeoutSec @postArgs
    $code = [int]$resp.StatusCode
    $retry = ConvertTo-DDRetryAfterSeconds -Value $resp.RetryAfter
    switch ($code) {
        202 { return (& $result 'Accepted' $code $null $kind $gz.Length $budget 0 'Accepted.') }
        429 { return (& $result 'RateLimited' $code $retry $kind $gz.Length $budget 5 'Rate limited; honour Retry-After.') }
        401 { return (& $result 'BackOff' $code $retry $kind $gz.Length $budget 5 'HTTP 401: the service did not accept the device''s signed identity; backing off. Check the device clock (more than five minutes behind the service''s is refused this way), that the device is enabled in Microsoft Entra, and that it uses the device anchor your DoctorDO deployment expects (-DeviceAnchor).') }
        422 { return (& $result 'Rejected' $code $null $kind $gz.Length $budget 5 'HTTP 422: the service refused the report''s collection time, which comes from the device clock. Check the device clock: more than five minutes ahead of the service''s (or more than 48 hours behind) is refused.') }
        407 { return (& $result 'Rejected' $code $null $kind $gz.Length $budget 5 "HTTP 407$($path): the proxy asked for credentials the account running the collector could not give. Exempt the ingest host from the proxy, or let the proxy accept the computer account.") }
        { $script:DDBackOffStatuses -contains $_ } { return (& $result 'BackOff' $code $retry $kind $gz.Length $budget 5 "HTTP $($code): the service or a gateway in front of it is unavailable; backing off.") }
        0 { return (& $result 'NetworkError' 0 $null $kind $gz.Length $budget 5 "Network error ($($resp.Error)) reaching the ingest host$path; backing off.") }
        default { return (& $result 'Rejected' $code $null $kind $gz.Length $budget 5 "HTTP $code.") }
    }
}
