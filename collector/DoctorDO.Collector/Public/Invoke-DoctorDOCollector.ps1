function Invoke-DoctorDOCollector {
    <#
    .SYNOPSIS
        Runs the DoctorDO collector: writes a local diagnostic bundle (the default) or, with -Fleet, reports this
        device's Delivery Optimization inventory and telemetry to your own DoctorDO ingest service.
    .DESCRIPTION
        Invoke-DoctorDOCollector is for a support bundle or fleet reporting; for a one-device report, start with
        New-DoctorDODeviceReport. It collects once per run and works in one of three modes, chosen by the parameters
        you pass. Run by hand at a console, it says what it is doing: one line per part of the collection as it
        finishes, then the connectivity checks counted by area and each one that failed or warned
        (-InformationAction SilentlyContinue hides that). Under SYSTEM, in an Intune remediation or scheduled task, or
        with its output redirected it writes none of it.

        LOCAL BUNDLE (the default, or -Bundle). Writes doctordo-<yyyyMMdd-HHmmss>.zip (UTC) to -OutputPath, for a
        support case or offline analysis. The zip holds manifest.json, bundle.json (the BundleV1 document) and, where
        they can be read, dosvc-registry.json, nlm-cost.txt and dsregcmd-status.txt; -IncludeLog adds doctordo.log, a
        scrubbed excerpt of the Delivery Optimization log. Nothing is uploaded. The bundle identifies the device
        unless you add -Anonymise. To read the logs, the local bundle runs Get-DeliveryOptimizationLog -Flush, which
        Microsoft documents as stopping the Delivery Optimization service (DoSvc) first; add -NoFlush to leave the
        service running.

        -ReproduceIssue turns on Delivery Optimization verbose logging while you reproduce a problem. It waits until
        you press a key (or for -ReproduceTimeoutMinutes), collects, and then restores the previous setting in a
        finally block, so an error, Ctrl+C or the timeout still restores it. Microsoft documents no way to read the
        current verbose-logging setting, so -ReproduceIssue runs only when you also pass -AssumeVerboseLoggingOff to
        confirm that it is off now. Without that switch the run stops with exit code 3 and changes nothing.

        FLEET (-Fleet -IngestUri). Sends signed reports to your own DoctorDO deployment at https://<host>/v1/ingest.
        A full inventory is sent on the first run, whenever the device's stable inventory hash changes, and as a
        keyframe: daily for the first week after the first inventory was accepted, then every -KeyframeDays days. A
        compact telemetry report is sent on every run, after the inventory when both are due. Each request is signed with the private key of the device's certificate (see -DeviceAnchor):
        no key, token or password is configured anywhere, and no TLS client certificate is presented. Only the HTTP
        status code of the reply is used; the response body is never read. -Anonymise is on by default in fleet
        mode. After an HTTP 429, 401 or 503 the collector backs off (honouring Retry-After), and runs inside that
        window exit 0 without sending. Fleet mode is meant to run as SYSTEM, from the Intune remediation script.

        REDACTION PREVIEW (-WhatIfRedaction). Prints the redaction profile (Data\redaction-profile.json in the module
        folder): what is always scrubbed and what -Anonymise changes. Collects nothing and needs no elevation.

        Every mode returns one result object; its ExitCode is also set as $LASTEXITCODE (see NOTES for the codes).
        Add -Verbose to see each step with its timing and result; the verbose lines name no host, user or address.
    .PARAMETER OutputPath
        Local bundle: the folder the zip is written to. It is created if it does not exist. Default: the temp folder
        of the account running the command ([System.IO.Path]::GetTempPath()).
    .PARAMETER Bundle
        Local bundle: selects local mode explicitly. Local mode is also the default when neither -Fleet nor
        -WhatIfRedaction is given, so this switch changes nothing else.
    .PARAMETER ReproduceIssue
        Local bundle: enable Delivery Optimization verbose logging, wait while you reproduce the problem, collect,
        then restore the previous setting. Requires -AssumeVerboseLoggingOff. Cannot be combined with -Fleet. This is
        the only option that changes a device setting, and the change is always reverted; if reverting fails the run
        exits 4 and the result's Message gives the command to run.
    .PARAMETER IncludeLog
        Local bundle: add doctordo.log to the zip, an excerpt of the Delivery Optimization log limited to the event
        patterns in the redaction profile, passed through the log-line scrub (the account forms it recognises, e-mail
        addresses and URL query strings), capped at 200 KB.
    .PARAMETER NoFlush
        Local bundle: read the Delivery Optimization log without -Flush, so DoSvc is not stopped. The newest entries
        may then be missing. Fleet runs never flush.
    .PARAMETER AssumeVerboseLoggingOff
        Local bundle, with -ReproduceIssue: states that Delivery Optimization verbose logging is off now, so the
        collector knows what to restore. Pass it only when you know the setting is off.
    .PARAMETER ReproduceTimeoutMinutes
        Local bundle, with -ReproduceIssue: how long to wait for you before collecting anyway, 1 to 60 minutes.
        Default 15.
    .PARAMETER Fleet
        Fleet mode: collect and send signed inventory and telemetry reports to -IngestUri instead of writing a zip.
        Run it as SYSTEM.
    .PARAMETER IngestUri
        Fleet: the ingest URL of your DoctorDO deployment, https://<host>/v1/ingest. A bare https://<host> is
        completed with /v1/ingest. Plain http, other paths and query strings are refused (the path is part of the
        signed request).
    .PARAMETER EntraDeviceId
        Fleet: the Microsoft Entra device ID. With entra-device it is an optional cross-check and must equal the
        DeviceId that dsregcmd /status reports; with tenant-ca it selects the certificate (read from dsregcmd or the
        inventory when omitted).
    .PARAMETER CertificateThumbprint
        Fleet: use only the certificate with this thumbprint in LocalMachine\My.
    .PARAMETER DeviceAnchor
        Fleet: which certificate identifies the device and signs each request. entra-device (default): the Entra
        device certificate (issuer MS-Organization-Access) that Windows creates when a device is Microsoft Entra
        joined or hybrid joined; nothing needs deploying. tenant-ca: the tenant's Intune SCEP or PKCS certificate.
        It must match the anchor your DoctorDO deployment was set up with.
    .PARAMETER CertificateIssuer
        Fleet, tenant-ca only: accept only certificates from this issuer (distinguished name or common name), the
        certification authority registered with your DoctorDO deployment.
    .PARAMETER KeyframeDays
        Fleet: send a full inventory at least this often even when nothing has changed, 1 to 30 days. Default 7. For
        the first week after the first inventory was accepted one is sent on every run at least 20 hours after the
        last, so a device the service could not yet place (for example, not yet in its Intune index) appears within
        a day.
    .PARAMETER ForceInventory
        Fleet: send a full inventory on this run whatever the change detection says.
    .PARAMETER EndpointCacheMinutes
        Fleet: reuse the endpoint-health results (endpoint-health.json beside the state file) for this many minutes,
        while the device is on the same subnet and the same hosts would be tested, so frequent runs do not probe
        Microsoft's endpoints every time. 0 to 10080; default 360; 0 probes on every run.
    .PARAMETER WhatIfRedaction
        Print the redaction profile as JSON and return. Nothing is collected, read or sent.
    .PARAMETER Anonymise
        Remove the host name and reduce or hash the other values that identify the device or the network (local
        subnet, default gateway, peer grouping ID, adapter name, PAC host, internal content hosts, and IPv4 and IPv6
        addresses in log text), as listed by -WhatIfRedaction. Off by default for the local bundle; on by default in fleet mode, where -Anonymise:$false
        turns it off.
    .PARAMETER SkipConnectivityChecks
        Do not probe the network: no DNS, TCP, TLS or HTTP checks, no Delivery Optimization geo request and no proxy
        auto-config (PAC) download. Use it in air-gapped or change-frozen environments. The checks are reported as
        not-collected, never as passed.
    .PARAMETER StatePath
        The collector's state file. Default: %ProgramData%\DoctorDO\state.json. The local bundle only reads it (for
        the per-device salt, so hashed identifiers are stable); fleet runs read and write it. A folder you choose here
        is never deleted or replaced by the collector.
    .PARAMETER PublicIpProbeUri
        Optional https URL of a service you trust that returns the caller's public IP address as plain text. It is
        used only when the Delivery Optimization geo answer gives no address, and supplying it turns on the public
        egress hash (as -CollectPublicEgress does). The address is hashed at once and never stored.
    .PARAMETER CollectPublicEgress
        Add a salted hash of the device's public egress address, read from the Delivery Optimization geo service's
        answer (no third-party service is called), for the source-IP checks. Off by default. The address itself is
        never stored or sent.
    .PARAMETER RangeProbeUri
        Optional extra object for the HTTP byte-range check. It is used only when its host is a Microsoft content
        host in the module's endpoint list (Data\endpoints.json). Normally not needed: a file the device itself
        downloaded is used.
    .EXAMPLE
        Invoke-DoctorDOCollector -OutputPath C:\Temp -Anonymise

        Writes an anonymised local bundle, for example C:\Temp\doctordo-20261018-093000.zip, to attach to a support
        case. Run it from an elevated prompt. Nothing leaves the device; the result shows BundlePath and Sha256.
    .EXAMPLE
        Invoke-DoctorDOCollector -OutputPath C:\Temp -ReproduceIssue -AssumeVerboseLoggingOff -IncludeLog

        Turns on Delivery Optimization verbose logging, waits while you reproduce a slow or failing download, then
        collects a bundle with the log excerpt and turns verbose logging off again, even if you press Ctrl+C.
    .EXAMPLE
        Invoke-DoctorDOCollector -WhatIfRedaction

        Prints what is always scrubbed and what -Anonymise changes, without collecting anything. Useful when your
        privacy or security team reviews the collector.
    .EXAMPLE
        $r = Invoke-DoctorDOCollector -Fleet -IngestUri https://ingest.contoso.example/v1/ingest
        Write-Output "DoctorDO: $($r.Outcome)"
        exit $r.ExitCode

        What the Intune remediation script (Remediate-DoctorDO.ps1) does, run as SYSTEM in 64-bit PowerShell with
        "Run this script using the logged-on credentials" set to No. The device signs each report with its Entra
        device key; the exit code is what Intune shows (0 success, 6 the device cannot identify itself, and so on).
    .EXAMPLE
        Invoke-DoctorDOCollector -Fleet -IngestUri https://ingest.contoso.example/v1/ingest -DeviceAnchor tenant-ca -CertificateIssuer 'CN=Contoso Issuing CA'

        Fleet run for a deployment that uses the tenant-ca anchor: the request is signed with the Intune SCEP or PKCS
        certificate issued by Contoso Issuing CA instead of the Entra device certificate.
    .EXAMPLE
        $r = Invoke-DoctorDOCollector -Fleet -IngestUri https://ingest.contoso.example/v1/ingest -ForceInventory -Verbose
        $r.Reports | Format-Table Kind, Outcome, StatusCode, CompressedBytes

        A test run on one device (as SYSTEM, for example through psexec -s): sends a full inventory and a telemetry
        report, shows each step, and lists what the service answered for each report.
    .INPUTS
        None. You cannot pipe objects to Invoke-DoctorDOCollector.
    .OUTPUTS
        System.Management.Automation.PSCustomObject. Always: ExitCode, Outcome, SchemaVersion, DurationMs.
        Local bundle: BundlePath, Sha256, DeviceId, Anonymised, NotCollected, and Message when something needs
        attention. Fleet: Reports (one Send-DoctorDOReport result per report sent), DeviceId, Anonymised,
        NotCollected, InventorySent, or Message on failure. -WhatIfRedaction: RedactionProfile.
    .NOTES
        Requirements: Windows, run elevated or as SYSTEM; Windows 10 2004 / Windows 11 or later for the full set of
        facts (on older builds whatever cannot be read is listed in NotCollected, never invented). Fleet mode needs
        SYSTEM so the device key can sign, and, for entra-device, a Microsoft Entra joined or hybrid joined device
        that is enrolled in Intune. Windows PowerShell 5.1 or PowerShell 7; no other module is needed.

        What it changes: no Delivery Optimization, firewall, proxy or service setting. The local bundle writes only its
        zip; its log flush stops DoSvc briefly (-NoFlush avoids it); -ReproduceIssue toggles verbose logging and always
        restores it. Fleet mode writes only its own state in %ProgramData%\DoctorDO (state.json and two caches, readable
        by SYSTEM and Administrators only) and the values LastSuccessfulCollection and LastReportKind under
        HKLM\SOFTWARE\DoctorDO for the Intune detection script. It never flushes logs, never enables verbose logging and
        never changes configuration. The connectivity checks connect out to the endpoints Delivery Optimization uses
        (-SkipConnectivityChecks turns them off).

        Privacy: reports go only to the -IngestUri you give, which is your own deployment; no report or device data
        goes to the DoctorDO project. Log lines pass through a scrub that replaces the account forms it recognises (profile folders after
        \Users\, UNC paths, DOMAIN\account, user SIDs, e-mail addresses); it works by pattern, so other forms can get
        through. Peer addresses are hashed in the peer list; in the endpoint list they are reduced to a /24 or /48
        network (internet peers always, other peers under -Anonymise, without which they are addresses); in log text
        -Anonymise replaces IPv4 and IPv6 addresses. The inventory's management section carries the Entra device,
        tenant and Intune device IDs, and the Entra device ID also reaches the service in the certificate that signs
        every request, whatever -Anonymise says. Run -WhatIfRedaction for the full list.

        Exit codes (ExitCode on the result and $LASTEXITCODE):
          0  success, or backing off after an HTTP 429, 401 or 503 (nothing sent this run)
          1  not elevated
          2  not running on Windows
          3  collection failed, or -ReproduceIssue without -AssumeVerboseLoggingOff
          4  verbose logging could not be restored (Message gives the command to run as administrator)
          5  fleet upload failed: network error, HTTP error, rate limited, report too large, or an IngestUri that is
             not https://<host>/v1/ingest
          6  the device cannot identify itself. entra-device: not Entra joined or hybrid joined, no usable device
             certificate, or the key could not sign (usually: not running as SYSTEM). tenant-ca: the Intune
             certificate profile has not reached the device
          7  fleet only: %ProgramData%\DoctorDO is not safe to use and could not be replaced (for example a standard
             user created it); nothing was read or sent. Delete the folder as an administrator.
    .LINK
        https://www.doctor-do.com/get-started/
    .LINK
        about_DoctorDO.Collector
    .LINK
        New-DoctorDODeviceReport
    .LINK
        Send-DoctorDOReport
    .LINK
        Get-DOInventory
    .LINK
        https://learn.microsoft.com/intune/device-management/tools/deploy-remediations
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Local')][string] $OutputPath = [System.IO.Path]::GetTempPath(),
        [Parameter(ParameterSetName = 'Local')][switch] $Bundle,
        [Parameter(ParameterSetName = 'Local')][switch] $ReproduceIssue,
        [Parameter(ParameterSetName = 'Local')][switch] $IncludeLog,
        [Parameter(ParameterSetName = 'Local')][switch] $NoFlush,
        [Parameter(ParameterSetName = 'Local')][switch] $AssumeVerboseLoggingOff,
        [Parameter(ParameterSetName = 'Local')][ValidateRange(1, 60)][int] $ReproduceTimeoutMinutes = 15,

        [Parameter(Mandatory, ParameterSetName = 'Fleet')][switch] $Fleet,
        [Parameter(Mandatory, ParameterSetName = 'Fleet')][uri] $IngestUri,
        [Parameter(ParameterSetName = 'Fleet')][string] $EntraDeviceId,
        [Parameter(ParameterSetName = 'Fleet')][string] $CertificateThumbprint,
        [Parameter(ParameterSetName = 'Fleet')][ValidateSet('entra-device', 'tenant-ca')][string] $DeviceAnchor = 'entra-device',
        [Parameter(ParameterSetName = 'Fleet')][string] $CertificateIssuer,
        [Parameter(ParameterSetName = 'Fleet')][ValidateRange(1, 30)][int] $KeyframeDays = 7,
        [Parameter(ParameterSetName = 'Fleet')][switch] $ForceInventory,
        [Parameter(ParameterSetName = 'Fleet')][ValidateRange(0, 10080)][int] $EndpointCacheMinutes = 360,

        [Parameter(Mandatory, ParameterSetName = 'WhatIfRedaction')][switch] $WhatIfRedaction,

        [Parameter(ParameterSetName = 'Local')]
        [Parameter(ParameterSetName = 'Fleet')][switch] $Anonymise,
        [Parameter(ParameterSetName = 'Local')]
        [Parameter(ParameterSetName = 'Fleet')][switch] $SkipConnectivityChecks,
        [Parameter(ParameterSetName = 'Local')]
        [Parameter(ParameterSetName = 'Fleet')][string] $StatePath,
        [Parameter(ParameterSetName = 'Local')]
        [Parameter(ParameterSetName = 'Fleet')][string] $PublicIpProbeUri,
        [Parameter(ParameterSetName = 'Local')]
        [Parameter(ParameterSetName = 'Fleet')][switch] $CollectPublicEgress,
        [Parameter(ParameterSetName = 'Local')]
        [Parameter(ParameterSetName = 'Fleet')][string] $RangeProbeUri
    )

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $runName = $(if ($PSCmdlet.ParameterSetName -eq 'Fleet') { 'Invoke-DoctorDOCollector -Fleet' } else { 'Invoke-DoctorDOCollector' })
    # Narrated to a person at the console: the collection's sections, then the bundle, or the two reports of a fleet run.
    $sections = @{ Local = $script:DDCollectionSections + 1; Fleet = $script:DDCollectionSections + 2; WhatIfRedaction = 0 }[$PSCmdlet.ParameterSetName]
    $quiet = Test-DDInformationQuiet -BoundParameters $PSBoundParameters
    $DDRun = Start-DDVerboseRun -Command $runName -Title $(if ($PSCmdlet.ParameterSetName -eq 'Fleet') { 'fleet report' } else { 'support bundle' }) `
        -Sections $sections -Quiet:$quiet
    $finish = {
        param($code, $outcome, $extra)
        $o = [ordered]@{ PSTypeName = 'DoctorDO.CollectorResult'; ExitCode = $code; Outcome = $outcome; SchemaVersion = 1; DurationMs = [int]$clock.ElapsedMilliseconds }
        if ($extra) { foreach ($k in $extra.Keys) { $o[$k] = $extra[$k] } }
        $global:LASTEXITCODE = $code
        Stop-DDVerboseRun -Run $DDRun -Command $runName -Summary ('{0}, exit {1}' -f $outcome, $code)
        [pscustomobject]$o
    }

    if ($WhatIfRedaction) {
        $p = Get-DDRedactionProfile
        Write-Information (ConvertTo-Json -InputObject $p -Depth 16) -InformationAction Continue
        return (& $finish 0 'RedactionProfilePrinted' @{ RedactionProfile = $p })
    }

    $isFleet = ($PSCmdlet.ParameterSetName -eq 'Fleet')
    $anonymise = $Anonymise.IsPresent -or ($isFleet -and -not $PSBoundParameters.ContainsKey('Anonymise'))
    if (-not $StatePath) { $StatePath = Get-DDDefaultStatePath }

    # ---- preflight (phase 1) -------------------------------------------------------------------------------------
    if (-not (Test-DDWindows)) { return (& $finish 2 'UnsupportedOs' @{ Message = 'The collector reads Windows state and only runs on Windows 10 2004 / Windows 11 or later.' }) }
    if (-not (Test-DDElevated)) { return (& $finish 1 'NotElevated' @{ Message = 'Run from an elevated session (or as SYSTEM): reading Delivery Optimization logs needs administrator rights.' }) }

    if ($isFleet) {
        # A standard user can create the state folder first and would own it. Fleet runs read and write it as
        # SYSTEM, so it is made safe before anything in it is used, or the run stops. Only the default folder is ever
        # replaced: a -StatePath elsewhere is the caller's folder, and the collector deletes nothing in it.
        $stateDir = Split-Path -Path $StatePath -Parent
        $isDefaultState = [string]::Equals($StatePath, (Get-DDDefaultStatePath), [System.StringComparison]::OrdinalIgnoreCase)
        $unsafe = Initialize-DDStateDirectory -Path $stateDir -AllowReset:$isDefaultState
        if ($unsafe) {
            Write-DDVerboseStep -Step 'State folder' -Result "not safe: $unsafe"
            return (& $finish 7 'StateFolderUntrusted' @{ Message = "The state folder $stateDir is not safe to use: $unsafe. A standard user may have created it. Delete it as an administrator; the next run creates it again for SYSTEM and Administrators only." })
        }
        Write-DDVerboseStep -Step 'State folder' -Result 'safe (SYSTEM and Administrators only)'
    }
    $stateRead = Read-DDState -Path $StatePath
    $state = $stateRead.State
    $now = Get-DDNowUtc
    Write-DDVerboseStep -Step 'State' -Result {
        if ($stateRead.Untrusted) { "ignored: $($stateRead.Untrusted)" }
        elseif ($stateRead.Reason -eq 'absent') { 'none yet (first run)' }
        elseif ($stateRead.Recovered) { 'unreadable, starting afresh' }
        else { 'report {0} sent last; last inventory {1}' -f $state['seq'], $(if ($state['lastInventoryAt']) { $state['lastInventoryAt'] } else { 'never' }) }
    }

    if ($isFleet) {
        # ---- fleet ---------------------------------------------------------------------------------------------
        if ($state['backoffUntil']) {
            $until = [datetime]::MinValue
            if ([datetime]::TryParse([string]$state['backoffUntil'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$until) -and $until -gt $now) {
                # Exit 0 while a back-off is young, so one busy moment does not mark the device as failing; after
                # $script:DDBackoffExitAfter failed runs in a row, exit 5, so Intune shows a device that cannot report.
                $failures = [int64]$(if ($state['consecutiveFailures']) { $state['consecutiveFailures'] } else { 0 })
                $code = $(if ($failures -ge $script:DDBackoffExitAfter) { 5 } else { 0 })
                return (& $finish $code 'BackingOff' @{ Message = "Backing off until $(Format-DDIso -Value $until): the last $failures run(s) could not report. The run before the back-off says why." })
            }
        }
        $since = [datetime]::MinValue
        if ($state['lastTelemetryAt']) {
            $t = [datetime]::MinValue
            if ([datetime]::TryParse([string]$state['lastTelemetryAt'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$t)) { $since = $t }
        }
        try {
            $collection = Get-DDRawCollection -Salt $state['salt'] -Anonymise:$anonymise -SkipConnectivityChecks:$SkipConnectivityChecks `
                -PublicIpProbeUri $PublicIpProbeUri -CollectPublicEgress:$CollectPublicEgress -RangeProbeUri $RangeProbeUri -Since $since -Mode fleet `
                -EndpointCachePath (Join-Path -Path (Split-Path -Path $StatePath -Parent) -ChildPath 'endpoint-health.json') -EndpointCacheMinutes $EndpointCacheMinutes
            $gaps = Get-DDRequiredFieldGaps -Collection $collection
            if ($gaps.Count -gt 0) { throw "required field(s) could not be collected: $($gaps -join ', ')" }
            $collection.Provisioning = Resolve-DDProvisioning -Fresh $collection.Provisioning -Stored $state['provisioning']
            $inventory = ConvertTo-DDInventory -Collection $collection
        } catch {
            return (& $finish 3 'CollectionFailed' @{ Message = "Collection failed: $($_.Exception.Message)" })
        }
        $fullHash = Get-DDInventoryHash -Inventory $inventory
        $stableHash = Get-DDStableInventoryHash -Inventory $inventory
        $utc = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
        # For a week after the first inventory was accepted the keyframe is daily: ingest can drop a new device's report while
        # the device is not yet in the hourly Intune index, and a daily keyframe brings it back within a day, not a week (E-02).
        # "Daily" is 20 hours, so a daily schedule's start jitter cannot push the next run just under a day and skip it.
        $firstWeek = $false
        $fa = [datetime]::MinValue
        if ($state['firstInventoryAt'] -and [datetime]::TryParse([string]$state['firstInventoryAt'], [System.Globalization.CultureInfo]::InvariantCulture, $utc, [ref]$fa)) { $firstWeek = ($now - $fa).TotalDays -lt 7 }
        $keyframeDue = $true
        if ($state['lastInventoryAt']) {
            $la = [datetime]::MinValue
            if ([datetime]::TryParse([string]$state['lastInventoryAt'], [System.Globalization.CultureInfo]::InvariantCulture, $utc, [ref]$la)) {
                $keyframeDue = $(if ($firstWeek) { ($now - $la).TotalHours -ge 20 } else { ($now - $la).TotalDays -ge $KeyframeDays })
            }
        }
        $sendInventory = $ForceInventory.IsPresent -or ($stableHash -ne $state['lastStableHash']) -or $keyframeDue -or (-not $state['lastInventoryHash'])
        Start-DDSection -Name 'Inventory'
        Write-DDVerboseStep -Step 'Inventory' -Result {
            if ($ForceInventory) { 'due (-ForceInventory)' } elseif (-not $state['lastInventoryHash']) { 'due (first report)' }
            elseif ($stableHash -ne $state['lastStableHash']) { 'due (the device changed)' }
            elseif ($keyframeDue -and $firstWeek) { 'due (keyframe, daily in the first week)' } elseif ($keyframeDue) { "due (keyframe, every $KeyframeDays days)" }
            else { 'unchanged, not sent' }
        }
        $reports = New-Object 'System.Collections.Generic.List[object]'
        $sendArgs = @{ IngestUri = $IngestUri; DeviceAnchor = $DeviceAnchor }
        # The dsregcmd result from this collection, so the send does not run dsregcmd again (it can take seconds).
        if ($null -ne $collection.PSObject.Properties['Dsreg'] -and $null -ne $collection.Dsreg) { $sendArgs.DsregStatus = $collection.Dsreg }
        if ($EntraDeviceId) { $sendArgs.EntraDeviceId = $EntraDeviceId }
        elseif ($DeviceAnchor -eq 'tenant-ca' -and $inventory['management']['entraDeviceId']) { $sendArgs.EntraDeviceId = $inventory['management']['entraDeviceId'] }
        if ($CertificateThumbprint) { $sendArgs.CertificateThumbprint = $CertificateThumbprint }
        if ($CertificateIssuer) { $sendArgs.CertificateIssuer = $CertificateIssuer }

        $fail = {
            param($r)
            $state['consecutiveFailures'] = [int64]($(if ($state['consecutiveFailures']) { $state['consecutiveFailures'] } else { 0 }) + 1)
            $wait = $null
            if ($r.Outcome -eq 'RateLimited') { $wait = $(if ($null -ne $r.RetryAfterSeconds) { $r.RetryAfterSeconds } else { 900 }) }
            # 401, 408, 500, 502, 503 and 504 (Send-DoctorDOReport's BackOff) and a network error: exponential, 1 minute
            # doubling to at most an hour, or Retry-After when the service gives a longer one.
            elseif ($r.Outcome -in 'BackOff', 'NetworkError') {
                $exp = [math]::Min(3600, 60 * [math]::Pow(2, [math]::Min(6, [int]$state['consecutiveFailures'] - 1)))
                $wait = [math]::Max([int]$exp, $(if ($null -ne $r.RetryAfterSeconds) { $r.RetryAfterSeconds } else { 0 }))
                $wait = [int]($wait + (Get-Random -Minimum 0 -Maximum 30))
            }
            if ($null -ne $wait) { $state['backoffUntil'] = Format-DDIso -Value $now.AddSeconds($wait) }
            try { Save-DDState -Path $StatePath -State $state } catch { Write-Verbose "state save failed: $($_.Exception.Message)" }
            $code = $r.ExitCode
            (& $finish $code $r.Outcome @{ Message = $r.Message; Reports = $reports.ToArray(); NotCollected = $inventory['notCollected'] })
        }

        $sent = { param($r) $s = Get-DDProp $r 'StatusCode'; '{0}{1}' -f $r.Outcome, $(if ($s) { " (HTTP $s)" } else { '' }) }
        if (-not $sendInventory) { Complete-DDSection -Result 'unchanged, not sent' }
        if ($sendInventory) {
            $r = Send-DoctorDOReport -Report $inventory @sendArgs
            $reports.Add($r)
            Write-DDVerboseStep -Step 'Inventory sent' -Result { & $sent $r }
            Complete-DDSection -Result { 'sent: ' + (& $sent $r) }
            if ($r.Outcome -ne 'Accepted') { return (& $fail $r) }
            Update-DDStateAfterInventory -State $state -Collection $collection -Inventory $inventory -FullHash $fullHash -StableHash $stableHash -Now $now
            $state['consecutiveFailures'] = 0; $state['backoffUntil'] = $null
            Save-DDState -Path $StatePath -State $state
            Set-DDLastSuccess -Kind 'inventory' -Timestamp $inventory['collectedAt']
        }
        $invHash = $(if ($sendInventory) { $fullHash } else { $state['lastInventoryHash'] })
        Start-DDSection -Name 'Telemetry'
        $telemetry = New-DDTelemetryFromCollection -Collection $collection -State $state -InventoryHash $invHash -Now $now
        $r = Send-DoctorDOReport -Report $telemetry @sendArgs
        $reports.Add($r)
        Write-DDVerboseStep -Step 'Telemetry sent' -Result { & $sent $r }
        Complete-DDSection -Result { 'sent: ' + (& $sent $r) }
        if ($r.Outcome -ne 'Accepted') { return (& $fail $r) }
        Update-DDStateAfterTelemetry -State $state -Collection $collection -Telemetry $telemetry -Now $now
        $state['consecutiveFailures'] = 0; $state['backoffUntil'] = $null
        Save-DDState -Path $StatePath -State $state
        Set-DDLastSuccess -Kind 'telemetry' -Timestamp $telemetry['collectedAt']
        Write-DDRunSummary -Run $DDRun -Rows $collection.Raw['connectivity'] -NotCollected @($inventory['notCollected']).Count -More 'New-DoctorDODeviceReport explains each' -Listed 'the inventory lists each, with why'
        return (& $finish 0 'Success' @{ Reports = $reports.ToArray(); Anonymised = $anonymise; DeviceId = $inventory['device']['deviceId']; NotCollected = $inventory['notCollected']; InventorySent = $sendInventory })
    }

    # ---- local deep bundle -----------------------------------------------------------------------------------------
    $collectScript = {
        Get-DDRawCollection -Salt $state['salt'] -Anonymise:$anonymise -SkipConnectivityChecks:$SkipConnectivityChecks `
            -PublicIpProbeUri $PublicIpProbeUri -CollectPublicEgress:$CollectPublicEgress -RangeProbeUri $RangeProbeUri -Mode single -IncludeBundleExtras -FlushLogs:(-not $NoFlush)
    }
    $restoreFailed = $false
    $restoreCommand = $null
    $reproduction = $null
    try {
        if ($ReproduceIssue) {
            $assume = $null
            if ($AssumeVerboseLoggingOff) { $assume = $false }
            $cycle = Invoke-DDVerboseCycle -Collect $collectScript -TimeoutMinutes $ReproduceTimeoutMinutes -AssumePreviousState $assume
            $collection = $cycle.Result
            $restoreFailed = -not $cycle.RestoreOk
            $restoreCommand = $cycle.RestoreCommand
            # dosvcStopped: the collector never stops DoSvc itself, but the default log flush does (Microsoft: "If Flush is
            # specified, the cmdlet stops DoSvc before reading logs"); -NoFlush leaves it running.
            $reproduction = [ordered]@{ verboseEnabledByCollector = [bool]$cycle['EnabledByCollector']; endedBy = $cycle['EndedBy']; restored = [bool]$cycle.RestoreOk; dosvcStopped = (-not $NoFlush) }
        } else {
            $collection = & $collectScript
        }
    } catch {
        return (& $finish 3 'CollectionFailed' @{ Message = "Collection failed: $($_.Exception.Message)" })
    }
    if ($null -eq $collection) { return (& $finish 3 'CollectionFailed' @{ Message = 'Collection produced no data.' }) }
    $gaps = Get-DDRequiredFieldGaps -Collection $collection
    if ($gaps.Count -gt 0) { return (& $finish 3 'CollectionFailed' @{ Message = "Required field(s) could not be collected: $($gaps -join ', ')."; NotCollected = $collection.Raw['notCollected'] }) }
    try {
        $log = $null
        if ($IncludeLog -and $collection.Raw.Contains('logExcerpt')) { $log = [string]$collection.Raw['logExcerpt'] }
        # Local bundle only: the DoSvc service key, the network cost and dsregcmd /status (never in a fleet report).
        $extraArgs = @{}
        if ($null -ne $collection.PSObject.Properties['DsregText'] -and @($collection.DsregText).Count -gt 0) { $extraArgs.DsregText = [string[]]@($collection.DsregText) }
        $extras = Get-DDLocalBundleExtras -Anonymise:$anonymise -Salt $state['salt'] -ComputerName (Get-DDHostName) @extraArgs
        foreach ($m in @($extras.Missing)) { Write-Verbose "local bundle extra not collected: $m" }
        Start-DDSection -Name 'Bundle'
        $file = New-DDBundleFile -Raw $collection.Raw -OutputPath $OutputPath -LogText $log -Now $now -Extras $extras.Files -Reproduction $reproduction
        Write-DDVerboseStep -Step 'Bundle written' -Result { '{0:N0} KB; {1} fact(s) not collected' -f ((Get-Item -LiteralPath $file.BundlePath).Length / 1KB), @($collection.Raw['notCollected']).Count }
        Complete-DDSection -Result { 'zip {0:N0} KB' -f ((Get-Item -LiteralPath $file.BundlePath).Length / 1KB) }
    } catch {
        return (& $finish 3 'CollectionFailed' @{ Message = "Packaging failed: $($_.Exception.Message)" })
    }
    $summary = @{
        BundlePath = $file.BundlePath; Sha256 = $file.Sha256; DeviceId = $collection.Raw['device']['deviceId']
        Anonymised = $anonymise; NotCollected = $collection.Raw['notCollected']
    }
    Write-DDRunSummary -Run $DDRun -Rows $collection.Raw['connectivity'] -NotCollected @($collection.Raw['notCollected']).Count -More 'New-DoctorDODeviceReport explains each' -Listed 'bundle.json in the zip lists each, with why'
    if (-not $quiet) { Write-Information ("DoctorDO bundle: {0} (sha256 {1}, {2} field(s) not collected)" -f $file.BundlePath, $file.Sha256, @($collection.Raw['notCollected']).Count) -InformationAction Continue }
    if ($restoreFailed) {
        $summary.Message = "Verbose logging could not be restored. Run as administrator: $restoreCommand"
        return (& $finish 4 'VerboseNotRestored' $summary)
    }
    & $finish 0 'Success' $summary
}
