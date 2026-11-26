function Get-DOTelemetry {
    <#
    .SYNOPSIS
        Collects one compact Delivery Optimization telemetry report (TelemetryV1) for this device and returns it,
        without sending it or changing the collector's state.
    .DESCRIPTION
        Get-DOTelemetry builds the small report that fleet mode sends on every run: the download status rows (the top
        25 files plus one row for the rest), peers and connections aggregated, at most 8 named peers (as 16-character
        hashes, never addresses), errors grouped by HRESULT, counter deltas since the last accepted report, device
        vitals and diagnosis signals, per-source totals (bytes, jobs and download time for each Connected Cache server
        and each HTTP host, over the jobs that finished since the last accepted report), and only the connectivity
        results that changed since the last accepted report. The compaction is the same as the DoctorDO service's own,
        and the result follows DoctorDO's TelemetryV1 schema.

        Deltas and "changed since" are worked out against the collector's state file, which this command reads and
        never writes: running it does not move the baseline for the next fleet report. Invoke-DoctorDOCollector
        -Fleet commits the state only after the ingest service has accepted a report. On a device that has never
        sent a report there is no baseline: each counter is reported as its running total and the connectivity
        results (up to 64) are all reported as changed.

        The command is read-only: no log flush (DoSvc is not stopped), no upload, no Microsoft Graph call. Unless
        -SkipConnectivityChecks is given it probes the Microsoft endpoints Delivery Optimization uses.
    .PARAMETER Anonymise
        Remove the host name and reduce or hash the values that identify the device or the network, as in fleet
        mode. Run Invoke-DoctorDOCollector -WhatIfRedaction for the full list.
    .PARAMETER SkipConnectivityChecks
        Do not probe the network; the connectivity checks are reported as not-collected.
    .PARAMETER StatePath
        The state file the deltas are computed from. Default: %ProgramData%\DoctorDO\state.json. It is read, never
        changed. A missing or untrusted state is treated as a first run.
    .PARAMETER InventoryHash
        The hash of the inventory this report belongs to (the telemetry's inventoryHash). Default: the last inventory
        hash in the state file or, when there is none, the hash of an inventory built from this same collection.
    .PARAMETER PublicIpProbeUri
        Optional https URL of a service you trust that returns the caller's public IP address as plain text, used
        only when the Delivery Optimization geo answer gives no address. Supplying it turns on the public egress
        hash. The address is hashed at once and never stored.
    .PARAMETER CollectPublicEgress
        Add a salted hash of the public egress address read from the Delivery Optimization geo service's answer (no
        third-party service is called). Off by default.
    .PARAMETER RangeProbeUri
        Optional extra object for the HTTP byte-range check, used only when its host is a Microsoft content host in
        Data\endpoints.json. Normally not needed.
    .EXAMPLE
        Get-DOTelemetry -Anonymise | ConvertTo-Json -Depth 32

        Shows exactly what the next fleet run would send as its telemetry report, without sending it and without
        moving the baseline for the next real report.
    .EXAMPLE
        $t = Get-DOTelemetry -SkipConnectivityChecks
        $t['files'] | ForEach-Object { [pscustomobject]$_ } | Format-Table -AutoSize

        Lists the per-file download rows this device would report (sources, bytes and status), without probing the
        network.
    .EXAMPLE
        $t = Get-DOTelemetry
        $t['errors'] | ForEach-Object { [pscustomobject]$_ } | Format-Table -AutoSize

        Shows the Delivery Optimization errors grouped by HRESULT since the last accepted report, as the DoctorDO
        console will decode them.
    .INPUTS
        None. You cannot pipe objects to Get-DOTelemetry.
    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary. One TelemetryV1 report (kind 'telemetry', schemaVersion 1).
        Convert it with ConvertTo-Json -Depth 32.
    .NOTES
        Runs on Windows. Elevation is not required, but without it the Delivery Optimization logs (and so the error
        rows) and some registry keys cannot be read; they are listed in notCollected.

        Read-only: the state file, the registry and the Delivery Optimization service are left as they are, and no
        report is sent (the connectivity checks still contact the endpoints they test, unless -SkipConnectivityChecks).
        Peer and connection addresses are hashed in the peer and connection rows; the endpoint rows reduce peers to a
        /24 or /48 network under -Anonymise and show LAN peers as addresses without it.
    .LINK
        https://www.doctor-do.com/data/
    .LINK
        about_DoctorDO.Collector
    .LINK
        Get-DOInventory
    .LINK
        Invoke-DoctorDOCollector
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [switch] $Anonymise,
        [switch] $SkipConnectivityChecks,
        [string] $StatePath,
        [string] $InventoryHash,
        [string] $PublicIpProbeUri,
        [switch] $CollectPublicEgress,
        [string] $RangeProbeUri
    )
    if (-not $StatePath) { $StatePath = Get-DDDefaultStatePath }
    $st = (Read-DDState -Path $StatePath).State
    $since = [datetime]::MinValue
    if ($st['lastTelemetryAt']) { $since = [datetime]::Parse($st['lastTelemetryAt'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) }
    $collection = Get-DDRawCollection -Salt $st['salt'] -Anonymise:$Anonymise -SkipConnectivityChecks:$SkipConnectivityChecks -PublicIpProbeUri $PublicIpProbeUri -CollectPublicEgress:$CollectPublicEgress -RangeProbeUri $RangeProbeUri -Since $since
    if (-not $InventoryHash) { $InventoryHash = $st['lastInventoryHash'] }
    if (-not $InventoryHash) { $InventoryHash = Get-DDInventoryHash -Inventory (ConvertTo-DDInventory -Collection $collection) }
    New-DDTelemetryFromCollection -Collection $collection -State $st -InventoryHash $InventoryHash
}
