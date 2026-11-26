function Get-DOConnectivityMatrix {
    <#
    .SYNOPSIS
        Runs the Delivery Optimization connectivity checks on this device and returns one result object per check,
        for filtering and scripting.
    .DESCRIPTION
        Get-DOConnectivityMatrix runs the probe engine the collector uses and returns its rows. It tests the endpoints
        in the module's endpoint list (Data\endpoints.json, rows named ep:<id>): DNS, TCP to the documented ports, a
        TLS handshake that judges the certificate's issuing chain (to spot TLS inspection), one HEAD request and one
        Range: bytes=0-0 request for a file this device itself downloaded, all through the proxy DoSvc would use in
        the background. Wildcard endpoints are tested only on hosts the device has used or Microsoft documents; the
        rest are reported as not testable. It also derives the local checks: download mode, peer port 7680 and the
        firewall rules for it, Teredo, the Connected Cache server, the Delivery Optimization geo service, the proxy
        auto-config (PAC) script, cache drive and memory eligibility, and whether DoSvc is running.

        Each result is pass, fail, warn, not-applicable or not-collected. A check that was not run is never shown as
        a pass. Endpoint probes take at most 4 seconds per stage, 8 hosts at a time and 40 seconds in total, and the
        results are never cached by this command.

        The command collects the device facts the checks depend on in the same way Get-DOInventory does: nothing is
        written, flushed or sent, and the only traffic is the checks themselves (and a DHCP-INFORM when the DHCP client
        has no cached answer for options 234 and 235). Its hashed values use a new random salt on every run. For the
        same checks as a table to read, use Test-DOConnectivity.
    .PARAMETER Anonymise
        Hash peer targets and internal names in the results and drop a non-Microsoft certificate issuer's name.
        Microsoft endpoints and the Connected Cache server stay in clear.
    .PARAMETER SkipConnectivityChecks
        Do not probe the network. Every network check is returned as not-collected; the local checks still run.
    .PARAMETER RangeProbeUri
        Optional extra object for the HTTP byte-range check, used only when its host is a Microsoft content host in
        Data\endpoints.json. Normally not needed: a file the device itself downloaded is used.
    .EXAMPLE
        Get-DOConnectivityMatrix | Where-Object { $_['result'] -eq 'fail' } | ForEach-Object { [pscustomobject]$_ } | Format-Table checkId, target, port, detail -Wrap

        Lists only the failed checks with the host, port and reason, for example a TLS-inspecting proxy in front of
        the Delivery Optimization content hosts.
    .EXAMPLE
        $rows = Get-DOConnectivityMatrix
        $rows | Group-Object { $_['result'] } -NoElement | Sort-Object Name

        Counts the results by outcome (pass, warn, fail, not-applicable, not-collected), as a quick health score in
        a script or a ticket.
    .EXAMPLE
        Get-DOConnectivityMatrix -Anonymise | ConvertTo-Json -Depth 8 | Set-Content -Path C:\Temp\do-connectivity.json -Encoding UTF8

        Saves the anonymised results as JSON, for example before and after a firewall or proxy change, to compare.
    .INPUTS
        None. You cannot pipe objects to Get-DOConnectivityMatrix.
    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary, one per check, with the keys checkId, target, protocol,
        port, result, latencyMs and detail, and code or evidence where they apply (the shape of connectivity[] in the
        inventory).
    .NOTES
        Runs on Windows. Elevation is not required; checks that need administrator rights are reported as
        not-collected. The probes reach only Microsoft endpoints, the Connected Cache server Delivery Optimization is
        configured with, peers the device already knows and the PAC scripts in force; nothing is sent to DoctorDO.
    .LINK
        https://www.doctor-do.com/get-started/
    .LINK
        about_DoctorDO.Collector
    .LINK
        Test-DOConnectivity
    .LINK
        Get-DOInventory
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [switch] $Anonymise,
        [switch] $SkipConnectivityChecks,
        [string] $RangeProbeUri
    )
    $collection = Get-DDRawCollection -Salt (New-DDRandomHex -Bytes 16) -Anonymise:$Anonymise -SkipConnectivityChecks:$SkipConnectivityChecks -RangeProbeUri $RangeProbeUri
    $collection.Raw['connectivity']
}
