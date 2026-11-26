function Test-DOConnectivity {
    <#
    .SYNOPSIS
        Checks whether this device can reach everything Delivery Optimization needs, and prints a summary by area
        followed by the checks that failed or warned.
    .DESCRIPTION
        Test-DOConnectivity runs the same checks as Get-DOConnectivityMatrix and formats them for reading: a table of
        the checks counted by area (cloud service, content, peer-to-peer, Connected Cache, proxy, local prerequisites
        and the Microsoft endpoints) and result, then each check that failed or warned, with where it looked and why.
        -Detailed lists every check instead, grouped by area. When you run it at a console, it says which part of the
        collection it is on while it works (-InformationAction SilentlyContinue hides that).

        It tests the Microsoft endpoints in the module's endpoint list (Data\endpoints.json, rows named ep:<id>):
        DNS, TCP to the documented ports, a TLS handshake that judges the certificate's issuing chain, one HEAD request and
        one Range: bytes=0-0 request for a file this device downloaded, through the proxy DoSvc would use in the
        background. Wildcard endpoints are tested only on hosts the device has used or Microsoft documents; the rest
        are reported as not testable. It adds the local checks: download mode, peer port 7680 and its firewall
        rules, Teredo, the Connected Cache server, the proxy auto-config (PAC) script, and whether DoSvc is running.

        Results are pass, fail, warn, not-applicable or not-collected; a check that was not run is never shown as a
        pass. Endpoint probes take at most 4 seconds per stage, 8 hosts at a time and 40 seconds in total, and the
        results are never cached. The command is read-only. It throws when the check itself cannot run.
    .PARAMETER Anonymise
        Hash peer targets and internal names in the output, for a result you can share.
    .PARAMETER RangeProbeUri
        Optional extra object for the HTTP byte-range check, used only when its host is a Microsoft content host in
        Data\endpoints.json. Normally not needed: a file the device itself downloaded is used.
    .PARAMETER Json
        Return the results as one JSON string (the shape of connectivity[] in the inventory) instead of the summary.
    .PARAMETER Detailed
        List every check, grouped by area, with its result, where it looked and its detail, instead of only the ones
        that failed or warned.
    .PARAMETER SkipConnectivityChecks
        Do not probe the network; every network check is reported as not-collected and only the local checks run.
    .EXAMPLE
        Test-DOConnectivity

        Prints the checks counted by area, then each one that failed or warned. Run it from an elevated prompt for
        the complete picture, for example when peers or a Connected Cache server are not being used.
    .EXAMPLE
        Test-DOConnectivity -Detailed

        Lists all of the checks, grouped by area, failures first within each area.
    .EXAMPLE
        (Test-DOConnectivity -Json | ConvertFrom-Json) | Where-Object result -eq 'fail' | Format-Table checkId, target, port, detail -Wrap

        Shows only the failed checks, read back from the JSON output. The parentheses make Windows PowerShell 5.1
        pass the rows on one at a time (its ConvertFrom-Json emits a JSON array as a single object).
    .EXAMPLE
        Test-DOConnectivity -Anonymise -Detailed | Set-Content -Path C:\Temp\do-connectivity.txt -Encoding UTF8

        Saves every check, anonymised, as text to attach to a ticket for your network or proxy team.
    .EXAMPLE
        $json = Test-DOConnectivity -Json
        $failed = @(($json | ConvertFrom-Json) | Where-Object result -eq 'fail')
        if ($failed.Count -gt 0) { Write-Output ($failed.checkId -join ', '); exit 1 }
        Write-Output 'Delivery Optimization connectivity: no failed checks.'; exit 0

        An Intune remediation detection script that reports a device with a failed check as non-compliant (exit 1)
        and names the failing checks in its output. Run it in 64-bit PowerShell; as SYSTEM it can read everything.
        The script needs the module installed on the device.
    .INPUTS
        None. You cannot pipe objects to Test-DOConnectivity.
    .OUTPUTS
        System.String. The summary as lines of plain text (no colour, so it can be saved or piped on), or with -Json
        one JSON string.
    .NOTES
        Runs on Windows. Elevation is not required; checks that need administrator rights are reported as
        not-collected. The probes reach only Microsoft endpoints, the configured Connected Cache server, peers the
        device already knows and the PAC scripts in force; nothing is sent to DoctorDO and nothing on the device is
        changed. Use Get-DOConnectivityMatrix for the rows as objects.
    .LINK
        https://www.doctor-do.com/get-started/
    .LINK
        about_DoctorDO.Collector
    .LINK
        Get-DOConnectivityMatrix
    .LINK
        https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-faq
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [switch] $Anonymise,
        [string] $RangeProbeUri,
        [switch] $Json,
        [switch] $Detailed,
        [switch] $SkipConnectivityChecks
    )
    $DDRun = Start-DDVerboseRun -Command 'Test-DOConnectivity' -Title 'connectivity checks' -Sections $script:DDCollectionSections -Quiet:(Test-DDInformationQuiet -BoundParameters $PSBoundParameters)
    try {
        $results = @(Get-DOConnectivityMatrix -Anonymise:$Anonymise -RangeProbeUri $RangeProbeUri -SkipConnectivityChecks:$SkipConnectivityChecks)
    } catch {
        throw "Connectivity check could not run: $($_.Exception.Message)"
    }
    Stop-DDVerboseRun -Run $DDRun -Command 'Test-DOConnectivity' -Summary (Get-DDCountText -Rows $results -Noun 'checks')
    if ($Json) { return (ConvertTo-Json -InputObject $results -Depth 8) }
    # Plain text, not coloured: this is the command's output, which is often saved or piped on.
    $width = Get-DDConsoleWidth
    ''
    if ($Detailed) {
        Format-DDCheckList -Rows $results -Width $width
    } else {
        Format-DDAreaTable -Rows $results
        ''
        Format-DDAttention -Rows $results -Width $width
        ''
        '  Every check, by area: Test-DOConnectivity -Detailed. What each one means and what to do: New-DoctorDODeviceReport.'
    }
    ''
}
