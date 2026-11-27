@{
    RootModule            = 'DoctorDO.Collector.psm1'
    ModuleVersion         = '1.2.3'
    GUID                  = '6f0d2a7e-3c5b-4e8a-9b1d-7a2c4e6f8b10'
    Author                = 'Maurice Daly'
    CompanyName           = 'DoctorDO'
    Copyright             = '(c) 2026 Maurice Daly. All rights reserved.'
    Description           = 'Diagnostics for Windows Delivery Optimization that change no Delivery Optimization, firewall, proxy or service setting. Writes an offline HTML device report or a local support bundle, checks the endpoints, proxy, peers and Connected Cache that Delivery Optimization depends on, and with -Fleet sends inventory and compact telemetry to your own DoctorDO deployment, each request signed with the device certificate key. No report leaves the device unless you run fleet mode with your own ingest URL. Windows 10 2004 / Windows 11 or later; Windows PowerShell 5.1 or PowerShell 7. DoctorDO is an independent community project, free to use, and in preview. Source-available under the PolyForm Shield License 1.0.0, not open source: free to use, change and share, except to provide a product that competes with it (see the licence).'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FunctionsToExport     = @('Invoke-DoctorDOCollector', 'Get-DOInventory', 'Get-DOTelemetry', 'Get-DOConnectivityMatrix', 'Test-DOConnectivity', 'Send-DoctorDOReport', 'New-DoctorDODeviceReport')
    # How the results of New-DoctorDODeviceReport and Invoke-DoctorDOCollector show at the console (a short list).
    FormatsToProcess      = @('DoctorDO.Collector.format.ps1xml')
    # Every file of the module folder, relative, with '/' (the module's own manifest included). The Intune remediation
    # (collector/intune/Remediate-DoctorDO.ps1) accepts an installed copy only when its files are exactly these and each
    # matches the release's SHA-256 list (collector-manifest.json); a test keeps this list equal to the folder.
    FileList              = @(
        'Data/device-report.html',
        'Data/endpoints.json',
        'Data/redaction-profile.json',
        'DoctorDO.Collector.format.ps1xml',
        'DoctorDO.Collector.psd1',
        'DoctorDO.Collector.psm1',
        'LICENSE',
        'Private/Bundle.ps1',
        'Private/Collect.ps1',
        'Private/Compact.ps1',
        'Private/Connectivity.ps1',
        'Private/Console.ps1',
        'Private/Context.ps1',
        'Private/Diag.ps1',
        'Private/DoData.ps1',
        'Private/Endpoints.ps1',
        'Private/Facts.ps1',
        'Private/Health.ps1',
        'Private/Http.ps1',
        'Private/Insight.ps1',
        'Private/Json.ps1',
        'Private/Pac.ps1',
        'Private/Platform.ps1',
        'Private/ProbeNative.ps1',
        'Private/Progress.ps1',
        'Private/Provisioning.ps1',
        'Private/Redact.ps1',
        'Private/Report.ps1',
        'Private/Signing.ps1',
        'Private/State.ps1',
        'Private/VerboseCycle.ps1',
        'Public/Get-DOConnectivityMatrix.ps1',
        'Public/Get-DOInventory.ps1',
        'Public/Get-DOTelemetry.ps1',
        'Public/Invoke-DoctorDOCollector.ps1',
        'Public/New-DoctorDODeviceReport.ps1',
        'Public/Send-DoctorDOReport.ps1',
        'Public/Test-DOConnectivity.ps1',
        'THIRD-PARTY-NOTICES.txt',
        'en-US/about_DoctorDO.Collector.help.txt'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData           = @{
        PSData = @{
            Tags         = @('DeliveryOptimization', 'ConnectedCache', 'WindowsUpdate', 'Intune', 'Diagnostics', 'Troubleshooting', 'Network', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core')
            # Pages on the DoctorDO site, open without signing in: the licence page shows the full licence text with its
            # Required Notice. Both must resolve before publishing (the Gallery shows them as the package's links).
            LicenseUri   = 'https://www.doctor-do.com/licence/'
            ProjectUri   = 'https://www.doctor-do.com/get-started/'
            # IconUri must be a direct link to an 85x85 PNG with a transparent background (not a page, not a file in
            # the package), at an address that will not change. None is published yet; add the line once one is, e.g.:
            # IconUri    = 'https://www.doctor-do.com/<path to the 85x85 PNG>'
            ReleaseNotes = '1.2.3: the report no longer says a firewall rule is out of force because its profile is not the active one when that is not the reason. With local rule merging turned off, Windows gives the built-in Delivery Optimization rules (set for every profile) two reasons, and the second only means their other profiles; the report now gives only the real one, that the firewall policy ignores local rules. 1.2.3 also carries the 1.2.2 changes, which were released on GitHub but not on the PowerShell Gallery. 1.2.2: the firewall checks no longer call a rule missing when they could not read every rule. Without administrator rights Windows refuses part of the firewall listing: the report now lists the firewall rules as not collected and says that whether a rule admits TCP 7680 is not known, instead of reporting it absent (DO-NET-010), and the outbound Block rule checks say the same instead of passing. A rule limited to another program or service no longer counts as admitting Delivery Optimization, whatever its port, and the finding names it. On a Windows that is not in English, the built-in Delivery Optimization rule was found only through its port, with the status of the stored rule rather than the rule in force, so a rule that policy keeps out of force (a local rule while local rule merging is off) counted as in force: it is now found by its name, which is not translated, and every status comes from the rules in force. 1.2.1: the offline device report has a new layout, prints cleanly and saves as PDF from the browser (Save as PDF). The help says to start with New-DoctorDODeviceReport for one device and Invoke-DoctorDOCollector for a support bundle or fleet reporting, and spells out -Format Both as Html,Json. A device whose inbound reachability cannot be measured now says a peer has to try to connect to it. 1.2.0: an internet provider''s Connected Cache is no longer counted as local. The offline device report shows it as a source of its own, ISP Connected Cache, beside the Microsoft CDN: the Delivery Optimization service assigns it, and its bytes cross your internet link. Delivery efficiency now counts only what stayed on your network: LAN and Group peers and your own Connected Cache (one that DOCacheHost or DHCP option 235 names); Internet peers no longer count either. The month card says whose Connected Cache its single cache total came from. 1.1.1: the offline device report says which window each figure covers. The headline numbers, data flow, content types, requesting apps and content sources cover the downloads Delivery Optimization lists now, and the month card names that window beside its own. On a device in HTTP-only mode (0), where Delivery Optimization keeps no finished download, the report says the job list misses most of what the device downloads and points to the month totals; the Autopilot panel says the same of what provisioning downloaded. 1.1.0: the commands you run by hand say what they are doing. Run at a console, New-DoctorDODeviceReport, Invoke-DoctorDOCollector and Test-DOConnectivity show each part of the collection as it finishes, with a progress bar for the part under way, and end with the connectivity checks counted by area and each one that failed or warned. -InformationAction SilentlyContinue hides this; nothing changes under SYSTEM, in an Intune remediation or scheduled task, or when the output is redirected. Test-DOConnectivity prints that summary instead of one row per check, and -Detailed lists every check grouped by area. The results of New-DoctorDODeviceReport and Invoke-DoctorDOCollector show as a short list; the objects are unchanged, and Format-List * shows every property. -Verbose still adds each step with its timing. 1.0.0 was the first public release. DoctorDO.Collector diagnoses Windows Delivery Optimization on one device: it reads Delivery Optimization''s configuration, status, peers and log, checks the endpoints, proxy and Connected Cache it depends on, works out what is wrong, and writes an offline HTML report or a local support bundle. It changes no Delivery Optimization, firewall, proxy or service setting, and with -Fleet it sends signed inventory and telemetry to your own DoctorDO deployment. The module is not signed. It is free, under the PolyForm Shield License 1.0.0 (source-available, not open source); DoctorDO, the independent community project it belongs to, is in preview. Commands: New-DoctorDODeviceReport, an offline HTML, PDF or JSON report of this device. Invoke-DoctorDOCollector, a local support bundle, or fleet reporting with -Fleet; -WhatIfRedaction prints what is scrubbed. Test-DOConnectivity and Get-DOConnectivityMatrix, the endpoint, proxy, peer and Connected Cache checks, as a table or as objects. Get-DOInventory and Get-DOTelemetry, the inventory and the telemetry report, returned without being sent. Send-DoctorDOReport, sends one signed report to your ingest service. More: Get-Help about_DoctorDO.Collector.'
            # No Prerelease label: releases are normal versions (Windows PowerShell 5.1's in-box PowerShellGet cannot
            # install prereleases, and the label is not part of the install folder).
        }
    }
}
