function New-DoctorDODeviceReport {
    <#
    .SYNOPSIS
        Writes an offline HTML report of this device's Delivery Optimization health (optionally PDF and JSON).
    .DESCRIPTION
        Start here for one device: no DoctorDO deployment is needed, and everything is worked out on the device.
        New-DoctorDODeviceReport collects once and writes one .html file with the data embedded: the DoctorDO
        console's device page for this device (Delivery Optimization health, network health and its topology, data
        flow, download sources and configuration), with the same analysis the console runs. The file is named
        DoctorDO-<host name>-<yyyyMMdd-HHmmss>.html (UTC), or DoctorDO-report-<yyyyMMdd-HHmmss>.html with -Anonymise;
        -FileName gives it a fixed name instead, which each run replaces. Open it in Microsoft Edge or Google Chrome.

        When it has finished, the command opens the report in the default browser, but only when a person is at the
        session: not when it runs as SYSTEM or a service account, in session 0, in a remote session, in a PowerShell
        started with -NonInteractive, or from an Intune remediation or platform script, a scheduled task or
        Configuration Manager. -NoOpen leaves it closed; -Open opens it even where it would not be opened by itself.

        At a console it also says what it is doing: one line per part of the collection as it finishes, with a
        progress bar for the part under way, then the connectivity checks counted by area and each one that failed or
        warned. -InformationAction SilentlyContinue hides that; it is never written where nobody is at the session (as
        above) or when the output is redirected. -Verbose adds each step with its timing.

        With -Format Pdf the page is also printed to a PDF with the same name and the extension pdf, by Microsoft Edge
        (or Google Chrome when Edge is not installed) running headless on this device: every section expanded, every
        table row drawn, light colours, no buttons, and no header or footer. Nothing is downloaded or installed for it.

        With -Format Json (or Both, which is Html,Json) the report's data is also written as a JSON file with the same name and the
        extension json (UTF-8 without a byte order mark, indented), for a script, a ticket or a spreadsheet import.
        It is exactly the data the HTML embeds, so the two cannot disagree, with two properties added at the top:
        schema ('doctordo-device-report/1') and collectorVersion. Everything else is the HTML's payload: kind, version,
        generatedAt, inventory (InventoryV1) and telemetry (an array of one TelemetryV1 report). -Anonymise applies to
        the JSON and the PDF exactly as it does to the HTML, and the file names have no host name either.

        The command is read-only: the collector's state file is not read or written, the Delivery Optimization log
        is not flushed (so DoSvc is not stopped), and nothing is uploaded. The page makes no network requests: its
        Content-Security-Policy allows none, so it can be opened offline or attached to a ticket.

        The report identifies the device (host name, Microsoft Entra, tenant and Intune device IDs, AD site, subnet,
        gateway) unless you add -Anonymise. PAC URLs are never in it, and no user name is read. Where an account
        turns up in a log line, an error sample or a firewall rule (a profile path, DOMAIN\user, a SID), the forms the
        scrub recognises are replaced; an unusual form can get through (Get-Help about_DoctorDO.Collector, PRIVACY).
    .PARAMETER OutputPath
        The folder the report is written to. It is created if it does not exist. Default: the temp folder of the
        account running the command. An existing report with the same name is replaced.
    .PARAMETER Format
        What to write, one value or several separated by commas: Html (the default), Pdf, Json, or Both. Both is
        Html and Json, kept for compatibility; prefer Html,Json. Each file is written in -OutputPath with the same name and its own extension, and replaces an existing
        file with that name. Pdf prints the page with Microsoft Edge, or Google Chrome when Edge is missing, and throws
        before collecting anything when neither is installed; -Format Pdf on its own keeps only the PDF. Html,Pdf
        writes both. With Json alone the page (Data\device-report.html) is not needed or read.
    .PARAMETER FileName
        The name of the report without a folder or an extension, in place of DoctorDO-<host name>-<yyyyMMdd-HHmmss>.
        Every format written uses it with its own extension (.html, .json, .pdf), and each run replaces the files of
        that name in -OutputPath, so a run that repeats, such as an Intune remediation or a scheduled task, keeps one
        report instead of adding one each time. The name is used exactly as given, also with -Anonymise, so leave the
        host name out of a report you will share. It must not contain a path separator, a character Windows does not
        allow in a file name (: * ? " < > |) or an extension (.html, .htm, .json, .pdf), must not start or end with a
        space or end with a full stop, must not be a name Windows reserves for a device (CON, PRN, AUX, NUL, COM0 to
        COM9, LPT0 to LPT9), and can be up to 200 characters. The command throws before collecting anything otherwise.
    .PARAMETER Anonymise
        A report to share: the local bundle's anonymisation and, in addition, no Entra, tenant or Intune device ID,
        ConfigMgr site code or AD site, and no host name in the file name. Hashes use a salt made for this report
        only, so nothing in it can be matched to your fleet data.
    .PARAMETER SkipConnectivityChecks
        Do not probe endpoints or download PAC files; the page shows those checks as not collected.
    .PARAMETER Open
        Open the report even where the command would not open it by itself, for example in a session it cannot tell
        is interactive. With -Format Json alone, the JSON file is opened with the program associated with JSON
        files (it is never opened unasked). Cannot be used with -NoOpen.
    .PARAMETER NoOpen
        Do not open the report when it has been written. Without it, the report opens in the default browser when a
        person is at the session (see the description): the PDF when one was written, otherwise the HTML page.
        Cannot be used with -Open.
    .EXAMPLE
        New-DoctorDODeviceReport

        Writes the report to the temp folder and opens it in the default browser. Run it from an elevated prompt:
        without elevation the Delivery Optimization logs and some settings cannot be read, and the report lists them
        as missing.
    .EXAMPLE
        New-DoctorDODeviceReport -OutputPath C:\Temp -Anonymise -Format Html,Pdf

        Writes a report you can share outside your organisation, for example in a forum post or with a consultant,
        as a page and as a PDF, and opens the PDF: no host name, no Entra, tenant or Intune IDs, and hashes that
        cannot be linked to your fleet.
    .EXAMPLE
        $r = New-DoctorDODeviceReport -OutputPath "$env:PUBLIC\Documents\DoctorDO" -SkipConnectivityChecks -NoOpen
        Write-Output ('{0} ({1:N0} KB, {2} facts not collected)' -f $r.Path, ($r.Bytes / 1KB), $r.NotCollected)

        Writes a report without network probes, for example from an Intune platform script run as SYSTEM on a device
        in a change-frozen network, to a folder the signed-in user can open, and prints where it went. As SYSTEM the
        report would not be opened anyway; -NoOpen says so plainly.
    .EXAMPLE
        New-DoctorDODeviceReport -OutputPath C:\Temp -Format Both

        Writes DoctorDO-<host>-<timestamp>.html and DoctorDO-<host>-<timestamp>.json to C:\Temp, from one collection,
        and opens the page.
    .EXAMPLE
        $r = New-DoctorDODeviceReport -Format Json -Anonymise -OutputPath C:\Temp
        (Get-Content -LiteralPath $r.JsonPath -Raw | ConvertFrom-Json).inventory.dataOrchestration

        Writes only the anonymised data, no page, and reads one section of it back. Nothing is opened.
    .EXAMPLE
        New-DoctorDODeviceReport -OutputPath "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs" -FileName 'DoctorDO-DeviceReport' -Format Html,Json

        From an Intune remediation run as SYSTEM: writes DoctorDO-DeviceReport.html and DoctorDO-DeviceReport.json
        into the Intune Management Extension's log folder, which Intune's "Collect diagnostics" gathers, and replaces
        the files the previous run wrote there, so the folder keeps one report however often the remediation runs.
    .INPUTS
        None. You cannot pipe objects to New-DoctorDODeviceReport.
    .OUTPUTS
        System.Management.Automation.PSCustomObject with Path (the HTML file; the PDF with -Format Pdf alone; the JSON
        file with -Format Json alone), Sha256, Bytes (of Path), Format, JsonPath, JsonSha256 and JsonBytes, PdfPath,
        PdfSha256 and PdfBytes (null unless that file was written), Opened (the file opened, or null), DeviceId,
        HostName, Anonymised, CollectedAt, NotCollected (the number of facts that could not be read) and DurationMs.
    .NOTES
        Runs on Windows only; it throws on other platforms. Elevation is recommended (it warns without it). It throws
        when the report page (Data\device-report.html) is missing or damaged: reinstall the module. A PDF needs
        Microsoft Edge or Google Chrome; it throws, naming both, when neither is installed, and when the browser writes
        no PDF within two minutes.

        Writes one file per format and changes nothing else. For a PDF alone the page is written beside it for the
        browser to print and removed again. The page bundles React, lucide-react, Tailwind CSS and the Poppins
        and Geist Mono fonts, under their own licences (THIRD-PARTY-NOTICES.txt in the module folder).
    .LINK
        https://www.doctor-do.com/get-started/
    .LINK
        about_DoctorDO.Collector
    .LINK
        Invoke-DoctorDOCollector
    .LINK
        Test-DOConnectivity
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string] $OutputPath = [System.IO.Path]::GetTempPath(),
        [ValidateSet('Html', 'Json', 'Pdf', 'Both')][string[]] $Format = 'Html',
        # A fixed name instead of the timestamped one (19 Oct 2026), so a scheduled run replaces its report rather than adding one.
        [ValidateNotNullOrEmpty()][string] $FileName,
        [switch] $Anonymise,
        [switch] $SkipConnectivityChecks,
        [switch] $Open,
        [switch] $NoOpen
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    # The caller's -InformationAction SilentlyContinue: no narration and no "written" lines (they are information too).
    $quiet = Test-DDInformationQuiet -BoundParameters $PSBoundParameters
    $DDRun = Start-DDVerboseRun -Command 'New-DoctorDODeviceReport' -Title 'device report' -Sections ($script:DDCollectionSections + 1) -Quiet:$quiet
    if (-not (Test-DDWindows)) { throw 'New-DoctorDODeviceReport reads Delivery Optimization from this device, so it runs on Windows only.' }
    if ($Open -and $NoOpen) { throw 'Use -Open or -NoOpen, not both.' }
    # Checked before anything is collected, like the PDF printer below: a bad name should cost nothing.
    if ($PSBoundParameters.ContainsKey('FileName')) {
        $badName = Test-DDReportBaseName -Name $FileName
        if ($badName) { throw "-FileName '$FileName' cannot be used: $badName." }
    }
    # Both is Html and Json (it predates Pdf); any mix can be named, as -Format Html,Pdf.
    $formats = @($Format | ForEach-Object { if ($_ -eq 'Both') { 'Html'; 'Json' } else { $_ } })
    $writeHtml = $formats -contains 'Html'
    $writeJson = $formats -contains 'Json'
    $writePdf = $formats -contains 'Pdf'
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $template = $null
    if ($writeHtml -or $writePdf) {
        $templatePath = Get-DDReportTemplatePath
        if (-not (Test-Path -LiteralPath $templatePath -PathType Leaf)) {
            throw "The device report page (Data/device-report.html) is missing from the module at $templatePath, so the installed copy is incomplete or damaged. Reinstall the module."
        }
        $template = [System.IO.File]::ReadAllText($templatePath, $utf8)
        $unusable = Test-DDReportTemplate -Template $template
        if ($unusable) { throw "The device report page at $templatePath cannot be used: $unusable. Reinstall the module." }
        Write-DDVerboseStep -Step 'Report page' -Result { '{0:N0} KB, intact' -f ($template.Length / 1KB) }
    }
    $browser = $null
    if ($writePdf) {
        # Before collecting: a missing browser should cost seconds, not a full collection.
        $browser = Find-DDPdfBrowser
        if ($null -eq $browser) {
            throw 'A PDF is printed by Microsoft Edge or Google Chrome, and neither is installed on this device. Install Microsoft Edge, or write the page (-Format Html) and print it to PDF from a browser on another device.'
        }
        Write-DDVerboseStep -Step 'PDF printer' -Result { '{0}, headless' -f $browser.Name }
    }
    if (-not (Test-DDElevated)) {
        Write-Warning 'Not running elevated: Delivery Optimization logs and some settings cannot be read. The report lists what is missing; run from an elevated prompt for the full picture.'
    }

    # A salt for this report only (never the state file's, which reading could move aside) and no endpoint cache.
    $salt = New-DDRandomHex -Bytes 32
    $collection = Get-DDRawCollection -Salt $salt -Anonymise:$Anonymise -SkipConnectivityChecks:$SkipConnectivityChecks -Mode single -IsolateSalt
    $gaps = Get-DDRequiredFieldGaps -Collection $collection
    if ($gaps.Count -gt 0) { throw "Required facts could not be read ($($gaps -join ', ')), so there is no report to write." }

    $inventory = ConvertTo-DDInventory -Collection $collection
    if ($Anonymise) { $inventory = Protect-DDReportInventory -Inventory $inventory }
    # One collection is one point in time: the period starts and ends at it, and nothing is a delta (New-DDState).
    $state = New-DDState
    $state['lastTelemetryAt'] = $collection.Raw['collectedAt']
    $telemetry = New-DDTelemetryFromCollection -Collection $collection -State $state -InventoryHash (Get-DDInventoryHash -Inventory $inventory) -Now $collection.Now
    $data = [ordered]@{ kind = 'doctordo-device-report'; version = 1; generatedAt = $collection.Raw['collectedAt']; inventory = $inventory; telemetry = @($telemetry) }
    Write-DDVerboseStep -Step 'Report data' -Result { '{0}; {1} fact(s) not collected' -f $(if ($Anonymise) { 'anonymised' } else { 'identifies the device' }), @($inventory['notCollected']).Count }

    Start-DDSection -Name 'Report'
    if (-not (Test-Path -LiteralPath $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath -Force) }
    $hostName = $inventory['device']['hostname']
    $htmlPath = $null
    $jsonPath = $null
    $pdfPath = $null
    $page = $(if ($writeHtml -or $writePdf) { ConvertTo-DDReportHtml -Template $template -Data $data } else { $null })
    if ($writeHtml) {
        $htmlPath = Join-Path -Path $OutputPath -ChildPath (Get-DDReportFileName -HostName $hostName -At $collection.Now -Anonymised:$Anonymise -BaseName $FileName)
        Write-DDReportFile -Path $htmlPath -Text $page
    }
    if ($writeJson) {
        $jsonPath = Join-Path -Path $OutputPath -ChildPath (Get-DDReportFileName -HostName $hostName -At $collection.Now -Anonymised:$Anonymise -Extension 'json' -BaseName $FileName)
        Write-DDReportFile -Path $jsonPath -Text (ConvertTo-DDReportJson -Data $data -CollectorVersion (Get-DDCollectorVersion))
        Write-DDVerboseStep -Step 'Report JSON' -Result { 'schema doctordo-device-report/1, collector {0}' -f (Get-DDCollectorVersion) }
    }
    if ($writePdf) {
        $pdfPath = Join-Path -Path $OutputPath -ChildPath (Get-DDReportFileName -HostName $hostName -At $collection.Now -Anonymised:$Anonymise -Extension 'pdf' -BaseName $FileName)
        # The browser prints a file, so a PDF alone still needs the page on disk for a moment: a name of its own, so an
        # HTML report already in the folder is never touched, removed again whatever happens.
        $source = $htmlPath
        $scratch = $null
        if (-not $writeHtml) {
            $scratch = Join-Path -Path $OutputPath -ChildPath ('DoctorDO-print-{0}.html' -f [guid]::NewGuid().ToString('N'))
            Write-DDReportFile -Path $scratch -Text $page
            $source = $scratch
        }
        try {
            if (Test-Path -LiteralPath $pdfPath) { Remove-Item -LiteralPath $pdfPath -Force }
            Invoke-DDHeadlessPrint -Browser $browser.Path -Url (Get-DDReportPrintUrl -Path $source) -PdfPath $pdfPath
        } finally {
            if ($scratch) { Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue }
        }
        if (-not (Test-DDPdfFile -Path $pdfPath)) {
            throw "$($browser.Name) did not write the PDF ($pdfPath). Write the page (-Format Html), open it and print it to PDF from the browser instead."
        }
        Write-DDVerboseStep -Step 'Report PDF' -Result { 'printed by {0}, {1:N0} KB' -f $browser.Name, ((Get-Item -LiteralPath $pdfPath).Length / 1KB) }
    }
    $path = $(if ($writeHtml) { $htmlPath } elseif ($writePdf) { $pdfPath } else { $jsonPath })
    Complete-DDSection -Result {
        $written = foreach ($f in @(@('HTML', $htmlPath), @('PDF', $pdfPath), @('JSON', $jsonPath))) { if ($f[1]) { '{0} {1:N0} KB' -f $f[0], ((Get-Item -LiteralPath $f[1]).Length / 1KB) } }
        @($written) -join ', '
    }

    # What to open: the PDF when there is one (it is what was asked for, and what will be sent on), else the page. Only
    # -Open opens a JSON file: an editor appearing unasked would be a surprise.
    $view = $(if ($writePdf) { $pdfPath } elseif ($writeHtml) { $htmlPath } else { $null })
    $opened = $null
    if ($Open) { $opened = $(if ($view) { $view } else { $jsonPath }) }
    elseif ($NoOpen) { Write-DDVerboseStep -Step 'Open' -Result 'not opened (-NoOpen)' }
    elseif ($null -eq $view) { Write-DDVerboseStep -Step 'Open' -Result 'not opened (JSON only; -Open opens it)' }
    else {
        $why = Get-DDNonInteractiveReason
        if ($why) { Write-DDVerboseStep -Step 'Open' -Result "not opened: $why" } else { $opened = $view }
    }
    if ($opened) { Write-DDVerboseStep -Step 'Open' -Result { 'opening {0}' -f (Split-Path -Path $opened -Leaf) } }

    $result = [pscustomobject]@{
        PSTypeName   = 'DoctorDO.DeviceReport'
        Path         = $path
        Sha256       = Get-DDFileSha256 -Path $path
        Bytes        = (Get-Item -LiteralPath $path).Length
        Format       = $Format -join ','
        JsonPath     = $jsonPath
        JsonSha256   = $(if ($writeJson) { Get-DDFileSha256 -Path $jsonPath } else { $null })
        JsonBytes    = $(if ($writeJson) { (Get-Item -LiteralPath $jsonPath).Length } else { $null })
        PdfPath      = $pdfPath
        PdfSha256    = $(if ($writePdf) { Get-DDFileSha256 -Path $pdfPath } else { $null })
        PdfBytes     = $(if ($writePdf) { (Get-Item -LiteralPath $pdfPath).Length } else { $null })
        Opened       = $opened
        DeviceId     = $inventory['device']['deviceId']
        HostName     = $hostName
        Anonymised   = [bool]$Anonymise
        CollectedAt  = $collection.Raw['collectedAt']
        NotCollected = @($inventory['notCollected']).Count
        DurationMs   = $sw.ElapsedMilliseconds
    }
    Write-DDRunSummary -Run $DDRun -Rows $collection.Raw['connectivity'] -NotCollected $result.NotCollected -More 'the report explains each'
    Stop-DDVerboseRun -Run $DDRun -Command 'New-DoctorDODeviceReport' -Summary ('report written, {0:N0} KB' -f ($result.Bytes / 1KB))
    if ($writeHtml -and -not $quiet) { Write-Information -MessageData ('Device report written: {0} ({1:N0} KB)' -f $htmlPath, ((Get-Item -LiteralPath $htmlPath).Length / 1KB)) -InformationAction Continue }
    if ($writePdf -and -not $quiet) { Write-Information -MessageData ('Device report PDF written: {0} ({1:N0} KB)' -f $pdfPath, ($result.PdfBytes / 1KB)) -InformationAction Continue }
    if ($writeJson -and -not $quiet) { Write-Information -MessageData ('Device report data (JSON) written: {0} ({1:N0} KB)' -f $jsonPath, ($result.JsonBytes / 1KB)) -InformationAction Continue }
    if ($opened) { Invoke-Item -LiteralPath $opened }
    $result
}
