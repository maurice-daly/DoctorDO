#Requires -Version 5.1
# The offline device report (ADR-0039, New-DoctorDODeviceReport): Data/device-report.html is the console's device page,
# compiled with the analysis engine by apps/web/scripts/build-device-report.mjs; this file puts one device's inventory and
# telemetry into it. Pure functions plus one mockable path, so the tests drive them with a fake device.

Set-StrictMode -Version Latest

$script:DDReportMarker = '"__DOCTORDO_REPORT_DATA__"'

function Get-DDReportTemplatePath {
    # Mockable seam.
    [CmdletBinding()]
    param()
    Join-Path -Path $script:ModuleRoot -ChildPath 'Data/device-report.html'
}

function Test-DDReportTemplate {
    <#
    .SYNOPSIS
        Why a template cannot be used, or $null when it can: the data placeholder must occur exactly once, and the page
        script must still match the hash its Content-Security-Policy names (a CRLF conversion would break it and the
        page would load blank).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Template)
    $first = $Template.IndexOf($script:DDReportMarker, [System.StringComparison]::Ordinal)
    if ($first -lt 0 -or $first -ne $Template.LastIndexOf($script:DDReportMarker, [System.StringComparison]::Ordinal)) { return 'the data placeholder is missing or appears more than once' }
    $hash = [regex]::Match($Template, "script-src 'sha256-([A-Za-z0-9+/=]+)'")
    $page = [regex]::Match($Template, '(?s)<script>(.*)</script>\s*</body>')
    if (-not $hash.Success -or -not $page.Success) { return 'the page script or its Content-Security-Policy hash is missing' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $actual = [Convert]::ToBase64String($sha.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($page.Groups[1].Value))) } finally { $sha.Dispose() }
    if ($actual -ne $hash.Groups[1].Value) { return 'the page script does not match its Content-Security-Policy hash (was the file converted to CRLF line endings?)' }
    $null
}

function Protect-DDReportInventory {
    <#
    .SYNOPSIS
        For an anonymised report, also drop what -Anonymise keeps in the inventory because the fleet needs it: the Entra
        device and tenant IDs, the Intune device ID, the ConfigMgr site code and the AD site. Each becomes a notCollected
        entry, so the page says why it is absent. Changes the inventory in place and returns it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Inventory)
    $removed = New-Object 'System.Collections.Generic.List[string]'
    $m = $Inventory['management']
    foreach ($k in 'entraDeviceId', 'tenantId') { if ($null -ne $m[$k]) { $m[$k] = $null; $removed.Add("management.$k") } }
    if ($null -ne $m['mdm'] -and $null -ne $m['mdm']['intuneDeviceId']) { $m['mdm']['intuneDeviceId'] = $null; $removed.Add('management.mdm.intuneDeviceId') }
    if ($null -ne $m['configMgr'] -and $null -ne $m['configMgr']['siteCode']) { $m['configMgr']['siteCode'] = $null; $removed.Add('management.configMgr.siteCode') }
    if ($null -ne $Inventory['network']['adSite']) { $Inventory['network']['adSite'] = $null; $removed.Add('network.adSite') }
    $nc = New-Object 'System.Collections.Generic.List[object]'
    foreach ($n in @($Inventory['notCollected'])) { $nc.Add($n) }
    foreach ($f in $removed) { $nc.Add([ordered]@{ field = $f; reason = 'skipped-by-flag'; detail = 'removed from an anonymised device report' }) }
    $Inventory['notCollected'] = @($nc | Select-Object -First 256)
    $Inventory
}

function ConvertTo-DDReportHtml {
    <#
    .SYNOPSIS
        The page with the report's data in place. The JSON is canonical (Json.ps1: the same text on Windows PowerShell
        5.1 and PowerShell 7) with every '<' written as its JSON escape (backslash, u003c), so nothing in it can end the
        data block early. String Replace is ordinal and literal: '$&' or '$1' in the data stay as they are.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Template, [Parameter(Mandatory)] $Data)
    $escapedLt = '\' + 'u003c'   # built in two parts so no tool or editor can collapse the escape back into '<'
    $json = (ConvertTo-DDCanonicalJson -InputObject $Data).Replace('<', $escapedLt)
    $Template.Replace($script:DDReportMarker, $json)
}

function Get-DDReportFileName {
    # DoctorDO-<host>-<yyyyMMdd-HHmmss>.html (UTC, like the bundle); no host name in an anonymised report's name. The JSON
    # and the PDF beside it have the same stem and the extensions 'json' and 'pdf'. -BaseName (New-DoctorDODeviceReport
    # -FileName, 19 Oct 2026, already checked by Test-DDReportBaseName) replaces the whole stem, so a scheduled run keeps one file.
    [CmdletBinding()]
    param([AllowNull()][string] $HostName, [Parameter(Mandatory)][datetime] $At, [switch] $Anonymised, [ValidateSet('html', 'json', 'pdf')][string] $Extension = 'html', [string] $BaseName)
    if ($BaseName) { return ('{0}.{1}' -f $BaseName, $Extension) }
    $stamp = $At.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
    $who = $(if ($Anonymised -or -not $HostName) { 'report' } else { $HostName -replace '[^A-Za-z0-9-]', '-' })
    'DoctorDO-{0}-{1}.{2}' -f $who, $stamp, $Extension
}

function Test-DDReportBaseName {
    <#
    .SYNOPSIS
        Why a -FileName for the device report cannot be used, or $null when it can (19 Oct 2026). A name, not a path: the
        folder is -OutputPath. The checks are Windows' own rules, written out rather than taken from
        [System.IO.Path]::GetInvalidFileNameChars(), which lists only '/' and NUL on Linux, so the result is the same everywhere.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string] $Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return 'it is empty' }
    if ($Name -match '[\\/]') { return 'it contains a path separator; put the folder in -OutputPath and only the name in -FileName' }
    if ($Name -match '[:*?"<>|\x00-\x1F]') { return 'it contains a character Windows does not allow in a file name (: * ? " < > | or a control character)' }
    if ($Name -ne $Name.Trim() -or $Name.EndsWith('.')) { return 'it starts or ends with a space, or ends with a full stop' }
    if ($Name.Length -gt 200) { return 'it is longer than 200 characters' }
    if ($Name -match '\.(html?|json|pdf)$') { return 'it ends with a file extension; give the name without one, each format adds its own (.html, .json, .pdf)' }
    # Windows reserves these device names whatever follows the first full stop (CON.html is the console, not a file).
    $stem = $Name.Split('.')[0].TrimEnd(' ')
    if ($stem -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9]|CONIN\$|CONOUT\$)$') { return ('{0} is a name Windows reserves for a device' -f $stem) }
    $null
}

function Get-DDReportPrintUrl {
    <#
    .SYNOPSIS
        The file URL a headless browser prints the report from, with the fragment #print: the page then draws itself for
        paper from its first frame (every section open, every table row, light colours, no controls; device-report/print.ts)
        rather than relying on the browser's print events, which a headless print does not wait for.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Path)
    (New-Object System.Uri([System.IO.Path]::GetFullPath($Path))).AbsoluteUri + '#print'
}

function Test-DDPdfFile {
    # True when the file is there and starts as a PDF does ('%PDF-'): a browser that fails can leave nothing, or an empty file.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $head = New-Object byte[] 5
    $fs = [System.IO.File]::OpenRead($Path)
    try { $n = $fs.Read($head, 0, 5) } finally { $fs.Dispose() }
    $n -eq 5 -and [System.Text.Encoding]::ASCII.GetString($head) -eq '%PDF-'
}

function ConvertTo-DDPrettyJson {
    <#
    .SYNOPSIS
        Indents compact JSON (two spaces, "key": value, one member or element per line; an empty object or array stays
        as {} or []). It only moves whitespace: strings, numbers and key order are untouched, so the result parses to
        what the input did. Walks the text once and tracks whether it is inside a string, so a brace or comma in a value
        is data.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Json)
    $sb = New-Object System.Text.StringBuilder
    $depth = 0
    $inString = $false
    $n = $Json.Length
    for ($i = 0; $i -lt $n; $i++) {
        $c = $Json[$i]
        if ($inString) {
            [void]$sb.Append($c)
            if ($c -eq '\') { $i++; if ($i -lt $n) { [void]$sb.Append($Json[$i]) } }
            elseif ($c -eq '"') { $inString = $false }
            continue
        }
        if ($c -eq '"') { $inString = $true; [void]$sb.Append($c) }
        elseif ($c -eq '{' -or $c -eq '[') {
            $close = $(if ($c -eq '{') { '}' } else { ']' })
            if ($i + 1 -lt $n -and $Json[$i + 1] -eq $close) { [void]$sb.Append($c).Append($close); $i++ }
            else { $depth++; [void]$sb.Append($c).Append("`n").Append(' ' * (2 * $depth)) }
        }
        elseif ($c -eq '}' -or $c -eq ']') { $depth--; [void]$sb.Append("`n").Append(' ' * (2 * $depth)).Append($c) }
        elseif ($c -eq ',') { [void]$sb.Append(",`n").Append(' ' * (2 * $depth)) }
        elseif ($c -eq ':') { [void]$sb.Append(': ') }
        else { [void]$sb.Append($c) }
    }
    $sb.ToString()
}

function ConvertTo-DDReportJson {
    <#
    .SYNOPSIS
        The report's data as the JSON file written by New-DoctorDODeviceReport -Format Json: the same data the page embeds
        (ConvertTo-DDReportHtml), indented, with two properties first: schema ('doctordo-device-report/1', the payload's
        kind and version) and collectorVersion. Below those two the keys are in the canonical order (UTF-16 ordinal), a
        newline ends the text, and '<' is written as itself (it is a file, not an HTML data block).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Data, [Parameter(Mandatory)][string] $CollectorVersion)
    $pretty = ConvertTo-DDPrettyJson -Json (ConvertTo-DDCanonicalJson -InputObject $Data)
    $schema = ConvertTo-DDJsonString -Value ('{0}/{1}' -f $Data['kind'], $Data['version'])
    $head = "{`n  `"schema`": $schema,`n  `"collectorVersion`": $(ConvertTo-DDJsonString -Value $CollectorVersion),`n  "
    $head + $pretty.Substring(4) + "`n"
}

function Write-DDReportFile {
    <#
    .SYNOPSIS
        Writes text as UTF-8 without a byte order mark, through a .tmp file beside the target, and replaces an existing
        file of that name (the report is a snapshot; the newest one wins). Nothing is left behind but the target.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][AllowEmptyString()][string] $Text)
    $tmp = $Path + '.tmp'
    [System.IO.File]::WriteAllText($tmp, $Text, (New-Object System.Text.UTF8Encoding($false)))
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    Move-Item -LiteralPath $tmp -Destination $Path
}
