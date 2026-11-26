#Requires -Version 5.1
<#
.SYNOPSIS
    Packaging step for a collector release: writes collector-manifest.json (the module's SHA-256 list) and stamps the
    same facts into the Intune remediation script.
.DESCRIPTION
    The remediation script (collector/intune/Remediate-DoctorDO.ps1) installs DoctorDO.Collector from a PowerShell
    repository and accepts a copy only when it matches a known list of files and SHA-256 values. This script makes both
    sources of that list from the built module folder, so they cannot disagree:

      * collector-manifest.json, written to -OutputPath (default collector/dist): schema, module name, version, GUID,
        author, the exported functions and every file of the module with its SHA-256. Attach it to the GitHub release
        with the tag collector-v<version>; the remediation's LatestVerified policy downloads it from there.
      * the GENERATED PINNED RELEASE block of the remediation script (-Stamp): the same facts for this version, which the
        Pinned policy trusts without any download.

    Run it on the folder that will be published (for example the release copy, made outside the repository before
    publishing): the SHA-256 values are those of its bytes. -Check changes nothing; it exits 1 when the
    committed remediation script does not describe the module in -ModulePath (a test runs it on every build).

    The module's FileList (in its manifest) must equal the files in the folder; it is checked here too.
.PARAMETER ModulePath
    The module folder (the one that holds DoctorDO.Collector.psd1). Default: collector/DoctorDO.Collector.
.PARAMETER RemediationScript
    The remediation script to stamp or check. Default: collector/intune/Remediate-DoctorDO.ps1.
.PARAMETER OutputPath
    Where collector-manifest.json is written. Default: collector/dist (not committed).
.PARAMETER Stamp
    Rewrite the GENERATED PINNED RELEASE block of the remediation script from the module.
.PARAMETER Check
    Write nothing; exit 1 when the remediation script's block (or the module's FileList) does not match the module.
.EXAMPLE
    pwsh -NoProfile -File collector/tools/package-collector.ps1 -Stamp

    Stamps the remediation script and writes collector/dist/collector-manifest.json.
.EXAMPLE
    pwsh -NoProfile -File collector/tools/package-collector.ps1 -Check

    Exits 1 if the committed remediation script is out of date for the module.
#>
[CmdletBinding()]
param(
    # Defaults are filled in below: Windows PowerShell 5.1 leaves $PSScriptRoot empty in a script's param block under -File.
    [string] $ModulePath,
    [string] $RemediationScript,
    [string] $OutputPath,
    [switch] $Stamp,
    [switch] $Check
)

Set-StrictMode -Version Latest

$script:BeginMarker = '# BEGIN GENERATED PINNED RELEASE (collector/tools/package-collector.ps1 -Stamp; do not edit by hand)'
$script:EndMarker = '# END GENERATED PINNED RELEASE'

function Get-CollectorFileHashes {
    # Every file under the module folder: relative path with '/', SHA-256 in lower-case hex, ordered by ordinal path.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ModulePath)
    # The root as Get-ChildItem spells the files under it. Resolve-Path keeps an 8.3 short name (C:\Users\MAURIC~1, as
    # $env:TEMP often is) that Get-Item and Get-ChildItem expand, and cutting at its length mangled every path.
    $root = (Get-Item -LiteralPath $ModulePath -Force).FullName.TrimEnd('\', '/')
    $byPath = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($f in (Get-ChildItem -LiteralPath $root -Recurse -File -Force)) {
            if (-not $f.FullName.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { throw "$($f.FullName) is not spelled as under $root, so its path in the module cannot be worked out." }
            $rel = $f.FullName.Substring($root.Length).TrimStart('\', '/').Replace('\', '/')
            $hex = (($sha.ComputeHash([System.IO.File]::ReadAllBytes($f.FullName)) | ForEach-Object { $_.ToString('x2') }) -join '')
            $byPath.Add($rel, [pscustomobject]@{ path = $rel; sha256 = $hex })
        }
    } finally { $sha.Dispose() }
    # Sort the keys alone: given a second (items) array, PowerShell passes [Array]::Sort a converted copy of it, which
    # left the rows in the file system's listing order (and that order differs between machines).
    $keys = [string[]]@($byPath.Keys)
    [Array]::Sort($keys, [System.StringComparer]::Ordinal)
    foreach ($k in $keys) { $byPath[$k] }
}

function Get-CollectorFacts {
    # What the remediation needs to know about a module folder, from its manifest and its files.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ModulePath)
    $psd1 = Join-Path -Path $ModulePath -ChildPath 'DoctorDO.Collector.psd1'
    $data = Import-PowerShellDataFile -LiteralPath $psd1
    $files = @(Get-CollectorFileHashes -ModulePath $ModulePath)
    $listed = @($data['FileList'] | ForEach-Object { ([string]$_).Replace('\', '/') })
    $onDisk = @($files | ForEach-Object { $_.path })
    $problems = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $onDisk) { if ($listed -cnotcontains $p) { $problems.Add("FileList lacks $p") } }
    foreach ($p in $listed) { if ($onDisk -cnotcontains $p) { $problems.Add("FileList names $p, which is not in the folder") } }
    $functions = [string[]]@($data['FunctionsToExport'])
    [Array]::Sort($functions, [System.StringComparer]::Ordinal)
    [pscustomobject]@{
        Name = 'DoctorDO.Collector'; Version = [string]$data['ModuleVersion']; Guid = [string]$data['GUID']; Author = [string]$data['Author']
        Functions = $functions; Files = $files; FileListProblems = @($problems)
    }
}

function ConvertTo-CollectorManifestJson {
    # The text of collector-manifest.json: two-space indentation, LF, a final newline, no escapes beyond JSON's own.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Facts)
    $q = { param($s) '"' + ([string]$s).Replace('\', '\\').Replace('"', '\"') + '"' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("{`n")
    [void]$sb.Append('  "schema": "doctordo-collector-manifest/1",' + "`n")
    [void]$sb.Append('  "module": ' + (& $q $Facts.Name) + ",`n")
    [void]$sb.Append('  "version": ' + (& $q $Facts.Version) + ",`n")
    [void]$sb.Append('  "guid": ' + (& $q $Facts.Guid) + ",`n")
    [void]$sb.Append('  "author": ' + (& $q $Facts.Author) + ",`n")
    [void]$sb.Append('  "exports": [' + ((@($Facts.Functions) | ForEach-Object { & $q $_ }) -join ', ') + "],`n")
    [void]$sb.Append("  `"files`": [`n")
    $rows = @($Facts.Files | ForEach-Object { '    { "path": ' + (& $q $_.path) + ', "sha256": ' + (& $q $_.sha256) + ' }' })
    [void]$sb.Append(($rows -join ",`n") + "`n  ]`n}`n")
    $sb.ToString()
}

function Get-PinnedBlock {
    # The block between the markers in the remediation script, for these facts. Single-quoted strings only.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Facts)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add($script:BeginMarker)
    $lines.Add("`$DoctorDOExpectedGuid = '$($Facts.Guid)'")
    $lines.Add("`$DoctorDOExpectedAuthor = '$($Facts.Author)'")
    $lines.Add('$DoctorDOExpectedFunctions = @(' + ((@($Facts.Functions) | ForEach-Object { "'$_'" }) -join ', ') + ')')
    $lines.Add("`$DoctorDOPinnedVersion = '$($Facts.Version)'")
    $lines.Add('$DoctorDOPinnedFiles = [ordered]@{')
    foreach ($f in $Facts.Files) { $lines.Add("    '$($f.path)' = '$($f.sha256)'") }
    $lines.Add('}')
    $lines.Add($script:EndMarker)
    $lines -join "`n"
}

function Get-RemediationBlock {
    # [pscustomobject]@{ Text; Start; Length } of the generated block in the script text, or $null.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ScriptText)
    $b = $ScriptText.IndexOf($script:BeginMarker, [System.StringComparison]::Ordinal)
    $e = $ScriptText.IndexOf($script:EndMarker, [System.StringComparison]::Ordinal)
    if ($b -lt 0 -or $e -lt $b) { return $null }
    $len = $e + $script:EndMarker.Length - $b
    [pscustomobject]@{ Text = $ScriptText.Substring($b, $len).Replace("`r`n", "`n"); Start = $b; Length = $len }
}

function Test-RemediationStamp {
    # $null when the script's block is what these facts produce, else why not.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ScriptPath, [Parameter(Mandatory)] $Facts)
    $text = [System.IO.File]::ReadAllText($ScriptPath)
    $block = Get-RemediationBlock -ScriptText $text
    if ($null -eq $block) { return "$ScriptPath has no GENERATED PINNED RELEASE block." }
    $expected = Get-PinnedBlock -Facts $Facts
    if ($block.Text -ceq $expected) { return $null }
    # Name what differs (a file's hash, the version, the exports), so a failure on another machine says which bytes moved.
    $have = @($block.Text -split "`r?`n")
    $want = @($expected -split "`n")
    $diff = New-Object 'System.Collections.Generic.List[string]'
    foreach ($l in $want) { if ($have -cnotcontains $l) { $diff.Add("module now: $($l.Trim())") } }
    foreach ($l in $have) { if ($want -cnotcontains $l) { $diff.Add("script pins: $($l.Trim())") } }
    $shown = @($diff | Select-Object -First 8) -join '; '
    "$(Split-Path -Path $ScriptPath -Leaf) pins a different release than the module folder (version $($Facts.Version)): run collector/tools/package-collector.ps1 -Stamp and commit the result. Differences: $shown"
}

function Set-RemediationStamp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ScriptPath, [Parameter(Mandatory)] $Facts)
    $text = [System.IO.File]::ReadAllText($ScriptPath)
    $block = Get-RemediationBlock -ScriptText $text
    if ($null -eq $block) { throw "$ScriptPath has no GENERATED PINNED RELEASE block to replace." }
    $eol = $(if ($text.Contains("`r`n")) { "`r`n" } else { "`n" })
    $new = $text.Substring(0, $block.Start) + (Get-PinnedBlock -Facts $Facts).Replace("`n", $eol) + $text.Substring($block.Start + $block.Length)
    [System.IO.File]::WriteAllText($ScriptPath, $new, (New-Object System.Text.UTF8Encoding($false)))
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $ModulePath) { $ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '../DoctorDO.Collector' }
    if (-not $RemediationScript) { $RemediationScript = Join-Path -Path $PSScriptRoot -ChildPath '../intune/Remediate-DoctorDO.ps1' }
    if (-not $OutputPath) { $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath '../dist' }
    $facts = Get-CollectorFacts -ModulePath $ModulePath
    if ($facts.FileListProblems.Count -gt 0) {
        Write-Error ("The module's FileList does not match its folder: " + ($facts.FileListProblems -join '; '))
        exit 1
    }
    if ($Check) {
        $why = Test-RemediationStamp -ScriptPath $RemediationScript -Facts $facts
        if ($why) { Write-Error $why; exit 1 }
        Write-Output "Remediate-DoctorDO.ps1 pins DoctorDO.Collector $($facts.Version) ($($facts.Files.Count) files): up to date."
        exit 0
    }
    if ($Stamp) { Set-RemediationStamp -ScriptPath $RemediationScript -Facts $facts }
    if (-not (Test-Path -LiteralPath $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath -Force) }
    $manifestPath = Join-Path -Path $OutputPath -ChildPath 'collector-manifest.json'
    [System.IO.File]::WriteAllText($manifestPath, (ConvertTo-CollectorManifestJson -Facts $facts), (New-Object System.Text.UTF8Encoding($false)))
    Write-Output "Wrote $manifestPath (DoctorDO.Collector $($facts.Version), $($facts.Files.Count) files)$(if ($Stamp) { '; stamped ' + (Split-Path -Path $RemediationScript -Leaf) })."
}
