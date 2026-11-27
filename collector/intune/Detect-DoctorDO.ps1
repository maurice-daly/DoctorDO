#Requires -Version 5.1
# Copyright (c) 2026 Maurice Daly. SPDX-License-Identifier: MIT (see LICENSE in this folder).
# The DoctorDO.Collector module is not MIT: it has its own licence (LICENSE in the module folder).

<#
.SYNOPSIS
    Intune remediation DETECTION script for DoctorDO. Performs NO collection and installs nothing.
.DESCRIPTION
    Exits 1 (non-compliant, which triggers the remediation script) when
      * the DoctorDO.Collector module is not installed for all users at or above -MinimumVersion (in the 64-bit
        %ProgramFiles%\WindowsPowerShell\Modules, where the remediation script installs it), or
      * there has been no successful collection inside the window,
    otherwise exits 0. Reads only the module folder's manifest and HKLM\SOFTWARE\DoctorDO\LastSuccessfulCollection, which
    the collector writes after the ingest service accepted a report. It does not verify the module's files: the
    remediation script does, on every run, before it imports anything (collector/intune/README.md).

    Writes the same CMTrace log as the remediation script (component Detect-DoctorDO):
        %ProgramData%\Microsoft\IntuneManagementExtension\Logs\DoctorDO-Remediation.log
    The log never contains a credential. The last line of output is one short sentence for the Remediations report.

    Assign with: run this script using the logged-on credentials = No (SYSTEM), enforce script signature check = per your policy,
    run in 64-bit PowerShell = Yes.
.PARAMETER MaxAgeHours
    How old the last successful collection may be and still count as fresh. It must be SHORTER than the schedule's
    interval: Intune runs detection about one interval after the last run, so a window longer than the interval finds
    yesterday's collection fresh, skips the run, and a daily schedule collects only every other day. Default 22 for a
    daily schedule (2 hours of early drift; a collection 24 hours old is due). Use 160 for a weekly schedule.
.PARAMETER ModuleName
    The module to look for. Default DoctorDO.Collector.
.PARAMETER MinimumVersion
    The oldest installed version that counts. Default 1.2.3; keep it equal to the remediation script's.
.PARAMETER ModulesPath
    The module folder to look in. Default: the 64-bit %ProgramFiles%\WindowsPowerShell\Modules (also from a 32-bit host).
.PARAMETER LogPath
    The CMTrace log. Default %ProgramData%\Microsoft\IntuneManagementExtension\Logs\DoctorDO-Remediation.log .
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 720)][int] $MaxAgeHours = 22,
    [string] $RegistryPath = 'HKLM:\SOFTWARE\DoctorDO',
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string] $ModuleName = 'DoctorDO.Collector',
    [string] $MinimumVersion = '1.2.3',
    [string] $ModulesPath = '',
    [string] $LogPath = ''
)

Set-StrictMode -Version Latest

# ---- CMTrace log ------------------------------------------------------------------------------------------------
# <![LOG[message]LOG]!><time="HH:mm:ss.fff+bias" date="MM-dd-yyyy" component="..." context="" type="1" thread="..." file="...">
# type 1 information, 2 warning, 3 error. bias: minutes, in the sign of the Windows time-zone bias (UTC = local + bias, so
# UTC+1 is -060 and UTC-7 is +420) -- TO VERIFY against CMTrace on a device: Microsoft documents the bias, not CMTrace's
# line format. The same functions are in Remediate-DoctorDO.ps1 (a test keeps them identical).
$script:DDLog = @{ Path = ''; Component = 'Detect-DoctorDO'; File = 'Detect-DoctorDO.ps1'; MaxBytes = 1048576; Failed = $false }

function Get-DoctorDODefaultLogPath {
    [CmdletBinding()]
    param()
    $pd = $env:ProgramData
    if (-not $pd) { $pd = [System.Environment]::GetFolderPath('CommonApplicationData') }
    Join-Path -Path (Join-Path -Path $pd -ChildPath 'Microsoft\IntuneManagementExtension\Logs') -ChildPath 'DoctorDO-Remediation.log'
}

function Initialize-DoctorDOLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Path, [Parameter(Mandatory)][string] $Component, [Parameter(Mandatory)][string] $File, [int] $MaxBytes = 1048576)
    $script:DDLog = @{ Path = $Path; Component = $Component; File = $File; MaxBytes = $MaxBytes; Failed = $false }
}

function Get-DoctorDOLogBias {
    [CmdletBinding()]
    param([datetime] $Time = [datetime]::Now)
    [int][math]::Round(-1 * [System.TimeZoneInfo]::Local.GetUtcOffset($Time).TotalMinutes)
}

function Hide-DoctorDOCredential {
    # Replaces what looks like a credential: an Authorization header, sas/sig/token/key/code/pass-type query values, and the
    # user:pass part of a URL. The script handles none of these; this is for text that comes from elsewhere (an error).
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Text)
    $t = $Text
    $t = $t -replace '(?i)(authorization\s*[:=]\s*)\S+(\s+\S+)?', '$1<hidden>'
    $t = $t -replace '(?i)([?&;]\s*(?:sig|sas\w*|token|key|code|pwd|pass\w*|auth\w*)=)[^&\s;]+', '$1<hidden>'
    $t = $t -replace '(?i)(://)[^/@\s]+@', '$1<hidden>@'
    $t
}

function ConvertTo-DoctorDOLogText {
    # One printable-ASCII line that cannot end the CMTrace message early.
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Text)
    $t = Hide-DoctorDOCredential -Text $Text
    $t = $t -replace '[\r\n\t]+', ' '
    $t = $t -replace '[^\x20-\x7E]', '?'
    $t = $t.Replace(']LOG]!>', ']LOG] !>')
    if ($t.Length -gt 4000) { $t = $t.Substring(0, 3997) + '...' }
    $t
}

function Format-DoctorDOLogLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string] $Message,
        [ValidateSet('Info', 'Warning', 'Error')][string] $Level = 'Info',
        [Parameter(Mandatory)][string] $Component,
        [string] $File = '',
        [datetime] $Time = [datetime]::Now,
        [int] $BiasMinutes = 0
    )
    if (-not $PSBoundParameters.ContainsKey('BiasMinutes')) { $BiasMinutes = Get-DoctorDOLogBias -Time $Time }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $type = @{ Info = 1; Warning = 2; Error = 3 }[$Level]
    $sign = $(if ($BiasMinutes -lt 0) { '-' } else { '+' })
    $bias = '{0}{1:000}' -f $sign, [math]::Abs($BiasMinutes)
    $safeComponent = $Component -replace '[^A-Za-z0-9._ -]', '_'
    $safeFile = $File -replace '[^A-Za-z0-9._:\\/ -]', '_'
    '<![LOG[{0}]LOG]!><time="{1}{2}" date="{3}" component="{4}" context="" type="{5}" thread="{6}" file="{7}">' -f (ConvertTo-DoctorDOLogText -Text $Message),
    $Time.ToString('HH:mm:ss.fff', $inv), $bias, $Time.ToString('MM-dd-yyyy', $inv), $safeComponent, $type,
    [System.Threading.Thread]::CurrentThread.ManagedThreadId, $safeFile
}

function Invoke-DoctorDOLogRotation {
    # Before a write that would take the file over the limit: log -> .lo_ (CMTrace's name for the previous log), replacing
    # the previous .lo_, and a new log starts.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][int] $MaxBytes, [int] $IncomingBytes = 0)
    $info = New-Object System.IO.FileInfo($Path)
    if (-not $info.Exists -or ($info.Length + $IncomingBytes) -le $MaxBytes) { return }
    $old = [System.IO.Path]::ChangeExtension($Path, 'lo_')
    if (Test-Path -LiteralPath $old) { Remove-Item -LiteralPath $old -Force }
    Move-Item -LiteralPath $Path -Destination $old -Force
}

function Write-DoctorDOLog {
    # Never throws: a log that cannot be written must not stop the run. Does nothing until Initialize-DoctorDOLog set a path.
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)][AllowEmptyString()][string] $Message, [ValidateSet('Info', 'Warning', 'Error')][string] $Level = 'Info')
    Write-Verbose -Message (ConvertTo-DoctorDOLogText -Text $Message)
    $path = [string]$script:DDLog.Path
    if (-not $path) { return }
    try {
        $line = (Format-DoctorDOLogLine -Message $Message -Level $Level -Component $script:DDLog.Component -File $script:DDLog.File) + "`r`n"
        $dir = Split-Path -Path $path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
        Invoke-DoctorDOLogRotation -Path $path -MaxBytes ([int]$script:DDLog.MaxBytes) -IncomingBytes $line.Length
        [System.IO.File]::AppendAllText($path, $line, (New-Object System.Text.UTF8Encoding($false)))
    } catch { $script:DDLog.Failed = $true }
}


# ---- the module -------------------------------------------------------------------------------------------------

function Get-DoctorDOAllUsersModulesPath {
    # The 64-bit AllUsers folder of Windows PowerShell 5.1 (which the remediation host and PowerShell 7 both search). In a
    # 32-bit host %ProgramFiles% is "Program Files (x86)", and %ProgramW6432% is the 64-bit one.
    [CmdletBinding()]
    param()
    $pf = $env:ProgramW6432
    if (-not $pf) { $pf = $env:ProgramFiles }
    if (-not $pf) { $pf = [System.Environment]::GetFolderPath('ProgramFiles') }
    Join-Path -Path $pf -ChildPath 'WindowsPowerShell\Modules'
}

function Get-DoctorDOInstalledVersions {
    # The version folders of the module under ModulesPath, newest first: @{ Version = [version]; Path }.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ModulesPath, [Parameter(Mandatory)][string] $ModuleName)
    $root = Join-Path -Path $ModulesPath -ChildPath $ModuleName
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { return @() }
    $found = New-Object 'System.Collections.Generic.List[object]'
    foreach ($d in [System.IO.Directory]::GetDirectories($root)) {
        $v = $null
        if ([version]::TryParse([System.IO.Path]::GetFileName($d), [ref]$v)) { $found.Add([pscustomobject]@{ Version = $v; Path = $d }) }
    }
    @($found.ToArray() | Sort-Object -Property Version -Descending)
}

function Test-DoctorDOModuleInstalled {
    # Present when a version folder named like its manifest's ModuleVersion, at or above the minimum, holds the manifest.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string] $ModulesPath, [Parameter(Mandatory)][string] $ModuleName, [Parameter(Mandatory)][string] $MinimumVersion)
    $min = $null
    if (-not [version]::TryParse($MinimumVersion, [ref]$min)) { $min = [version]'0.0' }
    $message = "Non-compliant: the $ModuleName module $MinimumVersion or later is not installed for all users."
    try {
        foreach ($i in @(Get-DoctorDOInstalledVersions -ModulesPath $ModulesPath -ModuleName $ModuleName)) {
            if ($i.Version -lt $min) { continue }
            $psd1 = Join-Path -Path $i.Path -ChildPath ($ModuleName + '.psd1')
            if (-not (Test-Path -LiteralPath $psd1 -PathType Leaf)) { continue }
            $data = Import-PowerShellDataFile -LiteralPath $psd1
            if ([version]([string]$data['ModuleVersion']) -eq $i.Version) { return [pscustomobject]@{ Present = $true; Version = $i.Version.ToString(); Message = '' } }
        }
    } catch {
        Write-DoctorDOLog "Could not read the installed module: $($_.Exception.Message)" -Level Warning
    }
    [pscustomobject]@{ Present = $false; Version = ''; Message = $message }
}

# ---- the last collection ----------------------------------------------------------------------------------------

function Test-DoctorDOCollectionFresh {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([int] $MaxAgeHours, [string] $RegistryPath, [datetime] $Now = [datetime]::UtcNow)

    $value = $null
    try {
        $item = Get-ItemProperty -LiteralPath $RegistryPath -Name 'LastSuccessfulCollection' -ErrorAction Stop
        $value = [string]$item.LastSuccessfulCollection
    } catch {
        return [pscustomobject]@{ Fresh = $false; Message = 'Non-compliant: no successful DoctorDO collection recorded yet.' }
    }
    $when = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if (-not [datetime]::TryParse($value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$when)) {
        return [pscustomobject]@{ Fresh = $false; Message = "Non-compliant: LastSuccessfulCollection is not a valid timestamp." }
    }
    # Intune guidance: detection output should be stable between runs (no timestamps or elapsed times), and must never be empty:
    # empty output is reported as "issue not found". https://learn.microsoft.com/intune/device-management/tools/deploy-remediations
    $age = ($Now.ToUniversalTime() - $when).TotalHours
    if ($age -le $MaxAgeHours) {
        return [pscustomobject]@{ Fresh = $true; Message = ("Compliant: last successful DoctorDO collection is inside the {0} h window." -f $MaxAgeHours) }
    }
    [pscustomobject]@{ Fresh = $false; Message = ("Non-compliant: last successful DoctorDO collection is outside the {0} h window." -f $MaxAgeHours) }
}

function Get-DoctorDODetection {
    # The module first (the remediation cannot collect without it), then the freshness of the last collection.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([int] $MaxAgeHours, [string] $RegistryPath, [string] $ModulesPath, [string] $ModuleName, [string] $MinimumVersion, [datetime] $Now = [datetime]::UtcNow)
    $module = Test-DoctorDOModuleInstalled -ModulesPath $ModulesPath -ModuleName $ModuleName -MinimumVersion $MinimumVersion
    if (-not $module.Present) {
        Write-DoctorDOLog "$($module.Message) Folder: $ModulesPath."
        return [pscustomobject]@{ Compliant = $false; Message = $module.Message }
    }
    Write-DoctorDOLog "Module $ModuleName $($module.Version) is installed."
    $fresh = Test-DoctorDOCollectionFresh -MaxAgeHours $MaxAgeHours -RegistryPath $RegistryPath -Now $Now
    Write-DoctorDOLog $fresh.Message
    [pscustomobject]@{ Compliant = [bool]$fresh.Fresh; Message = $fresh.Message }
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $LogPath) { $LogPath = Get-DoctorDODefaultLogPath }
    if (-not $ModulesPath) { $ModulesPath = Get-DoctorDOAllUsersModulesPath }
    Initialize-DoctorDOLog -Path $LogPath -Component 'Detect-DoctorDO' -File 'Detect-DoctorDO.ps1'
    try {
        $r = Get-DoctorDODetection -MaxAgeHours $MaxAgeHours -RegistryPath $RegistryPath -ModulesPath $ModulesPath -ModuleName $ModuleName -MinimumVersion $MinimumVersion
    } catch {
        Write-DoctorDOLog "Detection failed: $($_.Exception.Message)" -Level Error
        $r = [pscustomobject]@{ Compliant = $false; Message = 'Non-compliant: the DoctorDO detection could not complete.' }
    }
    Write-Output $r.Message
    if ($r.Compliant) { exit 0 }
    exit 1
}
