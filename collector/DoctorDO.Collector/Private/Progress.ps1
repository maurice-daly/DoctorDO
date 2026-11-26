#Requires -Version 5.1
# What the commands people run by hand (Invoke-DoctorDOCollector, New-DoctorDODeviceReport, Test-DOConnectivity) say
# while they run. Two layers:
#
# * For a person at the console (Test-DDConsoleNarration, 1.1.0): a header, one line per section as it finishes, with a
#   progress bar naming the section under way, then a summary (Console.ps1). On the Information stream, so
#   -InformationAction SilentlyContinue hides it; never under SYSTEM, Intune, a scheduled task or redirected output.
#
#     DoctorDO.Collector 1.1.0: device report
#     PowerShell 7.6.8 (Core), not elevated, started 2026-10-23 09:44:15 UTC
#
#       [1/8] Device and Windows ................... Microsoft Entra joined; Windows 10.0.26300; no ConfigMgr client
#       [6/8] Connectivity ......................... 65 checks: 39 pass, 2 warn, 2 fail, 18 not-applicable, 4 not-collected
#
# * With -Verbose: one line per step with the time since the start, what is happening and how it went, in aligned
#   columns. The header and the closing summary line are written only when nobody is narrated to (the narration has its
#   own). The lines name no host, user or address: a verbose transcript can be pasted into a support request as it is.
#
#     VERBOSE: DoctorDO.Collector 1.1.0 - New-DoctorDODeviceReport
#     VERBOSE: PowerShell 7.6.6 (Core), elevated, started 2026-10-15 17:30:12 UTC
#     VERBOSE: ------------------------------------------------------------------------------------------------
#     VERBOSE: [   0.8s] Device identity (dsregcmd) ................................. join type hybrid
#     VERBOSE: [  21.2s]   not collected: network.proxy.wininetScope ................ insufficient-rights
#     VERBOSE: ------------------------------------------------------------------------------------------------
#     VERBOSE: [  22.2s] Done ....................................................... report written, 752 KB
#
# The run (its clock, the command that owns it and whether anyone is watching) is the $DDRun variable of the public
# command, which every function it calls sees through PowerShell's dynamic scoping: nothing is kept in the module between
# calls, and a command called from another one (Test-DOConnectivity calling Get-DOConnectivityMatrix) joins the run
# already under way.

Set-StrictMode -Version Latest

$script:DDStepColumn = 60
$script:DDSectionColumn = 44
$script:DDRule = '-' * 100

function Start-DDVerboseRun {
    <#
    .SYNOPSIS
        A new run, with its header, or the run of the command that called this one. Assign it to $DDRun. -Title and
        -Sections describe the run to a person at the console; a run of no sections (and a -Quiet one: the caller's
        -InformationAction SilentlyContinue) is narrated to nobody.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Command, [string] $Title = '', [int] $Sections = 0, [switch] $Quiet)
    $outer = Get-Variable -Name DDRun -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $outer) { return $outer }
    $show = (-not $Quiet) -and $Sections -gt 0 -and (Test-DDConsoleNarration)
    $colour = $show -and (Test-DDConsoleColour)
    $run = [pscustomobject]@{
        Command = $Command; Clock = [System.Diagnostics.Stopwatch]::StartNew(); Show = $show; Colour = $colour
        Title = $Title; Total = $Sections; Index = 0; Current = ''; Width = $(if ($show) { Get-DDConsoleWidth } else { 120 })
    }
    if ($show -or $VerbosePreference -ne 'SilentlyContinue') {
        $rights = $(if (Test-DDSystemContext) { 'running as SYSTEM' } elseif (Test-DDElevated) { 'elevated' } else { 'not elevated' })
        $started = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        $platform = 'PowerShell {0} ({1}), {2}, started {3} UTC' -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $rights, $started
        if ($show) {
            Write-DDNarration (Format-DDColour -Text ('DoctorDO.Collector {0}: {1}' -f (Get-DDCollectorVersion), $Title) -Style bold -On $colour)
            Write-DDNarration (Format-DDColour -Text $platform -Style dim -On $colour)
            Write-DDNarration
        } else {
            Write-Verbose ('DoctorDO.Collector {0} - {1}' -f (Get-DDCollectorVersion), $Command)
            Write-Verbose $platform
            Write-Verbose $script:DDRule
        }
    }
    $run
}

function Write-DDNarration {
    # One line for a person at the console, on the Information stream with the tag DoctorDO, so 6>, -InformationVariable
    # and transcripts treat it like any other information. Callers check $DDRun.Show first.
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Message = '')
    Write-Information -MessageData $Message -Tags 'DoctorDO' -InformationAction Continue
}

function Start-DDSection {
    # The next section of a narrated run; the progress bar names it while it runs. Nothing when nobody is watching.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Name)
    $run = Get-Variable -Name DDRun -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $run -or -not $run.Show) { return }
    $run.Index++
    $run.Current = $Name
    $percent = [int][math]::Min(99, 100 * ($run.Index - 1) / [math]::Max(1, $run.Total))
    Write-Progress -Id 7680 -Activity ('DoctorDO.Collector: {0}' -f $run.Title) -Status ('[{0}/{1}] {2}' -f $run.Index, $run.Total, $Name) -PercentComplete $percent
}

function Complete-DDSection {
    # The line for the section that has just finished: its number, its name and how it went, the results in one column.
    # A scriptblock result is evaluated only when someone is watching, and a failure there never reaches the run.
    [CmdletBinding()]
    param($Result = 'done')
    $run = Get-Variable -Name DDRun -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $run -or -not $run.Show -or -not $run.Current) { return }
    if ($Result -is [scriptblock]) {
        try { $Result = [string](& $Result) } catch { $Result = "(not described: $($_.Exception.Message))" }
    }
    $label = '[{0}/{1}] {2}' -f $run.Index, $run.Total, $run.Current
    $leader = '.' * [math]::Max(2, $script:DDSectionColumn - $label.Length - 1)
    $counter = '[{0}/{1}]' -f $run.Index, $run.Total
    Write-DDNarration ('  {0} {1} {2} {3}' -f (Format-DDColour -Text $counter -Style dim -On $run.Colour), $run.Current,
        (Format-DDColour -Text $leader -Style dim -On $run.Colour), (Format-DDResultCounts -Text ([string]$Result) -On $run.Colour))
    $run.Current = ''
}

function Write-DDVerboseStep {
    # One step: the seconds since the run started, the step, a dotted leader to a fixed column, then the result. A
    # scriptblock result is evaluated only with -Verbose, and a failure there never reaches the run: describing a step
    # must not be able to break it.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Step, $Result = 'done')
    if ($VerbosePreference -eq 'SilentlyContinue') { return }
    if ($Result -is [scriptblock]) {
        try { $Result = [string](& $Result) } catch { $Result = "(not described: $($_.Exception.Message))" }
    }
    $run = Get-Variable -Name DDRun -ValueOnly -ErrorAction SilentlyContinue
    $time = $(if ($null -ne $run) { $run.Clock.Elapsed.TotalSeconds.ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture) + 's' } else { '' })
    $leader = '.' * [math]::Max(2, $script:DDStepColumn - $Step.Length - 1)
    Write-Verbose ('[{0,7}] {1} {2} {3}' -f $time, $Step, $leader, $Result)
}

function Stop-DDVerboseRun {
    # The end of the run, only for the command that started it (not one that joined it): the progress bar is cleared for
    # a narrated run, else -Verbose gets the closing rule and how the run ended.
    [CmdletBinding()]
    param($Run, [Parameter(Mandatory)][string] $Command, [Parameter(Mandatory)][string] $Summary)
    if ($null -eq $Run -or $Run.Command -ne $Command) { return }
    if ($Run.Show) {
        Write-Progress -Id 7680 -Activity ('DoctorDO.Collector: {0}' -f $Run.Title) -Completed
        return
    }
    if ($VerbosePreference -eq 'SilentlyContinue') { return }
    Write-Verbose $script:DDRule
    Write-DDVerboseStep -Step 'Done' -Result $Summary
}

function Get-DDCountText {
    # '27 results: 24 pass, 1 warn, 2 fail' from connectivity rows, naming only the results that occur.
    [CmdletBinding()]
    param([AllowEmptyCollection()] $Rows = @(), [string] $Noun = 'results')
    $list = @($Rows | Where-Object { $_ -is [System.Collections.IDictionary] })
    if ($list.Count -eq 0) { return "no $Noun" }
    $parts = foreach ($r in 'pass', 'warn', 'fail', 'not-applicable', 'not-collected') {
        $n = @($list | Where-Object { $_['result'] -eq $r }).Count
        if ($n) { '{0} {1}' -f $n, $r }
    }
    '{0} {1}: {2}' -f $list.Count, $Noun, (@($parts) -join ', ')
}
