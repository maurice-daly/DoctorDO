#Requires -Version 5.1
# What a person at the console sees (1.1.0): whether anyone is watching, colour, and the connectivity checks summed up by
# area with the ones that need attention. New-DoctorDODeviceReport and Invoke-DoctorDOCollector end their narration with
# it (Progress.ps1); Test-DOConnectivity returns it as its text. Lines in, lines out: nothing here collects anything.
#
#   Area                  Pass  Warn  Fail  N/A  Not collected
#   ----                  ----  ----  ----  ---  -------------
#   Cloud service            4     -     -    -              -
#   Peer-to-peer             2     1     2    6              -
#   ----                  ----  ----  ----  ---  -------------
#   Total (65 checks)       39     2     2   18              4

Set-StrictMode -Version Latest

# The areas of the catalogue (packages/analysis/src/connectivity/catalogue.ts, CONNECTIVITY_CATEGORIES) in its order,
# then the endpoint health rows (ep:<id>) and any check this list does not know yet. A test holds it to the catalogue.
$script:DDCheckAreas = [ordered]@{
    cloud     = 'Cloud service'
    content   = 'Content & metadata'
    p2p       = 'Peer-to-peer'
    mcc       = 'Connected Cache'
    proxy     = 'Proxy'
    local     = 'Local prerequisites'
    endpoints = 'Microsoft endpoints'
    other     = 'Other checks'
}
$script:DDCheckArea = @{}
foreach ($group in @(
        @('cloud', 'do-cloud-dns', 'do-cloud-tls', 'do-cloud-inspect', 'do-geo'),
        @('content', 'do-content-cdn', 'do-metadata-wu', 'do-range-support', 'do-content-by-caller'),
        @('p2p', 'p2p-listener', 'p2p-outbound', 'p2p-inbound', 'p2p-firewall-rule', 'p2p-firewall-scope', 'p2p-outbound-rule', 'dhcp-option-234', 'local-policy-merge', 'teredo-endpoint', 'teredo-state', 'teredo-outbound-rule'),
        @('mcc', 'mcc-config', 'mcc-cache-host', 'mcc-dhcp-235', 'mcc-reachable', 'mcc-serving'),
        @('proxy', 'proxy-tls-inspection', 'proxy-source-ip', 'proxy-scope', 'proxy-pac'),
        @('local', 'dosvc-running', 'download-mode', 'resource-eligibility', 'adapter-eligibility', 'do-cache-folder', 'do-state-file', 'power-upload'))) {
    foreach ($id in $group[1..($group.Count - 1)]) { $script:DDCheckArea[$id] = $group[0] }
}

# The results in the order a person reads them, with the word each is shown as.
$script:DDResultOrder = @('fail', 'warn', 'pass', 'not-applicable', 'not-collected')
$script:DDResultWord = @{ 'fail' = 'FAIL'; 'warn' = 'WARN'; 'pass' = 'pass'; 'not-applicable' = 'n/a'; 'not-collected' = 'n/c' }

function Test-DDConsoleNarration {
    <#
    .SYNOPSIS
        Whether a person is watching this run, so the commands people run by hand say what they are doing: nobody is
        when Get-DDNonInteractiveReason gives a reason (SYSTEM, a service, session 0, -NonInteractive, a remote session,
        a process Intune, the Task Scheduler, ConfigMgr or WMI started), or when the console's output is redirected, where
        the host would write the narration into the captured output (an Intune remediation's, or pwsh -Command > file).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try { if ([Console]::IsOutputRedirected) { return $false } } catch { return $false }
    $null -eq (Get-DDNonInteractiveReason)
}

function Test-DDInformationQuiet {
    # Whether the caller asked for no information (-InformationAction SilentlyContinue or Ignore). The narration is
    # written with -InformationAction Continue, which would override that, so the command checks first.
    [CmdletBinding()]
    [OutputType([bool])]
    param([System.Collections.IDictionary] $BoundParameters = @{})
    @($BoundParameters.Keys) -contains 'InformationAction' -and [string]$BoundParameters['InformationAction'] -in 'SilentlyContinue', 'Ignore'
}

function Test-DDConsoleColour {
    # Colour only where the console renders it: the host supports virtual terminal sequences, NO_COLOR is not set
    # (https://no-color.org) and PowerShell 7's $PSStyle.OutputRendering is not PlainText.
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($env:NO_COLOR) { return $false }
    $style = Get-Variable -Name PSStyle -ValueOnly -ErrorAction SilentlyContinue
    if ($null -ne $style -and [string]$style.OutputRendering -eq 'PlainText') { return $false }
    try { [bool]$Host.UI.SupportsVirtualTerminal } catch { $false }
}

function Get-DDConsoleWidth {
    # The width to wrap to: the console's, between 60 and 160 columns; 120 where the host has no window.
    [CmdletBinding()]
    [OutputType([int])]
    param()
    $w = 0
    try { $w = [int]$Host.UI.RawUI.WindowSize.Width } catch { $w = 0 }
    if ($w -lt 20) { return 120 }
    [int][math]::Min(160, [math]::Max(60, $w - 1))
}

function Format-DDColour {
    # The text in an ANSI colour when -On, else as it is.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string] $Text, [ValidateSet('red', 'yellow', 'green', 'dim', 'bold')][string] $Style, [bool] $On)
    if (-not $On -or -not $Text) { return $Text }
    $code = @{ red = '31'; yellow = '33'; green = '32'; dim = '90'; bold = '1' }[$Style]
    $esc = [char]27
    '{0}[{1}m{2}{0}[0m' -f $esc, $code, $Text
}

function Format-DDResultCounts {
    # '65 checks: 39 pass, 2 warn, 2 fail, ...' with the fail and warn counts in colour when -On.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string] $Text, [bool] $On)
    if (-not $On -or -not $Text) { return $Text }
    $t = [regex]::Replace($Text, '\b[1-9]\d* fail\b', { param($m) Format-DDColour -Text $m.Value -Style red -On $true })
    [regex]::Replace($t, '\b[1-9]\d* warn\b', { param($m) Format-DDColour -Text $m.Value -Style yellow -On $true })
}

function Format-DDCount {
    # '1 file', '24 files': a count with its noun, plural when it is not one (-Plural for an irregular one).
    [CmdletBinding()]
    [OutputType([string])]
    param([int] $Count, [Parameter(Mandatory)][string] $Noun, [string] $Plural)
    '{0} {1}' -f $Count, $(if ($Count -eq 1) { $Noun } elseif ($Plural) { $Plural } else { $Noun + 's' })
}

function Get-DDCheckArea {
    # The area a connectivity check belongs to: its catalogue category, 'endpoints' for an endpoint health row, else 'other'.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string] $CheckId)
    if ($CheckId.StartsWith('ep:')) { return 'endpoints' }
    if ($script:DDCheckArea.ContainsKey($CheckId)) { return $script:DDCheckArea[$CheckId] }
    'other'
}

function Format-DDWrapped {
    # The text broken at spaces into lines no longer than -Width (a longer word gets a line of its own).
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()][string] $Text, [int] $Width = 80)
    $line = ''
    foreach ($word in ($Text -split '\s+' | Where-Object { $_ })) {
        if ($line -and ($line.Length + 1 + $word.Length) -gt $Width) { $line; $line = $word }
        elseif ($line) { $line = $line + ' ' + $word }
        else { $line = $word }
    }
    if ($line) { $line }
}

function Format-DDCheckTarget {
    # Where a check looked: host:port, the port alone, the host alone, or nothing.
    [CmdletBinding()]
    [OutputType([string])]
    param([System.Collections.IDictionary] $Row)
    $target = [string]$Row['target']
    $port = [string]$Row['port']
    if ($target -and $port) { return '{0}:{1}' -f $target, $port }
    if ($port) { return 'port {0}' -f $port }
    $target
}

function Format-DDAreaTable {
    <#
    .SYNOPSIS
        The checks counted by area and result as lines of text: a heading, one line per area that has checks, then the
        total. A zero is a dash, so the counts that matter stand out; with -Colour the fail and warn counts are coloured.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()] $Rows = @(), [string] $Indent = '  ', [switch] $Colour)
    $list = @($Rows | Where-Object { $_ -is [System.Collections.IDictionary] })
    if ($list.Count -eq 0) { return "${Indent}No connectivity checks ran." }
    $columns = @(@('pass', 'Pass'), @('warn', 'Warn'), @('fail', 'Fail'), @('not-applicable', 'N/A'), @('not-collected', 'Not collected'))
    $counts = [ordered]@{}
    foreach ($r in $list) {
        $area = Get-DDCheckArea -CheckId ([string]$r['checkId'])
        if (-not $counts.Contains($area)) { $counts[$area] = @{} }
        $res = [string]$r['result']
        $counts[$area][$res] = 1 + $(if ($counts[$area].ContainsKey($res)) { $counts[$area][$res] } else { 0 })
    }
    $totalLabel = 'Total ({0} check{1})' -f $list.Count, $(if ($list.Count -eq 1) { '' } else { 's' })
    $labels = @($script:DDCheckAreas.Keys | Where-Object { $counts.Contains($_) } | ForEach-Object { $script:DDCheckAreas[$_] })
    $labelWidth = @(@($labels + 'Area' + $totalLabel) | ForEach-Object { $_.Length } | Measure-Object -Maximum)[0].Maximum
    $widths = @($columns | ForEach-Object { [math]::Max(4, $_[1].Length) })
    $line = {
        param([string] $Label, [string[]] $Cells, [bool] $Counts)
        $parts = for ($i = 0; $i -lt $columns.Count; $i++) {
            $cell = $Cells[$i].PadLeft($widths[$i])
            $style = ''
            if ($Counts -and $Cells[$i] -ne '-') { $style = @{ fail = 'red'; warn = 'yellow' }[$columns[$i][0]] }
            if ($style) { Format-DDColour -Text $cell -Style $style -On $Colour.IsPresent } else { $cell }
        }
        $Indent + $Label.PadRight($labelWidth) + '  ' + ($parts -join '  ')
    }
    $rule = [string[]]@($columns | ForEach-Object { '-' * $_[1].Length })
    & $line 'Area' ([string[]]@($columns | ForEach-Object { $_[1] })) $false
    & $line '----' $rule $false
    $total = @{}
    foreach ($area in $script:DDCheckAreas.Keys) {
        if (-not $counts.Contains($area)) { continue }
        $cells = [string[]]@($columns | ForEach-Object {
                $n = $(if ($counts[$area].ContainsKey($_[0])) { $counts[$area][$_[0]] } else { 0 })
                $total[$_[0]] = $n + $(if ($total.ContainsKey($_[0])) { $total[$_[0]] } else { 0 })
                $(if ($n) { [string]$n } else { '-' })
            })
        & $line $script:DDCheckAreas[$area] $cells $true
    }
    & $line '----' $rule $false
    & $line $totalLabel ([string[]]@($columns | ForEach-Object { $(if ($total[$_[0]]) { [string]$total[$_[0]] } else { '-' }) })) $true
}

function Format-DDAttention {
    <#
    .SYNOPSIS
        The checks that failed or warned, failures first, each with where it looked and its detail wrapped to -Width; at
        most -Limit of them (0: all), then how many more and -More. One line saying so when nothing failed or warned.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()] $Rows = @(), [int] $Width = 120, [int] $Limit = 0, [string] $More = '', [string] $Indent = '  ', [switch] $Colour)
    $list = @($Rows | Where-Object { $_ -is [System.Collections.IDictionary] })
    $fails = @($list | Where-Object { $_['result'] -eq 'fail' })
    $warns = @($list | Where-Object { $_['result'] -eq 'warn' })
    $bad = @($fails + $warns)
    if ($bad.Count -eq 0) { return "${Indent}Nothing needs attention: no check failed or warned." }
    $counts = @(@(@($fails.Count, 'fail'), @($warns.Count, 'warn')) | Where-Object { $_[0] } | ForEach-Object { '{0} {1}' -f $_[0], $_[1] }) -join ', '
    '{0}Needs attention ({1})' -f $Indent, (Format-DDResultCounts -Text $counts -On $Colour.IsPresent)
    $shown = @(if ($Limit -gt 0) { $bad | Select-Object -First $Limit } else { $bad })
    $idWidth = [math]::Min(24, @(@($shown | ForEach-Object { ([string]$_['checkId']).Length }) | Measure-Object -Maximum)[0].Maximum)
    $pad = $Indent + (' ' * 8)
    foreach ($r in $shown) {
        $res = [string]$r['result']
        $word = Format-DDColour -Text $script:DDResultWord[$res] -Style $(if ($res -eq 'fail') { 'red' } else { 'yellow' }) -On $Colour.IsPresent
        ('{0}  {1}  {2}  {3}' -f $Indent, $word, ([string]$r['checkId']).PadRight($idWidth), (Format-DDCheckTarget -Row $r)).TrimEnd()
        foreach ($l in (Format-DDWrapped -Text ([string]$r['detail']) -Width ([math]::Max(30, $Width - $pad.Length)))) { $pad + $l }
    }
    if ($shown.Count -lt $bad.Count) {
        '{0}  ... and {1} more{2}' -f $Indent, ($bad.Count - $shown.Count), $(if ($More) { ": $More" } else { '' })
    }
}

function Format-DDCheckList {
    <#
    .SYNOPSIS
        Every check, under the heading of its area with that area's counts; within an area failures first, then warnings,
        passes, not applicable and not collected, each in the order the checks ran, with its detail wrapped to -Width.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyCollection()] $Rows = @(), [int] $Width = 120, [string] $Indent = '  ')
    $list = @($Rows | Where-Object { $_ -is [System.Collections.IDictionary] })
    if ($list.Count -eq 0) { return "${Indent}No connectivity checks ran." }
    $idWidth = [math]::Min(24, @(@($list | ForEach-Object { ([string]$_['checkId']).Length }) | Measure-Object -Maximum)[0].Maximum)
    $pad = $Indent + (' ' * 8)
    $first = $true
    foreach ($area in $script:DDCheckAreas.Keys) {
        $index = 0
        $inArea = @(foreach ($r in $list) {
                if ((Get-DDCheckArea -CheckId ([string]$r['checkId'])) -eq $area) {
                    $rank = [array]::IndexOf($script:DDResultOrder, [string]$r['result'])
                    [pscustomobject]@{ Row = $r; Rank = $(if ($rank -lt 0) { $script:DDResultOrder.Count } else { $rank }); Index = $index }
                }
                $index++
            })
        if ($inArea.Count -eq 0) { continue }
        if (-not $first) { '' }
        $first = $false
        $tally = @(foreach ($res in $script:DDResultOrder) {
                $n = @($inArea | Where-Object { $_.Row['result'] -eq $res }).Count
                if ($n) { '{0} {1}' -f $n, $res }
            }) -join ', '
        '{0}{1} ({2})' -f $Indent, $script:DDCheckAreas[$area], $tally
        foreach ($e in @($inArea | Sort-Object -Property Rank, Index)) {
            $res = [string]$e.Row['result']
            $word = $(if ($script:DDResultWord.ContainsKey($res)) { $script:DDResultWord[$res] } else { $res })
            ('{0}  {1}  {2}  {3}' -f $Indent, $word.PadRight(4), ([string]$e.Row['checkId']).PadRight($idWidth), (Format-DDCheckTarget -Row $e.Row)).TrimEnd()
            foreach ($l in (Format-DDWrapped -Text ([string]$e.Row['detail']) -Width ([math]::Max(30, $Width - $pad.Length)))) { $pad + $l }
        }
    }
    ''
    '{0}n/a: not applicable on this device. n/c: not collected, so not known (often: run elevated).' -f $Indent
}

function Write-DDRunSummary {
    # The end of a narrated run: the checks by area, what needs attention (at most 8; -More says where the rest are) and
    # how many facts could not be read (-Listed says where they are). Nothing unless someone is watching the run.
    [CmdletBinding()]
    param($Run, [AllowEmptyCollection()] $Rows = @(), [int] $NotCollected = 0, [string] $More = '', [string] $Listed = 'the report lists each, with why')
    if ($null -eq $Run -or -not $Run.Show) { return }
    Write-DDNarration
    foreach ($l in (Format-DDAreaTable -Rows $Rows -Colour:$Run.Colour)) { Write-DDNarration $l }
    Write-DDNarration
    foreach ($l in (Format-DDAttention -Rows $Rows -Width $Run.Width -Limit 8 -More $More -Colour:$Run.Colour)) { Write-DDNarration $l }
    if ($NotCollected -gt 0) {
        Write-DDNarration
        $hint = $(if (-not (Test-DDElevated) -and -not (Test-DDSystemContext)) { ' Run from an elevated prompt to read most of them.' } else { '' })
        Write-DDNarration ('  {0} could not be read; {1}.{2}' -f (Format-DDCount -Count $NotCollected -Noun 'fact'), $Listed, $hint)
    }
    Write-DDNarration
}
