#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only check, on a device just provisioned with Windows Autopilot, of the sources the collector's provisioning summary
    reads (ADR-0043): the Enrollment Status Page tracking and Delivery Optimization's job list.
.DESCRIPTION
    Run it elevated, soon after the ESP finishes (and again a day or two later if you can). It changes nothing and sends
    nothing: it writes one JSON file you can read before sharing it. The file holds the tracking key's layout (key paths,
    value names and the small numeric states), how many Diagnostics subkeys carry a date the collector can read and a few
    examples of their names, and counts and sizes from Get-DeliveryOptimizationStatus. App IDs are Intune app GUIDs; no
    user name, URL or file name is written. User SIDs in key paths are replaced by "<user-sid>".

    What it answers: whether the documented keys exist in the layout the collector expects, the exact format of the
    timestamp subkey names (not documented), whether Win32 apps appear under ESPTrackingInfo\Diagnostics, and whether the
    provisioning downloads are still in DO's job list at the time you run it.
.PARAMETER OutputPath
    Where to write the JSON. Default: DoctorDO-provisioning-probe-<computer>-<time>.json in the current folder.
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-DoctorDOProvisioningProbe.ps1
#>
[CmdletBinding()]
param([string] $OutputPath)

Set-StrictMode -Version Latest
$root = 'SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking'
$dateRe = '(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})[T _-]?(\d{1,2}):(\d{2}):(\d{2})(?:[.,](\d{1,7}))?'
$now = [datetime]::UtcNow
$result = [ordered]@{ probe = 'doctordo-provisioning-probe/1'; ranAt = $now.ToString('o'); elevated = $null; os = $null; esp = $null; delivery = $null; errors = @() }
$errors = New-Object 'System.Collections.Generic.List[string]'

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $result.elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $errors.Add("elevation: $($_.Exception.Message)") }

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $result.os = [ordered]@{ caption = [string]$os.Caption; build = [string]$os.BuildNumber; installDate = $os.InstallDate.ToUniversalTime().ToString('o'); lastBoot = $os.LastBootUpTime.ToUniversalTime().ToString('o') }
} catch { $errors.Add("os: $($_.Exception.Message)") }

try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $base.OpenSubKey($root)
    if ($null -eq $key) { $result.esp = [ordered]@{ present = $false } }
    else {
        $keys = New-Object 'System.Collections.Generic.List[object]'
        $stack = New-Object 'System.Collections.Generic.Stack[object]'
        $stack.Push(@($key, ''))
        $dated = 0; $undated = 0; $examples = New-Object 'System.Collections.Generic.List[string]'; $undatedExamples = New-Object 'System.Collections.Generic.List[string]'
        $win32UnderDiagnostics = 0
        while ($stack.Count -gt 0 -and $keys.Count -lt 3000) {
            $item = $stack.Pop(); $k = $item[0]; $path = [string]$item[1]
            try {
                $shown = ($path -replace '(^|\\)S-1-[0-9-]+', '$1<user-sid>')
                $values = [ordered]@{}
                foreach ($n in @($k.GetValueNames() | Select-Object -First 64)) {
                    $v = $k.GetValue($n)
                    $kind = [string]$k.GetValueKind($n)
                    # Only small numbers are written: the states the collector reads. Anything else is reported by type.
                    $values[($n -replace 'S-1-[0-9-]+', '<user-sid>')] = $(if (($v -is [int] -or $v -is [long]) -and $v -ge 0 -and $v -le 100) { $v } else { "<$kind>" })
                }
                $keys.Add([ordered]@{ path = $shown; values = $values })
                if ($path -like 'ESPTrackingInfo\Diagnostics\*') {
                    $leaf = ($path -split '\\')[-1]
                    if ([regex]::IsMatch($leaf, $dateRe)) { $dated++; if ($examples.Count -lt 5) { $examples.Add($shown) } }
                    elseif ($values.Count -gt 0) { $undated++; if ($undatedExamples.Count -lt 5) { $undatedExamples.Add($shown) } }
                    if ("$path $(@($values.Keys) -join ' ')" -match 'Win32App_') { $win32UnderDiagnostics++ }
                }
                foreach ($s in @($k.GetSubKeyNames())) { $sub = $k.OpenSubKey($s); if ($null -ne $sub) { $stack.Push(@($sub, $(if ($path) { "$path\$s" } else { $s }))) } }
            } finally { $k.Dispose() }
        }
        while ($stack.Count -gt 0) { $stack.Pop()[0].Dispose() }
        $result.esp = [ordered]@{
            present = $true; keyCount = $keys.Count
            diagnostics = [ordered]@{ datedSubkeys = $dated; undatedSubkeysWithValues = $undated; datedExamples = $examples.ToArray(); undatedExamples = $undatedExamples.ToArray(); keysNamingWin32Apps = $win32UnderDiagnostics }
            win32AppTrackingKeys = @($keys | Where-Object { $_.path -match '\\Win32App_' -and $_.path -notlike 'ESPTrackingInfo*' }).Count
            keys = $keys.ToArray()
        }
    }
    $base.Dispose()
} catch { $errors.Add("esp: $($_.Exception.Message)") }

try {
    if (Get-Command -Name Get-DeliveryOptimizationStatus -ErrorAction SilentlyContinue) {
        $jobs = @(Get-DeliveryOptimizationStatus -ErrorAction Stop)
        $num = { param($o, $n) $p = $o.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { [double]$p.Value } else { 0 } }
        $expire = @($jobs | ForEach-Object { $_.PSObject.Properties['ExpireOn'] } | Where-Object { $_ -and $_.Value -is [datetime] } | ForEach-Object { $_.Value.ToUniversalTime() } | Sort-Object)
        $callers = [ordered]@{}
        foreach ($j in $jobs) {
            $c = $(if ($j.PSObject.Properties['PredefinedCallerApplication'] -and $j.PredefinedCallerApplication) { [string]$j.PredefinedCallerApplication } else { '(none)' })
            if ($c.Length -gt 64) { $c = $c.Substring(0, 64) }
            if (-not $callers.Contains($c)) { $callers[$c] = [ordered]@{ jobs = 0; bytes = 0 } }
            $callers[$c].jobs++; $callers[$c].bytes += (& $num $j 'FileSize')
        }
        $result.delivery = [ordered]@{
            jobs = $jobs.Count
            foreground = @($jobs | Where-Object { [string]$_.Priority -like 'Fore*' }).Count
            bytes = [ordered]@{
                size = ($jobs | ForEach-Object { & $num $_ 'FileSize' } | Measure-Object -Sum).Sum
                http = ($jobs | ForEach-Object { & $num $_ 'BytesFromHttp' } | Measure-Object -Sum).Sum
                cacheServer = ($jobs | ForEach-Object { & $num $_ 'BytesFromCacheServer' } | Measure-Object -Sum).Sum
                peers = ($jobs | ForEach-Object { (& $num $_ 'BytesFromLanPeers') + (& $num $_ 'BytesFromGroupPeers') + (& $num $_ 'BytesFromInternetPeers') } | Measure-Object -Sum).Sum
            }
            expireOnEarliest = $(if ($expire.Count) { $expire[0].ToString('o') } else { $null })
            expireOnLatest = $(if ($expire.Count) { $expire[-1].ToString('o') } else { $null })
            byCaller = $callers
        }
    } else { $errors.Add('delivery: Get-DeliveryOptimizationStatus is not available') }
} catch { $errors.Add("delivery: $($_.Exception.Message)") }

$result.errors = $errors.ToArray()
if (-not $OutputPath) { $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath ('DoctorDO-provisioning-probe-{0}-{1}.json' -f $env:COMPUTERNAME, $now.ToString('yyyyMMdd-HHmmss')) }
$json = $result | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($OutputPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Output "Wrote $OutputPath"
