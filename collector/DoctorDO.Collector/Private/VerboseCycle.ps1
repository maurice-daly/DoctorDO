#Requires -Version 5.1
# The verbose-logging cycle (docs/08 "The verbose-logging cycle", T-027). This is the ONLY place the collector
# changes device state, so it is explicit, bounded and reversible:
#   capture previous state -> enable -> wait for the reproduction (bounded) -> collect -> restore in `finally`
# `finally` also runs on Ctrl-C (PipelineStoppedException), on any error and on timeout. Restoration is verified;
# if it fails the exact manual command is returned and the caller exits with code 4.
# If the previous state cannot be determined the cycle REFUSES to run: it never enables what it cannot restore.

Set-StrictMode -Version Latest

function Wait-DDReproduction {
    # Wait until the operator presses Enter or the timeout elapses. Mockable seam.
    [CmdletBinding()]
    param([double] $TimeoutMinutes = 15, [string] $Message = 'Reproduce the issue now, then press Enter')

    Write-Information ("{0} (auto-continue in {1} min)" -f $Message, $TimeoutMinutes) -InformationAction Continue
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $interactive = $false
    try { $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected } catch { $interactive = $false }
    while ((Get-Date) -lt $deadline) {
        if ($interactive) {
            try { if ([Console]::KeyAvailable) { [void][Console]::ReadKey($true); return 'key' } } catch { $interactive = $false }
        }
        Start-Sleep -Seconds 1
    }
    'timeout'
}

function Invoke-DDVerboseCycle {
    <#
    .SYNOPSIS
        Run -Collect with verbose logging enabled, restoring the previous state in all cases.
    .OUTPUTS
        @{ Result = <collect output>; RestoreOk = bool; RestoreCommand = string|null; Reason = string|null }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock] $Collect,
        [double] $TimeoutMinutes = 15,
        # Microsoft documents Enable/Disable-DeliveryOptimizationVerboseLogs but no way to read the state. The operator can
        # state it ($false = "verbose logging is currently off"); otherwise an unknown state means the cycle refuses to run.
        [Nullable[bool]] $AssumePreviousState = $null
    )

    $previous = Get-DDDOVerboseLogState
    if ($null -eq $previous -and $null -ne $AssumePreviousState) { $previous = [bool]$AssumePreviousState }
    if ($null -eq $previous) {
        throw [System.InvalidOperationException]::new('Cannot determine the current Delivery Optimization verbose logging state (Microsoft documents no way to read it), so it will not be enabled: it could not be restored with certainty. Re-run with -AssumeVerboseLoggingOff if you know it is currently off, or collect without -ReproduceIssue.')
    }
    $enabledByUs = $false
    $result = $null
    $restoreOk = $true
    $restoreCommand = $null
    $restoreReason = $null
    $endedBy = $null
    try {
        if (-not $previous) {
            Enable-DDDOVerboseLogs
            $enabledByUs = $true
            Write-Information 'Step 1 of 3: Delivery Optimization verbose logging is on.' -InformationAction Continue
        } else {
            Write-Information 'Step 1 of 3: Delivery Optimization verbose logging was already on; it is left as it is.' -InformationAction Continue
        }
        $endedBy = Wait-DDReproduction -TimeoutMinutes $TimeoutMinutes -Message 'Step 2 of 3: reproduce the problem now (start the download, open the app or run the update that fails), then press Enter'
        Write-Information 'Step 3 of 3: capturing. DoctorDO does not stop or restart DoSvc; verbose logging is turned back off when the capture ends.' -InformationAction Continue
        $result = & $Collect
    } finally {
        if ($enabledByUs) {
            try {
                Disable-DDDOVerboseLogs
                $after = Get-DDDOVerboseLogState
                if ($null -ne $after -and $after -ne $previous) { throw 'verbose logging still reports enabled after Disable-DeliveryOptimizationVerboseLogs' }
            } catch {
                $restoreOk = $false
                $restoreReason = $_.Exception.Message
                $restoreCommand = 'Disable-DeliveryOptimizationVerboseLogs'
                Write-Warning "Could not restore Delivery Optimization verbose logging ($restoreReason). Run this command as administrator: $restoreCommand"
            }
        }
    }
    @{ Result = $result; RestoreOk = $restoreOk; RestoreCommand = $restoreCommand; Reason = $restoreReason; EnabledByCollector = $enabledByUs; EndedBy = $(if ($endedBy) { [string]$endedBy } else { $null }) }
}
