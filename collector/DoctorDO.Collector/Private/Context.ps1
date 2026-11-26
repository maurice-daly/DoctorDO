#Requires -Version 5.1
# Collection context: carries the notCollected list and the salt through a collection run, and turns
# exceptions into typed notCollected records instead of crashes. Uncollectable fields are NEVER silently
# absent (docs/08, contracts/*.schema.json notCollected).

Set-StrictMode -Version Latest

function New-DDContext {
    [CmdletBinding()]
    param(
        [string] $Salt = '',
        [string] $TenantSalt = '',
        [switch] $Anonymise,
        [string] $ComputerName = ''
    )
    [pscustomobject]@{
        Salt         = $Salt
        TenantSalt   = $(if ($TenantSalt) { $TenantSalt } else { $Salt })
        Anonymise    = [bool]$Anonymise
        ComputerName = $ComputerName
        NotCollected = (New-Object 'System.Collections.Generic.List[object]')
    }
}

function Get-DDNotCollectedReason {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $ErrorRecord)

    $ex = $ErrorRecord.Exception
    $msg = [string]$ex.Message
    if ($ex -is [System.Management.Automation.CommandNotFoundException] -or $msg -match 'is not recognized as (the name of )?a cmdlet') { return 'cmdlet-missing' }
    if ($ex -is [System.UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException] -or $msg -match '(?i)access (is )?denied|not authorized|requires elevation|administrator') { return 'insufficient-rights' }
    if ($ex -is [System.PlatformNotSupportedException] -or $ex -is [System.NotSupportedException] -or $msg -match '(?i)not supported|Windows only|invalid namespace|invalid class') { return 'unsupported-os' }
    if ($ex -is [System.TimeoutException] -or $ex -is [System.OperationCanceledException] -or $msg -match '(?i)time(d)? ?out') { return 'timeout' }
    'error'
}

function Add-DDNotCollected {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)][string] $Field,
        [Parameter(Mandatory)][ValidateSet('unsupported-os', 'insufficient-rights', 'cmdlet-missing', 'timeout', 'skipped-by-flag', 'error')][string] $Reason,
        [string] $Detail = ''
    )
    foreach ($e in $Context.NotCollected) { if ($e['field'] -eq $Field) { return } }
    $rec = [ordered]@{ field = $Field; reason = $Reason }
    if ($Detail) {
        $d = Protect-DDLogText -Text $Detail
        $rec['detail'] = $d.Substring(0, [math]::Min(200, $d.Length))
    }
    $Context.NotCollected.Add($rec)
    Write-DDVerboseStep -Step "  not collected: $Field" -Result $Reason
}

function Invoke-DDStep {
    <#
    .SYNOPSIS
        Run one collection step. On failure record notCollected for -Field and return -Default.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [Parameter(Mandatory)][string] $Field,
        [Parameter(Mandatory)][scriptblock] $Script,
        $Default = $null
    )
    try {
        & $Script
    } catch {
        Add-DDNotCollected -Context $Context -Field $Field -Reason (Get-DDNotCollectedReason -ErrorRecord $_) -Detail $_.Exception.Message
        $Default
    }
}

function Get-DDProp {
    # First non-null property among candidate names (strict-mode safe, case-insensitive). Works on objects and dictionaries.
    [CmdletBinding()]
    param($Object, [Parameter(Mandatory)][string[]] $Name)
    if ($null -eq $Object) { return $null }
    foreach ($n in $Name) {
        if ($Object -is [System.Collections.IDictionary]) {
            foreach ($k in $Object.Keys) { if ([string]$k -ieq $n -and $null -ne $Object[$k]) { return $Object[$k] } }
        } else {
            $p = $Object.PSObject.Properties[$n]
            if ($null -ne $p -and $null -ne $p.Value) { return $p.Value }
        }
    }
    $null
}

function Format-DDIso {
    [CmdletBinding()]
    param([Parameter(Mandatory)][datetime] $Value)
    $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}
