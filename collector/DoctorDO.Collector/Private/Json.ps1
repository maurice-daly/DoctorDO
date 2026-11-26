#Requires -Version 5.1
# JSON helpers shared by compaction, hashing and the golden tests.
#
# Why not ConvertFrom-Json: on PowerShell 7.4 it turns ISO 8601 strings into [datetime], which silently
# changes `collectedAt` and every timestamp on the way through (-DateKind arrived in 7.5). The wire
# contract is strings, so parsing is done here and dates stay strings on 5.1 and 7+.
#
# Parsed objects are [ordered] dictionaries (OrderedDictionary) and object[] arrays; numbers are [long]
# or [double]. Nothing in this file touches Windows-only APIs.

Set-StrictMode -Version Latest

function ConvertFrom-DDJsonElement {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Element)

    switch ($Element.ValueKind.ToString()) {
        'Object' {
            $o = [ordered]@{}
            foreach ($p in $Element.EnumerateObject()) { $o[$p.Name] = ConvertFrom-DDJsonElement -Element $p.Value }
            return $o
        }
        'Array' {
            $l = New-Object 'System.Collections.Generic.List[object]'
            foreach ($i in $Element.EnumerateArray()) { $l.Add((ConvertFrom-DDJsonElement -Element $i)) }
            return , $l.ToArray()
        }
        'String' { return $Element.GetString() }
        'Number' {
            $n = [long]0
            if ($Element.TryGetInt64([ref]$n)) { return $n }
            return $Element.GetDouble()
        }
        'True' { return $true }
        'False' { return $false }
        default { return $null }
    }
}

function ConvertFrom-DDLegacyJsonValue {
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) { $o[[string]$k] = ConvertFrom-DDLegacyJsonValue -Value $Value[$k] }
        return $o
    }
    if ($Value -is [string] -or $Value -is [bool]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = New-Object 'System.Collections.Generic.List[object]'
        foreach ($i in $Value) { $l.Add((ConvertFrom-DDLegacyJsonValue -Value $i)) }
        return , $l.ToArray()
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) { return [long]$Value }
    if ($Value -is [decimal]) {
        if ($Value -eq [math]::Truncate($Value) -and [math]::Abs($Value) -lt 9e18) { return [long]$Value }
        return [double]$Value
    }
    if ($Value -is [double] -or $Value -is [single]) { return [double]$Value }
    return $Value
}

function ConvertFrom-DDJson {
    <#
    .SYNOPSIS
        Parse JSON text into ordered dictionaries and object[] arrays, keeping dates as strings.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Text)

    if ('System.Text.Json.JsonDocument' -as [type]) {
        $doc = [System.Text.Json.JsonDocument]::Parse($Text)
        try { return ConvertFrom-DDJsonElement -Element $doc.RootElement } finally { $doc.Dispose() }
    }
    Add-Type -Verbose:$false -AssemblyName System.Web.Extensions
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int]::MaxValue
    $ser.RecursionLimit = 256
    return ConvertFrom-DDLegacyJsonValue -Value ($ser.DeserializeObject($Text))
}

function Read-DDJsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    ConvertFrom-DDJson -Text ([System.IO.File]::ReadAllText($Path, (New-Object System.Text.UTF8Encoding($false))))
}

function ConvertTo-DDJsonString {
    # Mirrors JSON.stringify string escaping exactly: quote, backslash, \b \f \n \r \t, other control
    # characters as \u00xx (lower-case hex), lone surrogates as \udxxx, everything else verbatim.
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Value)

    $sb = New-Object System.Text.StringBuilder ($Value.Length + 2)
    [void]$sb.Append('"')
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $c = $Value[$i]
        $code = [int]$c
        if ($c -eq '"') { [void]$sb.Append('\"') }
        elseif ($c -eq '\') { [void]$sb.Append('\\') }
        elseif ($code -eq 8) { [void]$sb.Append('\b') }
        elseif ($code -eq 12) { [void]$sb.Append('\f') }
        elseif ($code -eq 10) { [void]$sb.Append('\n') }
        elseif ($code -eq 13) { [void]$sb.Append('\r') }
        elseif ($code -eq 9) { [void]$sb.Append('\t') }
        elseif ($code -lt 32) { [void]$sb.Append('\u').Append($code.ToString('x4')) }
        elseif ($code -ge 0xD800 -and $code -le 0xDBFF) {
            if ($i + 1 -lt $Value.Length -and [int]$Value[$i + 1] -ge 0xDC00 -and [int]$Value[$i + 1] -le 0xDFFF) {
                [void]$sb.Append($c).Append($Value[$i + 1]); $i++
            } else { [void]$sb.Append('\u').Append($code.ToString('x4')) }
        }
        elseif ($code -ge 0xDC00 -and $code -le 0xDFFF) { [void]$sb.Append('\u').Append($code.ToString('x4')) }
        else { [void]$sb.Append($c) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function Write-DDCanonicalValue {
    [CmdletBinding()]
    param($Value, [System.Text.StringBuilder] $Builder)

    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($null -eq $Value) { [void]$Builder.Append('null'); return }
    if ($Value -is [string]) { [void]$Builder.Append((ConvertTo-DDJsonString -Value $Value)); return }
    if ($Value -is [bool]) { [void]$Builder.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [System.Numerics.BigInteger]) { [void]$Builder.Append((ConvertTo-DDJsonString -Value $Value.ToString())); return }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [sbyte]) {
        [void]$Builder.Append(([System.Convert]::ToString($Value, $inv))); return
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $d = [double]$Value
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { [void]$Builder.Append('null'); return }
        if ($d -eq [math]::Truncate($d) -and [math]::Abs($d) -lt 1e15) { [void]$Builder.Append(([long]$d).ToString($inv)) }
        else { [void]$Builder.Append($d.ToString('R', $inv)) }
        return
    }
    if ($Value -is [datetime]) { [void]$Builder.Append((ConvertTo-DDJsonString -Value $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $inv))); return }
    if ($Value -is [System.Enum]) { [void]$Builder.Append((ConvertTo-DDJsonString -Value $Value.ToString())); return }

    $isDict = $Value -is [System.Collections.IDictionary]
    $isObj = $Value -is [System.Management.Automation.PSCustomObject]
    if ($isDict -or $isObj) {
        $names = New-Object 'System.Collections.Generic.List[string]'
        $get = @{}
        if ($isDict) { foreach ($k in $Value.Keys) { $names.Add([string]$k); $get[[string]$k] = $Value[$k] } }
        else { foreach ($p in $Value.PSObject.Properties) { $names.Add($p.Name); $get[$p.Name] = $p.Value } }
        $arr = $names.ToArray()
        [Array]::Sort($arr, [System.StringComparer]::Ordinal)
        [void]$Builder.Append('{')
        $first = $true
        foreach ($n in $arr) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            [void]$Builder.Append((ConvertTo-DDJsonString -Value $n)).Append(':')
            Write-DDCanonicalValue -Value $get[$n] -Builder $Builder
        }
        [void]$Builder.Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        [void]$Builder.Append('[')
        $first = $true
        foreach ($i in $Value) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            Write-DDCanonicalValue -Value $i -Builder $Builder
        }
        [void]$Builder.Append(']')
        return
    }
    [void]$Builder.Append((ConvertTo-DDJsonString -Value ([string]$Value)))
}

function ConvertTo-DDCanonicalJson {
    <#
    .SYNOPSIS
        Canonical JSON identical to packages/wire canonicalJson: keys sorted (UTF-16 ordinal), no
        whitespace, BigInteger as a decimal string.
    #>
    [CmdletBinding()]
    param([AllowNull()] $InputObject)

    $sb = New-Object System.Text.StringBuilder
    Write-DDCanonicalValue -Value $InputObject -Builder $sb
    $sb.ToString()
}

function Get-DDSha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($Text))
        (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Get-DDInventoryHash {
    <#
    .SYNOPSIS
        sha256 of the canonical inventory excluding collectedAt and notCollected (packages/wire inventoryHash).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Inventory)

    $stable = [ordered]@{}
    if ($Inventory -is [System.Collections.IDictionary]) {
        foreach ($k in $Inventory.Keys) { if ($k -ne 'collectedAt' -and $k -ne 'notCollected') { $stable[$k] = $Inventory[$k] } }
    } else {
        foreach ($p in $Inventory.PSObject.Properties) { if ($p.Name -ne 'collectedAt' -and $p.Name -ne 'notCollected') { $stable[$p.Name] = $p.Value } }
    }
    'sha256:' + (Get-DDSha256Hex -Text (ConvertTo-DDCanonicalJson -InputObject $stable))
}

# ---- byte counters ---------------------------------------------------------------------------------------

function ConvertTo-DDBigInt {
    # ByteCount on the wire is a non-negative decimal string or an integer. Never throws: a counter it cannot read is 0, so
    # one odd value cannot fail a whole collection (the job list is mapped outside Invoke-DDStep).
    [CmdletBinding()]
    param($Value)

    if ($null -eq $Value) { return [System.Numerics.BigInteger]::Zero }
    if ($Value -is [System.Numerics.BigInteger]) { return $Value }
    $r = [System.Numerics.BigInteger]::Zero
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if ([System.Numerics.BigInteger]::TryParse($t, [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$r)) { return $r }
        return [System.Numerics.BigInteger]::Zero
    }
    # A UInt64 above 2^63 - 1 (DO's counters are unsigned) does not fit the [long] cast below.
    if ($Value -is [uint64]) { return [System.Numerics.BigInteger]::new([uint64]$Value) }
    try {
        if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { return [System.Numerics.BigInteger][math]::Truncate([double]$Value) }
        return [System.Numerics.BigInteger]([long]$Value)
    } catch {
        if ([System.Numerics.BigInteger]::TryParse(([string]$Value).Trim(), [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$r)) { return $r }
        [System.Numerics.BigInteger]::Zero
    }
}

function ConvertTo-DDByteCount {
    # A number when exact (<= 2^53 - 1), otherwise a decimal string. Mirrors `bc` in packages/wire.
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Numerics.BigInteger] $Value)

    if ($Value -le [System.Numerics.BigInteger]9007199254740991) { return [long]$Value }
    $Value.ToString()
}
