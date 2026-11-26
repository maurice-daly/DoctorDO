#Requires -Version 5.1
# Local deep-diagnostic bundle (BundleV1 + manifest, zipped). Nothing is uploaded: there is no endpoint in this path.

Set-StrictMode -Version Latest

function Get-DDFileSha256 {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { (($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant() } finally { $fs.Dispose(); $sha.Dispose() }
}

function Add-DDZipEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Archive, [Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][string] $Text)
    $entry = $Archive.CreateEntry($Name, [System.IO.Compression.CompressionLevel]::Optimal)
    $stream = $entry.Open()
    try {
        $b = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
        $stream.Write($b, 0, $b.Length)
    } finally { $stream.Dispose() }
}

function ConvertTo-DDBundleDocument {
    # BundleV1 forbids unknown top-level keys' meaning but tolerates them; keep exactly the contract's keys.
    # perfSnapMonth is no longer written (retired 19 Oct 2026): the contract keeps it optional only so older bundles still validate.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Raw)
    $keys = 'schemaVersion', 'collector', 'collectedAt', 'mode', 'anonymised', 'device', 'network', 'doConfig', 'firewallRules', 'status', 'peerInfo', 'connections', 'perfSnap', 'doMonth', 'connectivity', 'errors', 'logExcerpt', 'notCollected'
    $b = [ordered]@{}
    foreach ($k in $keys) { if ($Raw.Contains($k)) { $b[$k] = $Raw[$k] } }
    # doConfig.stores must hold only the five known stores.
    $b['doConfig'] = [ordered]@{ effective = $Raw['doConfig']['effective']; stores = $Raw['doConfig']['stores'] }
    if ($Raw['doConfig'].Contains('workingDirectory')) { $b['doConfig']['workingDirectory'] = $Raw['doConfig']['workingDirectory'] }
    if ($Raw['doConfig'].Contains('cacheFolder')) { $b['doConfig']['cacheFolder'] = $Raw['doConfig']['cacheFolder'] }
    $b
}

function New-DDBundleFile {
    <#
    .SYNOPSIS
        Write doctordo-<timestamp>.zip containing manifest.json, bundle.json and optionally doctordo.log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Raw,
        [Parameter(Mandatory)][string] $OutputPath,
        [string] $LogText,
        [Parameter(Mandatory)][datetime] $Now,
        # Further text files for the local bundle only (Get-DDLocalBundleExtras): name -> text.
        [System.Collections.IDictionary] $Extras = $null,
        # What the guided reproduction did, when it ran (Invoke-DDVerboseCycle).
        $Reproduction = $null
    )
    Add-Type -Verbose:$false -AssemblyName System.IO.Compression
    Add-Type -Verbose:$false -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath -Force) }
    $zipPath = Join-Path -Path $OutputPath -ChildPath ('doctordo-{0}.zip' -f $Now.ToString('yyyyMMdd-HHmmss', [System.Globalization.CultureInfo]::InvariantCulture))
    $bundle = ConvertTo-DDBundleDocument -Raw $Raw
    $bundleJson = ConvertTo-Json -InputObject $bundle -Compress -Depth 32
    $files = New-Object 'System.Collections.Generic.List[object]'
    $sha = { param($t) $h = [System.Security.Cryptography.SHA256]::Create(); try { (($h.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($t)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $h.Dispose() } }
    $files.Add([ordered]@{ name = 'bundle.json'; sha256 = (& $sha $bundleJson); bytes = (New-Object System.Text.UTF8Encoding($false)).GetByteCount($bundleJson) })
    if ($LogText) { $files.Add([ordered]@{ name = 'doctordo.log'; sha256 = (& $sha $LogText); bytes = (New-Object System.Text.UTF8Encoding($false)).GetByteCount($LogText) }) }
    $extraNames = @()
    if ($Extras) {
        foreach ($k in @($Extras.Keys)) {
            $t = [string]$Extras[$k]
            if (-not $t) { continue }
            $files.Add([ordered]@{ name = [string]$k; sha256 = (& $sha $t); bytes = (New-Object System.Text.UTF8Encoding($false)).GetByteCount($t) })
            $extraNames += [string]$k
        }
    }
    $manifest = [ordered]@{
        schemaVersion = 1
        collector     = $Raw['collector']
        collectedAt   = $Raw['collectedAt']
        anonymised    = $Raw['anonymised']
        mode          = $Raw['mode']
        files         = $files.ToArray()
        notCollected  = $Raw['notCollected']
    }
    if ($null -ne $Reproduction) { $manifest['reproduction'] = $Reproduction }
    $tmp = $zipPath + '.tmp'
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    $fs = New-Object System.IO.FileStream($tmp, [System.IO.FileMode]::CreateNew)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            Add-DDZipEntry -Archive $zip -Name 'manifest.json' -Text (ConvertTo-Json -InputObject $manifest -Compress -Depth 32)
            Add-DDZipEntry -Archive $zip -Name 'bundle.json' -Text $bundleJson
            if ($LogText) { Add-DDZipEntry -Archive $zip -Name 'doctordo.log' -Text $LogText }
            foreach ($k in $extraNames) { Add-DDZipEntry -Archive $zip -Name $k -Text ([string]$Extras[$k]) }
        } finally { $zip.Dispose() }
    } finally { $fs.Dispose() }
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    Move-Item -LiteralPath $tmp -Destination $zipPath
    [pscustomobject]@{ BundlePath = $zipPath; Sha256 = (Get-DDFileSha256 -Path $zipPath); BundleJson = $bundleJson }
}

function Get-DDLocalBundleExtras {
    <#
    .SYNOPSIS
        What only the admin-run local bundle carries beside bundle.json, never a fleet report: an export of the DoSvc service
        key (HKLM\SYSTEM\CurrentControlSet\Services\DoSvc, values and subkeys, read-only) and the network cost
        INetworkCostManager reports (`netsh nlm show cost`). `netsh nlm query all` is not run: it lists network names and
        SSIDs. Text passes the log-line scrub; a source that cannot be read is named in the returned Missing list.
    #>
    [CmdletBinding()]
    param([switch] $Anonymise, [string] $Salt = '', [string] $ComputerName = '', [AllowNull()][AllowEmptyCollection()][string[]] $DsregText = $null)
    $files = [ordered]@{}
    $missing = New-Object 'System.Collections.Generic.List[string]'
    try {
        $tree = Get-DDRegistryTree -Path 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' -Depth 3
        $files['dosvc-registry.json'] = Protect-DDLogText -Text (ConvertTo-Json -InputObject $tree -Depth 16) -Anonymise:$Anonymise -Salt $Salt -ComputerName $ComputerName
    } catch { $missing.Add("dosvc-registry.json: $($_.Exception.Message)") }
    try {
        $cost = @(Get-DDNlmCostText)
        if ($cost.Count -gt 0) { $files['nlm-cost.txt'] = Protect-DDLogText -Text (($cost | Select-Object -First 200) -join "`r`n") -Anonymise:$Anonymise -Salt $Salt -ComputerName $ComputerName }
    } catch { $missing.Add("nlm-cost.txt: $($_.Exception.Message)") }
    # `dsregcmd /status` as an admin would read it (1.3.1 of Microsoft's troubleshooter adds it to its support bundle). The text the
    # collection already read is reused; the fleet report never carries it (only the parsed join type, tenant and device id).
    try {
        $ds = $(if ($PSBoundParameters.ContainsKey('DsregText') -and $null -ne $DsregText) { @($DsregText) } else { @(Get-DDDsregStatusText) })
        if (@($ds).Count -gt 0) { $files['dsregcmd-status.txt'] = Protect-DDDsregText -Lines $ds -Anonymise:$Anonymise -Salt $Salt -ComputerName $ComputerName }
    } catch { $missing.Add("dsregcmd-status.txt: $($_.Exception.Message)") }
    [pscustomobject]@{ Files = $files; Missing = $missing.ToArray() }
}

function Protect-DDDsregText {
    <#
    .SYNOPSIS
        `dsregcmd /status` text for the local bundle: the log-line scrub always (UPNs, profile paths, URL queries); under
        -Anonymise also every GUID (tenant id, device id, key container, Intune ids), every certificate thumbprint or other long
        hex string, the tenant and domain names and the executing account. Documented fields:
        https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][AllowEmptyString()][string[]] $Lines = @(), [switch] $Anonymise, [string] $Salt = '', [string] $ComputerName = '')

    $text = (@($Lines) | ForEach-Object { ([string]$_).TrimEnd() }) -join "`r`n"
    $t = Protect-DDLogText -Text $text -Anonymise:$Anonymise -Salt $Salt -ComputerName $ComputerName
    if ($Anonymise) {
        $t = Hide-DDDsregIdentity -Raw $text -Scrubbed $t
        $t = [regex]::Replace($t, '\{?[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}?', '<guid>')
        $t = [regex]::Replace($t, '\b[0-9a-fA-F]{32,}\b', '<hex>')
    }
    $t
}

# Hosts that name Microsoft's own service, not the customer: kept in clear in the anonymised dsregcmd text because an admin needs
# them (which sign-in or registration endpoint, https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd).
# THE one place to extend. A host is kept when it equals a suffix or ends with `.<suffix>`; every other URL or UNC host is masked.
$script:DDDsregPublicHostSuffixes = @(
    'microsoft.com', 'microsoftonline.com', 'microsoftonline-p.com', 'windows.net', 'windows.com', 'live.com',
    'office.com', 'office365.com', 'azure.com', 'msauth.net', 'msftauth.net', 'aka.ms'
)
# Under an allowed suffix but named by the customer (`<account>.blob.core.windows.net`): masked all the same.
$script:DDDsregCustomerNamedHostSuffixes = @('core.windows.net')

function Test-DDDsregPublicHost {
    # True when -HostName is a Microsoft-owned host from the allow-list above. Pure.
    [CmdletBinding()]
    param([AllowEmptyString()][string] $HostName)
    $h = $HostName.Trim().TrimEnd('.').ToLowerInvariant()
    if ($h.Length -eq 0) { return $false }
    foreach ($c in $script:DDDsregCustomerNamedHostSuffixes) { if ($h -eq $c -or $h.EndsWith('.' + $c)) { return $false } }
    foreach ($a in $script:DDDsregPublicHostSuffixes) { if ($h -eq $a -or $h.EndsWith('.' + $a)) { return $true } }
    $false
}

function Hide-DDDsregHosts {
    # The host part of every URL (`scheme://host`) and UNC path (`\\host\share`) in the text becomes <host>, except Microsoft's own
    # (Test-DDDsregPublicHost). Port, path and share stay. Pure.
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Text = '')
    $t = [regex]::Replace($Text, '(?i)\b([a-z][a-z0-9+.-]*://)(\[[^\]\s]*\]|[^/\s:?#"''<>\\@]+)', {
            param($m)
            if (Test-DDDsregPublicHost -HostName $m.Groups[2].Value) { return $m.Value }
            $m.Groups[1].Value + '<host>'
        })
    [regex]::Replace($t, '(?<![\\\w])\\\\([^\\\s"''<>|:*?/]+)', {
            param($m)
            $h = $m.Groups[1].Value
            if ($h -eq '.' -or (Test-DDDsregPublicHost -HostName $h)) { return $m.Value }
            '\\<host>'
        })
}

function Hide-DDDsregIdentity {
    <#
    .SYNOPSIS
        The identity half of the -Anonymise scrub of `dsregcmd /status` text (Protect-DDDsregText): names, accounts, domains
        and free-text diagnostics, line by line. GUIDs and long hex strings are left to the caller.
    .DESCRIPTION
        * a line `Key : value` whose key names an identity (tenant, domain, device, account, user) has its value removed;
          `Device Name` becomes <host>;
        * a line whose key says `Error`, `Message`, `Diagnostics Reference` or `Prt Attempt` has its value removed, and so do
          the continuation lines that follow it, because Entra writes the user, the domain and the tenant display name into
          those messages. A value that is only a code (hex or decimal) stays: an admin reads it, and it names nobody;
          A line that follows a blanked one and is aligned under its value (or whose key does not start with a capital) is a
          continuation whatever its shape, `second line : ... alice` included. A capitalised `Key : value` line indented less
          than that cannot be told from the next real field and is kept (the learned names are still removed from it);
        * every value the identity lines held (tenant, domain, account and user names of any length, the domain part of an FQDN)
          is then removed wherever else it appears, as a whole token;
        * the host of every URL and UNC path is masked (`https://sts.contoso.com/adfs`, `\\dc01.corp.contoso.com`), except
          Microsoft's own hosts ($script:DDDsregPublicHostSuffixes, the one allow-list);
        * `<host>.corp.contoso.com` loses its domain suffix, and a down-level logon name (`DOMAIN\user`) becomes <account>.
    .PARAMETER Raw
        The text before any scrub, from which the identity values are read.
    .PARAMETER Scrubbed
        The same text after Protect-DDLogText; this is what is returned, changed.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Raw = '', [AllowEmptyString()][string] $Scrubbed = '')

    $keyLine = '^(?<ind>\s*)(?<key>[A-Za-z][A-Za-z0-9 ]*?)(?<sep>\s+:)(?<val>.*)$'
    $identityKey = '^(?i:Tenant ?Name|Workplace ?Tenant ?Name|Domain ?Name|Workplace ?Idp ?Domain|Idp ?Domain|Device ?Name|Executing Account Name|Work Account|User Principal Name|User ?Identity|(?:Workplace )?User ?Name|Display ?Name|Network ?Name)$'
    $freeTextKey = '(?i)error|message|diagnostics? ?reference|prt attempt'
    $codeOnly = '^(?:0[xX][0-9A-Fa-f]{1,8}|-?\d{1,10})$'

    # 1. what the identity lines hold in the raw text
    $secrets = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $add = {
        param($s)
        $s = ([string]$s).Trim().Trim('{', '}', '"', "'")
        if ($s.Length -lt 1 -or $s.StartsWith('<') -or $s -match '^(?i:yes|no|none|null|unknown|n/a|not set)$') { return }
        [void]$secrets.Add($s)
    }
    foreach ($line in ($Raw -split "\r?\n")) {
        $m = [regex]::Match($line, $keyLine)
        if (-not $m.Success -or $m.Groups['key'].Value.Trim() -notmatch $identityKey) { continue }
        foreach ($part in ($m.Groups['val'].Value -split '[,;]')) {
            $v = $part.Trim()
            if (-not $v) { continue }
            & $add $v
            if ($v.Contains('\')) { foreach ($side in $v.Split('\')) { & $add $side } }
            if ($v.Contains('@')) { foreach ($side in $v.Split('@')) { & $add $side } }
            $dot = $v.IndexOf('.')
            if ($dot -gt 0 -and $v -notmatch '\s' -and -not $v.Contains('@') -and -not $v.Contains('\')) {
                # a host or domain name: its first label, and the domain behind it when that has two labels or more
                & $add $v.Substring(0, $dot)
                $suffix = $v.Substring($dot + 1)
                if ($suffix.Contains('.')) { & $add $suffix }
            }
        }
    }

    # 2. line by line
    $out = New-Object 'System.Collections.Generic.List[string]'
    $continuation = $false
    $colon = 0
    foreach ($line in ($Scrubbed -split "\r?\n")) {
        $m = [regex]::Match($line, $keyLine)
        if ($m.Success -and $continuation) {
            # A `key : value` shaped line inside a blanked value is still the value (Entra writes whatever text it likes there):
            # it is aligned under the value, or its "key" is not a field name (those start with a capital).
            if ($m.Groups['ind'].Value.Length -ge $colon -or $m.Groups['key'].Value -cnotmatch '^[A-Z0-9]') { continue }
        }
        if ($m.Success) {
            $continuation = $false
            $key = $m.Groups['key'].Value.Trim(); $val = $m.Groups['val'].Value.Trim()
            $head = $m.Groups['ind'].Value + $m.Groups['key'].Value + $m.Groups['sep'].Value + ' '
            if ($key -match $identityKey) {
                $out.Add($head + $(if ($key -match '^(?i:Device ?Name)$') { '<host>' } else { '<removed>' }))
            } elseif ($key -match $freeTextKey -and $val -and $val -notmatch $codeOnly) {
                $out.Add($head + '<removed>')
                $continuation = $true
                $colon = $m.Groups['ind'].Value.Length + $m.Groups['key'].Value.Length + $m.Groups['sep'].Value.Length - 1
            } else { $out.Add($line) }
            continue
        }
        if ($continuation) {
            if ($line.Trim() -eq '' -or $line.TrimStart().StartsWith('+') -or $line.TrimStart().StartsWith('|')) { $continuation = $false; $out.Add($line) }
            continue
        }
        $out.Add($line)
    }
    $t = $out -join "`r`n"

    # 3. the same names anywhere else, longest first so a domain goes before its first label
    foreach ($s in ($secrets | Sort-Object -Property Length -Descending)) {
        $t = [regex]::Replace($t, '(?<![A-Za-z0-9])' + [regex]::Escape($s) + '(?![A-Za-z0-9])', '<removed>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
    $t = Hide-DDDsregHosts -Text $t
    $t = [regex]::Replace($t, '<host>(?:\.(?:[A-Za-z0-9-]+|<removed>))+', '<host>')
    $t = [regex]::Replace($t, '[\w.-]+\\[\w.$-]+', '<account>')
    $t
}

function Set-DDLastSuccess {
    # HKLM\SOFTWARE\DoctorDO: LastSuccessfulCollection (ISO 8601 UTC) read by the Intune detection script.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Kind, [Parameter(Mandatory)][string] $Timestamp)
    if (-not (Test-DDWindows)) { return }
    $path = 'HKLM:\SOFTWARE\DoctorDO'
    if (-not (Test-Path -LiteralPath $path)) { [void](New-Item -Path $path -Force) }
    Set-ItemProperty -LiteralPath $path -Name 'LastSuccessfulCollection' -Value $Timestamp -Type String
    Set-ItemProperty -LiteralPath $path -Name 'LastReportKind' -Value $Kind -Type String
}
