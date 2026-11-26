#Requires -Version 5.1
# Redaction and hashing. Pure functions (the machine name is passed in), driven by Data/redaction-profile.json.
# Hashing is pseudonymisation, not anonymity: private address space is small enough to enumerate if the salt
# is known, which is why the salt for device-level values stays in the protected state file.

Set-StrictMode -Version Latest

function Get-DDRedactionProfile {
    [CmdletBinding()]
    param()
    Read-DDJsonFile -Path (Join-Path -Path $script:ModuleRoot -ChildPath 'Data/redaction-profile.json')
}

function Get-DDSaltedHash {
    # 'sha256:<64 hex>' of "<domain>|<salt>|<value>". Domain separation keeps a serial hash from equalling an IP hash.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Value, [Parameter(Mandatory)][string] $Salt, [Parameter(Mandatory)][string] $Domain)
    'sha256:' + (Get-DDSha256Hex -Text ('{0}|{1}|{2}' -f $Domain, $Salt, $Value))
}

function Get-DDShortHash {
    # 16 hex characters, same function, for peers (telemetry topPeers.h) and tagged topology values.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string] $Value, [Parameter(Mandatory)][string] $Salt, [Parameter(Mandatory)][string] $Domain)
    (Get-DDSaltedHash -Value $Value -Salt $Salt -Domain $Domain).Substring(7, 16)
}

function ConvertTo-DDIPv4Number {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip) -or $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    $b = $ip.GetAddressBytes()
    [uint32](([uint32]$b[0] -shl 24) -bor ([uint32]$b[1] -shl 16) -bor ([uint32]$b[2] -shl 8) -bor [uint32]$b[3])
}

function Get-DDSubnetString {
    # '10.20.4.71', 22 -> '10.20.4.0/22'
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Address, [Parameter(Mandatory)][ValidateRange(0, 32)][int] $PrefixLength)
    $n = ConvertTo-DDIPv4Number -Address $Address
    if ($null -eq $n) { return $null }
    $mask = [uint32]0
    if ($PrefixLength -gt 0) { $mask = [uint32](([uint64]4294967295 -shl (32 - $PrefixLength)) -band 4294967295) }
    $net = [uint32]($n -band $mask)
    '{0}.{1}.{2}.{3}/{4}' -f (($net -shr 24) -band 255), (($net -shr 16) -band 255), (($net -shr 8) -band 255), ($net -band 255), $PrefixLength
}

function Test-DDLinkLocal {
    # 169.254.0.0/16 (RFC 3927) or fe80::/10 (RFC 4291): an address that is valid only on the link it is used on.
    [CmdletBinding()]
    param([AllowNull()][System.Net.IPAddress] $Ip)
    if ($null -eq $Ip) { return $false }
    if ($Ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $Ip.IsIPv6LinkLocal }
    $b = $Ip.GetAddressBytes()
    ($b[0] -eq 169 -and $b[1] -eq 254)
}

function Test-DDInPrefix {
    # Whether two addresses of one family share their first -PrefixLength bits.
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Net.IPAddress] $A, [Parameter(Mandatory)][System.Net.IPAddress] $B, [Parameter(Mandatory)][int] $PrefixLength)
    if ($A.AddressFamily -ne $B.AddressFamily) { return $false }
    $x = $A.GetAddressBytes(); $y = $B.GetAddressBytes()
    $bits = [math]::Max(0, [math]::Min($PrefixLength, $x.Length * 8))
    for ($i = 0; $i -lt $x.Length; $i++) {
        $left = $bits - ($i * 8)
        if ($left -le 0) { break }
        $mask = $(if ($left -ge 8) { 255 } else { (255 -shl (8 - $left)) -band 255 })
        if (($x[$i] -band $mask) -ne ($y[$i] -band $mask)) { return $false }
    }
    $true
}

function Test-DDSameSubnet {
    <#
    .SYNOPSIS
        Whether a peer address is on this device's own network: in the IPv4 subnet of -LocalAddress/-PrefixLength; a link-local
        address (169.254.0.0/16, fe80::/10), which by definition is on the same link; or, for IPv6, inside one of
        -LocalNetworks, the device's own IPv6 prefixes as 'address/length' (Get-DDNetworkFacts LocalNetworks).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Address, [Parameter(Mandatory)][AllowEmptyString()][string] $LocalAddress, [Parameter(Mandatory)][int] $PrefixLength,
        [AllowNull()][AllowEmptyCollection()][string[]] $LocalNetworks = @()
    )
    $ip = $null
    $text = $Address.Trim().TrimStart('[').TrimEnd(']')
    if (-not [System.Net.IPAddress]::TryParse($text, [ref]$ip)) { return $false }
    if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    if (Test-DDLinkLocal -Ip $ip) { return $true }
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        foreach ($n in @($LocalNetworks | Where-Object { $_ })) {
            $parts = ([string]$n).Split('/')
            $local = $null; $len = 64
            if ($parts.Count -eq 2 -and -not [int]::TryParse($parts[1], [ref]$len)) { continue }
            if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$local) -or $local.AddressFamily -ne $ip.AddressFamily) { continue }
            if (Test-DDInPrefix -A $ip -B $local -PrefixLength $len) { return $true }
        }
        return $false
    }
    if ([string]::IsNullOrEmpty($LocalAddress)) { return $false }
    $a = Get-DDSubnetString -Address $ip.ToString() -PrefixLength $PrefixLength
    $b = Get-DDSubnetString -Address $LocalAddress -PrefixLength $PrefixLength
    ($null -ne $a) -and ($a -eq $b)
}

function Protect-DDTopologyValue {
    # Internal hostnames and addresses (DOCacheHost, DHCP 235, PAC host, gateway) -> '<tag>:<16 hex>'.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Value, [Parameter(Mandatory)][string] $Salt, [string] $Tag = 'host')
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    '{0}:{1}' -f $Tag, (Get-DDShortHash -Value $Value.Trim().ToLowerInvariant() -Salt $Salt -Domain 'topology')
}

function Get-DDUrlHost {
    [CmdletBinding()]
    param([AllowNull()][string] $Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    $u = $null
    if ([System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$u)) { return $u.Host.ToLowerInvariant() }
    $null
}

function Protect-DDUrlText {
    # Reduce every URL in a text to scheme://host/<up to 2 non-identifier path segments>; drop query/fragment.
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Text)

    [regex]::Replace($Text, '(?i)\b(https?)://([^/\s"''<>?#]+)([^\s"''<>?#]*)[^\s"''<>]*', {
            param($m)
            $all = @($m.Groups[3].Value.Split('/') | Where-Object { $_ -ne '' })
            $segs = @($all | Where-Object { $_ -notmatch '^[0-9a-fA-F-]{8,}$' } | Select-Object -First 2)
            $path = ''
            if ($segs.Count -gt 0) { $path = '/' + ($segs -join '/') }
            # A path kept whole keeps its trailing slash, so a line scrubbed twice reads the same (https://host/Users/<user>).
            if ($segs.Count -eq $all.Count -and $m.Groups[3].Value.EndsWith('/')) { $path += '/' }
            '{0}://{1}{2}' -f $m.Groups[1].Value.ToLowerInvariant(), $m.Groups[2].Value.ToLowerInvariant(), $path
        })
}

# The account forms the baseline scrub replaces in free text (log lines, error samples, notCollected details, firewall rule
# names and programs). Each is a pattern over text, not a parse, so a form that is not listed here can get through; the list
# and what still gets through are tested form by form (Unit.Tests.ps1) and stated in docs/10 section 9. apps/api/src/errors.ts
# scrubLine repeats the same patterns on the server.
# - a profile folder after \Users\ or \Documents and Settings\, with any drive or prefix (C:\, C:/, \\?\C:\, \\host\c$\,
#   \Device\HarddiskVolume3\, %SystemDrive%\, file:///C:/, and JSON's doubled C:\\Users\\), a name with spaces included when
#   a path separator follows it;
$script:DDProfilePathRx = '(?i)([\\/](?:Users|Documents and Settings)\\?[\\/])(?:[^\\/"''<>|:*?\r\n]{1,64}(?=[\\/])|[^\\/\s"''<>|:*?]+)'
# - everything after the server of a UNC path (\\server\<path>; \\?\UNC\server\ too), since a share or folder can be named
#   after its user;
$script:DDUncPathRx = '(?<![\\\w])\\\\((?:\?\\UNC\\)?[A-Za-z0-9][A-Za-z0-9._$-]*)(?:\\[^\\/"''<>|:*?\r\n]{1,64}(?=\\))*\\[^\\/\s"''<>|:*?]+'
# - the account in DOMAIN\account: AzureAD\ and MicrosoftAccount\ in any case, otherwise an upper-case NetBIOS name (up to
#   15 characters, as Windows writes them), and only where the account is not followed by another path segment, so
#   C:\Program Files\Foo\foo.exe and registry paths are left alone. Built-in principals (NT AUTHORITY\, NT SERVICE\,
#   BUILTIN\, IIS APPPOOL\) and registry roots are not accounts and are kept;
$script:DDDomainAccountRx = '(?<![\w\\/:.%$@-])(?!(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_[A-Z_]+|SOFTWARE|SYSTEM|HARDWARE|SAM|SECURITY|AUTHORITY|SERVICE|BUILTIN|APPPOOL|MACHINE)\\)((?i:AzureAD|MicrosoftAccount)|[A-Z][A-Z0-9-]{1,14})\\(?>[^\\/\s"''<>|:*?,;()\[\]=]+)(?![\\/])'
# - a user's security identifier (S-1-5-21-<domain>-<RID>, and S-1-12-1-... for Microsoft Entra accounts); a domain SID
#   without a RID (one of DO's group ID sources) is kept.
$script:DDUserSidRx = '\bS-1-(?:5-21(?:-\d{1,10}){3}|12-1(?:-\d{1,10}){3})-\d{1,10}\b'
# IPv6 candidates for -Anonymise, confirmed by IPAddress.TryParse: groups of hex digits with at least two colons, an
# optional IPv4 tail (::ffff:10.1.2.3) and zone (%12). Times, MAC addresses and C++ scopes (CSwarm::Init) are not
# addresses and do not parse as one with a '::' or eight groups.
$script:DDIPv6Rx = '(?<![\w:.%])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?(?:%[0-9A-Za-z]{1,32})?(?![\w:])'

function Protect-DDAccountText {
    # The baseline account scrub (the forms above), in the order that leaves the markers alone.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = [regex]::Replace($Text, $script:DDUncPathRx, '\\${1}\<path>')
    $t = [regex]::Replace($t, $script:DDProfilePathRx, '${1}<user>')
    $t = [regex]::Replace($t, $script:DDDomainAccountRx, '${1}\<user>')
    [regex]::Replace($t, $script:DDUserSidRx, '<sid>')
}

function Protect-DDIPv6Text {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string] $Text, [string] $Salt = '')
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    [regex]::Replace($Text, $script:DDIPv6Rx, {
            param($m)
            $v = $m.Value
            $ip = $null
            $isV6 = ($v.Contains('::') -or ($v.Split(':').Count -eq 8)) -and [System.Net.IPAddress]::TryParse($v, [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
            if (-not $isV6) { return $v }
            $canonical = ([System.Net.IPAddress]::new($ip.GetAddressBytes())).ToString()
            '<ip:' + (Get-DDShortHash -Value $canonical -Salt $Salt -Domain 'ip').Substring(0, 8) + '>'
        })
}

function Protect-DDLogText {
    <#
    .SYNOPSIS
        Scrub free text. Baseline scrub always runs: URL paths and queries, accounts (profile folders, UNC paths,
        DOMAIN\account, user SIDs) and e-mail addresses. -Anonymise additionally replaces the machine name and IPv4 and IPv6
        addresses (<ip:8 hex>).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string] $Text,
        [switch] $Anonymise,
        [string] $Salt = '',
        [string] $ComputerName = ''
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    # URLs first, so a URL path that names a profile folder is cut to two segments and a query string is never left behind a marker.
    $t = Protect-DDUrlText -Text $t
    $t = Protect-DDAccountText -Text $t
    $t = [regex]::Replace($t, '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '<upn>')
    if ($Anonymise) {
        if ($ComputerName.Length -ge 3) { $t = [regex]::Replace($t, [regex]::Escape($ComputerName), '<host>', 'IgnoreCase') }
        $t = Protect-DDIPv6Text -Text $t -Salt $Salt
        $t = [regex]::Replace($t, '\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', {
                param($m) '<ip:' + (Get-DDShortHash -Value $m.Value -Salt $Salt -Domain 'ip').Substring(0, 8) + '>'
            })
    }
    $t
}

function Test-DDRetainedLogLine {
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Line, [Parameter(Mandatory)] $RedactionProfile)
    foreach ($p in $RedactionProfile['retainedEventPatterns']) { if ($Line -match $p) { return $true } }
    $false
}

function Protect-DDRegistryValues {
    # DOGroupId carries organisation topology: hashed under -Anonymise, with the salt the caller passes (the tenant's, so one
    # group ID compares equal across the tenant's devices). DOCacheHost names the Connected Cache server, which is
    # infrastructure and stays in clear (ADR-0031).
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()] $Values, [Parameter(Mandatory)][string] $Salt)
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($v in @($Values)) {
        $c = [ordered]@{ name = $v['name']; type = $v['type']; data = $v['data'] }
        if ($v['name'] -match '(?i)(^|DO)GroupId$' -and -not [string]::IsNullOrEmpty($v['data'])) {
            $c['data'] = Protect-DDTopologyValue -Value $v['data'] -Salt $Salt -Tag 'redacted'
        }
        $out.Add($c)
    }
    , $out.ToArray()
}
