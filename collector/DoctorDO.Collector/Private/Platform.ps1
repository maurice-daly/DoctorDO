#Requires -Version 5.1
# Platform wrappers.
#
# EVERY call that only exists on Windows (registry, CIM, dsregcmd, netsh, the DeliveryOptimization and
# NetSecurity modules, WinRT, certificate store) lives in a small function in this file so that:
#   * Pester can mock it (the tests run on Linux under pwsh 7.4),
#   * a missing cmdlet or a non-Windows host produces a clear, typed failure instead of a crash.
#
# The wrappers return plain data. Parsing and mapping live elsewhere and are pure functions.
# A wrapper never writes to the system: the collector is read-only except for the verbose-logging cycle
# (VerboseCycle.ps1), which is the one explicit, reversible exception.

Set-StrictMode -Version Latest

function Test-DDWindows {
    [CmdletBinding()]
    param()
    if ($PSVersionTable.PSVersion.Major -lt 6) { return $true }
    return [bool]$IsWindows
}

function Test-DDElevated {
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $false }
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) -or $id.IsSystem
}

function Test-DDWow64Process {
    # True for 32-bit PowerShell on 64-bit Windows: file-system redirection (System32 is SysWOW64, where dsregcmd.exe is not)
    # and the 32-bit WinHTTP proxy (netsh winhttp) give the wrong view. Registry reads already open the 64-bit view.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $false }
    [System.Environment]::Is64BitOperatingSystem -and -not [System.Environment]::Is64BitProcess
}

function Test-DDSystemContext {
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $false }
    [System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
}

function Test-DDCommandAvailable {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Name)
    [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-DDFullLanguage {
    # Runtime-compiled native code (Add-Type) and most .NET calls need Full Language; Constrained Language Mode (often
    # with WDAC) refuses them. Mockable.
    [CmdletBinding()]
    param()
    [string]$ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage'
}

function Get-DDParentProcessName {
    # The name of the process that started this one (no extension), or $null when it cannot be read. Mockable.
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if (-not (Test-DDWindows)) { return $null }
    try {
        $self = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $PID" -ErrorAction Stop
        (Get-Process -Id $self.ParentProcessId -ErrorAction Stop).ProcessName
    } catch { $null }
}

function Get-DDNonInteractiveReason {
    <#
    .SYNOPSIS
        Why nobody is at this session to see a window open, or $null when someone is. New-DoctorDODeviceReport opens the
        report it wrote only when a person ran it (product owner, 19 Oct 2026). Not interactive: another platform; a
        process that is not user-interactive (a service); SYSTEM, LocalService or NetworkService; session 0; PowerShell
        started with -NonInteractive; a remote session; or a process started by the Intune Management Extension, the Task
        Scheduler, ConfigMgr or WMI. The last test is there because an Intune remediation or a scheduled task set to run
        as the signed-in user runs in that user's session, so the identity and the session alone would let it through.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if (-not (Test-DDWindows)) { return 'not Windows' }
    if (-not [System.Environment]::UserInteractive) { return 'the process is not user-interactive' }
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($id.IsSystem) { return 'running as SYSTEM' }
    if ($id.User.Value -in 'S-1-5-19', 'S-1-5-20') { return 'running as a service account' }
    if ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { return 'running in session 0' }
    if (@([System.Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^[-/]noni' }).Count -gt 0) { return 'PowerShell was started with -NonInteractive' }
    if ($null -ne (Get-Variable -Name PSSenderInfo -Scope Global -ValueOnly -ErrorAction SilentlyContinue)) { return 'a remote session' }
    $parent = Get-DDParentProcessName
    if ($parent -match '^(AgentExecutor|IntuneManagementExtension|svchost|taskeng|taskhostw|CcmExec|WmiPrvSE|services)$') { return "started by $parent" }
    $null
}

function Find-DDPdfBrowser {
    <#
    .SYNOPSIS
        The browser New-DoctorDODeviceReport prints a PDF with: Microsoft Edge, else Google Chrome, as
        @{ Name; Path }, or $null when neither is installed. For each, the App Paths key (machine, then user) and then the
        standard install folders (Program Files, both views, and the per-user one). Mockable.
    #>
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $null }
    $browsers = @(
        @{ Name = 'Microsoft Edge'; Exe = 'msedge.exe'; Folder = 'Microsoft\Edge\Application' },
        @{ Name = 'Google Chrome'; Exe = 'chrome.exe'; Folder = 'Google\Chrome\Application' }
    )
    foreach ($b in $browsers) {
        $candidates = New-Object 'System.Collections.Generic.List[string]'
        foreach ($hive in 'HKLM', 'HKCU') {
            $v = Get-DDRegistryValue -Path "$hive\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($b.Exe)" -Name ''
            if ($v) { $candidates.Add(([string]$v).Trim().Trim('"')) }
        }
        foreach ($root in ${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA) {
            if ($root) { $candidates.Add((Join-Path -Path $root -ChildPath (Join-Path -Path $b.Folder -ChildPath $b.Exe))) }
        }
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c -PathType Leaf) { return [pscustomobject]@{ Name = $b.Name; Path = $c } }
        }
    }
    $null
}

function Invoke-DDHeadlessPrint {
    <#
    .SYNOPSIS
        Prints a page to PDF with Edge or Chrome in headless mode: no header or footer, a throwaway profile folder (so a
        browser the user has open is neither used nor disturbed), and a time limit, after which the browser is stopped.
        What the browser writes to its console is read and dropped. Throws when the browser cannot be started or does
        not finish in time; the caller checks that the PDF is there. Mockable.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $Browser,
        [Parameter(Mandatory)][string] $Url,
        [Parameter(Mandatory)][string] $PdfPath,
        [int] $TimeoutSeconds = 120
    )
    $profileDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ('DoctorDO-pdf-' + [guid]::NewGuid().ToString('N'))
    $arguments = @(
        '--headless', '--disable-gpu', '--no-pdf-header-footer', ('--print-to-pdf="{0}"' -f $PdfPath), ('--user-data-dir="{0}"' -f $profileDir),
        '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-sync', '--hide-scrollbars', ('"{0}"' -f $Url)
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Browser
    $psi.Arguments = $arguments -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    try {
        # Read both streams as they come, or a chatty browser could fill a pipe and wait for ever.
        $out = $p.StandardOutput.ReadToEndAsync()
        $err = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            # Kill() alone leaves the browser's child processes running on .NET Framework; taskkill /T stops the tree.
            & "$env:SystemRoot\System32\taskkill.exe" /T /F /PID $p.Id 2>&1 | Out-Null
            throw "The browser did not finish printing the PDF within $TimeoutSeconds seconds."
        }
        [void]$out.Wait(2000); [void]$err.Wait(2000)
    } finally {
        $p.Dispose()
        Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---- registry --------------------------------------------------------------------------------------------

function Split-DDRegistryPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    $m = [regex]::Match($Path, '^(?<hive>HKLM|HKCU|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS)\\(?<sub>.*)$')
    if (-not $m.Success) { throw "Unsupported registry path '$Path'." }
    $hive = switch -Regex ($m.Groups['hive'].Value) {
        '^(HKLM|HKEY_LOCAL_MACHINE)$' { 'LocalMachine' }
        '^(HKCU|HKEY_CURRENT_USER)$' { 'CurrentUser' }
        default { 'Users' }
    }
    [pscustomobject]@{ Hive = $hive; SubKey = $m.Groups['sub'].Value }
}

function Open-DDRegistryKey {
    # Read-only open of a key in the 64-bit view (the collector runs in 64-bit PowerShell; a 32-bit host
    # would otherwise be redirected into WOW6432Node and read the wrong key).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    if (-not (Test-DDWindows)) { return $null }
    $p = Split-DDRegistryPath -Path $Path
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]$p.Hive, [Microsoft.Win32.RegistryView]::Registry64)
    try { $base.OpenSubKey($p.SubKey, $false) } finally { $base.Dispose() }
}

function Format-DDRegistryData {
    [CmdletBinding()]
    param($Data, [string] $Kind)

    switch ($Kind) {
        'DWord' { return ([System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes([int]$Data), 0)).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        'QWord' { return ([System.BitConverter]::ToUInt64([System.BitConverter]::GetBytes([long]$Data), 0)).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        'MultiString' { return (@($Data) -join "`n") }
        'Binary' { return ((@($Data) | ForEach-Object { ([byte]$_).ToString('x2') }) -join '') }
        default { return [string]$Data }
    }
}

function ConvertTo-DDRegType {
    [CmdletBinding()]
    param([string] $Kind)
    switch ($Kind) {
        'DWord' { 'REG_DWORD' }
        'QWord' { 'REG_QWORD' }
        'ExpandString' { 'REG_EXPAND_SZ' }
        'MultiString' { 'REG_MULTI_SZ' }
        'Binary' { 'REG_BINARY' }
        default { 'REG_SZ' }
    }
}

function Get-DDRegistryValues {
    <#
    .SYNOPSIS
        Enumerate EVERY value in a key (never probe for expected names; docs/16 and docs/15 section 1).
    .OUTPUTS
        @{ Present = bool; Values = @(@{ name; type; data }) }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    $key = Open-DDRegistryKey -Path $Path
    if ($null -eq $key) { return @{ Present = $false; Values = @() } }
    try {
        $vals = New-Object 'System.Collections.Generic.List[object]'
        foreach ($name in $key.GetValueNames()) {
            $kind = $key.GetValueKind($name)
            $data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $display = $name
            if ($name -eq '') { $display = '(Default)' }
            $vals.Add([ordered]@{ name = $display; type = (ConvertTo-DDRegType -Kind $kind.ToString()); data = (Format-DDRegistryData -Data $data -Kind $kind.ToString()) })
        }
        @{ Present = $true; Values = $vals.ToArray() }
    } finally { $key.Dispose() }
}

function Get-DDRegistryValue {
    # An empty -Name reads the key's default value (App Paths keeps the program's path there).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][AllowEmptyString()][string] $Name)

    $key = Open-DDRegistryKey -Path $Path
    if ($null -eq $key) { return $null }
    try { $key.GetValue($Name, $null) } finally { $key.Dispose() }
}

function Get-DDRegistrySubKeyNames {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)

    $key = Open-DDRegistryKey -Path $Path
    if ($null -eq $key) { return @() }
    try { @($key.GetSubKeyNames()) } finally { $key.Dispose() }
}

# ---- CIM -------------------------------------------------------------------------------------------------

function Get-DDCim {
    # Wrapper over Get-CimInstance. Returns @() when unavailable; callers record notCollected.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ClassName, [string] $Namespace = 'root/cimv2', [int] $TimeoutSec = 10)

    if (-not (Test-DDWindows)) { return @() }
    @(Get-CimInstance -Verbose:$false -Namespace $Namespace -ClassName $ClassName -OperationTimeoutSec $TimeoutSec -ErrorAction Stop)
}

# ---- identity and management ------------------------------------------------------------------------------

function Get-DDDsregStatusText {
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('dsregcmd is Windows only.') }
    $exe = Join-Path -Path $env:SystemRoot -ChildPath 'System32\dsregcmd.exe'
    @(& $exe /status 2>&1 | ForEach-Object { [string]$_ })
}

function ConvertFrom-DDDsregStatus {
    <#
    .SYNOPSIS
        Parse `dsregcmd /status` (Device State, Device Details, Tenant Details, User State).
        Documented: https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd
    #>
    [CmdletBinding()]
    # Real dsregcmd output has blank lines between sections, so empty strings must bind.
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]] $Lines)

    $kv = @{}
    foreach ($l in $Lines) {
        $m = [regex]::Match($l, '^\s*([A-Za-z][A-Za-z0-9 ]*?)\s*:\s*(.*?)\s*$')
        if ($m.Success -and -not $kv.ContainsKey($m.Groups[1].Value)) { $kv[$m.Groups[1].Value] = $m.Groups[2].Value }
    }
    $yes = { param($n) $kv.ContainsKey($n) -and $kv[$n] -eq 'YES' }
    $guid = { param($n) if ($kv.ContainsKey($n) -and $kv[$n] -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $kv[$n].ToLowerInvariant() } else { $null } }
    $aad = & $yes 'AzureAdJoined'
    $dom = & $yes 'DomainJoined'
    $wpj = & $yes 'WorkplaceJoined'
    $join = 'none'
    if ($aad -and $dom) { $join = 'hybrid' } elseif ($aad) { $join = 'entra' } elseif ($dom) { $join = 'domain' } elseif ($wpj) { $join = 'registered' }
    [pscustomobject]@{
        Parsed       = ($kv.ContainsKey('AzureAdJoined') -or $kv.ContainsKey('DomainJoined'))
        JoinType     = $join
        AzureAdJoined = $aad
        DomainJoined = $dom
        DeviceId     = (& $guid 'DeviceId')
        TenantId     = (& $guid 'TenantId')
        # Device Details: "Thumbprint" is the device certificate's thumbprint (documented field name; on a lab device it
        # equals the MS-Organization-Access certificate's thumbprint). The entra-device selection requires a match.
        DeviceCertificateThumbprint = $(if ($kv.ContainsKey('Thumbprint') -and $kv['Thumbprint'] -match '^[0-9A-Fa-f]{40}$') { $kv['Thumbprint'].ToUpperInvariant() } else { $null })
        # KeyContainerId and KeyProvider name the device key (documented fields); on a lab device they equal the
        # certificate's key container and provider as certutil shows them. Used only as a signing fallback.
        KeyContainerId = $(if ($kv.ContainsKey('KeyContainerId') -and $kv['KeyContainerId'] -match '^\{?[0-9A-Fa-f-]{36}\}?$') { $kv['KeyContainerId'] } else { $null })
        KeyProvider  = $(if ($kv.ContainsKey('KeyProvider') -and $kv['KeyProvider']) { $kv['KeyProvider'] } else { $null })
    }
}

function Get-DDEnrollmentRecords {
    # MDM enrolment keys: HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}. The key location is the documented
    # place for enrolment state (https://learn.microsoft.com/windows/client-management/mdm-diagnose-enrollment);
    # the value names read here (ProviderID, EnrollmentType, DiscoveryServiceFullURL, EnrollmentState)
    # are TO-VERIFY on a Windows lab device. Returns one record per enrolment, never throws.
    [CmdletBinding()]
    param()

    $out = New-Object 'System.Collections.Generic.List[object]'
    $base = 'HKLM\SOFTWARE\Microsoft\Enrollments'
    foreach ($sub in (Get-DDRegistrySubKeyNames -Path $base)) {
        if ($sub -notmatch '^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$') { continue }
        $p = "$base\$sub"
        $out.Add([pscustomobject]@{
                EnrollmentId = $sub
                ProviderId   = (Get-DDRegistryValue -Path $p -Name 'ProviderID')
                EnrollmentType = (Get-DDRegistryValue -Path $p -Name 'EnrollmentType')
                EnrollmentState = (Get-DDRegistryValue -Path $p -Name 'EnrollmentState')
                DiscoveryUrl = (Get-DDRegistryValue -Path $p -Name 'DiscoveryServiceFullURL')
                EntDmId      = (Get-DDRegistryValue -Path $p -Name 'EntDMID')
            })
    }
    $out.ToArray()
}

function Get-DDIntuneDeviceIdFromCertificate {
    # The Intune MDM device certificate's subject CN is the Intune device ID (observed; TO-VERIFY).
    # Used only as a fallback when the enrolment keys carry no EntDMID.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $null }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
    try {
        $store.Open('ReadOnly')
        foreach ($c in $store.Certificates) {
            if ($c.Issuer -match 'Microsoft Intune MDM Device CA' -and $c.Subject -match 'CN=([0-9a-fA-F-]{36})') { return $Matches[1].ToLowerInvariant() }
        }
    } catch { Write-Verbose "Intune device certificate lookup failed: $($_.Exception.Message)" } finally { $store.Close() }
    $null
}

function Get-DDDevDetail {
    # DevDetail CSP through the MDM WMI bridge: MDM_DevDetail carries the nodes DevTyp, OEM, FwV, SwV and HwV
    # (https://learn.microsoft.com/windows/win32/dmwmibridgeprov/mdm-devdetail). MDM_DevDetail_Ext01, read before, holds only
    # DeviceHardwareData and WLANMACAddress, so the registry fallback supplied the make and model. Where the bridge refuses the
    # read (observed: access denied in an unelevated session), the registry is read instead.
    [CmdletBinding()]
    param()
    $r = @(Get-DDCim -Namespace 'root/cimv2/mdm/dmmap' -ClassName 'MDM_DevDetail')
    if ($r.Count -eq 0) { return $null }
    $r[0]
}

function Invoke-DDWithTimeout {
    <#
    .SYNOPSIS
        Run a script block in its own runspace and abandon it after -TimeoutSec (the collector must never hang).
        The block receives no variables from the caller; pass what it needs in -ArgumentList.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock] $Script, [object[]] $ArgumentList = @(), [int] $TimeoutSec = 30)

    $ps = [System.Management.Automation.PowerShell]::Create()
    try {
        [void]$ps.AddScript($Script.ToString())
        foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
        $async = $ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($TimeoutSec))) {
            [void]$ps.BeginStop($null, $null)
            throw [System.TimeoutException]::new("Timed out after $TimeoutSec s.")
        }
        $result = $ps.EndInvoke($async)
        if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0) { throw $ps.Streams.Error[0].Exception }
        $result
    } finally { $ps.Dispose() }
}

# ---- Delivery Optimization -------------------------------------------------------------------------------

function Test-DDDeliveryOptimizationModule {
    [CmdletBinding()]
    param()
    (Test-DDCommandAvailable -Name 'Get-DeliveryOptimizationStatus')
}

function Get-DDDOStatusRaw {
    [CmdletBinding()]
    param()
    (Invoke-DDWithTimeout -TimeoutSec 20 -Script { Get-DeliveryOptimizationStatus -ErrorAction Stop })
}

function Get-DDDOPeerInfoRaw {
    # Every peer of every file, as @{ FileId; Peers = @(@{ IP; PeerType; ConnectionEstablished; BytesSent; BytesReceived }) }.
    # Read from the CIM class behind `Get-DeliveryOptimizationStatus -PeerInfo` (root/Microsoft/Windows/DeliveryOptimization
    # MSFT_DeliveryOptimizationFilePeerInfo: FileId, IPs[], PeerTypes[], ConnectionEstablished[], BytesSent[],
    # BytesReceived[]; verified on Windows 11 26H2 and in DeliveryOptimizationStatus.psm1). The cmdlet itself keeps only the
    # top 5 peers per file and, without -AsObject, interleaves file IDs and peers, so it is the fallback only.
    [CmdletBinding()]
    param()
    (Invoke-DDWithTimeout -TimeoutSec 20 -Script {
            try {
                $swarms = @(Get-CimInstance -Verbose:$false -Namespace 'root/Microsoft/Windows/DeliveryOptimization' -ClassName 'MSFT_DeliveryOptimizationFilePeerInfo' -ErrorAction Stop)
                foreach ($s in $swarms) {
                    $peers = New-Object 'System.Collections.Generic.List[object]'
                    $ips = @($s.IPs)
                    for ($i = 0; $i -lt $ips.Count; $i++) {
                        if (-not $ips[$i]) { continue }
                        $peers.Add([pscustomobject]@{
                                IP = [string]$ips[$i]; PeerType = @($s.PeerTypes)[$i]; ConnectionEstablished = @($s.ConnectionEstablished)[$i]
                                BytesSent = @($s.BytesSent)[$i]; BytesReceived = @($s.BytesReceived)[$i]
                            })
                    }
                    [pscustomobject]@{ FileId = [string]$s.FileId; Peers = $peers.ToArray() }
                }
            } catch {
                Get-DeliveryOptimizationStatus -PeerInfo -AsObject -SelectPeerCount 50 -ErrorAction Stop
            }
        })
}

function Get-DDDoSvcTcpConnections {
    # DoSvc's TCP connections now, by the owning PID of its svchost. Get-NetTCPConnection works unelevated (verified).
    # Returns @() when DoSvc is not running, or runs and holds no connection (Get-NetTCPConnection's ObjectNotFound).
    # Throws when the table cannot be read at all, or when DoSvc shares its svchost with other services (Windows groups
    # services in one process below the service-split memory threshold), because the PID would then mix their connections
    # with DoSvc's: so "no rows" always means DoSvc holds no connection, and the caller records endpoints.tcp as not collected.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('Get-NetTCPConnection is Windows only.') }
    if (-not (Test-DDCommandAvailable -Name 'Get-NetTCPConnection')) { throw [System.Management.Automation.CommandNotFoundException]::new('Get-NetTCPConnection is not available.') }
    $svc = @(Get-CimInstance -Verbose:$false -ClassName Win32_Service -Filter "Name='DoSvc'" -ErrorAction Stop) | Select-Object -First 1
    if ($null -eq $svc -or -not $svc.ProcessId) { return @() }
    $pidNow = [int]$svc.ProcessId
    $shared = @(Get-CimInstance -Verbose:$false -ClassName Win32_Service -Filter "ProcessId=$pidNow" -ErrorAction Stop).Count
    if ($shared -gt 1) { throw [System.NotSupportedException]::new("DoSvc shares its process with $($shared - 1) other service(s), so its own TCP connections cannot be told apart") }
    try {
        @(Get-NetTCPConnection -OwningProcess $pidNow -ErrorAction Stop | Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, State, CreationTime)
    } catch {
        if ([string]$_.CategoryInfo.Category -eq 'ObjectNotFound') { return @() }
        throw
    }
}

function Get-DDDOPerfSnapRaw {
    # -Verbose adds bytes per source (documented as "bytes from peers per type, bytes from CDN"); captured from stream 4.
    [CmdletBinding()]
    param([switch] $ThisMonth)
    $month = [bool]$ThisMonth
    $all = @(Invoke-DDWithTimeout -TimeoutSec 20 -ArgumentList @($month) -Script {
            param($m)
            if ($m) { Get-DeliveryOptimizationPerfSnapThisMonth -Verbose -ErrorAction Stop 4>&1 } else { Get-DeliveryOptimizationPerfSnap -Verbose -ErrorAction Stop 4>&1 }
        })
    $verbose = New-Object 'System.Collections.Generic.List[string]'
    $obj = $null
    foreach ($r in $all) {
        if ($r -is [System.Management.Automation.VerboseRecord]) { $verbose.Add([string]$r.Message) } elseif ($null -eq $obj) { $obj = $r }
    }
    [pscustomobject]@{ Snap = $obj; Verbose = $verbose.ToArray() }
}

function Get-DDDOConfigRaw {
    # Get-DOConfig -Verbose: the effective value and its provider. The provider is reported on the VERBOSE
    # stream (stream 4) so both the output object and the verbose records are captured.
    [CmdletBinding()]
    param()
    $verbose = New-Object 'System.Collections.Generic.List[string]'
    $obj = $null
    $all = @(Invoke-DDWithTimeout -TimeoutSec 20 -Script { Get-DOConfig -Verbose -ErrorAction Stop 4>&1 })
    foreach ($r in $all) {
        if ($r -is [System.Management.Automation.VerboseRecord]) { $verbose.Add([string]$r.Message) }
        else { $obj = $r }
    }
    [pscustomobject]@{ Config = $obj; Verbose = $verbose.ToArray() }
}

function Get-DDDOLogEntries {
    # Microsoft guidance: flush before analysis. Flush is a read of in-memory buffers to the log files,
    # not a configuration change. https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-monitor
    [CmdletBinding()]
    param([switch] $Flush, [int] $Last = 20000)
    $flushIt = [bool]$Flush
    $all = Invoke-DDWithTimeout -TimeoutSec 45 -ArgumentList @($flushIt) -Script {
        param($f)
        if ($f) { Get-DeliveryOptimizationLog -Flush -ErrorAction Stop } else { Get-DeliveryOptimizationLog -ErrorAction Stop }
    }
    @($all | Select-Object -Last $Last)
}

function Get-DDDOLogConnections {
    [CmdletBinding()]
    param()
    (Invoke-DDWithTimeout -TimeoutSec 45 -Script { Get-DeliveryOptimizationLogAnalysis -ListConnections -ErrorAction Stop })
}

function Get-DDDOVerboseLogState {
    # TO-VERIFY: Get-DeliveryOptimizationVerboseLogs may report state; if the cmdlet is absent the state is
    # unknowable and the verbose cycle refuses to run (it never enables what it cannot restore).
    [CmdletBinding()]
    param()
    if (-not (Test-DDCommandAvailable -Name 'Get-DeliveryOptimizationVerboseLogs')) { return $null }
    $v = Get-DeliveryOptimizationVerboseLogs -ErrorAction Stop
    [bool]$v
}

function Enable-DDDOVerboseLogs {
    [CmdletBinding()]
    param()
    Enable-DeliveryOptimizationVerboseLogs -ErrorAction Stop
}

function Disable-DDDOVerboseLogs {
    [CmdletBinding()]
    param()
    Disable-DeliveryOptimizationVerboseLogs -ErrorAction Stop
}

function Get-DDDoSvcState {
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $null }
    $s = Get-Service -Name 'DoSvc' -ErrorAction SilentlyContinue
    if ($null -eq $s) { return $null }
    [pscustomobject]@{ Status = [string]$s.Status; StartType = [string]$s.StartType }
}

# ---- diagnosis signals (docs/27 section 3.8) ----------------------------------------------------------------------
# Two measurements only a device can make: how often DoSvc ended unexpectedly, and how many hours a day it is powered on.
# Pure parsers over plain event objects (Id, Provider, TimeCreated, Name) and thin wrappers over the System log, so the
# parsers are tested without an event log. Both reads are optional and bounded by the caller (Diag.ps1).
#   Service Control Manager 7031 / 7034: "The <service display name> service terminated unexpectedly. It has done this N
#   time(s)." (7031 adds the corrective action). Learn: https://learn.microsoft.com/troubleshoot/windows-server/system-management-components/error-1053-1067-7034-after-update-openssh-doesnt-start
#   Kernel-General 12 "The operating system started at system time ..." and 13 "The operating system is shutting down at
#   system time ...". Learn: https://learn.microsoft.com/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs
#   Event IDs are shared between sources, so the provider is filtered as well as the ID.
# That DoSvc itself writes 7031/7034 when it is killed, and how sleep, hibernate and Fast Startup show in 12/13, are to-verify
# on a Windows lab device.

function Get-DDDoSvcDisplayName {
    # The display name SCM writes into 7031/7034, read from the same device so it works in any display language.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('Services are Windows only.') }
    $s = Get-Service -Name 'DoSvc' -ErrorAction SilentlyContinue
    if ($null -eq $s) { return $null }
    [string]$s.DisplayName
}

function New-DDSystemEventFilter {
    <#
    .SYNOPSIS
        The Get-WinEvent -FilterHashtable for System-log events of one provider and IDs since -StartTime, optionally only
        those with an event-data value equal to -DataValue. Pure.
    .DESCRIPTION
        The `Data` key matches the event's data values, so the log itself drops other services' events before -MaxEvents is
        applied: a service that crash-loops cannot push the one we want out of the newest 5,000 events
        (https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent, Example 18).
        Service Control Manager 7031 and 7034 carry the service's display name in their first data value (param1)
        ("The <display name> service terminated unexpectedly"); the Learn pages show the message text, not the event data
        schema, so matching on that value is `to-verify` on Windows (docs/27 3.10).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ProviderName,
        [Parameter(Mandatory)][int[]] $Id,
        [Parameter(Mandatory)][datetime] $StartTime,
        [string] $DataValue
    )
    $f = @{ LogName = 'System'; ProviderName = $ProviderName; Id = $Id; StartTime = $StartTime }
    if (-not [string]::IsNullOrEmpty($DataValue)) { $f['Data'] = $DataValue }
    $f
}

function Get-DDSystemEventsRaw {
    # System-log events of one provider within the last -Days days, newest first, projected to plain objects:
    # Id, Provider, TimeCreated (UTC), Name (first event property, the service name for SCM events; message text is never read).
    # -DataValue keeps only events carrying that data value (New-DDSystemEventFilter), filtered by the log before -MaxEvents.
    # Read-only. No match is an empty list, not an error. -TimeoutSec bounds it (Invoke-DDWithTimeout).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $ProviderName,
        [Parameter(Mandatory)][int[]] $Id,
        [int] $Days = 7,
        [int] $MaxEvents = 5000,
        [int] $TimeoutSec = 5,
        [string] $DataValue
    )
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('The Windows event log is Windows only.') }
    $start = [datetime]::SpecifyKind((Get-DDNowUtc).AddDays(-$Days), [System.DateTimeKind]::Utc).ToLocalTime()
    $filter = New-DDSystemEventFilter -ProviderName $ProviderName -Id $Id -StartTime $start -DataValue $DataValue
    $rows = Invoke-DDWithTimeout -TimeoutSec $TimeoutSec -ArgumentList @($filter, $MaxEvents) -Script {
        param($filter, $max)
        $found = @()
        try {
            $found = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $max -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        }
        foreach ($e in $found) {
            $name = $null
            if ($e.Properties.Count -gt 0) { $name = [string]$e.Properties[0].Value }
            [pscustomobject]@{ Id = [int]$e.Id; Provider = [string]$e.ProviderName; TimeCreated = $e.TimeCreated.ToUniversalTime(); Name = $name }
        }
    }
    @($rows)
}

function Get-DDServiceTerminationEventsRaw {
    [CmdletBinding()]
    # -ServiceDisplayName is the display name SCM writes into the event (Get-DDDoSvcDisplayName). The log filters on it first, an
    # optimisation, so another service's crash loop cannot fill the newest 5,000 events. Whether the event data matches that
    # filter is to-verify on Windows, and a filter that matches nothing would read as "no crash", so when it finds nothing the
    # query runs again by provider and ID alone and the pure counter (Get-DDDoSvcCrashCount) matches the first property by name.
    # Empty: every service.
    param([int] $Days = 7, [int] $TimeoutSec = 5, [string] $ServiceDisplayName)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rows = @(Get-DDSystemEventsRaw -ProviderName 'Service Control Manager' -Id 7031, 7034 -Days $Days -TimeoutSec $TimeoutSec -DataValue $ServiceDisplayName)
    if ($rows.Count -gt 0 -or [string]::IsNullOrEmpty($ServiceDisplayName)) { return $rows }
    $left = [int][math]::Max(1, [math]::Ceiling($TimeoutSec - $sw.Elapsed.TotalSeconds))
    @(Get-DDSystemEventsRaw -ProviderName 'Service Control Manager' -Id 7031, 7034 -Days $Days -TimeoutSec $left)
}

function Get-DDKernelGeneralEventsRaw {
    [CmdletBinding()]
    param([int] $Days = 7, [int] $TimeoutSec = 5)
    Get-DDSystemEventsRaw -ProviderName 'Microsoft-Windows-Kernel-General' -Id 12, 13 -Days $Days -TimeoutSec $TimeoutSec
}

function Get-DDDeviceHistoryStartRaw {
    <#
    .SYNOPSIS
        The earliest evidence that the device existed with a working System log: the older of the OS install date
        (Win32_OperatingSystem.InstallDate) and the time of the System log's oldest record (UTC), or $null when neither could be
        read. Read-only; each source that fails is skipped, so the answer is $null only when both do.
    .DESCRIPTION
        Get-DDPoweredOnHours uses it to tell a new device (history starts inside the window) from a device that is mostly off
        (history reaches back past the window). Both sources are read, and the older wins, because either alone can mislead: the
        install date is reset by a feature update, and a small System log wraps. -TimeoutSec bounds the two reads together.
        https://learn.microsoft.com/windows/win32/cimwin32prov/win32-operatingsystem (InstallDate)
        https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent (-Oldest)
    #>
    [CmdletBinding()]
    param([int] $TimeoutSec = 5)
    if (-not (Test-DDWindows)) { return $null }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $found = New-Object 'System.Collections.Generic.List[datetime]'
    try {
        $os = @(Get-DDCim -ClassName 'Win32_OperatingSystem' -TimeoutSec $TimeoutSec) | Select-Object -First 1
        $i = Get-DDProp $os 'InstallDate'
        if ($i -is [datetime]) { $found.Add($i.ToUniversalTime()) }
    } catch { Write-Verbose "install date not read: $($_.Exception.Message)" }
    try {
        $left = [int][math]::Max(1, [math]::Ceiling($TimeoutSec - $sw.Elapsed.TotalSeconds))
        $oldest = @(Invoke-DDWithTimeout -TimeoutSec $left -Script {
                Get-WinEvent -LogName System -Oldest -MaxEvents 1 -ErrorAction Stop | ForEach-Object { $_.TimeCreated.ToUniversalTime() }
            }) | Select-Object -First 1
        if ($oldest -is [datetime]) { $found.Add($oldest.ToUniversalTime()) }
    } catch { Write-Verbose "oldest System log record not read: $($_.Exception.Message)" }
    if ($found.Count -eq 0) { return $null }
    ($found | Sort-Object | Select-Object -First 1)
}

function Test-DDEventProvider {
    # True when the event carries no provider (a plain fixture) or the provider is the expected one.
    [CmdletBinding()]
    param($EventRecord, [Parameter(Mandatory)][string] $Provider)
    $p = Get-DDProp $EventRecord 'Provider', 'ProviderName'
    ($null -eq $p) -or ([string]$p -ieq $Provider)
}

function ConvertTo-DDEventUtc {
    [CmdletBinding()]
    param($EventRecord)
    $t = Get-DDProp $EventRecord 'TimeCreated'
    if ($t -is [datetime]) { return $t.ToUniversalTime() }
    $parsed = [datetime]::MinValue
    if ($null -ne $t -and [datetime]::TryParse([string]$t, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $parsed }
    $null
}

function Get-DDDoSvcCrashCount {
    <#
    .SYNOPSIS
        Unexpected terminations of one service in the last -Days days: Service Control Manager events 7031 and 7034 whose
        service name equals -ServiceDisplayName (case-insensitive). Pure: no event log is read. Capped at 99 (the wire limit).
    .PARAMETER Events
        Plain event objects: Id, Provider (optional), TimeCreated, Name (the service name, else Properties[0].Value).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] $Events = @(),
        [Parameter(Mandatory)][string] $ServiceDisplayName,
        [Parameter(Mandatory)][datetime] $Now,
        [int] $Days = 7
    )
    $from = $Now.ToUniversalTime().AddDays(-$Days)
    $to = $Now.ToUniversalTime()
    $n = 0
    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $id = Get-DDProp $e 'Id'
        if ($null -eq $id -or ([int]$id -ne 7031 -and [int]$id -ne 7034)) { continue }
        if (-not (Test-DDEventProvider -EventRecord $e -Provider 'Service Control Manager')) { continue }
        $at = ConvertTo-DDEventUtc -EventRecord $e
        if ($null -eq $at -or $at -lt $from -or $at -gt $to) { continue }
        $name = Get-DDProp $e 'Name'
        if ($null -eq $name) {
            $props = Get-DDProp $e 'Properties'
            if ($null -ne $props -and @($props).Count -gt 0) { $first = @($props)[0]; $name = $(if ($null -ne (Get-DDProp $first 'Value')) { Get-DDProp $first 'Value' } else { $first }) }
        }
        if ($null -ne $name -and ([string]$name).Trim() -ieq $ServiceDisplayName.Trim()) { $n++ }
    }
    [math]::Min(99, $n)
}

function Get-DDPoweredOnHours {
    <#
    .SYNOPSIS
        Mean hours per day the device was powered on over the last -Days days, from Kernel-General 12 (started) and 13
        (shutting down). Pure: no event log is read. Returns a double in 0..24, or $null when the history to judge by is under
        24 hours.
    .DESCRIPTION
        Sessions run from a 12 to the next 13. A session that began before the window starts at the window's start; one
        still open ends at -Now; one with no 13 before the next 12 (power loss, crash) ends at that next 12. Sleep and
        hibernate are not subtracted, so the result is an upper bound. No 12 or 13 in the window means the device has been up
        for all of it (it is running now).
        The total is divided by the full window, -Days days, unless the device is demonstrably new: -HistoryStart, the earliest
        evidence the device existed (Get-DDDeviceHistoryStartRaw: the older of the OS install date and the System log's oldest
        record), falls inside the window. Then the history is the time since it, so a device enrolled two days ago is judged
        over two days, not over seven with five of them empty. A first event that is a 12 is NOT such evidence: a 12 means the
        device was off before it, and a device that is mostly off has few events and an early 12 whatever its age (one 8-hour
        session 1.5 days ago and off otherwise is 1.1 hours a day, not 5). Without -HistoryStart the window is the history.
        Under 24 hours of history there is nothing to average: $null.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] $Events = @(),
        [Parameter(Mandatory)][datetime] $Now,
        [int] $Days = 7,
        [Nullable[datetime]] $HistoryStart = $null
    )

    $to = $Now.ToUniversalTime()
    $from = $to.AddDays(-$Days)
    $begin = $from
    if ($null -ne $HistoryStart) {
        $hs = ([datetime]$HistoryStart).ToUniversalTime()
        if ($hs -gt $from) { $begin = $hs }
    }
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($e in @($Events)) {
        if ($null -eq $e) { continue }
        $id = Get-DDProp $e 'Id'
        if ($null -eq $id -or ([int]$id -ne 12 -and [int]$id -ne 13)) { continue }
        if (-not (Test-DDEventProvider -EventRecord $e -Provider 'Microsoft-Windows-Kernel-General')) { continue }
        $at = ConvertTo-DDEventUtc -EventRecord $e
        if ($null -eq $at -or $at -lt $from -or $at -gt $to) { continue }
        $list.Add([pscustomobject]@{ Id = [int]$id; At = $at; I = $list.Count })
    }
    if ($list.Count -eq 0) { return [double]24 }
    $cmp = [System.Comparison[object]] { param($a, $b) $c = $a.At.CompareTo($b.At); if ($c -ne 0) { return $c }; return ($a.I - $b.I) }
    $list.Sort($cmp)
    $total = [timespan]::Zero
    $open = $null
    if ($list[0].Id -eq 13) { $open = $(if ($begin -gt $list[0].At) { $list[0].At } else { $begin }) }
    foreach ($e in $list) {
        if ($e.Id -eq 12) {
            if ($null -ne $open) { $total += ($e.At - $open) }
            $open = $e.At
        } elseif ($null -ne $open) {
            $total += ($e.At - $open)
            $open = $null
        }
    }
    if ($null -ne $open) { $total += ($to - $open) }
    $history = $to - $begin
    if ($history -lt [timespan]::FromHours(24)) { return $null }
    $hours = $total.TotalHours / $history.TotalDays
    [math]::Round([math]::Min([double]24, [math]::Max([double]0, [double]$hours)), 2)
}

function Get-DDDirectorySize {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    # Unelevated, the NetworkService profile is not readable: no size, as for a missing folder, and no error printed (the
    # cache folder's access is reported as not collected where it is graded).
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $null }
    $sum = [long]0
    foreach ($f in [System.IO.Directory]::EnumerateFiles($Path, '*', [System.IO.SearchOption]::AllDirectories)) {
        try { $sum += ([System.IO.FileInfo]$f).Length } catch { Write-Verbose "skip $f" }
    }
    $sum
}

# ---- firewall, proxy, network ----------------------------------------------------------------------------

function Get-DDFirewallRulesRaw {
    <#
    .SYNOPSIS
        The firewall rules that decide Delivery Optimization's ports, from the active store (local, Group Policy and MDM
        merged; local rules drop out when policy turns off local rule merging), so "present" means "in force".
    .DESCRIPTION
        * the built-in Delivery Optimization rules (by Name, which is not translated), rules whose display name starts
          'Delivery Optimization', and every inbound rule whose port filter names TCP 7680, whatever its display name
          (Intune and Group Policy rules are often custom-named);
        * enabled inbound Block rules whose local port could shadow 7680 (Any or 7680);
        * enabled outbound Block rules that name TCP 7680 (connections to peers) or UDP 3544 (Teredo);
        * enabled Block rules that name UDP 67 or 68 (the DHCP client, which options 234 and 235 arrive through).
        Each with its PrimaryStatus and its remote address condition. The remote addresses are read here only so the
        mapper (ConvertFrom-DDFirewallRaw) can reduce them to a category and a count; they are never stored or sent.
        Windows can refuse part of a listing: without administrator rights the port-filter listing returns what it can
        and one "Access is denied" error (seen on Windows 11, 26 Nov 2026), and a standard user may be refused more. Each
        refused listing is returned as one more object, with ReadRefused (which listing) and Error, so the caller can
        record the rules as incomplete: a rule missing from them is then unknown, not absent. A filter that matches
        nothing (ObjectNotFound) is not a refusal.
        NetSecurity cmdlets: https://learn.microsoft.com/powershell/module/netsecurity/get-netfirewallrule
    #>
    [CmdletBinding()]
    param()
    $res = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $refusals = New-Object 'System.Collections.Generic.List[object]'
    $note = {
        param([string] $What, $Errors)
        $e = @(@($Errors) | Where-Object { $null -ne $_ -and [string]$_.CategoryInfo.Category -ne 'ObjectNotFound' })
        if ($e.Count -gt 0) { $refusals.Add([pscustomobject]@{ ReadRefused = $What; Error = $e[0] }) }
    }
    $add = {
        param($rule)
        if ($null -eq $rule -or -not $seen.Add([string]$rule.InstanceID)) { return }
        $port = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        # The service is on the service filter: the application filter has no Service property, and reading one under
        # strict mode threw, so no rule was ever collected on a real device (found on Windows 11 26H2, 13 Oct 2026).
        $svc = $rule | Get-NetFirewallServiceFilter -ErrorAction SilentlyContinue
        $addr = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $res.Add([pscustomobject]@{
                DisplayName = [string]$rule.DisplayName; Direction = [string]$rule.Direction; Action = [string]$rule.Action
                Enabled = [string]$rule.Enabled; Profile = [string]$rule.Profile; PrimaryStatus = [string](Get-DDProp $rule 'PrimaryStatus')
                EnforcementStatus = [string[]]@(Get-DDProp $rule 'EnforcementStatus' | ForEach-Object { [string]$_ })
                Protocol = $(if ($port) { [string]$port.Protocol } else { 'Any' })
                LocalPort = $(if ($port) { (@($port.LocalPort) -join ',') } else { 'Any' })
                RemotePort = $(if ($port -and $null -ne (Get-DDProp $port 'RemotePort')) { (@(Get-DDProp $port 'RemotePort') -join ',') } else { 'Any' })
                RemoteAddress = $(if ($addr -and $null -ne (Get-DDProp $addr 'RemoteAddress')) { [string[]]@(Get-DDProp $addr 'RemoteAddress') } else { [string[]]@('Any') })
                Program = $(if ($app) { $v = Get-DDProp $app 'Program', 'AppPath'; if ($v) { [string]$v } else { $null } } else { $null })
                Service = $(if ($svc) { $v = Get-DDProp $svc 'Service'; if ($v) { [string]$v } else { $null } } else { $null })
            })
    }
    $tcp = '^(?i)(TCP|6|Any|)$'
    $udp = '^(?i)(UDP|17|Any|)$'
    # The built-in rules by their language-neutral Name (DeliveryOptimization-TCP-In, -UDP-In): the display name is
    # translated on a non-English Windows ("Delivery Optimization (TCP-In)" only in English). Custom rules by display name.
    $named = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'DeliveryOptimization*' -ErrorAction SilentlyContinue -ErrorVariable builtInErr) +
        @(Get-NetFirewallRule -PolicyStore ActiveStore -DisplayName 'Delivery Optimization*' -ErrorAction SilentlyContinue -ErrorVariable namedErr)
    & $note 'the Delivery Optimization rules' (@($builtInErr) + @($namedErr))
    foreach ($r in $named) { & $add $r }
    # Port filters first (far fewer calls than reading each rule's filter): the ones that name a port Delivery Optimization
    # or the DHCP client uses, then the rule behind each.
    $filters = @(Get-NetFirewallPortFilter -PolicyStore ActiveStore -ErrorAction SilentlyContinue -ErrorVariable filterErr)
    & $note 'the port filters' $filterErr
    foreach ($pf in $filters) {
        $proto = [string]$pf.Protocol
        $lp = (@(Get-DDProp $pf 'LocalPort') -join ','); $rp = (@(Get-DDProp $pf 'RemotePort') -join ',')
        $names = { param($p) (Test-DDPortSpec -Spec $lp -Port $p) -or (Test-DDPortSpec -Spec $rp -Port $p) }
        $hit = ($proto -match $tcp -and ((Test-DDPortSpec -Spec $lp -Port 7680) -or (Test-DDPortSpec -Spec $rp -Port 7680))) -or
            ($proto -match $udp -and ((& $names 3544) -or (& $names 67) -or (& $names 68)))
        if (-not $hit) { continue }
        # The rule behind the filter, read from the active store by its ID. Piping the filter to Get-NetFirewallRule
        # returns the stored rule, whose PrimaryStatus is OK even when policy keeps it out of force (a local rule while
        # local rule merging is off: Inactive in the active store, OK through its filter; Windows 11, 26 Nov 2026). On a
        # non-English Windows the built-in rule was found only this way, so it counted as in force (issue 1). A filter
        # whose rule is not in the active store is not in force, and is left out.
        $id = [string](Get-DDProp $pf 'InstanceID')
        $behind = $(if ($id) { @(Get-NetFirewallRule -PolicyStore ActiveStore -Name ([System.Management.Automation.WildcardPattern]::Escape($id)) -ErrorAction SilentlyContinue) } else { @() })
        foreach ($r in $behind) {
            $inbound = [string]$r.Direction -match '(?i)^in'
            $block = [string]$r.Action -match '(?i)block'
            $on = [string]$r.Enabled -match '(?i)^(true|1)$'
            # Inbound 7680 rules in any state (a disabled allow rule is itself a finding); everything else only when it blocks.
            if (($inbound -and -not $block -and $proto -match $tcp -and (Test-DDPortSpec -Spec $lp -Port 7680)) -or ($block -and $on)) { & $add $r }
        }
    }
    $blocks = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue -ErrorVariable blockErr)
    & $note 'the inbound Block rules' $blockErr
    foreach ($r in $blocks) {
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $lp = if ($pf) { (@($pf.LocalPort) -join ',') } else { 'Any' }
        if ($lp -match '(?i)(^|,)Any(,|$)' -or (Test-DDPortSpec -Spec $lp -Port 7680)) { & $add $r }
    }
    , ($res.ToArray() + $refusals.ToArray())
}

function Get-DDFirewallProfilesRaw {
    [CmdletBinding()]
    param()
    # AllowInboundRules=False is "block all incoming connections": it overrides every allow rule, the DO rules included.
    @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.Name; Enabled = [string]$_.Enabled; AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
                AllowInboundRules = [string]$_.AllowInboundRules; DefaultInboundAction = [string]$_.DefaultInboundAction
            }
        })
}

function Get-DDNetshWinHttpProxy {
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $null }
    @(& (Join-Path $env:SystemRoot 'System32\netsh.exe') winhttp show proxy 2>&1 | ForEach-Object { [string]$_ })
}

function Get-DDInternetSettings {
    # WinINET proxy. Per-user = HKCU (HKU\S-1-5-18 when running as SYSTEM, which is NOT a real user setting);
    # device-wide = HKLM policy 'ProxySettingsPerUser'=0 or the machine-level key.
    # https://learn.microsoft.com/windows/deployment/do/delivery-optimization-proxy
    [CmdletBinding()]
    param()
    $user = Get-DDRegistryValues -Path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $machine = Get-DDRegistryValues -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    $perUser = Get-DDRegistryValue -Path 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'ProxySettingsPerUser'
    $conn = Get-DDRegistryValue -Path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name 'DefaultConnectionSettings'
    $hex = $null
    if ($conn -is [byte[]]) { $hex = (($conn | ForEach-Object { $_.ToString('x2') }) -join '') }
    [pscustomobject]@{ User = $user; Machine = $machine; ProxySettingsPerUser = $perUser; DefaultConnectionSettings = $hex }
}

function Get-DDPacSourcesRaw {
    # Where WinINET can be given a setup script (PAC), read-only (docs/17 section 4.3, ADR-0038): the device-wide store and
    # the per-machine policy's key (in force only when ProxySettingsPerUser = 0), each signed-in user's hive under
    # HKEY_USERS (S-1-5-21: domain and local accounts; S-1-12-1: Entra ID accounts) and NetworkService's (S-1-5-20), the
    # account DoSvc runs as. A user who is not signed in has no hive loaded and is not read: the collector never loads one.
    # Returns each scope's values only, never a SID, a user name or a profile path.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $null }
    $is = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $read = {
        param([string] $Root, [string] $Scope)
        $url = Get-DDRegistryValue -Path "$Root\$is" -Name 'AutoConfigURL'
        $conn = Get-DDRegistryValue -Path "$Root\$is\Connections" -Name 'DefaultConnectionSettings'
        $hex = $null
        if ($conn -is [byte[]]) { $hex = (($conn | ForEach-Object { $_.ToString('x2') }) -join '') }
        [pscustomobject]@{ Scope = $Scope; AutoConfigUrl = $(if ($url) { [string]$url } else { $null }); Connections = $hex }
    }
    $policy = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    $perUser = Get-DDRegistryValue -Path $policy -Name 'ProxySettingsPerUser'
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $entries.Add((& $read 'HKLM' 'device'))
    $polUrl = Get-DDRegistryValue -Path $policy -Name 'AutoConfigURL'
    if ($polUrl) { $entries.Add([pscustomobject]@{ Scope = 'device'; AutoConfigUrl = [string]$polUrl; Connections = $null }) }
    $users = 0; $unreadable = 0
    $hku = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    try { $sids = @($hku.GetSubKeyNames()) } finally { $hku.Dispose() }
    foreach ($sid in $sids) {
        $scope = $(if ($sid -match '^S-1-(?:5-21|12-1)-\d+-\d+-\d+-\d+$') { 'user' } elseif ($sid -eq 'S-1-5-20') { 'service' } else { $null })
        if (-not $scope) { continue }
        try {
            $entries.Add((& $read "HKU\$sid" $scope))
            if ($scope -eq 'user') { $users++ }
        } catch { if ($scope -eq 'user') { $unreadable++ } }
    }
    [pscustomobject]@{ PerMachine = ($null -ne $perUser -and [int]$perUser -eq 0); Entries = $entries.ToArray(); UsersRead = $users; UsersUnreadable = $unreadable }
}

function Get-DDNetworkRaw {
    # Active adapter = the one carrying the lowest-metric IPv4 default route.
    [CmdletBinding()]
    param()
    $route = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property { $_.RouteMetric + $_.InterfaceMetric }) | Select-Object -First 1
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Name = [string]$_.Name; Description = [string]$_.InterfaceDescription; Status = [string]$_.Status
                MediaType = [string]$_.MediaType; PhysicalMediaType = [string]$_.PhysicalMediaType; IfIndex = [int]$_.ifIndex; IfType = [int]$_.InterfaceType }
        })
    $ip = $null; $v6 = @()
    if ($route) {
        $ip = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        # The IPv6 prefixes of the same interface, 'address/length', so an IPv6 peer can be judged on this device's network
        # (link-local is on the link by definition and is not listed). In memory only: never sent.
        $v6 = @(Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                Where-Object { [string]$_.IPAddress -notmatch '(?i)^fe[89ab]' } | Select-Object -First 8 | ForEach-Object { '{0}/{1}' -f $_.IPAddress, $_.PrefixLength })
    }
    [pscustomobject]@{
        DefaultInterfaceIndex = $(if ($route) { [int]$route.InterfaceIndex } else { $null })
        Gateway = $(if ($route) { [string]$route.NextHop } else { $null })
        IPv4 = $(if ($ip) { [string]$ip.IPAddress } else { $null })
        PrefixLength = $(if ($ip) { [int]$ip.PrefixLength } else { $null })
        IPv6Networks = [string[]]$v6
        Adapters = $adapters
    }
}

function Get-DDConnectionCost {
    # WinRT NetworkCostType. Not available in PowerShell 7+ (no WinRT projection): returns $null there.
    [CmdletBinding()]
    param()
    if ($PSVersionTable.PSVersion.Major -ge 6) { return $null }
    try {
        [void][Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
        $p = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
        if ($null -eq $p) { return $null }
        [string]$p.GetConnectionCost().NetworkCostType
    } catch { $null }
}

function Get-DDAdSiteName {
    # Netlogon caches the computer's AD site in DynamicSiteName (no directory query needed); falls back to the .NET
    # directory API. A workgroup / non-domain device has no site: $null without an error.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return $null }
    $cached = Get-DDRegistryValue -Path 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DynamicSiteName'
    if ($cached) { return [string]$cached }
    Add-Type -Verbose:$false -AssemblyName System.DirectoryServices
    try { [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name }
    catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] { $null }
}

function Get-DDAdapterCandidatesRaw {
    <#
    .SYNOPSIS
        Every network interface, in the order Windows enumerates them (GetAdaptersAddresses, through .NET NetworkInterface),
        with its state, IANA type, interface index, IPv4 addresses and prefix lengths, and whether a connector is present.
    .DESCRIPTION
        ConnectorPresent comes from MSFT_NetAdapter (Get-NetAdapter), documented as "TRUE if this is a physical adapter or
        FALSE if this is not a physical adapter", which is the flag GetIfEntry2 reports in InterfaceAndOperStatusFlags; reading
        it through CIM needs no runtime-compiled code. The adapter GUID stays on the device: only the DHCP request uses it.
    #>
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return @() }
    $connector = @{}
    foreach ($a in @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)) {
        $g = [string]$a.InterfaceGuid
        if ($g) { $connector[$g.ToLowerInvariant()] = [bool]$a.ConnectorPresent }
    }
    $out = New-Object 'System.Collections.Generic.List[object]'
    $order = 0
    foreach ($n in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        $ipv4 = New-Object 'System.Collections.Generic.List[object]'
        $ifIndex = $null
        try {
            $props = $n.GetIPProperties()
            try { $ifIndex = [int]$props.GetIPv4Properties().Index } catch { $ifIndex = $null }
            foreach ($u in $props.UnicastAddresses) {
                if ($u.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $ipv4.Add([pscustomobject]@{ Address = $u.Address.ToString(); PrefixLength = [int]$u.PrefixLength }) }
            }
        } catch { Write-Verbose "IP properties of $($n.Name): $($_.Exception.Message)" }
        $id = [string]$n.Id
        $out.Add([pscustomobject]@{
                Order = $order; Id = $id; Name = [string]$n.Name; Description = [string]$n.Description
                Up = ([string]$n.OperationalStatus -eq 'Up'); IfType = [int]$n.NetworkInterfaceType; IfIndex = $ifIndex
                ConnectorPresent = $(if ($connector.ContainsKey($id.ToLowerInvariant())) { $connector[$id.ToLowerInvariant()] } else { $null })
                IPv4 = $ipv4.ToArray()
            })
        $order++
    }
    , $out.ToArray()
}

function Get-DDDhcpOptionsRaw {
    # DHCP options on one adapter (DhcpRequestParams; ProbeNative.ps1). Mockable in tests.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $AdapterId, [Parameter(Mandatory)][int[]] $OptionIds, [int] $TimeoutMs = 8000)
    Invoke-DDDhcpRequest -AdapterId $AdapterId -OptionIds $OptionIds -TimeoutMs $TimeoutMs
}

function Test-DDPathExists {
    # Whether a path exists, telling "absent" ($false) from "not allowed to look" (throws, so Invoke-DDStep records
    # insufficient-rights): Test-Path answers $false to both.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string] $Path, [switch] $Container)
    try { $i = Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch [System.Management.Automation.ItemNotFoundException] { return $false }
    if ($Container) { return [bool]$i.PSIsContainer }
    $true
}

function Get-DDCacheFolderAclRaw {
    <#
    .SYNOPSIS
        The access rules on the Delivery Optimization cache folder, by SID (language independent), and the SID of
        NT SERVICE\DoSvc as Windows resolves it. Read-only (Get-Acl).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-DDWindows)) { return $null }
    $doSvc = $null
    try { $doSvc = (New-Object System.Security.Principal.NTAccount('NT SERVICE', 'DoSvc')).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $doSvc = $null }
    if (-not (Test-DDPathExists -Path $Path -Container)) { return [pscustomobject]@{ Exists = $false; DoSvcSid = $doSvc; Entries = @() } }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $entries = @(foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            [pscustomobject]@{
                Sid = [string]$r.IdentityReference.Value; Type = [string]$r.AccessControlType; Rights = (([long][int]$r.FileSystemRights) -band 4294967295)
                Inheritance = [string]$r.InheritanceFlags; Propagation = [string]$r.PropagationFlags
            }
        })
    [pscustomobject]@{ Exists = $true; DoSvcSid = $doSvc; Entries = $entries }
}

function Test-DDDoStateFile {
    # DoSvc's state file under the NetworkService profile. It does not follow DOModifyCacheDrive (the working directory may
    # move; the state does not).
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows) -or -not $env:SystemRoot) { return $null }
    Test-DDPathExists -Path (Join-Path $env:SystemRoot 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State\dosvcState.dat')
}

function Get-DDUusVersionRaw {
    # The Unified Update Stack version file, as Microsoft's DeliveryOptimizationTroubleshooter reads it. Not a documented
    # interface: absent means $null, not an error.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows) -or -not $env:ProgramData) { return $null }
    $p = Join-Path $env:ProgramData 'Microsoft\Windows\UUS\State\_active.uusver'
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
    [string](Get-Content -LiteralPath $p -TotalCount 1 -ErrorAction Stop)
}

function Get-DDActivePowerPlan {
    # Win32_PowerPlan (root/cimv2/power) whose IsActive is true: its ElementName.
    [CmdletBinding()]
    param()
    $p = @(Get-DDCim -Namespace 'root/cimv2/power' -ClassName 'Win32_PowerPlan' | Where-Object { $_.IsActive -eq $true }) | Select-Object -First 1
    if ($null -eq $p) { return $null }
    [string]$p.ElementName
}

function Get-DDNlmCostText {
    # `netsh nlm show cost`: INetworkCostManager's cost per interface (cost, data limit, bandwidth). Local bundle only. It
    # names no network or SSID; `netsh nlm query all`, which lists network names, is deliberately not run.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('netsh nlm is Windows only.') }
    @(& (Join-Path $env:SystemRoot 'System32\netsh.exe') nlm show cost 2>&1 | ForEach-Object { [string]$_ })
}

function Get-DDRegistryTree {
    # A key, its values and its subkeys to -Depth, read-only: the local bundle's export of the DoSvc service key.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [int] $Depth = 3)
    $v = Get-DDRegistryValues -Path $Path
    $node = [ordered]@{ key = $Path; present = [bool]$v.Present; values = @($v.Values | Select-Object -First 256); subkeys = @() }
    if ($v.Present -and $Depth -gt 0) {
        $node['subkeys'] = @(foreach ($s in @(Get-DDRegistrySubKeyNames -Path $Path | Select-Object -First 32)) { Get-DDRegistryTree -Path "$Path\$s" -Depth ($Depth - 1) })
    }
    $node
}

function Get-DDBatteryRaw {
    [CmdletBinding()]
    param()
    @(Get-DDCim -ClassName 'Win32_Battery')
}

function Get-DDLocalDisks {
    [CmdletBinding()]
    param()
    @(Get-DDCim -ClassName 'Win32_LogicalDisk' | Where-Object { $_.DriveType -eq 3 } | ForEach-Object {
            [pscustomobject]@{ DeviceId = [string]$_.DeviceID; Size = [long]$_.Size; FreeSpace = [long]$_.FreeSpace }
        })
}

function Get-DDPhysicalDisks {
    # MSFT_PhysicalDisk (Storage namespace): MediaType 3=HDD 4=SSD, BusType 17=NVMe.
    [CmdletBinding()]
    param()
    @(Get-DDCim -Namespace 'root/Microsoft/Windows/Storage' -ClassName 'MSFT_PhysicalDisk' | ForEach-Object {
            [pscustomobject]@{ MediaType = [int]$_.MediaType; BusType = [int]$_.BusType; Size = [long]$_.Size }
        })
}

function Get-DDTpmRaw {
    [CmdletBinding()]
    param()
    $t = @(Get-DDCim -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_Tpm')
    if ($t.Count -eq 0) { return $null }
    [pscustomobject]@{ SpecVersion = [string]$t[0].SpecVersion }
}

function Get-DDConfigMgrRaw {
    # SMS client presence and site code: root\ccm SMS_Authority (TO-VERIFY). Boundary groups are not read. The co-management
    # workload flags: HKLM\SOFTWARE\Microsoft\CCM CoManagementFlags (TO-VERIFY), the value the client's handlers test a
    # workload's bit against (Microsoft's co-management troubleshooting shows "workloadFlags"); $null when absent.
    [CmdletBinding()]
    param()
    $svc = Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return [pscustomobject]@{ Client = $false; SiteCode = $null; CoManagementFlags = $null } }
    $site = $null
    try {
        $a = @(Get-DDCim -Namespace 'root/ccm' -ClassName 'SMS_Authority')
        if ($a.Count -gt 0 -and [string]$a[0].Name -match '^SMS:(.+)$') { $site = $Matches[1] }
    } catch { Write-Verbose "SMS_Authority: $($_.Exception.Message)" }
    $flags = $null
    $raw = Get-DDRegistryValue -Path 'HKLM\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
    if ($null -ne $raw) { try { $flags = [long]$raw; if ($flags -lt 0 -or $flags -gt 4294967295) { $flags = $null } } catch { $flags = $null } }
    [pscustomobject]@{ Client = $true; SiteCode = $site; CoManagementFlags = $flags }
}

function Get-DDMachineGuid {
    [CmdletBinding()]
    param()
    [string](Get-DDRegistryValue -Path 'HKLM\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid')
}

function Get-DDHostName {
    [CmdletBinding()]
    param()
    [System.Environment]::MachineName
}

function Get-DDNowUtc {
    [CmdletBinding()]
    param()
    [datetime]::UtcNow
}

# ---- certificates -----------------------------------------------------------------------------------------

function Get-DDMachineCertificates {
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { return @() }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
    try {
        $store.Open('ReadOnly')
        @($store.Certificates | ForEach-Object { $_ })
    } finally { $store.Close() }
}

function Open-DDMachineRsaKey {
    # Open a machine-scope CNG RSA key by container name and provider (for example the Entra device key in the
    # Microsoft Platform Crypto Provider). Windows only; needs SYSTEM or administrator rights to use the key.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $KeyContainer, [Parameter(Mandatory)][string] $KeyProvider)
    $provider = New-Object System.Security.Cryptography.CngProvider($KeyProvider)
    $key = [System.Security.Cryptography.CngKey]::Open($KeyContainer.Trim('{', '}'), $provider, [System.Security.Cryptography.CngKeyOpenOptions]::MachineKey)
    New-Object System.Security.Cryptography.RSACng($key)
}

# ---- protected files --------------------------------------------------------------------------------------

function Protect-DDPath {
    # Restrict a directory to SYSTEM and Administrators (inheritance removed). Windows only.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-DDWindows)) { return }
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-DDDirectorySecurityRaw {
    <#
    .SYNOPSIS
        What Test-DDTrustedDirectory judges the state folder by: whether it exists, whether it is itself a
        junction or link, its owner, whether its access rules are protected from inheritance, the rules (SID, Allow or
        Deny, rights), and how many subfolders and links it holds. Read-only; never follows a link. $null off Windows,
        where there is no ACL to judge. An error reading any of it is returned in Error, which is never trusted.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-DDWindows)) { return $null }
    $o = [ordered]@{ Exists = $false; ReparsePoint = $false; Owner = $null; Protected = $false; Rules = @(); Subdirectories = 0; Links = 0; Error = $null }
    try {
        # GetAttributes reads the entry itself: for a junction or symbolic link it is the link's attributes, not the target's.
        $attr = [System.IO.File]::GetAttributes($Path)
    } catch {
        $ex = $_.Exception
        if ($ex.InnerException) { $ex = $ex.InnerException }
        if ($ex -is [System.IO.FileNotFoundException] -or $ex -is [System.IO.DirectoryNotFoundException]) { return [pscustomobject]$o }
        $o['Exists'] = $true; $o['Error'] = $ex.Message
        return [pscustomobject]$o
    }
    $o['Exists'] = $true
    if ($attr -band [System.IO.FileAttributes]::ReparsePoint) { $o['ReparsePoint'] = $true; return [pscustomobject]$o }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $o['Owner'] = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $o['Protected'] = [bool]$acl.AreAccessRulesProtected
        $o['Rules'] = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                [pscustomobject]@{ Sid = $_.IdentityReference.Value; Type = [string]$_.AccessControlType; Rights = [int64]$_.FileSystemRights }
            })
        foreach ($e in [System.IO.Directory]::GetFileSystemEntries($Path)) {
            $a = [System.IO.File]::GetAttributes($e)
            if ($a -band [System.IO.FileAttributes]::ReparsePoint) { $o['Links']++ } elseif ($a -band [System.IO.FileAttributes]::Directory) { $o['Subdirectories']++ }
        }
    } catch { $o['Error'] = $_.Exception.Message }
    [pscustomobject]$o
}

function New-DDProtectedDirectory {
    # A folder only SYSTEM and Administrators can use (Protect-DDPath). Windows only; elsewhere a plain folder.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    [void](New-Item -ItemType Directory -Path $Path -Force)
    Protect-DDPath -Path $Path
}

# The only names the collector writes in its state folder: the state, the two caches, their temporary files, and the
# corrupt copies older collectors left. Reset-DDStateDirectory deletes nothing unless everything there has one of them.
$script:DDStateFolderNames = '^(state|endpoint-health|geo)\.json(\.[0-9a-f]{8}\.tmp|\.corrupt-\d{14})?$'

function Reset-DDStateDirectory {
    <#
    .SYNOPSIS
        Replace the collector's own state folder, when it cannot be trusted, with a new protected one. Called
        only for the default %ProgramData%\DoctorDO (Initialize-DDStateDirectory -AllowReset). First every entry is
        checked: a real subfolder, or any name the collector does not write, and this throws having deleted nothing.
        Only then are the entries deleted one by one, never following a link (deleting a link removes the link, not its
        target), the folder, or the junction standing in for it, is removed without recursing, and it is created again
        for SYSTEM and Administrators only. Windows only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-DDWindows)) { return }
    $link = [System.IO.FileAttributes]::ReparsePoint
    $entries = @()
    if (-not ([System.IO.File]::GetAttributes($Path) -band $link)) { $entries = @([System.IO.Directory]::GetFileSystemEntries($Path)) }
    foreach ($e in $entries) {
        $a = [System.IO.File]::GetAttributes($e)
        if (($a -band [System.IO.FileAttributes]::Directory) -and -not ($a -band $link)) { throw 'it holds a folder the collector did not create' }
        if ([System.IO.Path]::GetFileName($e) -notmatch $script:DDStateFolderNames) { throw 'it holds a file the collector did not create' }
    }
    foreach ($e in $entries) {
        if ([System.IO.File]::GetAttributes($e) -band [System.IO.FileAttributes]::Directory) { [System.IO.Directory]::Delete($e, $false) } else { [System.IO.File]::Delete($e) }
    }
    [System.IO.Directory]::Delete($Path, $false)
    New-DDProtectedDirectory -Path $Path
}
