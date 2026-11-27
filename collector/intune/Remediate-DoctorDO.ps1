#Requires -Version 5.1
# Copyright (c) 2026 Maurice Daly. SPDX-License-Identifier: MIT (see LICENSE in this folder).
# The DoctorDO.Collector module that this script uses is not MIT: it has its own licence (LICENSE in the module folder).

<#
.SYNOPSIS
    Intune remediation script for DoctorDO: installs and updates the collector module, then runs it in fleet mode as
    SYSTEM and posts to the ingest service.
.DESCRIPTION
    * Must run as SYSTEM: assign it with "Run this script using the logged-on credentials = No". The device key that
      signs each report is a machine key; a user context cannot use it (exit 6).
    * Runs in 64-bit PowerShell (relaunches itself in 64-bit if Intune started a 32-bit host).
    * Waits a random 0..MaxJitterSeconds first so a fleet on one schedule does not hit the service at the same instant.
    * Makes sure the DoctorDO.Collector module is installed for all users (%ProgramFiles%\WindowsPowerShell\Modules,
      the 64-bit folder) at or above -MinimumVersion, installing or updating it from a PowerShell repository
      (-Repository, default PSGallery; point it at your own). See "How the module is installed and trusted" below.
    * Calls Invoke-DoctorDOCollector -Fleet -IngestUri https://<host>/v1/ingest -DeviceAnchor <anchor> (and
      -CollectPublicEgress only when that setting is turned on; it is off by default). Each report is
      signed with the device key (ADR-0029): there is no credential in this script and none is needed.
        entra-device (default): the Entra device certificate. The device must be Microsoft Entra joined or hybrid
                                joined and enrolled in Intune; no certificate profile is needed.
        tenant-ca:              the tenant's Intune SCEP or PKCS certificate profile.
    * Writes a log in CMTrace format (open it with CMTrace or OneTrace):
        %ProgramData%\Microsoft\IntuneManagementExtension\Logs\DoctorDO-Remediation.log
      A folder that Intune's "Collect diagnostics" device action collects. At about 1 MB it is renamed to
      DoctorDO-Remediation.lo_ (the previous .lo_ is replaced) and a new file starts. Nothing in it is a credential,
      and anything that looks like one is replaced before it is written.
    * Prints one short line last, for the Remediations report in the Intune admin center (its output is limited to
      2,048 characters). The log has the detail.
    * Apart from the module install, the one thing the run writes is HKLM\SOFTWARE\DoctorDO (timestamp for the detection
      script) and the protected state file under %ProgramData%\DoctorDO.
    * Budget: under 60 seconds and 5 MB per device once the module is in place. Failure is silent to the user.

    How the module is installed and trusted (ADR-0041). The module is not signed, so before every Import-Module, on every
    run, the script checks the copy it is about to load, and loads nothing that fails a check (the failing copy is
    removed when it was just installed, and the previous version, if it passes, is used instead):
      1. Permissions: the version folder, its parent and every file can be written only by SYSTEM, Administrators and
         TrustedInstaller; no link anywhere in the tree.
      2. Contents: exactly the files the release lists, nothing else (PowerShellGet's own PSGetModuleInfo.xml excepted).
      3. Hashes: the SHA-256 of every file equals the release's list for that exact version.
      4. Identity: the module manifest is valid; its GUID and author equal the values in this script; its version is the
         folder's; its exported functions and its FileList are the expected ones.
      5. The module is imported by the full path of that version's .psd1, never by name.
      6. Optionally, with -ExpectedSignerThumbprint, every .ps1, .psm1 and .psd1 must also carry a Valid Authenticode
         signature by that certificate. Set it as soon as you sign the module.
    The release's list comes from -UpdatePolicy:
      LatestVerified (default): the newest version in the repository (up to -MaximumVersion), checked against the
        collector-manifest.json attached to the GitHub release with the same tag (-ManifestUrlTemplate, -GitHubOwner,
        -GitHubRepo). An attacker has to change the repository and the release. If the manifest cannot be read or does
        not match, nothing is updated: the version already installed and still verified keeps being used.
      Pinned: only the version stamped into this script (with the SHA-256 of its files), installed from the repository
        if missing. Nothing is downloaded but the module. Update the module by uploading a newer script.

    Exit codes: 0 success; 1 not elevated; 2 unsupported OS; 3 collection failed or script not configured;
    5 upload failed; 6 the device cannot identify itself: with entra-device, not Entra joined or hybrid joined
    (see dsregcmd /status) or no usable device certificate; with tenant-ca, the certificate profile is not deployed;
    7 the state folder is not safe to use; 8 the module is missing or too old and could not be installed;
    9 the module failed verification and no earlier verified version is installed; 10 the verified module could not be
    imported; 11 no version could be verified (the release manifest could not be read) and none is installed.

    EDIT $ConfiguredIngestUri (and $ConfiguredDeviceAnchor if the deployment uses tenant-ca) below, or set the
    DOCTORDO_INGEST_URI and DOCTORDO_DEVICE_ANCHOR machine environment variables, before uploading the script.
    Remediation scripts take no arguments in Intune, so the settings are in the script text: edit the defaults of the
    parameters.
.PARAMETER MaxJitterSeconds
    Upper bound of the random start delay. Default 600. Set 0 to disable.
.PARAMETER ModuleName
    The module to install. Default DoctorDO.Collector.
.PARAMETER Repository
    The name of a registered PowerShell repository to install from. Default PSGallery. The repository's trust setting
    is never changed; the install passes -Force for this one call.
.PARAMETER UpdatePolicy
    LatestVerified (default) or Pinned, as above.
.PARAMETER MinimumVersion
    The oldest version that may run. Default 1.2.3. With LatestVerified a version below it is replaced; with Pinned the
    stamped version is the requirement and this is not used.
.PARAMETER MaximumVersion
    Optional cap for LatestVerified: do not install or use anything newer. Empty (default) for no cap.
.PARAMETER GitHubOwner
    The GitHub account or organisation that publishes the release. Used in -ManifestUrlTemplate.
.PARAMETER GitHubRepo
    The repository that publishes the release. Used in -ManifestUrlTemplate.
.PARAMETER ManifestUrlTemplate
    Where collector-manifest.json is downloaded from, with {owner}, {repo} and {version} replaced. Default
    https://github.com/{owner}/{repo}/releases/download/collector-v{version}/collector-manifest.json . It must be
    https. A repository that is private cannot be read without a sign-in, which this script does not do: host the file
    somewhere the devices can read (for example an internal web site or a storage account's public blob) and put its
    address here.
.PARAMETER ExpectedSignerThumbprint
    Optional. When set, every .ps1, .psm1 and .psd1 of the module must have a Valid Authenticode signature by the
    certificate with this thumbprint. Why to set it: the other checks prove that the files are the ones the release
    lists, but only a signature proves who made the release, and it also holds if both the repository and the
    release site are compromised.
.PARAMETER ModulesPath
    The module folder to install into and check. Default: the 64-bit %ProgramFiles%\WindowsPowerShell\Modules. For
    testing only.
.PARAMETER LogPath
    The CMTrace log. Default %ProgramData%\Microsoft\IntuneManagementExtension\Logs\DoctorDO-Remediation.log .
.PARAMETER CollectPublicEgress
    Passes -CollectPublicEgress to the collector: each report then carries a tenant-salted hash of the device's public
    egress address, read from the Delivery Optimization geo service's answer (no other service is called), which the
    source-IP checks (proxy-source-ip, DO-NET-009) compare between devices on one subnet. Off by default; without it those
    checks read not-collected. The address itself is never stored or sent, but anyone who knows the tenant ID can test a
    guessed address against the hash. In Intune, set $ConfiguredCollectPublicEgress = $true in the script text, or the
    DOCTORDO_COLLECT_PUBLIC_EGRESS machine environment variable to 1.
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 3600)][int] $MaxJitterSeconds = 600,
    [string] $IngestUri = '',
    [string] $DeviceAnchor = '',
    [ValidatePattern('^[A-Za-z0-9._-]+$')][string] $ModuleName = 'DoctorDO.Collector',
    [ValidatePattern('^[A-Za-z0-9._ -]+$')][string] $Repository = 'PSGallery',
    [ValidateSet('Pinned', 'LatestVerified')][string] $UpdatePolicy = 'LatestVerified',
    # LatestVerified looks for a newer version in -Repository at most this often while a version that meets the minimum is
    # installed (0: every run). The time of the last successful look is kept in HKLM:\SOFTWARE\DoctorDO.
    [ValidateRange(0, 720)][int] $UpdateCheckHours = 24,
    [string] $MinimumVersion = '1.2.3',
    [string] $MaximumVersion = '',
    [string] $GitHubOwner = 'maurice-daly',
    [string] $GitHubRepo = 'doctordo',
    [string] $ManifestUrlTemplate = 'https://github.com/{owner}/{repo}/releases/download/collector-v{version}/collector-manifest.json',
    [string] $ExpectedSignerThumbprint = '',
    [string] $ModulesPath = '',
    [string] $LogPath = '',
    [switch] $CollectPublicEgress
)

Set-StrictMode -Version Latest

# ---- configuration (edit) ----------------------------------------------------------------------------------------
$ConfiguredIngestUri = 'https://REPLACE-WITH-YOUR-INGEST-HOST/v1/ingest'
$ConfiguredDeviceAnchor = 'entra-device'      # or 'tenant-ca'; must match the deployment's deviceAnchor
# $true adds a tenant-salted hash of each device's public egress address, read from the DO geo service's answer, so the
# source-IP checks (proxy-source-ip, DO-NET-009) can run. Off by default: it is a hash of the address, and anyone with the
# tenant ID can test a guessed address against it (see -CollectPublicEgress below).
$ConfiguredCollectPublicEgress = $false
# ------------------------------------------------------------------------------------------------------------------

# The release this script was built with. Written by collector/tools/package-collector.ps1 -Stamp from the module folder
# (a test fails when it is out of date): the identity every installed copy must have, and, for -UpdatePolicy Pinned (and
# for this version under LatestVerified), the SHA-256 of every file.
# BEGIN GENERATED PINNED RELEASE (collector/tools/package-collector.ps1 -Stamp; do not edit by hand)
$DoctorDOExpectedGuid = '6f0d2a7e-3c5b-4e8a-9b1d-7a2c4e6f8b10'
$DoctorDOExpectedAuthor = 'Maurice Daly'
$DoctorDOExpectedFunctions = @('Get-DOConnectivityMatrix', 'Get-DOInventory', 'Get-DOTelemetry', 'Invoke-DoctorDOCollector', 'New-DoctorDODeviceReport', 'Send-DoctorDOReport', 'Test-DOConnectivity')
$DoctorDOPinnedVersion = '1.2.3'
$DoctorDOPinnedFiles = [ordered]@{
    'Data/device-report.html' = '2fa4298c17f209dbb60c1761f09b86d9d7f249dfda5e1961427ecf5879bc3edd'
    'Data/endpoints.json' = '16e669ea016790177e37f62ff9d7d01e1b0231fac0a441b7b09847b9fd35967c'
    'Data/redaction-profile.json' = '5f9d48524d3902f7f739654397ce5b87cf293a5caee8c0164eb1c744dd9a5fb7'
    'DoctorDO.Collector.format.ps1xml' = '77f5d0cd91d3e12f1fe8f9da732dea69778b4a56ad9a38335277f3def4401bad'
    'DoctorDO.Collector.psd1' = 'edc6ecc94aaa94737122935c4663884ea35a663c8b9478420a9319db52a7ad93'
    'DoctorDO.Collector.psm1' = 'f4ffb6d048124c4883bd40093c0a746b86fa8ad9ac73b6fb5b029c1fea059b2f'
    'LICENSE' = 'f09acf271009e72367046b49b22aa1332794011a51b4c170b2f76c26a140ccb0'
    'Private/Bundle.ps1' = 'c1cafcb677a1fb113290d477dad7dc9936fb0e8cf27532b36a2b990cd5e9d12e'
    'Private/Collect.ps1' = 'c553e24df921418b3051c84174b83bd8657529e5342c6689ece1db98f86da29d'
    'Private/Compact.ps1' = '2b2d1e3b61e7ed86582b691852afbd0307feb4fe2671accd541c4cb5a08a2500'
    'Private/Connectivity.ps1' = '6d5c0c7ae903e1b4128dce6a72151436d4d5a2f72bb6f36db9ba4e2ec5605dcd'
    'Private/Console.ps1' = '6d732bf152f48842c31e7282f531b7f22d90e7ebb350b92044483bf3bc85dfb2'
    'Private/Context.ps1' = '98248bb91957b4cdc72e9b16ce4dd14578c3c4551dfa7e1d2e0358f6cb19dea2'
    'Private/Diag.ps1' = '64acddb5f3d63683ac2e55cc1612cae56498237d845f98073d4ef34bd1350d19'
    'Private/DoData.ps1' = '0470cfe7bd89fee2d19c6841e65afd871dcf9931fb2385ff126eada9c2e51cfa'
    'Private/Endpoints.ps1' = 'ec053d7c7d548f75f9e278f05d4adbe9de12d3231876d85ab1467387b7543ee5'
    'Private/Facts.ps1' = '39665c1633f00f8661347f47839b594c5d2ac6e171f004c8477b397d97d58bd2'
    'Private/Health.ps1' = '0526eef58aec103096bfb630e6294d1197ce7d61589bad675c42af5f9365f48a'
    'Private/Http.ps1' = '5dcbd81f450414832daee56dcf1ed25d91912ee41a558899af8720e16637c85d'
    'Private/Insight.ps1' = 'f67adea637361c3fc79308b01f0f4e987917b1d3569ab1481fc6d440fa5791cd'
    'Private/Json.ps1' = '53c434cad16886edf3e7c4a5f1d24cc09147a5cd3f6eae25d9b55db61e74da61'
    'Private/Pac.ps1' = '1582da9f49e800fa95410f93a5b3e9126c20b925579c2a10b5bed72eb33d2413'
    'Private/Platform.ps1' = '1d248c650fb1baa5f531da30b2b0d779ec3c28b1f7d210b837294868be22be41'
    'Private/ProbeNative.ps1' = 'ec95aca7fda99007445321e7f86788a911b84865d327cc985d3395c52753a330'
    'Private/Progress.ps1' = 'f234c0a2441b38e71c562e268f15c072c3900211dca9bd8fbdd6f03e31d96ed1'
    'Private/Provisioning.ps1' = '43e0e523d8fb123a12fd840a993dac7abb6a96fb6318612c541202706d2a8be8'
    'Private/Redact.ps1' = 'b76e75a2ffc335ea633de68e30f016d8f17e1d26d51d09812fa396d1dc84192e'
    'Private/Report.ps1' = '2768cb211641c2525fb05528a8517aeb8791369cf9d62350f7a95efa6d2abc96'
    'Private/Signing.ps1' = 'b8d3129135252bbd45c89b517d1d51fea597f9f2d8e18d1ba0a1c2f93fc2b83a'
    'Private/State.ps1' = '26dbb6048df3dc1b92b0bf56eb9d739d288a23a0fe99c9783d167a8dae22710e'
    'Private/VerboseCycle.ps1' = 'd0eb4ab94f38c180efb4c2f4acede6d0e2268bf48a63bebc664a090552e75b12'
    'Public/Get-DOConnectivityMatrix.ps1' = 'de9ce0bfedc58e9c5e6806008cf8bb1b1bc0a7022e0e8e1a015b1f94a43caa60'
    'Public/Get-DOInventory.ps1' = 'd7c8c19df9fb67c28577fd76bfa2126615617e77cee70c151d385226423eb833'
    'Public/Get-DOTelemetry.ps1' = 'b79333ebae93b211f7c0fc45f26582293377a2e15a310ca1215dc3a31c8394a1'
    'Public/Invoke-DoctorDOCollector.ps1' = 'a9f807576f8f2c1e01066ef250c95d12318a8df290f27e191d2bfca8b39dadde'
    'Public/New-DoctorDODeviceReport.ps1' = 'f3a102cb71610f00c04303492e035b3db32e2a0604887a4d47a95175a00690d7'
    'Public/Send-DoctorDOReport.ps1' = 'ff55722b2773dc5c8308b6bcfcc69c48ff6488a08d12552b56ece8fe57984392'
    'Public/Test-DOConnectivity.ps1' = '87c0ba2565317c970e6e5052af5d687f433f0bfefc3f7658485b6fb124db6486'
    'THIRD-PARTY-NOTICES.txt' = 'a0574f4c4628f9fc44830cfe659223f829ef9b3e1dbea815b5446f19d0301aaa'
    'en-US/about_DoctorDO.Collector.help.txt' = '09e73014ce7e2deaad92846dd5856589f84191bec05073743f22bf2901ba5235'
}
# END GENERATED PINNED RELEASE

# Exit codes added for the module install (the others are the collector's: collector/intune/README.md).
$script:ExitModuleInstall = 8
$script:ExitModuleIntegrity = 9
$script:ExitModuleImport = 10
$script:ExitModuleUnverified = 11

# ---- CMTrace log ------------------------------------------------------------------------------------------------
# <![LOG[message]LOG]!><time="HH:mm:ss.fff+bias" date="MM-dd-yyyy" component="..." context="" type="1" thread="..." file="...">
# type 1 information, 2 warning, 3 error. bias: minutes, in the sign of the Windows time-zone bias (UTC = local + bias, so
# UTC+1 is -060 and UTC-7 is +420) -- TO VERIFY against CMTrace on a device: Microsoft documents the bias, not CMTrace's
# line format. The same functions are in Detect-DoctorDO.ps1 (a test keeps them identical).
$script:DDLog = @{ Path = ''; Component = 'Remediate-DoctorDO'; File = 'Remediate-DoctorDO.ps1'; MaxBytes = 1048576; Failed = $false }

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

# ---- configuration of the run -------------------------------------------------------------------------------------

function Resolve-DoctorDOIngestUri {
    # https://<host>/v1/ingest only: the path is part of the signed request, so anything else would be refused by the
    # service. A bare https://<host> is completed with /v1/ingest.
    [CmdletBinding()]
    param([string] $Explicit, [string] $Configured, [string] $FromEnvironment)
    foreach ($c in $Explicit, $FromEnvironment, $Configured) {
        if ($c -and $c -notmatch 'REPLACE-WITH') {
            $u = $null
            if ([System.Uri]::TryCreate($c, [System.UriKind]::Absolute, [ref]$u) -and $u.Scheme -eq 'https' -and -not $u.Query) {
                if ($u.AbsolutePath -eq '/') { $u = New-Object System.Uri($u, '/v1/ingest') }
                if ($u.AbsolutePath -ceq '/v1/ingest') { return $u }
            }
        }
    }
    $null
}

function Resolve-DoctorDODeviceAnchor {
    [CmdletBinding()]
    param([string] $Explicit, [string] $Configured, [string] $FromEnvironment)
    foreach ($c in $Explicit, $FromEnvironment, $Configured) {
        if ($c) {
            $v = $c.Trim().ToLowerInvariant()
            if ($v -in 'entra-device', 'tenant-ca') { return $v }
            return $null     # a value that is set but wrong is a configuration error, not a reason to fall through
        }
    }
    'entra-device'
}

function Resolve-DoctorDOCollectPublicEgress {
    # Off unless a setting turns it on: the -CollectPublicEgress switch, the DOCTORDO_COLLECT_PUBLIC_EGRESS machine variable
    # ('1' or 'true'), or $ConfiguredCollectPublicEgress = $true in the script text.
    [CmdletBinding()]
    param([bool] $Explicit, [bool] $Configured, [string] $FromEnvironment)
    $Explicit -or $Configured -or ([string]$FromEnvironment).Trim() -in '1', 'true'
}

function Get-DoctorDOStartDelay {
    [CmdletBinding()]
    param([int] $MaxJitterSeconds)
    if ($MaxJitterSeconds -le 0) { return 0 }
    Get-Random -Minimum 0 -Maximum ($MaxJitterSeconds + 1)
}

# ---- the module: where it is, what it must be ---------------------------------------------------------------------

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

function New-DoctorDOSpec {
    # What a copy of one version must be: identity (GUID, author, exported functions) and its files with SHA-256.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $ModuleName, [Parameter(Mandatory)][string] $Version, [Parameter(Mandatory)][string] $Guid, [Parameter(Mandatory)][string] $Author,
        [Parameter(Mandatory)][string[]] $Functions, [Parameter(Mandatory)] $Files, [Parameter(Mandatory)][string] $Source)
    $map = @{}
    foreach ($k in $Files.Keys) { $map[([string]$k).Replace('\', '/')] = ([string]$Files[$k]).ToLowerInvariant() }
    [pscustomobject]@{ ModuleName = $ModuleName; Version = $Version; Guid = $Guid; Author = $Author; Functions = @($Functions); Files = $map; Source = $Source }
}

function Get-DoctorDOJsonMember {
    # A property of a parsed JSON object, or $null when it is not there (strict mode would throw).
    [CmdletBinding()]
    param($Object, [Parameter(Mandatory)][string] $Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    $p.Value
}

function ConvertTo-DoctorDOSpecFromManifest {
    # Reads collector-manifest.json. Throws a reason when it is not the manifest of this module and version.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Json, [Parameter(Mandatory)][string] $ModuleName, [Parameter(Mandatory)][string] $Version,
        [Parameter(Mandatory)][string] $ExpectedGuid, [Parameter(Mandatory)][string] $ExpectedAuthor)
    try { $m = $Json | ConvertFrom-Json -ErrorAction Stop } catch { throw 'the release manifest is not valid JSON' }
    if ((Get-DoctorDOJsonMember $m 'schema') -cne 'doctordo-collector-manifest/1') { throw 'the release manifest has an unknown schema' }
    if ((Get-DoctorDOJsonMember $m 'module') -cne $ModuleName) { throw 'the release manifest is for another module' }
    if ([string](Get-DoctorDOJsonMember $m 'version') -ne $Version) { throw "the release manifest is for version $(Get-DoctorDOJsonMember $m 'version'), not $Version" }
    if ([string](Get-DoctorDOJsonMember $m 'guid') -ne $ExpectedGuid) { throw 'the release manifest carries a different module GUID than this script expects' }
    if ([string](Get-DoctorDOJsonMember $m 'author') -cne $ExpectedAuthor) { throw 'the release manifest carries a different author than this script expects' }
    $exports = @(Get-DoctorDOJsonMember $m 'exports')
    if ($exports.Count -lt 1 -or $exports.Count -gt 200) { throw 'the release manifest lists no exported functions' }
    foreach ($e in $exports) { if (($e -isnot [string]) -or $e -notmatch '^[A-Za-z][A-Za-z0-9-]*$') { throw 'the release manifest lists an invalid function name' } }
    $rows = @(Get-DoctorDOJsonMember $m 'files')
    if ($rows.Count -lt 1 -or $rows.Count -gt 500) { throw 'the release manifest lists no files, or too many' }
    $files = [ordered]@{}
    foreach ($r in $rows) {
        $p = [string](Get-DoctorDOJsonMember $r 'path')
        $h = [string](Get-DoctorDOJsonMember $r 'sha256')
        if (-not $p -or $p.StartsWith('/') -or $p.Contains('\') -or $p.Contains(':') -or ($p -split '/') -contains '..' -or ($p -split '/') -contains '.' -or ($p -split '/') -contains '') { throw 'the release manifest lists an unsafe file path' }
        if ($h -notmatch '^[0-9A-Fa-f]{64}$') { throw 'the release manifest lists an invalid SHA-256' }
        if ($files.Contains($p.ToLowerInvariant())) { throw 'the release manifest lists a file twice' }
        $files[$p.ToLowerInvariant()] = $h
    }
    New-DoctorDOSpec -ModuleName $ModuleName -Version $Version -Guid $ExpectedGuid -Author $ExpectedAuthor -Functions ([string[]]$exports) -Files $files -Source 'release manifest'
}

function Get-DoctorDOManifestUrl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Template, [Parameter(Mandatory)][string] $Owner, [Parameter(Mandatory)][string] $Repo, [Parameter(Mandatory)][string] $Version)
    $url = $Template.Replace('{owner}', [System.Uri]::EscapeDataString($Owner)).Replace('{repo}', [System.Uri]::EscapeDataString($Repo)).Replace('{version}', [System.Uri]::EscapeDataString($Version))
    $u = $null
    if (-not [System.Uri]::TryCreate($url, [System.UriKind]::Absolute, [ref]$u) -or $u.Scheme -ne 'https' -or $u.UserInfo) { throw 'the manifest URL is not an https address' }
    $u.AbsoluteUri
}

function Set-DoctorDOTls12 {
    # Windows PowerShell 5.1 can default to TLS 1.0/1.1, which the Gallery and GitHub refuse.
    [CmdletBinding()]
    param()
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
}

function Get-DoctorDOReleaseManifestText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Url)
    Set-DoctorDOTls12
    $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
    $c = $r.Content
    if ($c -is [byte[]]) { $c = (New-Object System.Text.UTF8Encoding($false)).GetString($c) }
    $c = ([string]$c).TrimStart([char]0xFEFF)
    if ($c.Length -gt 262144) { throw 'the release manifest is larger than 256 KB' }
    $c
}

# ---- the checks ---------------------------------------------------------------------------------------------------

# SYSTEM, Administrators, TrustedInstaller, and CREATOR OWNER (a placeholder for the owner, who is checked separately).
$script:DDTrustedWriters = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')
# FileSystemRights bits that change a file or folder: WriteData, AppendData, WriteExtendedAttributes, DeleteSubdirectoriesAndFiles,
# WriteAttributes, Delete, ChangePermissions, TakeOwnership, GenericWrite, GenericAll.
$script:DDWriteMask = [int64](0x2 + 0x4 + 0x10 + 0x40 + 0x100 + 0x10000 + 0x40000 + 0x80000 + 0x10000000 + 0x40000000)

function Get-DoctorDOPathSecurityRaw {
    <#
    .SYNOPSIS
        What the permission check judges a folder or file by: whether it exists, whether it is a link, its owner, and its
        access rules (SID, Allow or Deny, rights), inherited ones included. Read-only, never follows a link. The same reader
        as the collector's Get-DDDirectorySecurityRaw (the state folder), kept here because this script runs before the
        module is trusted. $null off Windows. Mocked in tests.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return $null }
    $o = [ordered]@{ Exists = $false; ReparsePoint = $false; Owner = $null; Rules = @(); Error = $null }
    try {
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
        $o['Rules'] = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                [pscustomobject]@{ Sid = $_.IdentityReference.Value; Type = [string]$_.AccessControlType; Rights = [int64]$_.FileSystemRights }
            })
    } catch { $o['Error'] = $_.Exception.Message }
    [pscustomobject]$o
}

function Test-DoctorDOPathSecurity {
    <#
    .SYNOPSIS
        Why a folder or file may be changed by someone other than SYSTEM, Administrators and TrustedInstaller, or $null
        when it may not. The module folder inherits from Program Files, so unlike the state folder it is not required to
        be protected: what counts is who can write, whether the rule was inherited or not. Allow rules for Users,
        Authenticated Users, Everyone or any other account that grant a write, delete, permission or ownership right make it
        unsafe; Deny rules are ignored. A $null Raw is not trusted. Reasons name no account (they reach the Intune output).
    #>
    [CmdletBinding()]
    param($Raw)
    if ($null -eq $Raw) { return 'its permissions could not be read' }
    if (-not $Raw.Exists) { return 'it is missing' }
    if ($Raw.Error) { return 'its permissions could not be read' }
    if ($Raw.ReparsePoint) { return 'it is a junction or symbolic link' }
    if ($script:DDTrustedWriters -notcontains [string]$Raw.Owner) { return 'it is owned by an account other than SYSTEM, Administrators or TrustedInstaller' }
    foreach ($r in @($Raw.Rules)) {
        if ($r.Type -ne 'Allow') { continue }
        if ($script:DDTrustedWriters -contains [string]$r.Sid) { continue }
        if (([int64]$r.Rights -band $script:DDWriteMask) -ne 0) { return 'other accounts than SYSTEM, Administrators and TrustedInstaller can change it' }
    }
    $null
}

function Get-DoctorDOTreeListing {
    # Files, links and folders under a folder, as relative paths with '/'. A link is listed and never entered.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Root)
    $base = $Root.TrimEnd('\', '/')
    $files = New-Object 'System.Collections.Generic.List[string]'
    $links = New-Object 'System.Collections.Generic.List[string]'
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($base)
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        foreach ($e in [System.IO.Directory]::GetFileSystemEntries($d)) {
            $a = [System.IO.File]::GetAttributes($e)
            $rel = $e.Substring($base.Length).TrimStart('\', '/').Replace('\', '/')
            if ($a -band [System.IO.FileAttributes]::ReparsePoint) { $links.Add($rel) }
            elseif ($a -band [System.IO.FileAttributes]::Directory) { $stack.Push($e) }
            else { $files.Add($rel) }
        }
    }
    [pscustomobject]@{ Files = @($files.ToArray()); Links = @($links.ToArray()) }
}

function New-DoctorDOCheckResult {
    [CmdletBinding()]
    param([bool] $Valid, [string] $Check = '', [string] $Reason = '')
    [pscustomobject]@{ Valid = $Valid; Check = $Check; Reason = $Reason }
}

function Test-DoctorDOModuleFolder {
    <#
    .SYNOPSIS
        Whether the installed copy in a version folder is the release in Spec. Every check fails closed (an error is a
        failure). Order: permissions, contents, hashes, then identity; the manifest is only parsed once nobody else could
        have changed the files and they are the ones the release lists. Returns Valid, Check (permissions, contents,
        hashes, identity, signature, error) and Reason.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)] $Spec, [string] $ExpectedSignerThumbprint = '')
    try {
        $root = $Path.TrimEnd('\', '/')
        # 4. permissions: the version folder, the module folder above it, and every file.
        $listing = Get-DoctorDOTreeListing -Root $root
        if ($listing.Links.Count -gt 0) { return New-DoctorDOCheckResult $false 'permissions' "it contains a link ($($listing.Links[0]))" }
        foreach ($p in @($root, (Split-Path -Path $root -Parent))) {
            $why = Test-DoctorDOPathSecurity -Raw (Get-DoctorDOPathSecurityRaw -Path $p)
            if ($why) { return New-DoctorDOCheckResult $false 'permissions' ("the folder $(Split-Path -Path $p -Leaf): $why") }
        }
        foreach ($f in $listing.Files) {
            $why = Test-DoctorDOPathSecurity -Raw (Get-DoctorDOPathSecurityRaw -Path (Join-Path -Path $root -ChildPath $f))
            if ($why) { return New-DoctorDOCheckResult $false 'permissions' "the file ${f}: $why" }
        }
        # 2. contents: exactly the release's files (PowerShellGet adds its own PSGetModuleInfo.xml when it installs).
        $onDisk = @{}
        foreach ($f in $listing.Files) { if ($f -ine 'PSGetModuleInfo.xml') { $onDisk[$f.ToLowerInvariant()] = $f } }
        foreach ($k in $onDisk.Keys) { if (-not $Spec.Files.ContainsKey($k)) { return New-DoctorDOCheckResult $false 'contents' "unexpected file $($onDisk[$k])" } }
        foreach ($k in $Spec.Files.Keys) { if (-not $onDisk.ContainsKey($k)) { return New-DoctorDOCheckResult $false 'contents' "missing file $k" } }
        # 3. hashes.
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            foreach ($k in $onDisk.Keys) {
                $hex = (($sha.ComputeHash([System.IO.File]::ReadAllBytes((Join-Path -Path $root -ChildPath $onDisk[$k]))) | ForEach-Object { $_.ToString('x2') }) -join '')
                if ($hex -ne $Spec.Files[$k]) { return New-DoctorDOCheckResult $false 'hashes' "the SHA-256 of $($onDisk[$k]) is not the release's" }
            }
        } finally { $sha.Dispose() }
        # 1. identity.
        $psd1 = Join-Path -Path $root -ChildPath ($Spec.ModuleName + '.psd1')
        $info = Test-ModuleManifest -Path $psd1 -ErrorAction Stop -WarningAction SilentlyContinue
        if ([string]$info.Guid -ne $Spec.Guid) { return New-DoctorDOCheckResult $false 'identity' 'the module GUID is not the expected one' }
        if ([string]$info.Author -cne $Spec.Author) { return New-DoctorDOCheckResult $false 'identity' 'the module author is not the expected one' }
        if ([version]$info.Version -ne [version]$Spec.Version) { return New-DoctorDOCheckResult $false 'identity' "the manifest version is $($info.Version), not $($Spec.Version)" }
        if ([System.IO.Path]::GetFileName($root) -ne $Spec.Version) { return New-DoctorDOCheckResult $false 'identity' 'the folder name is not the version' }
        $exported = @($info.ExportedFunctions.Keys | ForEach-Object { [string]$_ })
        if ($exported.Count -ne @($Spec.Functions).Count -or @($exported | Where-Object { $Spec.Functions -cnotcontains $_ }).Count -gt 0) { return New-DoctorDOCheckResult $false 'identity' 'the exported functions are not the expected ones' }
        $data = Import-PowerShellDataFile -LiteralPath $psd1
        $listed = @{}
        foreach ($f in @($data['FileList'])) { $listed[([string]$f).Replace('\', '/').ToLowerInvariant()] = $true }
        if ($listed.Count -eq 0) { return New-DoctorDOCheckResult $false 'identity' 'the manifest has no FileList' }
        foreach ($k in $onDisk.Keys) { if (-not $listed.ContainsKey($k)) { return New-DoctorDOCheckResult $false 'identity' "the manifest FileList lacks $($onDisk[$k])" } }
        foreach ($k in $listed.Keys) { if (-not $onDisk.ContainsKey($k)) { return New-DoctorDOCheckResult $false 'identity' "the manifest FileList names $k, which is not there" } }
        # Optional: a signature by the expected certificate on every script and manifest.
        if ($ExpectedSignerThumbprint) {
            $want = ($ExpectedSignerThumbprint -replace '\s', '').ToUpperInvariant()
            foreach ($k in $onDisk.Keys) {
                if ($k -notmatch '\.(ps1|psm1|psd1)$') { continue }
                $sig = Get-AuthenticodeSignature -FilePath (Join-Path -Path $root -ChildPath $onDisk[$k])
                if ([string]$sig.Status -ne 'Valid') { return New-DoctorDOCheckResult $false 'signature' "$($onDisk[$k]) has no valid signature (status $($sig.Status))" }
                if ([string]$sig.SignerCertificate.Thumbprint -ne $want) { return New-DoctorDOCheckResult $false 'signature' "$($onDisk[$k]) is signed by another certificate than the expected one" }
            }
        }
        New-DoctorDOCheckResult $true 'all' ''
    } catch {
        New-DoctorDOCheckResult $false 'error' "the check itself failed: $($_.Exception.Message)"
    }
}

# ---- install, import, clean up ------------------------------------------------------------------------------------

function Initialize-DoctorDONuGetProvider {
    # The NuGet package provider that PowerShellGet needs. Installed only when missing; the repository trust is untouched.
    [CmdletBinding()]
    param()
    $minimum = [version]'2.8.5.201'
    $have = @(Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue | Where-Object { [version]$_.Version -ge $minimum })
    if ($have.Count -gt 0) { Write-DoctorDOLog "NuGet package provider $($have[0].Version) is present." ; return }
    Write-DoctorDOLog 'NuGet package provider 2.8.5.201 or later is missing: installing it.'
    Set-DoctorDOTls12
    [void](Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop)
    Write-DoctorDOLog 'NuGet package provider installed.'
}

function Remove-DoctorDOTree {
    # Deletes a folder tree without following a link: a link is removed, never its target.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path)
    $a = [System.IO.File]::GetAttributes($Path)
    $isDir = [bool]($a -band [System.IO.FileAttributes]::Directory)
    if ($a -band [System.IO.FileAttributes]::ReparsePoint) {
        if ($isDir) { [System.IO.Directory]::Delete($Path, $false) } else { [System.IO.File]::Delete($Path) }
        return
    }
    if ($isDir) {
        foreach ($e in [System.IO.Directory]::GetFileSystemEntries($Path)) { Remove-DoctorDOTree -Path $e }
        [System.IO.Directory]::Delete($Path, $false)
    } else {
        [System.IO.File]::SetAttributes($Path, [System.IO.FileAttributes]::Normal)
        [System.IO.File]::Delete($Path)
    }
}

function Remove-DoctorDOModuleVersion {
    # Removes one version folder, and only a folder directly under <ModulesPath>\<ModuleName>.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $ModulesPath, [Parameter(Mandatory)][string] $ModuleName)
    $expectedParent = (Join-Path -Path $ModulesPath -ChildPath $ModuleName).TrimEnd('\', '/')
    $parent = (Split-Path -Path $Path.TrimEnd('\', '/') -Parent).TrimEnd('\', '/')
    $v = $null
    if ($parent -ine $expectedParent -or -not [version]::TryParse([System.IO.Path]::GetFileName($Path.TrimEnd('\', '/')), [ref]$v)) { throw "refusing to remove ${Path}: it is not a version folder of $ModuleName" }
    if (Test-Path -LiteralPath $Path) { Remove-DoctorDOTree -Path $Path }
}

function Import-DoctorDOModuleFromPath {
    # By the full path of the version's .psd1, never by name; then checks that what loaded is that folder and version.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $VersionPath, [Parameter(Mandatory)][string] $ModuleName, [Parameter(Mandatory)][string] $Version)
    $base = $VersionPath.TrimEnd('\', '/')
    foreach ($loaded in @(Get-Module -Name $ModuleName)) {
        if ([string]$loaded.ModuleBase -ine $base) {
            Write-DoctorDOLog "Another copy of $ModuleName is already loaded in this session ($($loaded.Version)): unloading it." -Level Warning
            Remove-Module -Name $ModuleName -Force -ErrorAction Stop
            break
        }
    }
    $m = Import-Module -Name (Join-Path -Path $base -ChildPath ($ModuleName + '.psd1')) -Force -PassThru -ErrorAction Stop
    if ($null -eq $m -or ([string]$m.ModuleBase).TrimEnd('\', '/') -ine $base -or [version]$m.Version -ne [version]$Version) { throw 'the module that loaded is not the one that was verified' }
    $m
}

function Get-DoctorDOSpecForVersion {
    # How a version is verified: the stamped release for the stamped version, else (LatestVerified only) the release's
    # manifest. Returns Spec, or Error (the reason it cannot be verified).
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)][version] $Version)
    $key = $Version.ToString()
    if ($Context.SpecCache.ContainsKey($key)) { return $Context.SpecCache[$key] }
    $r = [pscustomobject]@{ Spec = $null; Error = $null }
    if ($Version -eq [version]$Context.Pinned.Version) {
        $r.Spec = $Context.Pinned
    } elseif ($Context.Policy -eq 'Pinned') {
        $r.Error = "version $key is not the pinned release ($($Context.Pinned.Version)), so there is nothing to verify it against"
    } else {
        try {
            $url = Get-DoctorDOManifestUrl -Template $Context.Template -Owner $Context.Owner -Repo $Context.Repo -Version $key
            Write-DoctorDOLog "Reading the release manifest for $key from $url"
            $text = Get-DoctorDOReleaseManifestText -Url $url
            $r.Spec = ConvertTo-DoctorDOSpecFromManifest -Json $text -ModuleName $Context.ModuleName -Version $key -ExpectedGuid $Context.Pinned.Guid -ExpectedAuthor $Context.Pinned.Author
            $r.Spec.Source = 'release manifest'
        } catch {
            $r.Error = "the release manifest for $key could not be used: $($_.Exception.Message)"
        }
    }
    $Context.SpecCache[$key] = $r
    $r
}

function Get-DoctorDOVersionState {
    # Valid, Invalid (with the failed Check and Reason) or Unverifiable (no list to check against), once per version per run.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Context, [Parameter(Mandatory)] $Installed)
    $key = $Installed.Version.ToString()
    if ($Context.StateCache.ContainsKey($key)) { return $Context.StateCache[$key] }
    $spec = Get-DoctorDOSpecForVersion -Context $Context -Version $Installed.Version
    if ($null -eq $spec.Spec) {
        $s = [pscustomobject]@{ State = 'Unverifiable'; Check = 'manifest'; Reason = $spec.Error }
    } else {
        $c = Test-DoctorDOModuleFolder -Path $Installed.Path -Spec $spec.Spec -ExpectedSignerThumbprint $Context.Thumbprint
        $s = [pscustomobject]@{ State = $(if ($c.Valid) { 'Valid' } else { 'Invalid' }); Check = $c.Check; Reason = $c.Reason }
        if ($c.Valid) { Write-DoctorDOLog "Version $key verified against the $($spec.Spec.Source): permissions, contents, SHA-256 of $($spec.Spec.Files.Count) files and identity." }
    }
    $Context.StateCache[$key] = $s
    $s
}

function New-DoctorDOModuleResult {
    [CmdletBinding()]
    param([int] $ExitCode, [string] $Message = '', [string] $Summary = '', [string] $Version = '')
    [pscustomobject]@{ ExitCode = $ExitCode; Message = $Message; Summary = $Summary; Version = $Version }
}

function Get-DoctorDOLastUpdateCheck {
    # When the remediation last looked in the repository for a newer version (UTC), or $null when it never did or the value
    # cannot be read.
    [CmdletBinding()]
    [OutputType([datetime])]
    param([Parameter(Mandatory)][string] $RegistryPath)
    try {
        $v = [string](Get-ItemProperty -LiteralPath $RegistryPath -Name 'LastModuleUpdateCheck' -ErrorAction Stop).LastModuleUpdateCheck
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($v, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$t)) { return $t }
    } catch { Write-Verbose "No previous update check recorded: $($_.Exception.Message)" }
    $null
}

function Set-DoctorDOLastUpdateCheck {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string] $RegistryPath, [Parameter(Mandatory)][datetime] $At)
    try {
        if (-not $PSCmdlet.ShouldProcess($RegistryPath, 'Record the time of the update check')) { return }
        if (-not (Test-Path -LiteralPath $RegistryPath)) { [void](New-Item -Path $RegistryPath -Force -ErrorAction Stop) }
        Set-ItemProperty -LiteralPath $RegistryPath -Name 'LastModuleUpdateCheck' -Value ($At.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)) -Type String -ErrorAction Stop
    } catch { Write-DoctorDOLog "Could not record the time of this update check: $($_.Exception.Message). The next run looks again." -Level Warning }
}

function Initialize-DoctorDOModule {
    <#
    .SYNOPSIS
        Leaves exactly one verified version of the collector module imported, or says why not. Install or update first
        (when the policy and the repository say there is something newer), then walk the installed versions from the
        newest: a version that fails a check is removed when it was just installed (or its content is wrong) and the next
        one is tried; the first that passes is imported by path. Steps are logged; each has its own try/catch.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $ModuleName, [Parameter(Mandatory)][string] $Repository,
        [Parameter(Mandatory)][ValidateSet('Pinned', 'LatestVerified')][string] $UpdatePolicy,
        [string] $MinimumVersion = '', [string] $MaximumVersion = '', [Parameter(Mandatory)][string] $ModulesPath,
        [Parameter(Mandatory)] $PinnedSpec, [string] $ManifestUrlTemplate = '', [string] $GitHubOwner = '', [string] $GitHubRepo = '',
        [string] $ExpectedSignerThumbprint = '',
        # LatestVerified: look in the repository at most this often while a version that meets the minimum is installed; 0
        # looks every run. 30 minutes' tolerance keeps a daily schedule, whose start time moves by its jitter, daily.
        [ValidateRange(0, 720)][int] $UpdateCheckHours = 0,
        [string] $UpdateCheckRegistryPath = 'HKLM:\SOFTWARE\DoctorDO',
        [datetime] $Now = [datetime]::UtcNow
    )
    $min = $null; $max = $null
    if ($MinimumVersion -and -not [version]::TryParse($MinimumVersion, [ref]$min)) { return New-DoctorDOModuleResult 3 "DoctorDO is not configured: -MinimumVersion '$MinimumVersion' is not a version." }
    if ($MaximumVersion -and -not [version]::TryParse($MaximumVersion, [ref]$max)) { return New-DoctorDOModuleResult 3 "DoctorDO is not configured: -MaximumVersion '$MaximumVersion' is not a version." }
    $ctx = @{ ModuleName = $ModuleName; Policy = $UpdatePolicy; Pinned = $PinnedSpec; Template = $ManifestUrlTemplate; Owner = $GitHubOwner; Repo = $GitHubRepo
        Thumbprint = $ExpectedSignerThumbprint; SpecCache = @{}; StateCache = @{} }
    Write-DoctorDOLog "Module check: $ModuleName, policy $UpdatePolicy, repository $Repository, minimum $MinimumVersion, maximum $(if ($MaximumVersion) { $MaximumVersion } else { 'none' }), folder $ModulesPath."
    if ($ExpectedSignerThumbprint) { Write-DoctorDOLog 'An expected signer thumbprint is set: every script and manifest must carry a valid signature by it.' }
    else { Write-DoctorDOLog 'No signer thumbprint is set: the module is unsigned, so it is checked by permissions, file list, SHA-256 values and identity only.' }

    # Step: what is installed.
    $installed = @()
    try { $installed = @(Get-DoctorDOInstalledVersions -ModulesPath $ModulesPath -ModuleName $ModuleName) }
    catch { Write-DoctorDOLog "Could not list the installed versions: $($_.Exception.Message)" -Level Error }
    Write-DoctorDOLog $(if ($installed.Count -gt 0) { 'Installed: ' + (($installed | ForEach-Object { $_.Version.ToString() }) -join ', ') + '.' } else { 'No version is installed.' })

    # Step: what version is wanted.
    $target = $null
    $updateNote = ''
    if ($UpdatePolicy -eq 'Pinned') {
        $target = [version]$PinnedSpec.Version
    } else {
        $lookDue = $true
        if ($UpdateCheckHours -gt 0 -and @($installed | Where-Object { -not $min -or $_.Version -ge $min }).Count -gt 0) {
            $last = Get-DoctorDOLastUpdateCheck -RegistryPath $UpdateCheckRegistryPath
            if ($null -ne $last -and $last -le $Now -and ($Now - $last).TotalMinutes -lt ($UpdateCheckHours * 60 - 30)) {
                $lookDue = $false
                Write-DoctorDOLog "Last looked in $Repository for a newer version at $($last.ToString('u')); the next look is due $UpdateCheckHours hours after it (-UpdateCheckHours). Using what is installed."
            }
        }
        if ($lookDue) {
            try {
                Initialize-DoctorDONuGetProvider
                Set-DoctorDOTls12
                $find = @{ Name = $ModuleName; Repository = $Repository; ErrorAction = 'Stop' }
                if ($max) { $find['MaximumVersion'] = $max.ToString() }
                $newest = @(Find-Module @find | Sort-Object -Property { [version]$_.Version } -Descending)[0]
                $tv = $null
                if ($null -ne $newest -and [version]::TryParse([string]$newest.Version, [ref]$tv)) {
                    $target = $tv
                    Write-DoctorDOLog "Newest version in $Repository`: $tv."
                } else { throw "$Repository has no usable version of $ModuleName" }
                if ($UpdateCheckHours -gt 0) { Set-DoctorDOLastUpdateCheck -RegistryPath $UpdateCheckRegistryPath -At $Now }
            } catch {
                $updateNote = "could not query $Repository ($($_.Exception.Message))"
                Write-DoctorDOLog "Cannot look for a newer version: $updateNote." -Level Warning
            }
        }
        if ($target -and $min -and $target -lt $min) { Write-DoctorDOLog "The newest version ($target) is below the minimum ($min): not installing it." -Level Warning; $updateNote = "newest version $target is below the minimum"; $target = $null }
        if ($target -and $max -and $target -gt $max) { $target = $null }
    }

    # Steps: install the wanted version when it is not there, then choose and import the newest one that verifies. When the
    # wanted version was there but failed a check and was removed, a second pass installs it again (a repair).
    $newly = $null
    $installFailed = $false
    $integrity = $false
    $unverifiable = $false
    $active = $null
    $importFailed = $false
    $removedTarget = $false
    for ($pass = 1; $pass -le 2; $pass++) {
    $installed = @(Get-DoctorDOInstalledVersions -ModulesPath $ModulesPath -ModuleName $ModuleName)
    if ($target -and @($installed | Where-Object { $_.Version -eq $target }).Count -eq 0) {
        $proceed = $true
        if ($UpdatePolicy -eq 'LatestVerified' -and $target -ne [version]$PinnedSpec.Version) {
            $pre = Get-DoctorDOSpecForVersion -Context $ctx -Version $target
            if ($null -eq $pre.Spec) {
                $proceed = $false; $unverifiable = $true
                $updateNote = "update to $target skipped: $($pre.Error)"
                Write-DoctorDOLog "Not installing $target`: $($pre.Error). The version already installed and verified, if any, stays." -Level Warning
            }
        }
        if ($proceed) {
            Write-DoctorDOLog "Installing $ModuleName $target from $Repository for all users."
            try {
                Initialize-DoctorDONuGetProvider
                Set-DoctorDOTls12
                Install-Module -Name $ModuleName -RequiredVersion $target.ToString() -Repository $Repository -Scope AllUsers -Force -ErrorAction Stop
                Write-DoctorDOLog "Install-Module finished for $target."
            } catch {
                $installFailed = $true
                $updateNote = "install of $target failed ($($_.Exception.Message))"
                Write-DoctorDOLog "Install failed: $($_.Exception.Message)" -Level Error
            }
            if (-not $installFailed) {
                $landed = @(Get-DoctorDOInstalledVersions -ModulesPath $ModulesPath -ModuleName $ModuleName | Where-Object { $_.Version -eq $target })
                if ($landed.Count -eq 0) {
                    $installFailed = $true
                    $updateNote = "install of $target left nothing in $ModulesPath"
                    Write-DoctorDOLog "Install-Module reported success but $target is not in $ModulesPath." -Level Error
                } else {
                    $st = Get-DoctorDOVersionState -Context $ctx -Installed $landed[0]
                    if ($st.State -eq 'Valid') { $newly = $target }
                    else {
                        # The files just installed are removed, whatever failed.
                        Write-DoctorDOLog "The installed $target failed the $($st.Check) check: $($st.Reason). Removing it." -Level Error
                        try { Remove-DoctorDOModuleVersion -Path $landed[0].Path -ModulesPath $ModulesPath -ModuleName $ModuleName } catch { Write-DoctorDOLog "Could not remove $($landed[0].Path): $($_.Exception.Message)" -Level Error }
                        $ctx.StateCache.Remove($target.ToString())
                        $updateNote = "install of $target rejected ($($st.Check))"
                        if ($st.State -eq 'Invalid') { $integrity = $true } else { $unverifiable = $true }
                    }
                }
            }
        }
    }

    $candidates = @(Get-DoctorDOInstalledVersions -ModulesPath $ModulesPath -ModuleName $ModuleName)
    foreach ($c in $candidates) {
        if ($min -and $UpdatePolicy -eq 'LatestVerified' -and $c.Version -lt $min) { Write-DoctorDOLog "Version $($c.Version) is below the minimum ($min): not used." -Level Warning; continue }
        if ($max -and $c.Version -gt $max) { continue }
        if ($UpdatePolicy -eq 'Pinned' -and $c.Version -ne [version]$PinnedSpec.Version) { Write-DoctorDOLog "Version $($c.Version) is not the pinned release: not used." -Level Warning; continue }
        $st = Get-DoctorDOVersionState -Context $ctx -Installed $c
        if ($st.State -eq 'Unverifiable') {
            $unverifiable = $true
            Write-DoctorDOLog "Version $($c.Version) cannot be verified: $($st.Reason). Not used." -Level Warning
            continue
        }
        if ($st.State -eq 'Invalid') {
            $integrity = $true
            Write-DoctorDOLog "Version $($c.Version) failed the $($st.Check) check: $($st.Reason). Not imported." -Level Error
            if ($st.Check -eq 'permissions') {
                Write-DoctorDOLog "Version $($c.Version) is left in place: reinstalling would not change who can write to the folder. Fix the permissions on $ModulesPath." -Level Error
            } else {
                try {
                    Remove-DoctorDOModuleVersion -Path $c.Path -ModulesPath $ModulesPath -ModuleName $ModuleName
                    Write-DoctorDOLog "Removed version $($c.Version)." -Level Warning
                    $ctx.StateCache.Remove($c.Version.ToString())
                    if ($target -and $c.Version -eq $target) { $removedTarget = $true }
                } catch { Write-DoctorDOLog "Could not remove version $($c.Version): $($_.Exception.Message)" -Level Error }
            }
            continue
        }
        try {
            [void](Import-DoctorDOModuleFromPath -VersionPath $c.Path -ModuleName $ModuleName -Version $c.Version.ToString())
            $active = $c
            Write-DoctorDOLog "Imported $ModuleName $($c.Version) from $($c.Path)."
            break
        } catch {
            $importFailed = $true
            Write-DoctorDOLog "Import of $($c.Version) failed: $($_.Exception.Message)" -Level Error
            if ($newly -and $c.Version -eq $newly) {
                try { Remove-DoctorDOModuleVersion -Path $c.Path -ModulesPath $ModulesPath -ModuleName $ModuleName } catch { Write-DoctorDOLog "Could not remove $($c.Path): $($_.Exception.Message)" -Level Error }
                $newly = $null
            }
        }
    }
    if ($active -or -not $removedTarget -or $pass -ge 2) { break }
    Write-DoctorDOLog "Version $target failed verification and was removed: installing it again." -Level Warning
    }

    if ($null -eq $active) {
        if ($integrity) { return New-DoctorDOModuleResult $script:ExitModuleIntegrity "DoctorDO module failed verification and no earlier verified version is installed.$(if ($updateNote) { ' (' + $updateNote + ')' })" }
        if ($importFailed) { return New-DoctorDOModuleResult $script:ExitModuleImport 'DoctorDO module was verified but could not be imported; see DoctorDO-Remediation.log.' }
        if ($unverifiable) { return New-DoctorDOModuleResult $script:ExitModuleUnverified "DoctorDO module cannot be verified and none is installed.$(if ($updateNote) { ' (' + $updateNote + ')' })" }
        $why = $(if ($updateNote) { $updateNote } else { "no version of $ModuleName at or above $MinimumVersion is available" })
        return New-DoctorDOModuleResult $script:ExitModuleInstall "DoctorDO module is not installed and could not be: $why."
    }

    # Step: after a successful update, keep one previous version for rollback and remove the older ones.
    if ($newly -and $active.Version -eq $newly) {
        $older = @(Get-DoctorDOInstalledVersions -ModulesPath $ModulesPath -ModuleName $ModuleName | Where-Object { $_.Version -lt $active.Version })
        foreach ($o in @($older | Select-Object -Skip 1)) {
            try { Remove-DoctorDOModuleVersion -Path $o.Path -ModulesPath $ModulesPath -ModuleName $ModuleName; Write-DoctorDOLog "Removed old version $($o.Version) (kept the previous one for rollback)." }
            catch { Write-DoctorDOLog "Could not remove old version $($o.Version): $($_.Exception.Message)" -Level Warning }
        }
    }

    $summary = "module $($active.Version) "
    if ($newly -and $active.Version -eq $newly) { $summary += 'installed' } else { $summary += 'verified' }
    if ($target -and $active.Version -lt $target) { $summary += $(if ($updateNote) { "; $updateNote" } else { "; update to $target not applied" }) }
    elseif ($updateNote -and $UpdatePolicy -eq 'LatestVerified') { $summary += "; $updateNote" }
    if ($updateNote) { Write-DoctorDOLog "Update note: $updateNote." -Level Warning }
    New-DoctorDOModuleResult 0 '' $summary $active.Version.ToString()
}

# ---- the run ------------------------------------------------------------------------------------------------------

function Format-DoctorDOSummary {
    # The one line Intune shows: no line breaks, not long.
    [CmdletBinding()]
    param([AllowEmptyString()][string] $Text)
    $t = (ConvertTo-DoctorDOLogText -Text $Text) -replace '\s+', ' '
    if ($t.Length -gt 400) { $t = $t.Substring(0, 397) + '...' }
    $t.Trim()
}

function Invoke-DoctorDORemediation {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([int] $MaxJitterSeconds, [string] $IngestUri, [string] $ConfiguredIngestUri, [string] $DeviceAnchor, [string] $ConfiguredDeviceAnchor,
        [scriptblock] $Collector, [scriptblock] $Sleep = { param($s) Start-Sleep -Seconds $s },
        [scriptblock] $PrepareModule, [hashtable] $PrepareArguments = @{},
        [bool] $CollectPublicEgress = $false, [bool] $ConfiguredCollectPublicEgress = $false)

    $uri = Resolve-DoctorDOIngestUri -Explicit $IngestUri -Configured $ConfiguredIngestUri -FromEnvironment ([System.Environment]::GetEnvironmentVariable('DOCTORDO_INGEST_URI', 'Machine'))
    if ($null -eq $uri) {
        Write-DoctorDOLog 'The ingest URL is not configured.' -Level Error
        return [pscustomobject]@{ ExitCode = 3; Message = 'DoctorDO is not configured: set the ingest URL https://<host>/v1/ingest in Remediate-DoctorDO.ps1 (see collector/intune/README.md).' }
    }
    $anchor = Resolve-DoctorDODeviceAnchor -Explicit $DeviceAnchor -Configured $ConfiguredDeviceAnchor -FromEnvironment ([System.Environment]::GetEnvironmentVariable('DOCTORDO_DEVICE_ANCHOR', 'Machine'))
    if ($null -eq $anchor) {
        Write-DoctorDOLog 'The device anchor is not configured.' -Level Error
        return [pscustomobject]@{ ExitCode = 3; Message = "DoctorDO is not configured: the device anchor must be 'entra-device' or 'tenant-ca' (see collector/intune/README.md)." }
    }
    $egress = Resolve-DoctorDOCollectPublicEgress -Explicit $CollectPublicEgress -Configured $ConfiguredCollectPublicEgress -FromEnvironment ([System.Environment]::GetEnvironmentVariable('DOCTORDO_COLLECT_PUBLIC_EGRESS', 'Machine'))
    Write-DoctorDOLog "Configuration read: ingest host $($uri.Host), device anchor $anchor, public egress hash $(if ($egress) { 'on' } else { 'off' })."
    $delay = Get-DoctorDOStartDelay -MaxJitterSeconds $MaxJitterSeconds
    if ($delay -gt 0) { Write-DoctorDOLog "Waiting $delay seconds (start jitter)."; & $Sleep $delay }
    $moduleNote = ''
    if ($null -ne $PrepareModule) {
        $m = $null
        try { $m = & $PrepareModule $PrepareArguments }
        catch {
            Write-DoctorDOLog "The module step failed unexpectedly: $($_.Exception.Message)" -Level Error
            return [pscustomobject]@{ ExitCode = $script:ExitModuleInstall; Message = "DoctorDO module step failed: $($_.Exception.Message)" }
        }
        if ([int]$m.ExitCode -ne 0) {
            Write-DoctorDOLog "Stopping: $($m.Message) (exit $($m.ExitCode))." -Level Error
            return [pscustomobject]@{ ExitCode = [int]$m.ExitCode; Message = [string]$m.Message }
        }
        $moduleNote = [string]$m.Summary
    }
    Write-DoctorDOLog 'Running the collector in fleet mode.'
    $r = & $Collector $uri $anchor $egress
    $msg = 'DoctorDO run finished.'
    if ($null -ne $r.PSObject.Properties['Message'] -and $r.Message) { $msg = [string]$r.Message }
    elseif ($null -ne $r.PSObject.Properties['Outcome']) { $msg = "DoctorDO: $($r.Outcome)" }
    if ($moduleNote) { $msg = "$msg [$moduleNote]" }
    $level = $(if ([int]$r.ExitCode -eq 0) { 'Info' } else { 'Error' })
    Write-DoctorDOLog "Collector finished with exit code $([int]$r.ExitCode): $msg" -Level $level
    [pscustomobject]@{ ExitCode = [int]$r.ExitCode; Message = $msg }
}

if ($MyInvocation.InvocationName -ne '.') {
    # Intune can start a 32-bit host on 64-bit Windows; the registry and CIM views would then be the wrong ones, and
    # %ProgramFiles% would be the 32-bit folder. Only the settings that are set are passed on (an empty argument is not
    # reliably passed to a native program by Windows PowerShell 5.1).
    if ([System.Environment]::Is64BitOperatingSystem -and -not [System.Environment]::Is64BitProcess) {
        $sysnative = Join-Path -Path $env:windir -ChildPath 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
        $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-MaxJitterSeconds', [string]$MaxJitterSeconds,
            '-ModuleName', $ModuleName, '-Repository', $Repository, '-UpdatePolicy', $UpdatePolicy, '-UpdateCheckHours', [string]$UpdateCheckHours, '-MinimumVersion', $MinimumVersion,
            '-GitHubOwner', $GitHubOwner, '-GitHubRepo', $GitHubRepo, '-ManifestUrlTemplate', $ManifestUrlTemplate)
        foreach ($p in @(@('-IngestUri', $IngestUri), @('-DeviceAnchor', $DeviceAnchor), @('-MaximumVersion', $MaximumVersion), @('-ExpectedSignerThumbprint', $ExpectedSignerThumbprint), @('-ModulesPath', $ModulesPath), @('-LogPath', $LogPath))) {
            if ($p[1]) { $relaunch += $p }
        }
        if ($CollectPublicEgress) { $relaunch += '-CollectPublicEgress' }
        & $sysnative @relaunch
        exit $LASTEXITCODE
    }
    if (-not $LogPath) { $LogPath = Get-DoctorDODefaultLogPath }
    if (-not $ModulesPath) { $ModulesPath = Get-DoctorDOAllUsersModulesPath }
    Initialize-DoctorDOLog -Path $LogPath -Component 'Remediate-DoctorDO' -File 'Remediate-DoctorDO.ps1'
    $collector = {
        param($uri, $anchor, $egress)
        Invoke-DoctorDOCollector -Fleet -IngestUri $uri -DeviceAnchor $anchor -CollectPublicEgress:([bool]$egress)
    }
    $prepare = { param($a) Initialize-DoctorDOModule @a }
    try {
        Write-DoctorDOLog "Started (PowerShell $($PSVersionTable.PSVersion), $(if ([System.Environment]::Is64BitProcess) { '64' } else { '32' })-bit, user $([System.Environment]::UserName), script policy $UpdatePolicy)."
        $pinned = New-DoctorDOSpec -ModuleName $ModuleName -Version $DoctorDOPinnedVersion -Guid $DoctorDOExpectedGuid -Author $DoctorDOExpectedAuthor -Functions $DoctorDOExpectedFunctions -Files $DoctorDOPinnedFiles -Source 'release stamped into this script'
        $prepareArgs = @{ ModuleName = $ModuleName; Repository = $Repository; UpdatePolicy = $UpdatePolicy; MinimumVersion = $MinimumVersion; MaximumVersion = $MaximumVersion
            ModulesPath = $ModulesPath; PinnedSpec = $pinned; ManifestUrlTemplate = $ManifestUrlTemplate; GitHubOwner = $GitHubOwner; GitHubRepo = $GitHubRepo
            ExpectedSignerThumbprint = $ExpectedSignerThumbprint; UpdateCheckHours = $UpdateCheckHours }
        $result = Invoke-DoctorDORemediation -MaxJitterSeconds $MaxJitterSeconds -IngestUri $IngestUri -ConfiguredIngestUri $ConfiguredIngestUri `
            -DeviceAnchor $DeviceAnchor -ConfiguredDeviceAnchor $ConfiguredDeviceAnchor -Collector $collector -PrepareModule $prepare -PrepareArguments $prepareArgs `
            -CollectPublicEgress $CollectPublicEgress.IsPresent -ConfiguredCollectPublicEgress $ConfiguredCollectPublicEgress
        Write-DoctorDOLog "Finished with exit code $($result.ExitCode)." -Level $(if ([int]$result.ExitCode -eq 0) { 'Info' } else { 'Error' })
        Write-Output (Format-DoctorDOSummary -Text $result.Message)
        exit $result.ExitCode
    } catch {
        Write-DoctorDOLog "DoctorDO collection failed: $($_.Exception.Message)" -Level Error
        Write-Output (Format-DoctorDOSummary -Text "DoctorDO collection failed: $($_.Exception.Message)")
        exit 3
    }
}
