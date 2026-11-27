# DoctorDO.Collector

The PowerShell collector for [DoctorDO](https://www.doctor-do.com), Delivery Optimization diagnostics for Windows: the one
component that runs on a device. It is **read-only**, makes **no call to Microsoft Graph**, authenticates by **signing each
request with the device key** of the Entra device certificate (default) or of a tenant SCEP/PKCS certificate (no key or secret
anywhere, no mutual TLS), and treats the ingest service's reply as an opaque status code.

```
collector/
  DoctorDO.Collector/            the module (PowerShell 5.1 compatible, 7+ supported, built-in modules only)
    Public/                      Invoke-DoctorDOCollector, Get-DOInventory, Get-DOTelemetry, Get-DOConnectivityMatrix,
                                 Test-DOConnectivity, Send-DoctorDOReport, New-DoctorDODeviceReport
    Private/Platform.ps1         EVERY Windows-only call (registry, CIM, dsregcmd, netsh, DO cmdlets, firewall,
                                 certificate store) behind a small function: the seam Pester mocks
    Private/Compact.ps1          telemetry compaction, byte for byte the service's (the golden fixtures in tests/)
    Private/Json.ps1             date-safe JSON parser, canonical JSON + inventory hash identical to the service's
    Private/ProbeNative.ps1      C# probe helper (DNS, TCP, TLS issuer, HTTP Range), 5 s per probe, 60 s total
    Private/Connectivity.ps1     the connectivity matrix   Private/Facts.ps1, DoData.ps1   fact builders and mappers
    Private/State.ps1            protected, atomic, tolerant state file
    Private/Redact.ps1           hashing and scrubbing     Private/VerboseCycle.ps1        the one reversible footprint
    Private/Http.ps1, Bundle.ps1 gzip, certificate selection, POST (no client certificate);  local zip bundle
    Private/Signing.ps1          signed-request protocol v1 (contract C1): canonical string, nonce, RSA/ECDSA signature
    Private/Report.ps1, Pac.ps1  the offline device report; PAC (proxy auto-config) inspection
    Data/redaction-profile.json  exactly what -Anonymise changes (printed by -WhatIfRedaction)
    Data/device-report.html      the offline device report's page, built from DoctorDO's console: do not edit
    en-US/                       about_DoctorDO.Collector (Get-Help about_DoctorDO.Collector)
    LICENSE                      PolyForm Shield License 1.0.0 (source-available)    THIRD-PARTY-NOTICES.txt  bundled components
  intune/                        Detect / Remediate / Install scripts (MIT, LICENSE) and the deployment README (SCEP profile,
                                 revocation, the self-installing remediation and its log; Win32 packaging as an option)
  tools/package-collector.ps1    release step: collector-manifest.json (SHA-256 of every module file) and the release stamped
                                 into Remediate-DoctorDO.ps1 (-Stamp)
  tests/                         Pester 5 suite, fixtures/, run-tests.ps1
  DoctorDO/                      the name module: Install-Module DoctorDO installs DoctorDO.Collector (below)
```

## Install

From the PowerShell Gallery, in Windows PowerShell 5.1 or PowerShell 7:

```powershell
Install-Module DoctorDO.Collector -Scope CurrentUser                # or Install-Module DoctorDO, the short name
```

To deploy it to devices through Intune instead, see [intune/README.md](intune/README.md). Getting started with the whole
solution: <https://www.doctor-do.com/get-started/>.

## Use

```powershell
Import-Module DoctorDO.Collector                                 # or, from a clone: .\collector\DoctorDO.Collector\DoctorDO.Collector.psd1
Get-Help about_DoctorDO.Collector                                # what it reads, never changes, privacy, Intune, troubleshooting
Get-Help Invoke-DoctorDOCollector -Full                          # every command: parameters, examples, exit codes

# Local device report (nothing leaves the device): one HTML file, the console's device page, no Azure needed
New-DoctorDODeviceReport                                         # identifies the device; to the temp folder, opened when run interactively (-NoOpen: not)
New-DoctorDODeviceReport -Format Html,Pdf                        # also a PDF, printed by Edge (or Chrome) headless; the PDF is opened
New-DoctorDODeviceReport -OutputPath C:\Temp -Anonymise          # one to share
New-DoctorDODeviceReport -OutputPath C:\Temp -Format Both       # also the data as DoctorDO-<host>-<time>.json (-Format Json: data only)
New-DoctorDODeviceReport -OutputPath C:\Temp -FileName DoctorDO-DeviceReport  # a fixed name (no folder, no extension) each run replaces: a remediation keeps one report
New-DoctorDODeviceReport -Verbose                                # also each step, its timing and result, aligned (also Invoke-DoctorDOCollector, Test-DOConnectivity)

# Local deep bundle (nothing leaves the device): zip with manifest.json + bundle.json (BundleV1), for support
Invoke-DoctorDOCollector -OutputPath C:\Temp -Anonymise
Invoke-DoctorDOCollector -OutputPath C:\Temp -ReproduceIssue -AssumeVerboseLoggingOff   # see "Verbose cycle"
Invoke-DoctorDOCollector -WhatIfRedaction                                                 # print the profile, collect nothing

# Fleet: inventory once, telemetry after; SYSTEM, from the Intune remediation (intune/README.md)
Invoke-DoctorDOCollector -Fleet -IngestUri https://<ingest host>/v1/ingest                    # -DeviceAnchor entra-device (default)
Invoke-DoctorDOCollector -Fleet -IngestUri https://<ingest host>/v1/ingest -DeviceAnchor tenant-ca

# The parts
Get-DOInventory -Anonymise | ConvertTo-Json -Depth 32
Get-DOTelemetry -Anonymise | ConvertTo-Json -Depth 32      # read-only: never writes the state file
Test-DOConnectivity [-Detailed] [-Json] [-SkipConnectivityChecks]     # the checks by area and those that failed or warned; -Detailed: every check (Get-DOConnectivityMatrix: as objects)
```

At a console (collectors from 1.1.0), `New-DoctorDODeviceReport`, `Invoke-DoctorDOCollector` and `Test-DOConnectivity` say what
they are doing: a line per section of the collection as it finishes, a progress bar for the one under way, then the checks by area
and those that need attention (`Private/Progress.ps1`, `Private/Console.ps1`). It is on the Information stream, so
`-InformationAction SilentlyContinue` hides it, and it is never written where nobody is at the session (`Get-DDNonInteractiveReason`)
or when stdout is redirected, so an Intune remediation's output is unchanged. Results show as a short list
(`DoctorDO.Collector.format.ps1xml`); the objects themselves are unchanged.

`Invoke-DoctorDOCollector` returns an object with `ExitCode`, `Outcome`, `DurationMs`, and for a bundle `BundlePath`, `Sha256`,
`SchemaVersion`, `DeviceId`, `Anonymised`, `NotCollected`. Exit codes: 0 ok, 1 not elevated, 2 unsupported OS,
3 collection failed, 4 verbose logging not restored, 5 upload failed, 6 the device cannot identify itself (`entra-device`: not
Entra joined or hybrid joined per `dsregcmd /status`, or no usable device certificate; `tenant-ca`: the certificate profile is not deployed),
7 the state folder `%ProgramData%\DoctorDO` is not safe to use (fleet only). The Intune remediation script adds 8 (the module
is missing or too old and could not be installed), 9 (it failed verification), 10 (it would not import) and 11 (no version could be
verified): `intune/README.md`.

`New-DoctorDODeviceReport -Format Json|Both` writes the data the page embeds as UTF-8 without a BOM, indented: `schema`
(`doctordo-device-report/1`) and `collectorVersion` first, then `kind`, `version`, `generatedAt`, `inventory` (InventoryV1) and
`telemetry` (an array of one TelemetryV1 report). The result object has `Format`, `JsonPath`, `JsonSha256` and `JsonBytes`, `PdfPath`,
`PdfSha256` and `PdfBytes`, and `Opened`; `Path` is the page, else the PDF, else the JSON file. `-Anonymise` applies to every file.

`-Format` takes several values (`Html,Pdf`; `Both` is `Html,Json`). `Pdf` prints the page with Microsoft Edge, or Google Chrome when Edge
is missing (App Paths key, then the standard install folders), headless, from a throwaway profile, with a two-minute limit; it throws before
collecting when neither is installed. The page is printed from `file:///...html#print`, which lays it out for paper from its first frame:
every section open, every table row, light colours, no controls. With `Pdf` alone the page is written for the browser and removed again.

When the report is written it is opened (the PDF when there is one, else the page; a JSON file only with `-Open`), unless `-NoOpen` is
given or nobody is at the session: not as SYSTEM or a service account, in session 0, with `-NonInteractive`, in a remote session, or when
started by the Intune Management Extension (`AgentExecutor`), the Task Scheduler (`svchost`, `taskhostw`), ConfigMgr (`CcmExec`) or WMI.
`-Open` opens it regardless. `-Verbose` says which, and why.

## Signing and execution policy

The releases of DoctorDO.Collector are **not signed**; signing is planned for a later version. Most estates
need nothing extra: the Intune remediation runs with "Enforce script signature check" set to No, and installs and loads the
module itself, checking its permissions, file list and SHA-256 values instead of a signature.

Two kinds of estate need a signature, and the module's licence lets you add your own (re-signing is not a change, as
long as nothing else in the files changes):

- **An AllSigned execution policy set by Group Policy.** A Group Policy execution policy takes precedence over
  `-ExecutionPolicy Bypass` on the command line, so an unsigned module does not load.
- **App Control for Business (WDAC) with script enforcement, or AppLocker script rules.** Scripts the policy does not
  trust run in Constrained Language Mode, where the collector's .NET calls and its probe helper (compiled at run time
  with `Add-Type`) are refused, so it cannot collect properly.

**Workaround: re-sign the module with a certificate your devices trust**, on the packaging machine, and publish the signed
copy to an **internal repository** (the remediation would otherwise install the unsigned Gallery release over it). Then
set `-Repository` and `-ExpectedSignerThumbprint` in `Remediate-DoctorDO.ps1`, and make `collector-manifest.json` and the
script's stamp from the signed folder (`pwsh collector/tools/package-collector.ps1 -ModulePath <signed folder> -Stamp`),
because a signature changes the bytes the hashes cover. Or deploy the signed module as a Win32 app:

```powershell
Save-PSResource -Name DoctorDO.Collector -Path .\package          # Windows PowerShell 5.1: Save-Module
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Thumbprint -eq '<your thumbprint>'
$ts = '<your certificate authority''s RFC 3161 timestamp URL>'
$files = Get-ChildItem .\package\DoctorDO.Collector -Recurse -Include *.ps1, *.psm1, *.psd1
$files | Set-AuthenticodeSignature -Certificate $cert -TimestampServer $ts -HashAlgorithm SHA256
$files | Get-AuthenticodeSignature | Where-Object Status -ne 'Valid'     # no output
```

- Sign `Install-DoctorDOCollector.ps1`, `Detect-DoctorDO.ps1` and `Remediate-DoctorDO.ps1` the same way (after setting
  the ingest URL in `Remediate-DoctorDO.ps1`): under AllSigned the Win32 install command needs a signed script too, and
  "Enforce script signature check" = Yes needs signed remediation scripts.
- The devices must trust the signer. For AllSigned, the certificate chains to a trusted root and is in
  `Cert:\LocalMachine\TrustedPublisher`; otherwise PowerShell asks whether to run it, which an unattended run cannot
  answer. For App Control, the policy allows scripts signed by that certificate.
- Sign a copy outside any git working tree: a line-ending conversion breaks every signature. The timestamp keeps the
  signatures valid after the certificate expires.
- Re-sign each new release before you deploy it, and let devices get it only from your internal repository (or the Win32
  app), never from the Gallery, `Update-Module` or `Update-PSResource`, which would bring the unsigned release back.

## Run the tests

Pester 5 is required (`Install-Module Pester -MinimumVersion 5.0.0 -Scope CurrentUser`). From the repository root:

```powershell
pwsh -NoProfile -File collector/tests/run-tests.ps1                          # PowerShell 7
powershell.exe -NoProfile -File collector/tests/run-tests.ps1                # Windows PowerShell 5.1
Invoke-ScriptAnalyzer -Path collector -Recurse -Settings collector/PSScriptAnalyzerSettings.psd1 |
    Where-Object { -not ($_.RuleName -eq 'PSAvoidGlobalVars' -and $_.ScriptPath -match '[\\/]tests[\\/]') }   # no output
```

The suite needs no network and no administrator rights: every Windows call is mocked, and the probe and TLS tests use
loopback sockets. Under Windows PowerShell 5.1 the schema checks that need `Test-Json` are
skipped. One test compares the console's connectivity catalogue with the service's code, and is skipped where that code is
not present, as in the public repository.

The golden fixtures in `tests/fixtures` come from DoctorDO's service code: `Compact.Tests.ps1` runs the PowerShell
compaction on the same inputs and requires byte-identical output, and every report the suite produces is validated against
`contracts/*.schema.json`.

## The DoctorDO name module

`DoctorDO/` holds the short name `DoctorDO` on the PowerShell Gallery, so anyone who types `Install-Module DoctorDO` gets
the collector. It is a manifest with no code: `RequiredModules` names `DoctorDO.Collector` by its GUID, so installing
`DoctorDO` installs the collector and importing it loads the collector's commands. It exports nothing itself. Each collector
release has a `DoctorDO` release of the same version that requires it, so `Update-Module DoctorDO` brings the new collector.
`tests/NameModule.Tests.ps1` keeps it pointing at the collector.

## How it works

1. **One collection per run** (`Get-DDRawCollection`): identity (`dsregcmd /status`), MDM enrolment, hardware (CIM), OS, network, the DO
   configuration (`Get-DOConfig -Verbose` plus raw enumeration of the five registry stores, never probing for expected names), firewall
   rules, DO status/peers/perf/log, the System event log (DoSvc crashes, power-on time), the Enrollment Status Page's tracking on a device
   that showed it (the inventory's `provisioning` section, below), and the connectivity matrix. Anything that cannot be collected becomes a
   typed `notCollected` record (`insufficient-rights`, `cmdlet-missing`, `unsupported-os`, `timeout`, `skipped-by-flag`, `error`), never a
   silent gap or an invented value.
2. **Project** the inventory (InventoryV1) and compute two hashes: the *change-detection* hash (excludes `collectedAt`, `notCollected` and the
   connectivity matrix) and the *inventory hash* that telemetry carries.
3. **Send** an inventory on first run, when the change-detection hash differs, and every 7 days; then always a telemetry report. Telemetry
   is compacted: top 25 files plus `filesOther`, aggregated peers, 8 named peers (16-hex hashes), aggregated
   connections, grouped errors with a sample only for a new HRESULT, counter deltas with restart handling, changed-only connectivity.
4. **State** (`%ProgramData%\DoctorDO\state.json`, SYSTEM and Administrators only, written to a temp file then replaced, read tolerantly; a
   corrupt file is left in place and replaced by the next save, and that run is a full inventory and telemetry) holds the sequence number,
   last counters, last connectivity, recent HRESULTs, last inventory hash and the per-device salt. It is committed **only after HTTP 202**.
   The folder is checked before anything in it is read or written: not a link, owned by SYSTEM or Administrators, permissions
   protected, no other account, nothing in it the collector did not make. A fleet run on the default folder replaces one that fails,
   but only when everything in it is the collector's own (state and caches; files deleted one by one, never following a link); it
   stops with exit 7 if the folder still fails. A custom `-StatePath` folder is never changed. Read-only commands ignore state in it.
5. **Transport**: `ConvertTo-Json -Compress -Depth 32`, gzip (`GZipStream`), then a POST to `https://<host>/v1/ingest` over TLS 1.2+
   with normal server validation and **no client certificate**. The certificate comes from `LocalMachine\My`:
   - `entra-device` (default): issuer CN exactly `MS-Organization-Access`, subject CN = the `dsregcmd /status` DeviceId, valid now,
     private key, thumbprint = dsregcmd's *Device Details* `Thumbprint`; exactly one, else exit 6. The device must be Entra joined or
     hybrid joined (`AzureAdJoined : YES`), else exit 6.
   - `tenant-ca`: the SCEP/PKCS certificate (valid now, private key, client-authentication EKU, Entra device ID in the SAN or subject,
     latest expiry), never an `MS-Organization-*` one, optionally pinned to `-CertificateIssuer`.

   Each request is signed (contract C1, `contracts/signing/signing-v1.vector.json`): the canonical string `DOCTORDO-SIG-1`, method, path,
   host (the ingest URI's host, lower case, no port), kind, collected-at, signed-at, nonce and the base64 SHA-256 of the gzip bytes, joined
   by LF; RSA PKCS#1 v1.5 with SHA-256 or ECDSA P-256 (P1363), through `GetRSAPrivateKey()` / `GetECDsaPrivateKey()` (TPM and software
   key providers alike; if the certificate cannot give its RSA key, the key named by dsregcmd's `KeyContainerId`/`KeyProvider` is opened
   instead, and used only if it matches the certificate). Headers: `Content-Type: application/vnd.doctordo.report+json`,
   `Content-Encoding: gzip`, `X-DoctorDO-Schema: 1`, `X-DoctorDO-Kind`, `X-DoctorDO-Collected-At`, `X-DoctorDO-Device-Cert` (DER, base64),
   `X-DoctorDO-Signed-At` (UTC, whole seconds), `X-DoctorDO-Nonce` (16 random bytes, base64url) and `X-DoctorDO-Signature`. Only the
   status code (and `Retry-After`) is read; **the response stream is never opened**. 202 ok; 429 waits `Retry-After`; 401/503 back off
   exponentially (cap one hour). Reports over the 64 KB compressed hard cap are not sent. Typical sizes: 10 KB for an inventory, 4 KB for a
   telemetry report.

### Verbose cycle (the only footprint)

`-ReproduceIssue` (local mode only; rejected with `-Fleet` by the parameter sets): capture previous state, enable, wait for Enter or 15 minutes,
collect, **restore in `finally`** (error, Ctrl-C, timeout), verify, else print the exact command and exit 4. Microsoft documents no way to read
the verbose state, so the cycle refuses to run unless the operator states it (`-AssumeVerboseLoggingOff`): it never enables what it cannot restore.

### Decisions where the spec or documentation needed a call

| Topic | Decision | Why |
|---|---|---|
| `Get-DeliveryOptimizationLog -Flush` | Local bundle only (opt out `-NoFlush`); fleet never | Microsoft: "-Flush stops DoSvc before reading logs". A fleet run must not stop a service on every device. |
| Device ID salt | Persisted per-device salt, not per-run | A per-run salt changes `deviceId` and so the inventory hash every cycle, forcing a full inventory every time. |
| Peer / egress hashes | Tenant-wide salt (sha256 of the tenant ID) | Telemetry's 16-hex peer hash exists to link a peer across a tenant's devices; DO-NET-009 compares egress hashes across devices. Hashing is pseudonymisation, not anonymity. |
| Public egress IP | Off unless `-PublicIpProbeUri` is supplied | No Microsoft-documented echo endpoint; DoctorDO does not call a third-party IP service by default. |
| `Get-DOConfig` | Documented property names mapped to CSP names; `*Bps` limits keep their own names; `WorkingDirectory` = cache location | The cmdlet's properties are not the CSP names; the Bps unit is not stated. |
| Bytes per source | Verbose stream if it parses, else the current job list (recorded in `notCollected`); `bytesFromHttp` excludes cache bytes | PerfSnap does not document per-source bytes; Microsoft: BytesFromHTTP includes BytesFromCacheServer, while the analysis sums five disjoint sources. |
| Change detection | Hash excludes the connectivity matrix | Latencies jitter every run; changes travel in `connectivityChanged`. |
| Required fields | If OS build, RAM or system disk cannot be read (two sources each) the run exits 3 | A report the schema would reject is not sent. |
| Inventory + telemetry in one run | Inventory first, telemetry after | The server gets the baseline counters and the matrix state in the same run. |
| `HKCU` as SYSTEM | Per-user WinINET proxy not observable; recorded in `notCollected` | HKCU under SYSTEM is not a user's setting. |

## Sources and confidence

`documented` = stated on Microsoft Learn; `to-verify` = recorded, never the sole basis of a finding.

| Field group | Source | Status |
|---|---|---|
| Join type, Entra device ID, tenant ID | `dsregcmd /status` ([doc](https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd)) | documented (field names). Parsing is English-label based. |
| MDM enrolment, Intune device ID | `HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}` ([doc](https://learn.microsoft.com/windows/client-management/mdm-diagnose-enrollment): the location); DMClient `EntDMID` / `EnrollmentType` / `ManagementServiceAddress` ([DMClient CSP](https://learn.microsoft.com/windows/client-management/mdm/dmclient-csp)) | node names documented; **the registry value names and the Intune MDM certificate fallback are to-verify** |
| Manufacturer / model | DevDetail CSP `OEM` / `DevTyp` via the MDM WMI bridge, falling back to the BIOS registry key | CSP documented; bridge class name to-verify |
| Serial | `Win32_BaseBoard` (salted hash; placeholders ignored) | documented class |
| TPM, disks, CPU | `Win32_Tpm.SpecVersion`, `MSFT_PhysicalDisk` (MediaType 3 HDD / 4 SSD, BusType 17 NVMe), `Win32_Processor` | documented classes; BusType value to-verify |
| OS | `HKLM\...\CurrentVersion` (Windows 11 build 22000+ reported as "Windows 11" although ProductName says 10) | observed behaviour |
| DO configuration | `Get-DOConfig -Verbose` ([doc](https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-monitor)) + six registry stores | **verified on Windows 11 26H2**: the provider of each setting is an object property `<Name>Provider` of enum `ConfigProvider` (RegistryProvider 5, MdmProvider 7, SettingsProvider 8, AdminProvider 9, DefaultProvider 99), not verbose text; the documented text form is still accepted |
| Who set each setting | Get-DOConfig's provider first, then `PolicyManagercurrentdeviceDeliveryOptimization` (`<Name>_WinningProvider` GUID to `Enrollments<GUID>ProviderID`, `MS DM Server` = Intune), the Group Policy key, and the Settings app store `HKUS-1-5-20...DeliveryOptimizationSettings`; MDM and GP both set: MDM only under `ControlPolicyConflictMDMWinsOverGP` = 1, otherwise no winner claimed | PolicyManager and Enrollments layout **verified** on an Intune-managed device; RegistryProvider = Group Policy and the Settings-store value names are inferred |
| Endpoints | job list `CacheHost`; CIM `MSFT_DeliveryOptimizationFilePeerInfo` (all peers, not the cmdlet's top 5); DO log lines (download-completed telemetry, HTTP/peer connections, peer failures, cache host origin); DoSvc TCP connections | CIM class and `CacheHost` **verified** on 26H2; log formats read from a real DO log export; TCP snapshot verified unelevated. Cache server and CDN in clear; internet peers always /24 or /48; LAN/group peers a prefix under `-Anonymise` |
| Status / peers / perf / log analysis | `Get-DeliveryOptimizationStatus [-PeerInfo]`, `PerfSnap`, `LogAnalysis -ListConnections` (same page) | property lists documented for status, peers and PerfSnap; log entry and `ListConnections` property names and the PerfSnap `-Verbose` format **to-verify** |
| Month totals (`doMonth`, 19 Oct 2026) | `Get-DeliveryOptimizationPerfSnapThisMonth`: `MonthStartDate`, `DownloadHttpBytes` (includes the cache's), `DownloadCacheHostBytes`, `DownloadLanBytes`, `DownloadInternetBytes`, `UploadLanBytes`, `UploadInternetBytes`; `DownloadGroupBytes` where present | Learn documents the cmdlet ("limited to the current calendar month") but not its fields; property names **verified on Windows 11 26H2**, which has no group counter. Other builds **to-verify** |
| Firewall rules, LocalPolicyMerge | `Get-NetFirewallRule`, `Get-NetFirewallProfile` (`AllowLocalFirewallRules`) ([CSP](https://learn.microsoft.com/windows/client-management/mdm/firewall-csp) AllowLocalPolicyMerge) | rules documented; property-to-CSP equivalence to-verify |
| Proxy | WinINET registry + `netsh winhttp show proxy` | registry locations and English `netsh` text to-verify |
| DHCP options 234 / 235 | none found | **not collected** (listed in `notCollected`); lab to evaluate `DhcpRequestParams` |
| Autopilot group tag, ConfigMgr boundary groups | none found | **not collected** |
| Autopilot provisioning (`provisioning`, collectors from 0.5.0) | `HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking` ([ESP troubleshooting](https://learn.microsoft.com/troubleshoot/mem/intune/device-enrollment/understand-troubleshoot-esp), [EnrollmentStatusTracking CSP](https://learn.microsoft.com/windows/client-management/mdm/enrollmentstatustracking-csp)), only on a device that showed the ESP: for up to 30 Win32 apps the Intune app ID, phase, installation state, reboot flag and status times; once, within 7 days of the ESP's last status, DO's jobs of that time by priority and source and the 10 largest (calling application up to 64 characters) | per-app `InstallationState` and `RebootRequired` documented; the name format of the `ESPTrackingInfo\Diagnostics` subkeys **to-verify** (parsed leniently; an entry that does not parse is counted, not guessed) |
| Connectivity matrix and endpoint health | endpoints from `Data/endpoints.json`: wildcards tested on hosts the device used, then hosts Microsoft documents, else "not testable"; byte ranges on a file the device downloaded | verified read-only on one Windows 11 device 13 Oct 2026; behind a real TLS-inspecting proxy still to do |

## Security properties (each enforced by a test)

- No parameter, header or file carries a key, token or password; identity is the device certificate plus a signature made with its key.
- No TLS client certificate is ever attached (the transport has no parameter for one, and a loopback server that asks gets none).
- The response body is never read, logged or acted on; the result object has no field that could hold it.
- Peer and connection addresses are never sent raw, with or without `-Anonymise`.
- Fleet mode never enables verbose logging, never flushes logs, never changes configuration; it writes only its state file and two values under `HKLM\SOFTWARE\DoctorDO` (`LastSuccessfulCollection`, `LastReportKind`).
- A run that cannot establish what it needs fails with a code instead of sending an invalid report; plain `http` is refused.

## Licence

DoctorDO is an independent community project, free to use, and in preview. The collector comes under two licences:

- **The module (`DoctorDO.Collector/`)** is **source-available, not open source**. It is licensed under the
  [PolyForm Shield License 1.0.0](DoctorDO.Collector/LICENSE), a standard licence from the PolyForm Project
  (<https://polyformproject.org/licenses/shield/1.0.0>), as is the rest of DoctorDO.
- **The Intune scripts (`intune/`)**, `Detect-DoctorDO.ps1`, `Remediate-DoctorDO.ps1` and
  `Install-DoctorDOCollector.ps1`, are licensed under the [MIT License](intune/LICENSE), so they can be adapted
  freely: setting the ingest URL in `Remediate-DoctorDO.ps1` is an example.

What the module's licence allows, in short:

- **Use it free of charge for any purpose** that does not compete (below), including in an organisation to manage its
  own devices.
- **Install it from the PowerShell Gallery, keep internal copies, package it** (an Intune Win32 app, a Configuration
  Manager package, an install script of your own), deploy it across an estate and run it on a schedule.
- **Change it**, for example to fix a problem before a release does, and **re-sign it** with your own code-signing
  certificate where an execution policy or application control requires it (see "Signing and execution policy").
- **Share copies**, changed or not, as long as each copy carries the licence and its `Required Notice:` line.
- **Consultants and managed service providers** may install, operate and support it for a client, on that client's
  devices, and charge the client for their own time.

What it does not allow:

- **Providing any product that competes** with the module, or with a product the licensor provides using it, such
  as DoctorDO. A product competes even when it is free, and anything marketed as a practical substitute for DoctorDO
  competes: a hosted or managed Delivery Optimization reporting service built on it, for example.

The module comes as is, with no warranty and no support. The offline device report page bundles React, zod, lucide-react, Tailwind CSS and the Poppins and Geist Mono fonts under
their own licences ([THIRD-PARTY-NOTICES.txt](DoctorDO.Collector/THIRD-PARTY-NOTICES.txt)). Problems and ideas are
welcome as GitHub issues; code contributions are not accepted. This summary is not the licence: the
[LICENSE](DoctorDO.Collector/LICENSE) file is.
