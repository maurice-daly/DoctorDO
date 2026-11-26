# DoctorDO collector: Intune deployment

Every device you want reporting needs an **identity** (a certificate whose private key signs each report) and the
**collector** (the module, which the remediation script pair installs and keeps up to date). No key, secret or token is deployed or needed. Nothing in this
folder talks to Microsoft Graph.

The deployment chooses one **device anchor**, and the collector must use the same one:

| Anchor | Identity on the device | Tenant-side work | Default |
|---|---|---|---|
| `entra-device` | the Entra device certificate (issuer `MS-Organization-Access`) that Windows creates when the device joins | none: no certificate profile, no CA | **yes** |
| `tenant-ca` | an Intune SCEP or PKCS certificate from the tenant's own CA | trusted-certificate and SCEP/PKCS profiles, CA registered with DoctorDO | fallback |

```
 Intune                                       Device (SYSTEM)                                  DoctorDO ingest
 ------                                       ----------------                                 ---------------
 (entra-device: nothing to deploy)            MS-Organization-Access cert in LocalMachine\My
 Remediation (Detect + Remediate)       --->  daily: Detect -> exit 1 -> Remediate
                                              Remediate installs/updates the module from a PowerShell repository,
                                              checks it, then loads it from
                                              %ProgramFiles%\WindowsPowerShell\Modules\DoctorDO.Collector\<version>
                                              signed POST https://<host>/v1/ingest  ---------> signature, then Entra device
                                              (device cert + signature in headers, no mTLS)    binding; Intune check later
```

## 1. Device prerequisites (`entra-device`, the default)

- **Microsoft Entra joined or Microsoft Entra hybrid joined.** `dsregcmd /status` shows `AzureAdJoined : YES`. Entra
  *registered* (BYOD, workplace joined) devices cannot report: their certificate is in the user's store and the collector
  runs as SYSTEM. Domain-only devices cannot report either.
- **Enrolled in Intune.** The service drops reports from devices it cannot find in Intune.
  Autopilot-provisioned devices meet both requirements.
- **The device is enabled in Entra.** `dsregcmd /status` shows `DeviceAuthStatus : SUCCESS` (Windows 10 21H1 and later).
  A disabled or deleted device is refused by the service.

Why this works without deploying anything: when a device joins, Entra device registration issues the
**MS-Organization-Access** certificate; for Entra joined and hybrid joined devices it is in `Local Computer\Personal\Certificates`
and has a ten-year lifetime ([Microsoft Entra device management FAQ](https://learn.microsoft.com/entra/identity/devices/faq#what-are-the-ms-organization-access-certificates-present-on-our-windows-10-11-devices)).
Its key is the device key, "TPM bound (preferred) RSA 2048 bit"
([How it works: Device registration](https://learn.microsoft.com/entra/identity/devices/device-registration-how-it-works)).

How the collector picks the certificate (`Select-DDEntraDeviceCertificate`): in `LocalMachine\My`, issuer CN exactly
`MS-Organization-Access`, subject CN equal to the `DeviceId` from `dsregcmd /status`, valid now, with a private key, and
with the thumbprint `dsregcmd /status` reports under *Device Details* (`Thumbprint`,
[dsregcmd fields](https://learn.microsoft.com/entra/identity/devices/troubleshoot-device-dsregcmd#device-details)). Exactly
one must qualify, or the run exits 6. The same store also holds an **MS-Organization-P2P-Access** certificate with the same
subject CN ([same FAQ](https://learn.microsoft.com/entra/identity/devices/faq#what-are-the-ms-organization-p2p-access-certificates-present-on-our-windows-10-11-devices));
it is never used.

To check one device, from an elevated prompt:

```powershell
dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|DeviceId|Thumbprint|KeyProvider|TpmProtected|DeviceAuthStatus'
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -match 'CN=MS-Organization-Access' } | Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
```

## 2. The tenant-ca anchor (fallback): SCEP or PKCS certificate profile

Use this only when the deployment's `deviceAnchor` is `tenant-ca` (for example if Microsoft changes the Entra device
binding the default anchor depends on). Set `$ConfiguredDeviceAnchor = 'tenant-ca'` in the
remediation script (or the `DOCTORDO_DEVICE_ANCHOR` machine environment variable). The request is signed in exactly the
same way; only the certificate differs.

Create a **trusted certificate profile** with your issuing CA's root, then a **SCEP certificate profile** assigned to
the **device group** you want reporting. Reference:
[Create and assign SCEP certificate profiles in Intune](https://learn.microsoft.com/intune/device-configuration/certificates/scep-profiles).

| Setting | Value | Why |
|---|---|---|
| Certificate type | **Device** | The collector runs as SYSTEM; there is no user. Assign to a device group, not a user group. |
| Subject name format | `CN={{AAD_Device_ID}}` | `{{AAD_Device_ID}}` (or `{{AzureADDeviceId}}`) identifies the device by its Microsoft Entra device ID. Microsoft substitutes it from the Entra registration, not from anything on the device. |
| Subject alternative name | Attribute **URI**, value `urn:doctordo:device:{{AAD_Device_ID}}` | The structured form the service parses first. The collector selects its certificate by finding the Entra device ID anywhere in the SAN or the subject, so a bare `{{AAD_Device_ID}}` URI also works. |
| Certificate validity period | 1 year or less | Bounds the damage from one compromised device. Intune supports up to 24 months; use five days or more or the MDM agent can reject a near-expiry certificate on arrival (same page). |
| Key storage provider | *Enroll to TPM KSP if present, otherwise Software KSP* | Non-exportable where a TPM exists. Do not use "otherwise fail" on a fleet that includes virtual machines. 4096-bit keys are not supported in the TPM KSP: use 2048. |
| Key usage | Digital signature (and key encipherment for RSA) | The key signs the request. |
| Key size | 2048 (RSA), or an EC P-256 key | The signing protocol defines RSA (PKCS#1 v1.5, SHA-256) and ECDSA P-256 only. |
| Hash algorithm | SHA-2 | |
| Extended key usage | **Client Authentication** (1.3.6.1.5.5.7.3.2) | Constrains the certificate to this use. The collector ignores certificates without it. |
| Root certificate | the trusted certificate profile above | |
| Renewal threshold | 20% (default is fine) | |
| SCEP server URLs | your NDES/SCEP URL or Microsoft Cloud PKI | |

Notes from Microsoft's page that matter here:

- *"Avoid using {{DeviceId}} for subject name on Windows devices"* (it can make sync with Intune fail): use
  `{{AAD_Device_ID}}`.
- Subject or SAN fields such as `IMEI`, `SerialNumber` and `FullyQualifiedDomainName` "could be spoofed by a person
  with access to the device". DoctorDO uses only `{{AAD_Device_ID}}` for identity.
- A device must support every variable in the profile, or the profile fails to install on it.

The tenant-ca selection never picks an `MS-Organization-*` certificate (they carry the device ID as their CN and the
client-authentication EKU too). `Invoke-DoctorDOCollector -CertificateIssuer '<issuer DN or CN>'` restricts it to the
CA you registered.

**Register the issuing CA with DoctorDO once.** That registration, not anything on the device, is the trust anchor.
Until a tenant registers its CA the ingest tier refuses everything.

### Revocation and device lifecycle (tenant-ca)

What Intune does with the certificate
([Remove SCEP and PKCS certificates](https://learn.microsoft.com/intune/device-configuration/certificates/remove-profiles),
Windows section):

| Event | SCEP certificate |
|---|---|
| User unenrols; admin runs **wipe** or **retire** | revoked **and** removed |
| Device removed from the Entra group; profile removed from the assignment | revoked **and** removed |
| Admin **changes or updates the SCEP profile** | revoked (devices then receive new certificates). Plan profile edits: they roll the whole fleet's certificates. |
| Intune licence withdrawn; user or group removed from Entra | **stays**, not revoked or removed |
| Third-party certification authority | "removed but **not revoked**" ([third-party CA note](https://learn.microsoft.com/intune/fundamentals/certificates/third-party-ca-scep#removing-certificates)) |

With `tenant-ca` the ingest tier relies on **revocation checking against the CRL/OCSP endpoint you registered**, so use a
CA that actually revokes (Microsoft Cloud PKI, or an ADCS/NDES CA with a reachable CRL). With `entra-device`, revocation
comes from Entra and Intune instead: a device disabled or deleted in Entra is refused, and a device retired from Intune is
dropped.

## 3. The collector

### How the module gets onto the device

Nothing to package. `Remediate-DoctorDO.ps1` installs `DoctorDO.Collector` and keeps it up to date;
`Detect-DoctorDO.ps1` also exits 1 when the module
is not installed at or above the minimum version, so a device that never had it is remediated on its first run. On every run:

1. **Where.** `%ProgramFiles%\WindowsPowerShell\Modules\DoctorDO.Collector\<version>` in 64-bit PowerShell (the script
   relaunches itself into 64-bit; a 32-bit host would otherwise use `Program Files (x86)`). Windows PowerShell 5.1, which Intune
   uses for remediations, and PowerShell 7 both search that folder.
2. **What version.** `-UpdatePolicy LatestVerified` (default): the newest version in the repository (`Find-Module`, up to
   `-MaximumVersion`, never below `-MinimumVersion`). The repository is searched at most once every `-UpdateCheckHours` (24 by
   default, with 30 minutes' allowance for the schedule's jitter) while a version at or above the minimum is installed, and
   on every run while none is; the time of the last successful search is kept in `HKLM:\SOFTWARE\DoctorDO`
   (`LastModuleUpdateCheck`). `-UpdatePolicy Pinned`: only the version stamped into the script.
3. **Install if it is missing.** TLS 1.2 is enforced; the NuGet provider is installed if it is not there
   (`Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force`); then
   `Install-Module -Name DoctorDO.Collector -RequiredVersion <v> -Repository <repository> -Scope AllUsers -Force`. The
   repository's trust setting is not changed (`-Force` applies to that one call).
4. **Check what is there, before every import** (the module is not signed, so these are the controls):

   | Check | Fails when |
   |---|---|
   | Permissions | the version folder, the module folder above it or any file can be written by an account other than SYSTEM, Administrators or TrustedInstaller (inherited rules count), has another owner, or the tree has a link |
   | Contents | a file is there that the release does not list (`PSGetModuleInfo.xml` excepted), or one is missing |
   | Hashes | the SHA-256 of any file differs from the release's |
   | Identity | the manifest does not load, or its GUID or author is not the one in the script, or its version is not the folder's, or its exported functions or `FileList` differ |
   | Signature (optional) | `-ExpectedSignerThumbprint` is set and a `.ps1`, `.psm1` or `.psd1` is not `Valid` or is signed by another certificate |

   Then the module is imported by the full path of that version's `.psd1`. A copy that fails is removed (if it was just
   installed, or its content is wrong); the newest earlier version that passes is used and the run goes on; if none passes the
   run exits 9 (or 11), imports nothing and sends nothing. After a successful update, the previous version is kept for rollback
   and older ones are removed.

**Where the release's hashes come from.**

| Policy | Source | Network | Use when |
|---|---|---|---|
| `LatestVerified` (default) | `collector-manifest.json` from the GitHub release `collector-v<version>` (`-ManifestUrlTemplate`, `-GitHubOwner`, `-GitHubRepo`), for any version but the one stamped into the script | repository and release host | you want new releases to reach the fleet without touching the script |
| `Pinned` | the version and file hashes stamped into the script by `collector/tools/package-collector.ps1 -Stamp` | repository only | you update by uploading a newer script, on your own change schedule |

An attacker has to change **both** the repository and the release to get code onto a device under `LatestVerified`. If
the manifest cannot be read or does not match, nothing is updated and the verified version keeps running (a warning in the
log, exit 0); exit 11 means there was no verified version to fall back to. **The script does not sign in to GitHub**, and a version
whose release has no `collector-manifest.json` cannot be verified, so it is skipped. To host the manifests yourself, put
them where the devices can read them over https and set `-ManifestUrlTemplate` to that address (`{owner}`, `{repo}` and
`{version}` are replaced), or use `Pinned`.

**An internal repository.** Register it on the devices (a Settings catalog or a script of your own), or set `-Repository` to a
name already registered, and publish the module there; keep the manifest next to it. Nothing else changes.

**Set `-ExpectedSignerThumbprint` as soon as you sign the module.** The hashes prove the files are the ones the project listed; only
a signature proves who made the release, and it still holds if both the repository and the release host are compromised. Until the
module is signed the thumbprint is empty and the log says that no signature was asked for.

**Releasing (the person who publishes the module).** From the module folder that is published, run
`collector/tools/package-collector.ps1 -Stamp`: it writes `collector/dist/collector-manifest.json` and re-stamps `Remediate-DoctorDO.ps1`.
Attach the manifest to the release `collector-v<version>` **before or when** the Gallery package is published, and commit the
re-stamped script (a test fails if it does not match the module).

**Installing the module by hand, or with a Win32 app, still works.** `Install-DoctorDOCollector.ps1` (below) puts the same files in the
same folder; the remediation uses that copy if it passes the checks, and updates over it. Do not install the module with PowerShell 7's
`Install-PSResource -Scope AllUsers`: that writes to `%ProgramFiles%\PowerShell\Modules`, which Windows PowerShell 5.1 does not search.

#### Optional: deploy the module as a Win32 app instead

For an estate that wants Intune to own the module (and can re-sign it). Build the app from the Gallery release, unchanged:

```powershell
Save-PSResource -Name DoctorDO.Collector -Path .\package       # Windows PowerShell 5.1: Save-Module -Name DoctorDO.Collector -Path .\package
Copy-Item collector\intune\Install-DoctorDOCollector.ps1 .\package
IntuneWinAppUtil.exe -c .\package -s Install-DoctorDOCollector.ps1 -o .\out
```

| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-DoctorDOCollector.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-DoctorDOCollector.ps1 -Uninstall` |
| Install behavior | System |
| Detection rule | File: path `%ProgramFiles%\WindowsPowerShell\Modules\DoctorDO.Collector\<version>`, file `DoctorDO.Collector.psd1`, *File or folder exists*, **Associated with a 32-bit app on 64-bit clients: No** |

- Intune starts `powershell.exe` from a Win32 app command line as a **32-bit** process, where `%ProgramFiles%` is
  `Program Files (x86)` ([Add a Win32 app](https://learn.microsoft.com/intune/app-management/deployment/add-win32#step-2-program)).
  `Install-DoctorDOCollector.ps1` relaunches itself in 64-bit PowerShell, so the module lands in the 64-bit folder.
  Intune does not expand environment variables in the uninstall command, which is why both commands call `powershell.exe` and
  leave the switch to 64-bit to the script.
- With both routes in use, the remediation updates over the Win32 copy and the app's detection rule (a version folder) can then
  show the old version missing: use one route per device group.
- Licences: the module's licence, the PolyForm Shield License 1.0.0, allows packaging it, changing it and re-signing
  it with your own code-signing certificate. The scripts in this folder, including
  `Install-DoctorDOCollector.ps1`, are MIT ([LICENSE](LICENSE)): edit them as you need, for example the defaults of
  `Remediate-DoctorDO.ps1`.
- The module is not signed. Under an AllSigned execution policy set by Group Policy, App Control for Business
  (WDAC) or AppLocker script rules, or "Enforce script signature check" = Yes, re-sign the module and these scripts
  with a certificate the devices trust: see "Signing and execution policy" in the [collector README](../README.md). A re-signed
  module has other bytes, so make the manifest and the stamp from the signed copy and set `-ExpectedSignerThumbprint`.

### The remediation pair

Intune: **Devices > Scripts and remediations > Remediations > Create** ([Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations)).

| Field | Value |
|---|---|
| Detection script | `Detect-DoctorDO.ps1` |
| Remediation script | `Remediate-DoctorDO.ps1` (edit the ingest URL first, see below; it installs the module) |
| Run this script using the logged-on credentials | **No** (required) |
| Enforce script signature check | your policy (No unless you sign) |
| Run script in 64-bit PowerShell | **Yes** (the script also relaunches itself in 64-bit if it finds a 32-bit host) |
| Schedule | **Daily** (use **Use UTC** if you like). A missed run executes as soon as the device is online. Keep `-MaxAgeHours` shorter than the interval: 22 (the default) for daily, 160 for weekly. |
| Assignment | a **device** group of Entra joined or hybrid joined, Intune-enrolled devices (for tenant-ca: the same device group as the certificate profile). Do not mix user and device groups. |

**Run this script using the logged-on credentials = No is required configuration, not a default to rely on.** *No* runs
the script in the system context ([Use PowerShell scripts on Windows devices](https://learn.microsoft.com/intune/device-management/tools/run-powershell-scripts-windows#create-a-script-policy-and-assign-it));
Microsoft's Remediations page leaves the value "dependent on the script"
([Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations#create-and-deploy-custom-script-packages)).
DoctorDO needs SYSTEM: the device key is a machine key that a user context cannot use (exit 6), and reading Delivery
Optimization state needs administrator rights (exit 1).

Files must be UTF-8 (these are pure ASCII).

**Why a detection script that does no collecting?** Per Microsoft, detection must `exit 1` to trigger remediation;
any other code means no remediation, and *empty output is treated as "issue not found"*. `Detect-DoctorDO.ps1` reads
only `HKLM\SOFTWARE\DoctorDO\LastSuccessfulCollection` (written after the service accepted a report), exits 1 when it
is missing or older than `-MaxAgeHours` (default 22; use 160 for a weekly cadence), and always prints a line. Its output
is stable between runs (Microsoft advises against timestamps in detection output).

#### Script settings

Remediation scripts take no arguments in Intune, so settings live in the script text (edit the parameter defaults) or the machine environment:

| Setting | Where | Default | Meaning |
|---|---|---|---|
| `$ConfiguredIngestUri` | top of `Remediate-DoctorDO.ps1` | placeholder (script refuses to run, exit 3) | `https://<host>/v1/ingest`, for example `https://func-doctordo-ingest-<suffix>.azurewebsites.net/v1/ingest`. The path is part of the signed request, so no other path (and no query string) is accepted; a bare `https://<host>` is completed with `/v1/ingest`. |
| `DOCTORDO_INGEST_URI` | machine environment variable | unset | overrides the script text; same rules |
| `$ConfiguredDeviceAnchor` | top of `Remediate-DoctorDO.ps1` | `entra-device` | `entra-device` or `tenant-ca`; must match the deployment's `deviceAnchor`. Any other value: exit 3. |
| `DOCTORDO_DEVICE_ANCHOR` | machine environment variable | unset | overrides the script text |
| `-ModuleName` | script parameter (edit default) | `DoctorDO.Collector` | the module to install |
| `-Repository` | script parameter (edit default) | `PSGallery` | the registered PowerShell repository to install from; an internal one works. Its trust setting is never changed |
| `-UpdatePolicy` | script parameter (edit default) | `LatestVerified` | `LatestVerified` or `Pinned`, as above |
| `-UpdateCheckHours` | script parameter (edit default) | `24` | `LatestVerified` searches the repository at most this often while a usable version is installed; `0` searches every run |
| `-MinimumVersion` | script parameter (edit default) | `1.2.1` | the oldest version that may run; older ones are replaced (`LatestVerified`) |
| `-MaximumVersion` | script parameter (edit default) | empty | a cap on what is installed and used (`LatestVerified`) |
| `-GitHubOwner`, `-GitHubRepo` | script parameters (edit defaults) | `maurice-daly`, `doctordo` | fill `{owner}` and `{repo}` in the manifest URL |
| `-ManifestUrlTemplate` | script parameter (edit default) | `https://github.com/{owner}/{repo}/releases/download/collector-v{version}/collector-manifest.json` | where the release's hash list is downloaded from; https only |
| `-ExpectedSignerThumbprint` | script parameter (edit default) | empty | when set, every script and manifest of the module must have a `Valid` signature by this certificate |
| `-ModulesPath`, `-LogPath` | script parameters | the 64-bit AllUsers folder; the log below | for testing |
| `-MaxJitterSeconds` | script parameter (edit default) | 600 | random start delay 0..N s so a fleet on one schedule does not arrive in the same second |
| `-MinimumVersion` | `Detect-DoctorDO.ps1` | `1.2.1` | keep equal to the remediation's: below it the detection exits 1 |
| `-MaxAgeHours` | `Detect-DoctorDO.ps1` | 22 | freshness window: shorter than the schedule's interval (22 for daily, 160 for weekly). Intune runs detection about one interval after the last collection, so a window as long as the interval (26 was the old default) finds yesterday's collection fresh and a daily schedule collects only every other day |

The remediation calls `Invoke-DoctorDOCollector -Fleet -IngestUri <uri> -DeviceAnchor <anchor>`: anonymisation is on by
default in fleet mode, no log dump is taken, **no flush** (so DoSvc is never stopped), no verbose logging, nothing is
changed on the device. Each request carries the device certificate (`X-DoctorDO-Device-Cert`) and a signature over the
request (`X-DoctorDO-Signature`, with `X-DoctorDO-Signed-At` and `X-DoctorDO-Nonce`); no TLS client certificate is
presented. The device's clock must be within five minutes of the service's. Budget: under 60 seconds and 5 MB.

#### Exit codes (what Intune shows)

| Code | Meaning | Action |
|---|---|---|
| 0 | Success, or backing off after a 429/401/503 (nothing sent this run) | none |
| 1 | Not elevated | check the script runs as SYSTEM (logged-on credentials = No) |
| 2 | Unsupported OS | Windows 10 2004 / Windows 11 or later |
| 3 | Collection failed, or the script is not configured | check `$ConfiguredIngestUri` and `$ConfiguredDeviceAnchor`; check the run output |
| 4 | (not used in fleet mode) | verbose logging is never enabled in fleet mode |
| 5 | Upload failed | network path to the ingest host; the next run retries with the same counters |
| 6 | **The device cannot identify itself** | `entra-device`: the device is not Microsoft Entra joined or hybrid joined, or it has no usable device certificate, or the device key could not sign. Run `dsregcmd /status` as SYSTEM and check *AzureAdJoined*, *DeviceId*, *Thumbprint* and *DeviceAuthStatus*; the output line says which. `tenant-ca`: the SCEP/PKCS profile is not deployed to this device (or has not arrived yet). Either way a configuration state, not a bug. |
| 7 | **The state folder is not safe to use** (collector 0.2.0 and later) | `%ProgramData%\DoctorDO` is a link, is owned by an account other than SYSTEM or Administrators, inherits its permissions, grants access to another account, or holds something the collector did not make, and could not be replaced. A standard user may have created it before the first run. Nothing was read or sent. Delete the folder as an administrator; the next run creates it again for SYSTEM and Administrators only. |
| 8 | **The module is missing or too old and could not be installed** | the log says which step failed: the NuGet provider, `Find-Module`, `Install-Module` (a repository that is not registered, a proxy, TLS), or no version at or above the minimum exists. Run the same commands in an elevated 64-bit Windows PowerShell on the device |
| 9 | **The module failed verification** and no earlier verified version is installed | a file differs from the release, a file is extra or missing, the GUID or author is not the expected one, or the folder can be written by other accounts. The log names the check; the failed copy was removed (except for permissions: fix the ACL on `%ProgramFiles%\WindowsPowerShell\Modules`). Treat a hash failure on a release from the repository as a possible supply-chain event until it is explained |
| 10 | **The verified module could not be imported** | the log has the import error; the failed copy was removed if it was just installed |
| 11 | **No version could be verified** and none is installed | `-UpdatePolicy LatestVerified` could not read or accept `collector-manifest.json` (private repository, no route to the release host, a manifest for another version). Fix `-ManifestUrlTemplate`, or use `Pinned` |

Exit 0 can also mean the module was not updated: when the manifest or the repository was unreachable, or a new release failed
verification, the verified version keeps running and the line in the Remediations report says `update to <v> skipped` or `install of <v> rejected`.

A 401 from the service (exit 5, then back-off) with a device that passes all of the above usually means the device is
disabled or deleted in Entra, its clock is more than five minutes out, or the deployment uses the other anchor.

### The log: DoctorDO-Remediation.log

Both scripts write one log in CMTrace format:

```
%ProgramData%\Microsoft\IntuneManagementExtension\Logs\DoctorDO-Remediation.log
```

That folder is where the Intune Management Extension keeps its own logs, which Microsoft documents as readable with `CMTrace.exe`
([Troubleshoot Win32 app issues](https://learn.microsoft.com/intune/app-management/deployment/troubleshoot-win32#logs-displayed-through-cmtrace)),
and it is among the files Intune's **Collect diagnostics** device action gathers
([Collect diagnostics](https://learn.microsoft.com/intune/device-management/actions/collect-diagnostics)), so an administrator
can read what happened without touching the device. To read it:

1. In the Intune admin center, **Devices > the device > Collect diagnostics**, then download the zip when it is ready; or copy the file from the device.
2. Open `DoctorDO-Remediation.log` (and `DoctorDO-Remediation.lo_`, the previous log) in **CMTrace** (`CMTrace.exe`, from Configuration
   Manager's tools) or **OneTrace**. Warnings are yellow and errors red. The component column says `Detect-DoctorDO` or `Remediate-DoctorDO`.

Each line is `<![LOG[message]LOG]!><time="HH:mm:ss.fff+bias" date="MM-dd-yyyy" component="..." context="" type="1|2|3" thread="..." file="...">`
(type 1 information, 2 warning, 3 error). The bias is the Windows time-zone bias in minutes, with the sign of the Windows value (UTC = local + bias:
UTC+1 is `-060`, UTC-7 is `+420`); **to verify against CMTrace on a device**, since Microsoft documents the bias and not CMTrace's line format.
At about 1 MB the log is renamed to `DoctorDO-Remediation.lo_` (replacing the previous one) and a new file starts. The text is plain ASCII, one
line per event, and never holds a credential: anything that looks like one is replaced before it is written.

The last line the script prints is one short sentence for the output columns of the Remediations report
(the output there is limited to 2,048 characters, [Remediations](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations#prerequisites)),
for example `DoctorDO run finished. [module 0.5.0 verified]` or `... [module 0.5.0 verified; update to 0.6.0 skipped: the release manifest for 0.6.0 could not be used: ...]`.

### Checking one device

From an elevated prompt on a test device, after the module has arrived (for SYSTEM, use `psexec -s`):

```powershell
Import-Module DoctorDO.Collector
Invoke-DoctorDOCollector -Fleet -IngestUri https://<your ingest host>/v1/ingest
Invoke-DoctorDOCollector -Fleet -IngestUri https://<your ingest host>/v1/ingest -DeviceAnchor tenant-ca   # fallback anchor
```

For a local look without sending anything: `New-DoctorDODeviceReport -Open` writes one HTML file, the console's device
page for this device, that opens in Edge or Chrome with no deployment (add `-Anonymise` for one to share).
`Invoke-DoctorDOCollector -OutputPath C:\Temp -Anonymise` writes the deep bundle (a zip) for support.
