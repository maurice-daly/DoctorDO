# DoctorDO

Delivery Optimization diagnostics for Windows. DoctorDO shows where your devices get their updates and apps from
(Microsoft's CDN, peers on the LAN or in a group, a Connected Cache) and, when Delivery Optimization isn't working, why.

DoctorDO is an independent community project. It's free to use and in preview. Find out more, and see a demo of the
console, at <https://www.doctor-do.com>.

## What's in this repository

The parts of DoctorDO that run on your devices, as published to the PowerShell Gallery:

| Folder | What it is |
|---|---|
| [`collector/DoctorDO.Collector`](collector/DoctorDO.Collector) | The PowerShell module `DoctorDO.Collector`. It diagnoses Delivery Optimization on one device and writes an offline HTML report or a local support bundle. With `-Fleet` it sends signed reports to your own DoctorDO deployment. |
| [`collector/DoctorDO`](collector/DoctorDO) | The `DoctorDO` name module: `Install-Module DoctorDO` installs the collector. |
| [`collector/intune`](collector/intune) | The Intune remediation scripts that install the module, keep it up to date and run it on a schedule, and the deployment guide. |
| [`collector/tests`](collector/tests) | The Pester suite. |
| [`contracts`](contracts) | The JSON schemas of what the collector produces (inventory, telemetry, support bundle) and the test vector of the signed-request protocol. |

The console, the ingest service and the Azure deployment aren't in this repository.

## Quick start

In an elevated Windows PowerShell 5.1 or PowerShell 7 session:

```powershell
Install-Module DoctorDO.Collector -Scope CurrentUser
New-DoctorDODeviceReport
```

`New-DoctorDODeviceReport` reads this device's Delivery Optimization configuration, status, peers and log, checks the
endpoints, proxy and Connected Cache it depends on, works out what's wrong, and opens the result as one HTML file. It's
read-only and nothing leaves the device. Add `-Anonymise` for a report you can share.

More:

- [collector/README.md](collector/README.md): every command, how the collector works, and what it reads.
- [collector/intune/README.md](collector/intune/README.md): deploying it with Intune.
- `Get-Help about_DoctorDO.Collector`, after installing.
- <https://www.doctor-do.com/get-started/>.

## Licence

DoctorDO is **source-available, not open source**. It's licensed under the
[PolyForm Shield License 1.0.0](LICENSE): you can use it free of charge for any purpose that doesn't compete with it,
change it, and share copies. The Intune scripts in `collector/intune` are under the MIT License
([collector/intune/LICENSE](collector/intune/LICENSE)), and the components bundled in the offline report keep their own
licences ([THIRD-PARTY-NOTICES.txt](collector/DoctorDO.Collector/THIRD-PARTY-NOTICES.txt)). This summary isn't the
licence: the [LICENSE](LICENSE) file is.

## Issues

Problems and ideas are welcome as GitHub issues. Code contributions aren't accepted. DoctorDO comes as is, with no
warranty and no support.
