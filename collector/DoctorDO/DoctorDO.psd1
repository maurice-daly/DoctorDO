@{
    # DoctorDO holds the short name on the PowerShell Gallery and installs the collector: it has no code of its own, and
    # RequiredModules makes Install-Module DoctorDO install DoctorDO.Collector, and Import-Module DoctorDO load it.
    # The collector's commands come from DoctorDO.Collector; this module exports nothing.
    # Released with every collector release, with the collector's version (27 Nov 2026): Update-Module DoctorDO only
    # looks for a newer DoctorDO, so without one an install made with Install-Module DoctorDO never got a newer collector.
    ModuleVersion         = '1.2.3'
    GUID                  = '77dcd36d-a6ba-41a9-b3c2-1936674cd834'
    Author                = 'Maurice Daly'
    CompanyName           = 'DoctorDO'
    Copyright             = '(c) 2026 Maurice Daly. All rights reserved.'
    Description           = 'Installs DoctorDO.Collector, the DoctorDO module for diagnosing Windows Delivery Optimization. This package has no commands of its own: Install-Module DoctorDO installs DoctorDO.Collector, and its commands (New-DoctorDODeviceReport, Invoke-DoctorDOCollector, Test-DOConnectivity and the rest) work as soon as it is installed. Installing DoctorDO.Collector directly does the same. DoctorDO is an independent community project, free to use, and in preview. Source-available under the PolyForm Shield License 1.0.0, not open source: free to use, change and share, except to provide a product that competes with it (see the licence).'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    # The floor is the collector release of the same version, so installing or updating DoctorDO brings at least that
    # collector (an older one already installed does not count). It must be on the Gallery before DoctorDO is published.
    RequiredModules       = @(
        @{ ModuleName = 'DoctorDO.Collector'; ModuleVersion = '1.2.3'; GUID = '6f0d2a7e-3c5b-4e8a-9b1d-7a2c4e6f8b10' }
    )
    FileList              = @('DoctorDO.psd1', 'LICENSE')
    FunctionsToExport     = @()
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData           = @{
        PSData = @{
            Tags         = @('DeliveryOptimization', 'ConnectedCache', 'WindowsUpdate', 'Intune', 'Diagnostics', 'Troubleshooting', 'Network', 'Windows', 'PSEdition_Desktop', 'PSEdition_Core')
            # The same pages as DoctorDO.Collector's links, open without signing in.
            LicenseUri   = 'https://www.doctor-do.com/licence/'
            ProjectUri   = 'https://www.doctor-do.com/get-started/'
            ReleaseNotes = '1.2.3: DoctorDO now has the version of the collector it installs, and requires that version: installing or updating DoctorDO (Update-Module DoctorDO) brings DoctorDO.Collector 1.2.3 or later, even when an older collector is already installed. From now on DoctorDO is released with every collector release. 1.0.0: the first release. DoctorDO installs DoctorDO.Collector (1.0.0 or later), which holds every command; run Get-Help about_DoctorDO.Collector after installing.'
        }
    }
}
