@{
    # DoctorDO holds the short name on the PowerShell Gallery and installs the collector: it has no code of its own, and
    # RequiredModules makes Install-Module DoctorDO install DoctorDO.Collector, and Import-Module DoctorDO load it.
    # The collector's commands come from DoctorDO.Collector; this module exports nothing.
    ModuleVersion         = '1.0.0'
    GUID                  = '77dcd36d-a6ba-41a9-b3c2-1936674cd834'
    Author                = 'Maurice Daly'
    CompanyName           = 'DoctorDO'
    Copyright             = '(c) 2026 Maurice Daly. All rights reserved.'
    Description           = 'Installs DoctorDO.Collector, the DoctorDO module for diagnosing Windows Delivery Optimization. This package has no commands of its own: Install-Module DoctorDO installs DoctorDO.Collector, and its commands (New-DoctorDODeviceReport, Invoke-DoctorDOCollector, Test-DOConnectivity and the rest) work as soon as it is installed. Installing DoctorDO.Collector directly does the same. DoctorDO is an independent community project, free to use, and in preview. Source-available under the PolyForm Shield License 1.0.0, not open source: free to use, change and share, except to provide a product that competes with it (see the licence).'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    # The floor is the first Gallery release of the collector; Install-Module installs its newest version.
    RequiredModules       = @(
        @{ ModuleName = 'DoctorDO.Collector'; ModuleVersion = '1.0.0'; GUID = '6f0d2a7e-3c5b-4e8a-9b1d-7a2c4e6f8b10' }
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
            ReleaseNotes = '1.0.0: the first release. DoctorDO installs DoctorDO.Collector (1.0.0 or later), which holds every command; run Get-Help about_DoctorDO.Collector after installing.'
        }
    }
}
