#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# The DoctorDO module holds the short name on the Gallery and installs DoctorDO.Collector (collector/README.md, "The
# DoctorDO name module"). These checks keep it pointing at the collector it is meant to install.
BeforeAll {
    $script:Name = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot '../DoctorDO/DoctorDO.psd1')
    $script:Collector = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot '../DoctorDO.Collector/DoctorDO.Collector.psd1')
    $script:Folder = Join-Path $PSScriptRoot '../DoctorDO'
}

Describe 'The DoctorDO name module' {
    It 'requires DoctorDO.Collector by its GUID, at the collector''s version' {
        $req = @($script:Name.RequiredModules)
        $req | Should -HaveCount 1
        $req[0].ModuleName | Should -Be 'DoctorDO.Collector'
        $req[0].GUID | Should -Be $script:Collector.GUID
        # The floor is the collector release DoctorDO goes out with, so installing or updating DoctorDO brings it.
        $req[0].ModuleVersion | Should -Be $script:Collector.ModuleVersion
    }

    It 'has the collector''s version, so each collector release has a DoctorDO release (27 Nov 2026)' {
        # Update-Module DoctorDO only looks for a newer DoctorDO: one that stayed at 1.0.0 never brought a newer collector.
        $script:Name.ModuleVersion | Should -Be $script:Collector.ModuleVersion
    }

    It 'has no code and exports nothing of its own' {
        $script:Name.ContainsKey('RootModule') | Should -BeFalse
        $script:Name.ContainsKey('NestedModules') | Should -BeFalse
        foreach ($k in 'FunctionsToExport', 'CmdletsToExport', 'VariablesToExport', 'AliasesToExport') { @($script:Name[$k]) | Should -HaveCount 0 }
    }

    It 'has its own GUID, and runs where the collector runs' {
        $script:Name.GUID | Should -Not -Be $script:Collector.GUID
        $script:Name.PowerShellVersion | Should -Be $script:Collector.PowerShellVersion
        $script:Name.CompatiblePSEditions | Should -Be $script:Collector.CompatiblePSEditions
    }

    It 'links to the same licence and project pages, and ships the same licence text' {
        $script:Name.PrivateData.PSData.LicenseUri | Should -Be $script:Collector.PrivateData.PSData.LicenseUri
        $script:Name.PrivateData.PSData.ProjectUri | Should -Be $script:Collector.PrivateData.PSData.ProjectUri
        (Get-FileHash (Join-Path $script:Folder 'LICENSE')).Hash | Should -Be (Get-FileHash (Join-Path $PSScriptRoot '../DoctorDO.Collector/LICENSE')).Hash
    }

    It 'lists exactly the files in its folder' {
        $files = @(Get-ChildItem -Path $script:Folder -Recurse -File | ForEach-Object { $_.FullName.Substring((Resolve-Path $script:Folder).Path.Length + 1) -replace '\\', '/' } | Sort-Object)
        $files | Should -Be @($script:Name.FileList | Sort-Object)
    }
}
