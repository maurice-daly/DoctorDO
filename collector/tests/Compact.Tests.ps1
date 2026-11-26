#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:Fixtures = Join-Path $PSScriptRoot 'fixtures'
}

Describe 'Golden: compaction equals packages/wire compactTelemetry' {
    $cases = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures/manifest.json') -Raw | ConvertFrom-Json).cases
    It 'produces byte-identical canonical JSON for case <_>' -ForEach $cases {
        $name = $_
        InModuleScope DoctorDO.Collector -Parameters @{ Name = $name; Dir = $script:Fixtures } {
            param($Name, $Dir)
            $raw = Read-DDJsonFile -Path (Join-Path $Dir "$Name.raw.json")
            $ctx = Read-DDJsonFile -Path (Join-Path $Dir "$Name.context.json")
            $expected = (Get-Content -LiteralPath (Join-Path $Dir "$Name.expected.json") -Raw -Encoding UTF8).TrimEnd("`n")
            $args2 = @{ Raw = $raw; Seq = [int]$ctx['seq']; InventoryHash = $ctx['inventoryHash']; PeriodFrom = $ctx['period']['from']; PeriodTo = $ctx['period']['to'] }
            if ($ctx.Contains('previousConnectivity')) { $args2.PreviousConnectivity = $ctx['previousConnectivity'] }
            # Present (even $null, a baseline): a fleet report against the state's counters; absent: a snapshot (compactTelemetry's previousCounters).
            if ($ctx.Contains('previousCounters')) { $args2.PreviousCounters = $ctx['previousCounters'] }
            if ($ctx.Contains('recentHresults')) { $args2.RecentHresults = [string[]]$ctx['recentHresults'] }
            if ($ctx.Contains('sourcesSeen')) { $args2.SourcesSeen = @($ctx['sourcesSeen']) }
            $actual = ConvertTo-DDCanonicalJson -InputObject (ConvertTo-DDTelemetry @args2)
            $actual | Should -BeExactly $expected
        }
    }
}

Describe 'Content path: sent only for Microsoft content hosts, never an identifier' {
    It 'recognises Microsoft content hosts on a label boundary' {
        InModuleScope DoctorDO.Collector {
            foreach ($h in 'au.download.windowsupdate.com', '1d.tlu.dl.delivery.mp.microsoft.com', 'officecdn.microsoft.com', 'f.c2r.ts.cdn.office.net',
                'swdb01-mscdn.manage.microsoft.com', 'cdn.storeedgefd.dsx.mp.microsoft.com', 'DL.DELIVERY.MP.MICROSOFT.COM.') {
                Test-DDMicrosoftContentHost -HostName $h | Should -BeTrue -Because $h
            }
            foreach ($h in 'wsus01.corp.contoso.com', '10.1.2.3', 'notwindowsupdate.com', 'windowsupdate.com.evil.example', 'fp.msedge.net', '', $null) {
                Test-DDMicrosoftContentHost -HostName $h | Should -BeFalse -Because "$h"
            }
        }
    }

    It 'keeps classifying segments for Microsoft hosts and drops everything else' {
        InModuleScope DoctorDO.Collector {
            Get-DDContentPath -HostName 'au.download.windowsupdate.com' -Hint '/software/defu' | Should -BeExactly '/software/defu'
            Get-DDContentPath -HostName 'dl.delivery.mp.microsoft.com' -Hint '/filestreamingservice/files/0a1b2c3d' | Should -BeExactly '/filestreamingservice/files'
            Get-DDContentPath -HostName 'wsus01.corp.contoso.com' -Hint '/Content/software' | Should -BeNullOrEmpty
            Get-DDContentPath -HostName 'swdb01-mscdn.manage.microsoft.com' -Hint '/868f5ac2-e355-430e-be14-cfdd4e5ef28f.intunewin.bin' | Should -BeNullOrEmpty
            Get-DDContentPath -HostName 'dl.delivery.mp.microsoft.com' -Hint '/a%2Fb/files?P1=1/x' | Should -BeExactly '/x'
            Get-DDContentPath -HostName $null -Hint '/software/defu' | Should -BeNullOrEmpty
        }
    }

    It 'reduces a Microsoft Update catalog URL to its kind and category' {
        InModuleScope DoctorDO.Collector {
            Get-DDUrlPathHint -Url 'http://au.download.windowsupdate.com/d/msdownload/update/software/defu/2026/09/am_delta_aa55a10c2c9987cc2af1b4da531ded64ae8e4c75.exe' | Should -BeExactly '/software/defu'
            Get-DDUrlPathHint -Url 'http://download.windowsupdate.com/c/msdownload/update/driver/drvs/2019/07/x.cab' | Should -BeExactly '/driver/drvs'
            Get-DDUrlPathHint -Url 'http://1d.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/5c1f4bd4-0c4e-4e8e-9d1a-2f0d0f7c1a11?P1=1' | Should -BeExactly '/filestreamingservice/files'
        }
    }
}
