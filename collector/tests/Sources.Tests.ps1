#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Content sources (docs/08 "Content sources: bytes and time per host"): DownloadDuration, the per-host summary, and the state
# that makes each finished job count once. The compaction itself is proven equal to packages/wire by the golden cases
# `sources` and `sources-busy` in Compact.Tests.ps1; these cover the collector's own parts.
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:TelemetrySchema = Get-ContractPath 'telemetry-v1.schema.json'
}

Describe 'DownloadDuration' {
    It 'reads the TimeSpan the cmdlet returns as whole milliseconds' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDDownloadMs ([timespan]::Parse('00:02:52.0970000', [System.Globalization.CultureInfo]::InvariantCulture)) | Should -Be 172097
            ConvertTo-DDDownloadMs ([timespan]::FromTicks(3025000)) | Should -Be 303 -Because '302.5 ms rounds half away from zero'
            ConvertTo-DDDownloadMs ([timespan]::Zero) | Should -Be 0
        }
    }

    It 'takes a number as seconds, as Microsoft documents, and parses TimeSpan text' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDDownloadMs 15.032 | Should -Be 15032
            ConvertTo-DDDownloadMs ([uint32]9) | Should -Be 9000
            ConvertTo-DDDownloadMs '00:00:05.5290000' | Should -Be 5529
        }
    }

    It 'returns null for anything else, never zero' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDDownloadMs $null | Should -BeNullOrEmpty
            ConvertTo-DDDownloadMs 'soon' | Should -BeNullOrEmpty
            ConvertTo-DDDownloadMs ([timespan]::FromSeconds(-1)) | Should -BeNullOrEmpty
            ConvertTo-DDDownloadMs $true | Should -BeNullOrEmpty
        }
    }

    It 'is carried on every status row' {
        InModuleScope DoctorDO.Collector {
            $ctx = [pscustomobject]@{ Anonymise = $false; Salt = 'aa'; TenantSalt = 'bb'; NotCollected = (New-Object 'System.Collections.Generic.List[object]') }
            $item = [pscustomobject]@{ FileId = 'f1'; FileSize = [uint64]10; TotalBytesDownloaded = [uint64]10; BytesFromHttp = [uint64]10; BytesFromCacheServer = [uint64]0
                Status = 'Caching'; Priority = 'Background'; SourceURL = [uri]'http://1d.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/x'; CacheHost = [uri]'http://198.51.100.202/'
                DownloadDuration = [timespan]::FromMilliseconds(4400) }
            $row = ConvertTo-DDStatusRow -Item $item -Context $ctx
            $row['downloadMs'] | Should -Be 4400
            $row['cacheHost'] | Should -Be '198.51.100.202'
        }
    }
}

Describe 'The per-host summary' {
    BeforeAll {
        $script:Row = {
            param($Id, $Status, $Total, $Http, $Cache, $Lan, $Ms, $HostName, $Ch)
            [ordered]@{ fileId = $Id; status = $Status; totalBytesDownloaded = [string]$Total; bytesFromHttp = [string]$Http; bytesFromLanPeers = [string]$Lan
                bytesFromGroupPeers = '0'; bytesFromInternetPeers = '0'; bytesFromCacheServer = [string]$Cache; downloadMs = $Ms; sourceUrlHost = $HostName; cacheHost = $Ch }
        }
    }

    It 'skips jobs still downloading or paused, and jobs summarised before' {
        InModuleScope DoctorDO.Collector -Parameters @{ Row = $script:Row } {
            param($Row)
            $rows = @(
                (& $Row 'a' 'Caching' 104857600 104857600 0 0 10000 'tlu.dl.delivery.mp.microsoft.com' $null),
                (& $Row 'b' 'Downloading' 104857600 104857600 0 0 10000 'tlu.dl.delivery.mp.microsoft.com' $null),
                (& $Row 'c' 'Paused' 104857600 104857600 0 0 10000 'tlu.dl.delivery.mp.microsoft.com' $null),
                (& $Row 'd' 'Complete' 52428800 52428800 0 0 5000 'tlu.dl.delivery.mp.microsoft.com' $null),
                (& $Row 'e' 'Caching' 52428800 52428800 0 0 5000 'tlu.dl.delivery.mp.microsoft.com' $null))
            $s = ConvertTo-DDSourcesSection -Status $rows -Seen @('e') -Anonymised $false
            $s['http'].Count | Should -Be 1
            $s['http'][0]['n'] | Should -Be 2 -Because 'a and d finished and were not summarised before'
            $s['http'][0]['b'] | Should -Be 157286400
            $s.Contains('mcc') | Should -BeFalse -Because 'an empty list is left out'
        }
    }

    It 'times a job only for the source that delivered at least 90% of its bytes and at least 4 MiB' {
        InModuleScope DoctorDO.Collector -Parameters @{ Row = $script:Row } {
            param($Row)
            $rows = @(
                # all from the cache: timed for the cache
                (& $Row 'a' 'Caching' 116914016 116914016 116914016 0 9300 '3.au.download.windowsupdate.com' '198.51.100.204'),
                # 7% from the cache, 93% from LAN peers: bytes counted, time not
                (& $Row 'b' 'Caching' 44058222 3163758 3163758 40894464 15032 '1d.tlu.dl.delivery.mp.microsoft.com' '198.51.100.202'),
                # all from the CDN but under 4 MiB: bytes counted, time not
                (& $Row 'c' 'Caching' 910919 910919 0 0 300 'swda01-mscdn.manage.microsoft.com' $null),
                # all from the CDN, 46 MiB: timed for the CDN host (the collector's bytesFromHttp is HTTP without cache bytes)
                (& $Row 'd' 'Caching' 48906928 48906928 0 0 5529 'swda01-mscdn.manage.microsoft.com' $null))
            $rows[0]['bytesFromHttp'] = '0'; $rows[1]['bytesFromHttp'] = '0'
            $s = ConvertTo-DDSourcesSection -Status $rows -Seen @() -Anonymised $false
            $c204 = $s['mcc'] | Where-Object { $_['h'] -eq '198.51.100.204' }
            @($c204['t']) | Should -Be @(9300, 116914016, 1)
            $c202 = $s['mcc'] | Where-Object { $_['h'] -eq '198.51.100.202' }
            $c202['n'] | Should -Be 1
            $c202.Contains('t') | Should -BeFalse
            $sw = $s['http'] | Where-Object { $_['h'] -eq 'swda01-mscdn.manage.microsoft.com' }
            $sw['n'] | Should -Be 2
            @($sw['t']) | Should -Be @(5529, 48906928, 1)
        }
    }

    It 'names at most eight HTTP hosts and folds the rest, and unnamed bytes, into one row with a count' {
        InModuleScope DoctorDO.Collector -Parameters @{ Row = $script:Row } {
            param($Row)
            $rows = @(1..11 | ForEach-Object { & $Row "f$_" 'Caching' ($_ * 10485760) ($_ * 10485760) 0 0 1000 ("{0}.tlu.dl.delivery.mp.microsoft.com" -f $_) $null })
            $rows += & $Row 'nohost' 'Caching' 1048576 1048576 0 0 100 $null $null
            $s = ConvertTo-DDSourcesSection -Status $rows -Seen @() -Anonymised $false
            $s['http'].Count | Should -Be 9
            $s['http'][0]['h'] | Should -Be '11.tlu.dl.delivery.mp.microsoft.com' -Because 'most bytes first'
            $other = $s['http'][8]
            $other['h'] | Should -BeNullOrEmpty
            $other['k'] | Should -Be 3
            $other['n'] | Should -Be 4 -Because 'three folded hosts and one job with no host'
        }
    }

    It 'names only Microsoft content hosts or pseudonyms under -Anonymise; the cache server stays in clear (ADR-0031)' {
        InModuleScope DoctorDO.Collector -Parameters @{ Row = $script:Row } {
            param($Row)
            $rows = @(
                (& $Row 'a' 'Caching' 10485760 10485760 0 0 1000 'wsus01.corp.contoso.example' 'MCC01.contoso.example'),
                (& $Row 'b' 'Caching' 10485760 10485760 0 0 1000 'host:0123456789abcdef' $null))
            $rows[0]['bytesFromCacheServer'] = '1048576'
            $s = ConvertTo-DDSourcesSection -Status $rows -Seen @() -Anonymised $true
            @($s['http'] | ForEach-Object { $_['h'] }) | Should -Contain 'host:0123456789abcdef'
            @($s['http'] | ForEach-Object { $_['h'] }) | Should -Not -Contain 'wsus01.corp.contoso.example'
            $s['mcc'][0]['h'] | Should -Be 'mcc01.contoso.example' -Because 'host names are compared in lower case'
        }
    }
}

Describe 'Each finished job counts once' {
    BeforeEach { Initialize-FakeDevice -FileCount 6 }

    It 'a baseline (no counters in the state: a first report) summarises no job, and marks every finished one as summarised' {
        InModuleScope DoctorDO.Collector {
            $st = New-DDState
            $c = Get-DDRawCollection -Salt $st['salt'] -Anonymise
            $t = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'a' * 64)
            $t['counters'] | Should -Be 'baseline'
            @($t['sources'].Keys).Count | Should -Be 0 -Because 'what the cache held before the first report is not this window''s content'
            Update-DDStateAfterTelemetry -State $st -Collection $c -Telemetry $t -Now (Get-DDNowUtc)
            @($st['sourcesSeen']).Count | Should -Be 6
        }
    }

    It 'a second report from the same job list carries an empty section, and the state remembers the jobs' {
        InModuleScope DoctorDO.Collector {
            $st = New-DDState
            # The last report had none of these jobs, so every one of them finished since.
            $st['counters'] = Get-DDNextCounters -Raw ([ordered]@{ status = @(); peerInfo = @(); connections = @(); notCollected = @() }) -Previous $null
            $c = Get-DDRawCollection -Salt $st['salt'] -Anonymise
            $t1 = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'a' * 64)
            $t1['sources']['http'][0]['h'] | Should -Be 'tlu.dl.delivery.mp.microsoft.com'
            $t1['sources']['http'][0]['n'] | Should -Be 6
            $t1['sources']['http'][0].Contains('t') | Should -BeFalse -Because 'the fake jobs are half from peers, so no job is timed'
            Update-DDStateAfterTelemetry -State $st -Collection $c -Telemetry $t1 -Now (Get-DDNowUtc)
            @($st['sourcesSeen']).Count | Should -Be 6
            $t2 = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'a' * 64)
            $t2['sources'].Count | Should -Be 0 -Because 'nothing finished since the last report'
        }
    }

    It 'forgets a job that left the cache, so a file downloaded again is a new job' {
        InModuleScope DoctorDO.Collector {
            $seen = @('gone', ('{0:x40}' -f 1))
            $rows = @([ordered]@{ fileId = ('{0:x40}' -f 1); status = 'Caching' }, [ordered]@{ fileId = 'new'; status = 'Complete' }, [ordered]@{ fileId = 'busy'; status = 'Downloading' })
            (Get-DDNextSourcesSeen -Status $rows -Seen $seen) -join ',' | Should -Be ('{0:x40},new' -f 1)
        }
    }

    It 'sends no section, and keeps the state, when the job list could not be read' {
        InModuleScope DoctorDO.Collector {
            $st = New-DDState
            $st['sourcesSeen'] = @('kept')
            $c = Get-DDRawCollection -Salt $st['salt'] -Anonymise
            $c.Raw['notCollected'] = @(@($c.Raw['notCollected']) + @([ordered]@{ field = 'status'; reason = 'timeout'; detail = 'Timed out after 20 s.' }))
            $t = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'a' * 64)
            $t.Contains('sources') | Should -BeFalse
            Update-DDStateAfterTelemetry -State $st -Collection $c -Telemetry $t -Now (Get-DDNowUtc)
            @($st['sourcesSeen']) | Should -Be @('kept')
        }
    }

    It 'keeps sourcesSeen through a save and a read, and drops what is not a file ID' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-src-" + [guid]::NewGuid().ToString('N'))
        InModuleScope DoctorDO.Collector -Parameters @{ Sp = (Join-Path $dir 'state.json') } {
            param($Sp)
            $st = New-DDState
            $st['sourcesSeen'] = @('a', 'b')
            Save-DDState -Path $Sp -State $st
            @((Read-DDState -Path $Sp).State['sourcesSeen']) | Should -Be @('a', 'b')
            (ConvertTo-DDValidState -Candidate ([ordered]@{ sourcesSeen = @('ok', 7, '', ('x' * 300)) }))['sourcesSeen'] | Should -Be @('ok')
            @((ConvertTo-DDValidState -Candidate ([ordered]@{}))['sourcesSeen']).Count | Should -Be 0 -Because 'a state written before the field starts empty'
        }
        Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'the report with the section validates against contracts/telemetry-v1.schema.json' {
        $t = Get-DOTelemetry -StatePath (Join-Path ([System.IO.Path]::GetTempPath()) ("dd-src-" + [guid]::NewGuid().ToString('N') + '/state.json')) -Anonymise
        $t.Contains('sources') | Should -BeTrue
        Assert-ValidAgainstSchema -Object $t -SchemaFile $script:TelemetrySchema
    }
}
