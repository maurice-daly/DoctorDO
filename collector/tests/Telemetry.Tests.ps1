#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:TelemetrySchema = Get-ContractPath 'telemetry-v1.schema.json'
    $script:InventorySchema = Get-ContractPath 'inventory-v1.schema.json'
}

Describe 'Get-DOTelemetry with every Windows call mocked' {
    BeforeEach {
        Initialize-FakeDevice -FileCount 40
        # A device whose last accepted report had no jobs, peers or connections: every one listed now is new since then (docs/08).
        # A new file each time: replacing one just written can be refused while it is still being scanned.
        $script:State = Join-Path $TestDrive ('s-{0}\state.json' -f [guid]::NewGuid().ToString('N'))
        InModuleScope DoctorDO.Collector -Parameters @{ P = $script:State } {
            param($P)
            $st = New-DDState
            $st['counters'] = Get-DDNextCounters -Raw ([ordered]@{ status = @(); peerInfo = @(); connections = @(); notCollected = @() }) -Previous $null
            Save-DDState -Path $P -State $st
        }
    }

    It 'validates against contracts/telemetry-v1.schema.json' {
        Assert-ValidAgainstSchema -Object (Get-DOTelemetry -StatePath $script:State -Anonymise) -SchemaFile $script:TelemetrySchema
    }

    It 'the schema check can fail: a deliberately broken report is rejected (negative control)' {
        $t = Get-DOTelemetry -StatePath $script:State -Anonymise
        $t['seq'] = -1
        { Assert-ValidAgainstSchema -Object $t -SchemaFile $script:TelemetrySchema } | Should -Throw
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        $inv.Remove('os')
        { Assert-ValidAgainstSchema -Object $inv -SchemaFile $script:InventorySchema } | Should -Throw
    }

    It 'keeps the top 25 files and accounts for the rest in one filesOther row' {
        $t = Get-DOTelemetry -StatePath $script:State -Anonymise
        $t.files.Count | Should -Be 25
        $t.filesOther.count | Should -Be 15
        $sizes = $t.files | ForEach-Object { [long]$_.size }
        $sizes[0] | Should -BeGreaterThan $sizes[24]
    }

    It 'aggregates peers, names at most 8 with 16-hex hashes, and never carries an address' {
        $t = Get-DOTelemetry -StatePath $script:State -Anonymise
        $t.peers.Count | Should -BeGreaterThan 0
        $t.topPeers.Count | Should -BeLessOrEqual 8
        $t.topPeers | ForEach-Object { $_.h | Should -Match '^[0-9a-f]{16}$' }
        (ConvertTo-Json -InputObject $t -Depth 32 -Compress) | Should -Not -Match '10\.20\.\d+\.\d+(?![\d/])'
        ($t.peers | Where-Object { $_.type -eq 'Lan' }).sameSubnet | Should -BeTrue
        ($t.peers | Where-Object { $_.type -eq 'Group' }).sameSubnet | Should -BeFalse
    }

    It 'groups errors, scrubs the sample line and sends a sample only for a new HRESULT' {
        $t = Get-DOTelemetry -StatePath $script:State -Anonymise
        $g = $t.errors | Where-Object hresult -eq '0x80D02002'
        $g.n | Should -Be 2
        $g.sample | Should -Not -Match 'alice'
        $g.sample | Should -Not -Match 'CONTOSO-LT-0042'
        $g.sample | Should -Not -Match 'secret|token=zzz'
        $g.sample | Should -Not -Match '10\.20\.4\.55'
        $g.sample.Length | Should -BeLessOrEqual 200
        ($t.errors | Where-Object hresult -eq '0x80072EE2').sample | Should -Not -Match 'alice@contoso.com'
    }

    It 'a first report (no state) is a baseline: nothing the cache already held is presented as this period''s traffic' {
        $t = Get-DOTelemetry -StatePath (Join-Path $TestDrive 'none\state.json') -Anonymise
        $t['counters'] | Should -Be 'baseline'
        @($t['files']).Count | Should -Be 0
        $t['filesOther'] | Should -BeNullOrEmpty
        @($t['topPeers']).Count | Should -Be 0
        @($t['connections']).Count | Should -Be 0
        @($t['sources'].Keys).Count | Should -Be 0
        foreach ($k in @($t['perf'].Keys | Where-Object { $_ -like '*Bytes' })) { $t['perf'][$k] | Should -Be 0 -Because $k }
        $t['perf']['numberOfPeers'] | Should -Be 38 -Because 'the readings of the moment are still sent'
        Assert-ValidAgainstSchema -Object $t -SchemaFile $script:TelemetrySchema
    }

    It 'sends each job only for what it moved since the last accepted report, so a job in the cache for days is counted once (A-01)' {
        $sp = Join-Path $TestDrive 'delta\state.json'
        $last = InModuleScope DoctorDO.Collector -Parameters @{ Sp = $sp } {
            param($Sp)
            $st = (Read-DDState -Path $Sp).State
            $c = Get-DDRawCollection -Salt $st['salt'] -Anonymise
            $t1 = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'a' * 64)
            $t1['counters'] | Should -Be 'baseline'
            Update-DDStateAfterTelemetry -State $st -Collection $c -Telemetry $t1 -Now (Get-DDNowUtc)
            Save-DDState -Path $Sp -State $st
            $st2 = (Read-DDState -Path $Sp).State
            $st2['seq'] | Should -Be 1
            @($st2['counters']['jobs']['entries'].Keys).Count | Should -Be 40 -Because 'the state keeps each job''s counters'
            # The same job list a day later: nothing moved, whatever the jobs still in the cache hold.
            $t2 = New-DDTelemetryFromCollection -Collection $c -State $st2 -InventoryHash ('sha256:' + 'a' * 64)
            $t2['seq'] | Should -Be 2
            $t2['counters'] | Should -Be 'delta'
            @($t2['files']).Count | Should -Be 0 -Because 'no job moved a byte since the previous report'
            $t2['perf']['downloadHttpBytes'] | Should -Be 0
            $t2['connectivityChanged'].Count | Should -Be 0 -Because 'nothing changed'
            ($t2['errors'] | Where-Object { $_['hresult'] -eq '0x80D02002' }).sample | Should -BeNullOrEmpty -Because 'already reported'
            # Job 1 moved 5,000 more bytes over HTTP and served 300 more to LAN peers; job 2 left the cache (its cache expired).
            $row = $c.Raw['status'][0]
            $row['bytesFromHttp'] = ([long]$row['bytesFromHttp'] + 5000).ToString()
            $row['bytesToLanPeers'] = ([long]$row['bytesToLanPeers'] + 300).ToString()
            $c.Raw['status'] = @($c.Raw['status'] | Where-Object { $_['fileId'] -ne ('{0:x40}' -f 2) })
            $t3 = New-DDTelemetryFromCollection -Collection $c -State $st2 -InventoryHash ('sha256:' + 'a' * 64)
            @($t3['files']).Count | Should -Be 1
            $t3['files'][0]['b'][0] | Should -Be 5000
            $t3['perf']['downloadHttpBytes'] | Should -Be 5000 -Because 'a job leaving the cache is not read as a service restart (A-02)'
            $t3['perf']['uploadLanBytes'] | Should -Be 300
            # A job whose counters went back (the same file downloaded again) is counted in full.
            $row['bytesFromHttp'] = '10'
            $t4 = New-DDTelemetryFromCollection -Collection $c -State $st2 -InventoryHash ('sha256:' + 'a' * 64)
            $t4['files'][0]['b'][0] | Should -Be 10
            $t4
        }
        Assert-ValidAgainstSchema -Object $last -SchemaFile $script:TelemetrySchema
    }

    It 'the offline device report''s single collection is a snapshot: the counters as read' {
        InModuleScope DoctorDO.Collector {
            $st = New-DDState
            $c = Get-DDRawCollection -Salt $st['salt'] -Anonymise -Mode single
            $t = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'a' * 64)
            $t['counters'] | Should -Be 'snapshot'
            @($t['files']).Count | Should -Be 25
        }
    }

    It 'reports a connectivity result only when it changes' {
        InModuleScope DoctorDO.Collector {
            $st = New-DDState
            $c = Get-DDRawCollection -Salt $st['salt'] -Anonymise
            $first = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'b' * 64)
            $first['connectivityChanged'].Count | Should -Be $c.Raw['connectivity'].Count
            Update-DDStateAfterTelemetry -State $st -Collection $c -Telemetry $first -Now (Get-DDNowUtc)
            $c.Raw['connectivity'][0]['result'] = 'fail'
            $second = New-DDTelemetryFromCollection -Collection $c -State $st -InventoryHash ('sha256:' + 'b' * 64)
            $second['connectivityChanged'].Count | Should -Be 1
            $second['connectivityChanged'][0]['result'] | Should -Be 'fail'
        }
    }

    It 'stays inside the compressed telemetry budget for a busy device (4 KB typical)' {
        $t = Get-DOTelemetry -StatePath $script:State -Anonymise
        InModuleScope DoctorDO.Collector -Parameters @{ T = $t } {
            param($T)
            $b = ConvertTo-DDReportBytes -Report $T
            Get-DDReportBudget -Kind telemetry -CompressedBytes $b.Gzip.Length | Should -BeIn 'within', 'over-typical'
            $b.Gzip.Length | Should -BeLessThan (64 * 1024)
        }
    }

    It 'stays inside the compressed inventory budget (10 KB typical)' {
        $inv = Get-DOInventory -StatePath $script:State -Anonymise
        InModuleScope DoctorDO.Collector -Parameters @{ I = $inv } {
            param($I)
            $b = ConvertTo-DDReportBytes -Report $I
            $b.Gzip.Length | Should -BeLessThan (10 * 1024) -Because "inventory compressed is $($b.Gzip.Length) bytes"
        }
    }

    It 'does not touch the state file (Get-DOTelemetry is read-only)' {
        $sp = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-ro-" + [guid]::NewGuid().ToString('N') + '/state.json')
        $null = Get-DOTelemetry -StatePath $sp -Anonymise
        Test-Path $sp | Should -BeFalse
    }
}
