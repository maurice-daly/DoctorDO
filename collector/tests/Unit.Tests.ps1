#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
    $script:Fix = Join-Path $PSScriptRoot 'fixtures'
}

Describe 'JSON helpers' {
    It 'matches packages/wire canonicalJson and inventoryHash byte for byte (unicode, escapes, doubles, key order)' {
        InModuleScope DoctorDO.Collector -Parameters @{ Fix = $script:Fix } {
            param($Fix)
            $g = Read-DDJsonFile -Path (Join-Path $Fix 'inventory-hash.golden.json')
            $stable = [ordered]@{}
            foreach ($k in $g['input'].Keys) { if ($k -ne 'collectedAt' -and $k -ne 'notCollected') { $stable[$k] = $g['input'][$k] } }
            ConvertTo-DDCanonicalJson -InputObject $stable | Should -BeExactly $g['canonical']
            Get-DDInventoryHash -Inventory $g['input'] | Should -BeExactly $g['hash']
        }
    }

    It 'keeps ISO 8601 strings as strings (ConvertFrom-Json on PowerShell 7.4 would turn them into DateTime)' {
        InModuleScope DoctorDO.Collector {
            $o = ConvertFrom-DDJson -Text '{"collectedAt":"2026-09-06T14:22:10Z","n":5,"f":1.5,"big":9007199254740993,"a":[1,[2],{"x":null}],"t":true}'
            $o['collectedAt'] | Should -BeOfType [string]
            $o['collectedAt'] | Should -Be '2026-09-06T14:22:10Z'
            $o['n'] | Should -BeOfType [long]
            $o['f'] | Should -BeOfType [double]
            $o['a'][1][0] | Should -Be 2
            $o['a'][2]['x'] | Should -BeNullOrEmpty
            $o['t'] | Should -BeTrue
        }
    }

    It 'escapes like JSON.stringify' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDJsonString -Value "a`"b\c`n`t$([char]1)$([char]0x2028)" | Should -BeExactly ('"a\"b\\c\n\t\u0001' + [char]0x2028 + '"')
            ConvertTo-DDJsonString -Value ([string][char]0xD800) | Should -BeExactly '"\ud800"'
        }
    }

    It 'renders byte counters as a number when exact and a decimal string above 2^53' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDByteCount -Value ([System.Numerics.BigInteger]5) | Should -Be 5
            ConvertTo-DDByteCount -Value ([System.Numerics.BigInteger]9007199254740991) | Should -BeOfType [long]
            ConvertTo-DDByteCount -Value ([System.Numerics.BigInteger]::Parse('9007199254740993')) | Should -BeExactly '9007199254740993'
            (ConvertTo-DDBigInt -Value '18446744073709551615').ToString() | Should -Be '18446744073709551615'
            (ConvertTo-DDBigInt -Value 42).ToString() | Should -Be '42'
            (ConvertTo-DDBigInt -Value $null).ToString() | Should -Be '0'
            (ConvertTo-DDBigInt -Value 'not a number').ToString() | Should -Be '0'
        }
    }

    It 'ConvertTo-Json -Compress output (what is sent) parses back to the same canonical form' {
        InModuleScope DoctorDO.Collector -Parameters @{ Fix = $script:Fix } {
            param($Fix)
            $inv = Read-DDJsonFile -Path (Join-Path $Fix 'inventory.sample.json')
            $sent = ConvertTo-DDReportBytes -Report $inv
            $back = ConvertFrom-DDJson -Text $sent.Json
            ConvertTo-DDCanonicalJson -InputObject $back | Should -BeExactly (ConvertTo-DDCanonicalJson -InputObject $inv)
        }
    }

    It 'gzip output round-trips through GZipStream' {
        InModuleScope DoctorDO.Collector {
            $payload = ConvertTo-DDReportBytes -Report ([ordered]@{ schemaVersion = 1; kind = 'telemetry'; text = ('x' * 5000) })
            $ms = New-Object System.IO.MemoryStream (, $payload.Gzip)
            $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
            $sr = New-Object System.IO.StreamReader($gz)
            $sr.ReadToEnd() | Should -BeExactly $payload.Json
            $payload.Gzip.Length | Should -BeLessThan 200
        }
    }
}

Describe 'State file' {
    BeforeEach { $script:Dir = Join-Path ([System.IO.Path]::GetTempPath()) ("dd-state-" + [guid]::NewGuid().ToString('N')); Initialize-FakeDevice }

    It 'starts fresh when absent, with a random salt, and round-trips atomically' {
        InModuleScope DoctorDO.Collector -Parameters @{ Dir = $script:Dir } {
            param($Dir)
            $p = Join-Path $Dir 'state.json'
            $r = Read-DDState -Path $p
            $r.Recovered | Should -BeFalse
            $r.State['salt'] | Should -Match '^[0-9a-f]{64}$'
            $r.State['seq'] = 7
            $r.State['counters'] | Should -BeNullOrEmpty -Because 'no report yet: the first telemetry is a baseline'
            $m = New-DDOrdinalMap; $m['f1'] = [string[]]@('9007199254740993', '0', '0', '0', '0', '5', '0', '0')
            $r.State['counters'] = [ordered]@{ jobs = [ordered]@{ entries = $m; capped = $false }; peers = $null; connections = $null }
            Save-DDState -Path $p -State $r.State
            @(Get-ChildItem $Dir -Filter '*.tmp').Count | Should -Be 0 -Because 'the temp file is moved over the target'
            $back = (Read-DDState -Path $p).State
            $back['seq'] | Should -Be 7
            $back['salt'] | Should -Be $r.State['salt']
            $back['counters']['jobs']['entries']['f1'][0] | Should -Be '9007199254740993'
            $back['counters']['peers'] | Should -BeNullOrEmpty -Because 'a list never read stays a starting point'
            Save-DDState -Path $p -State $back
            ((Read-DDState -Path $p).State)['salt'] | Should -Be $r.State['salt'] -Because 'overwrite keeps the file valid'
        }
    }

    It 'recovers from a corrupt file: starts fresh, never throws, never moves the file; the next save replaces it' {
        InModuleScope DoctorDO.Collector -Parameters @{ Dir = $script:Dir } {
            param($Dir)
            New-Item -ItemType Directory -Path $Dir | Out-Null
            $p = Join-Path $Dir 'state.json'
            [System.IO.File]::WriteAllText($p, '{ this is not json')
            $r = Read-DDState -Path $p
            $r.Recovered | Should -BeTrue
            $r.State['seq'] | Should -Be 0
            $r.State['lastInventoryHash'] | Should -BeNullOrEmpty
            @(Get-ChildItem $Dir).Name | Should -Be @('state.json') -Because 'reading never writes: no .corrupt- file is left'
            Save-DDState -Path $p -State $r.State
            (Read-DDState -Path $p).Recovered | Should -BeFalse
        }
    }

    It 'reads nothing from a state folder it cannot trust, and writes nothing there' {
        InModuleScope DoctorDO.Collector -Parameters @{ Dir = $script:Dir } {
            param($Dir)
            New-Item -ItemType Directory -Path $Dir | Out-Null
            $p = Join-Path $Dir 'state.json'
            [System.IO.File]::WriteAllText($p, '{"seq":41,"salt":"' + ('ab' * 16) + '","backoffUntil":"2099-01-01T00:00:00Z"}')
            Mock Get-DDDirectorySecurityRaw { [pscustomobject]@{ Exists = $true; ReparsePoint = $false; Owner = 'S-1-5-21-1-2-3-1001'; Protected = $false; Rules = @(); Subdirectories = 0; Links = 0; Error = $null } }
            $r = Read-DDState -Path $p
            $r.Untrusted | Should -Match 'owned by an account other than SYSTEM or Administrators'
            $r.State['seq'] | Should -Be 0 -Because 'a planted file is not read'
            $r.State['backoffUntil'] | Should -BeNullOrEmpty
            Mock Reset-DDStateDirectory { throw 'not expected' }
            { Save-DDState -Path $p -State $r.State } | Should -Throw '*not safe to use: it is owned by an account other than*'
            [System.IO.File]::ReadAllText($p) | Should -Match '"seq":41' -Because 'nothing was written'
            Should -Invoke Reset-DDStateDirectory -Times 0 -Exactly -Because 'only the fleet run may replace the folder, and only the default one'
        }
    }

    It 'keeps the fields that are valid and replaces the ones that are not (tolerant recovery)' {
        InModuleScope DoctorDO.Collector -Parameters @{ Dir = $script:Dir } {
            param($Dir)
            New-Item -ItemType Directory -Path $Dir | Out-Null
            $p = Join-Path $Dir 'state.json'
            [System.IO.File]::WriteAllText($p, '{"version":1,"seq":12,"salt":"not-hex!","lastInventoryHash":"garbage","lastConnectivity":{"a|b|dns|":"pass","c":5},"recentHresults":[{"hresult":"0x80D02002","at":"2026-10-11T00:00:00Z"},{"hresult":"bad","at":"x"}],"lastCounters":{"downloadHttpBytes":"5"},"counters":{"jobs":{"entries":{"ok":["1","2","3","4","5","6","7","8"],"short":["1"],"neg":["-1","0","0","0","0","0","0","0"]},"capped":false},"peers":"oops","connections":{"entries":{"c":2,"d":"x"}}}}')
            $s = (Read-DDState -Path $p).State
            $s['seq'] | Should -Be 12
            $s['salt'] | Should -Match '^[0-9a-f]{64}$'
            $s['lastInventoryHash'] | Should -BeNullOrEmpty
            $s['lastConnectivity'].Count | Should -Be 1
            @($s['recentHresults']).Count | Should -Be 1
            $s.Contains('lastCounters') | Should -BeFalse -Because 'the job-list sums of collectors before 0.6.0 are dropped: the next report is a baseline'
            @($s['counters']['jobs']['entries'].Keys) | Should -Be @('ok')
            $s['counters']['jobs']['capped'] | Should -BeTrue -Because 'an entry it dropped must never be counted whole later'
            $s['counters']['peers'] | Should -BeNullOrEmpty
            $s['counters']['connections']['entries']['c'] | Should -Be 2
            $s['counters']['connections']['capped'] | Should -BeTrue
        }
    }

    It 'retries a save while another process holds the file for a moment, so an accepted report''s counters are committed' {
        if (-not ('DDTestFileHolder' -as [type])) {
            Add-Type -TypeDefinition @'
using System.IO; using System.Threading;
public static class DDTestFileHolder {
    // Opens the file with no sharing, as a scanner does, and lets it go after ms milliseconds on a thread of its own.
    public static void HoldFor(string path, int ms) {
        var fs = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
        new Thread(() => { Thread.Sleep(ms); fs.Dispose(); }).Start();
    }
}
'@
        }
        $p = Join-Path $TestDrive 'held\state.json'
        InModuleScope DoctorDO.Collector -Parameters @{ P = $p } {
            param($P)
            $st = New-DDState
            Save-DDState -Path $P -State $st
            $st['seq'] = 9
            [DDTestFileHolder]::HoldFor($P, 250)
            Save-DDState -Path $P -State $st
            (Read-DDState -Path $P).State['seq'] | Should -Be 9
            @(Get-ChildItem (Split-Path $P) -Filter '*.tmp').Count | Should -Be 0
        }
    }

    It 'a JSON root that is not an object also recovers' {
        InModuleScope DoctorDO.Collector -Parameters @{ Dir = $script:Dir } {
            param($Dir)
            New-Item -ItemType Directory -Path $Dir | Out-Null
            $p = Join-Path $Dir 'state.json'
            [System.IO.File]::WriteAllText($p, '[1,2,3]')
            (Read-DDState -Path $p).Recovered | Should -BeTrue
        }
    }

    It 'a failed write leaves the previous state intact' {
        InModuleScope DoctorDO.Collector -Parameters @{ Dir = $script:Dir } {
            param($Dir)
            $p = Join-Path $Dir 'state.json'
            $s = (Read-DDState -Path $p).State; $s['seq'] = 3
            Save-DDState -Path $p -State $s
            $s['seq'] = 4
            Mock ConvertTo-DDCanonicalJson { throw 'boom' }
            { Save-DDState -Path $p -State $s } | Should -Throw
            ((Read-DDState -Path $p).State)['seq'] | Should -Be 3
        }
    }

    It 'remembers reported HRESULTs for a week and forgets older ones' {
        InModuleScope DoctorDO.Collector {
            $s = New-DDState
            $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
            Add-DDRecentHresults -State $s -Hresults @('0x80D02002') -Now $now.AddDays(-10)
            Add-DDRecentHresults -State $s -Hresults @('0x80072EE2') -Now $now.AddDays(-1)
            $recent = Get-DDRecentHresultList -State $s -Now $now
            $recent | Should -Contain '0x80072EE2'
            $recent | Should -Not -Contain '0x80D02002'
        }
    }
}

Describe 'State folder trust' {
    It 'trusts only a protected folder owned by SYSTEM or Administrators, with no other account, link or subfolder' {
        InModuleScope DoctorDO.Collector {
            $ok = { [pscustomobject]@{ Exists = $true; ReparsePoint = $false; Owner = 'S-1-5-18'; Protected = $true; Subdirectories = 0; Links = 0; Error = $null
                    Rules = @([pscustomobject]@{ Sid = 'S-1-5-18'; Type = 'Allow'; Rights = 2032127 }, [pscustomobject]@{ Sid = 'S-1-5-32-544'; Type = 'Allow'; Rights = 2032127 }) } }
            $with = { param($k, $v) $r = & $ok; $r.$k = $v; $r }
            Test-DDTrustedDirectory -Raw (& $ok) | Should -BeNullOrEmpty
            Test-DDTrustedDirectory -Raw (& $with 'Owner' 'S-1-5-32-544') | Should -BeNullOrEmpty
            Test-DDTrustedDirectory -Raw $null | Should -BeNullOrEmpty -Because 'off Windows there are no ACLs to judge'
            Test-DDTrustedDirectory -Raw (& $with 'Exists' $false) | Should -Be 'missing'
            Test-DDTrustedDirectory -Raw (& $with 'ReparsePoint' $true) | Should -Match 'junction or symbolic link'
            Test-DDTrustedDirectory -Raw (& $with 'Owner' 'S-1-5-21-1-2-3-1001') | Should -Match 'owned by an account other than'
            Test-DDTrustedDirectory -Raw (& $with 'Protected' $false) | Should -Match 'inherits permissions'
            Test-DDTrustedDirectory -Raw (& $with 'Rules' @([pscustomobject]@{ Sid = 'S-1-5-32-545'; Type = 'Allow'; Rights = 1179817 })) | Should -Match 'grants access to accounts other than'
            Test-DDTrustedDirectory -Raw (& $with 'Rules' @([pscustomobject]@{ Sid = 'S-1-1-0'; Type = 'Deny'; Rights = 2032127 })) | Should -BeNullOrEmpty -Because 'a Deny rule takes nothing away from SYSTEM'
            Test-DDTrustedDirectory -Raw (& $with 'Links' 1) | Should -Match 'folders or links'
            Test-DDTrustedDirectory -Raw (& $with 'Subdirectories' 1) | Should -Match 'folders or links'
            Test-DDTrustedDirectory -Raw (& $with 'Error' 'Access is denied') | Should -Be 'its permissions could not be read'
            (Test-DDTrustedDirectory -Raw (& $with 'Owner' 'S-1-5-21-1-2-3-1001')) | Should -Not -Match 'S-1-5-21' -Because 'reasons reach the Intune output and name no account'
        }
    }

    It 'creates a missing folder protected; replaces an untrusted one only with -AllowReset, then checks again' {
        InModuleScope DoctorDO.Collector {
            Mock New-DDProtectedDirectory { $script:Made = $true }
            Mock Reset-DDStateDirectory { $script:Replaced = $true }
            $script:Made = $false; $script:Replaced = $false
            $script:Seq = @([pscustomobject]@{ Exists = $false }, [pscustomobject]@{ Exists = $true; ReparsePoint = $false; Owner = 'S-1-5-18'; Protected = $true; Rules = @(); Subdirectories = 0; Links = 0; Error = $null })
            $script:Call = 0
            Mock Get-DDDirectorySecurityRaw { $script:Seq[[math]::Min($script:Call++, $script:Seq.Count - 1)] }
            Initialize-DDStateDirectory -Path 'C:\ProgramData\DoctorDO' | Should -BeNullOrEmpty
            $script:Made | Should -BeTrue -Because 'creating a new folder deletes nothing, so it needs no -AllowReset'

            $owned = [pscustomobject]@{ Exists = $true; ReparsePoint = $true; Owner = $null; Protected = $false; Rules = @(); Subdirectories = 0; Links = 0; Error = $null }
            $script:Seq = @($owned, $script:Seq[1]); $script:Call = 0
            Initialize-DDStateDirectory -Path 'C:\ProgramData\DoctorDO' | Should -Be 'it is a junction or symbolic link'
            $script:Replaced | Should -BeFalse -Because 'without -AllowReset nothing is ever deleted'

            $script:Call = 0
            Initialize-DDStateDirectory -Path 'C:\ProgramData\DoctorDO' -AllowReset | Should -BeNullOrEmpty
            $script:Replaced | Should -BeTrue

            $script:Seq = @($owned, $owned); $script:Call = 0
            Initialize-DDStateDirectory -Path 'C:\ProgramData\DoctorDO' -AllowReset | Should -Match 'junction or symbolic link, and after it was replaced it is a junction'
            Mock Reset-DDStateDirectory { throw 'it holds a file the collector did not create' }
            $script:Seq = @($owned); $script:Call = 0
            Initialize-DDStateDirectory -Path 'C:\ProgramData\DoctorDO' -AllowReset | Should -Match 'could not be replaced \(it holds a file the collector did not create\)'
        }
    }

    It 'a fleet run stops with exit 7 before reading state or sending anything, and replaces only the default folder' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDDirectorySecurityRaw { [pscustomobject]@{ Exists = $true; ReparsePoint = $false; Owner = 'S-1-5-21-1-2-3-1001'; Protected = $false; Rules = @(); Subdirectories = 0; Links = 0; Error = $null } }
        Mock -ModuleName DoctorDO.Collector Reset-DDStateDirectory { throw 'access denied' }
        Mock -ModuleName DoctorDO.Collector Read-DDState { throw 'state read' }
        Mock -ModuleName DoctorDO.Collector Send-DoctorDOReport { throw 'sent' }
        $custom = Join-Path $TestDrive 'dd\state.json'
        $r = Invoke-DoctorDOCollector -Fleet -IngestUri 'https://ingest.contoso.example/v1/ingest' -StatePath $custom
        $r.ExitCode | Should -Be 7
        $r.Outcome | Should -Be 'StateFolderUntrusted'
        $r.Message | Should -Match 'not safe to use: it is owned by an account other than SYSTEM or Administrators\. A standard user'
        Should -Invoke -ModuleName DoctorDO.Collector Reset-DDStateDirectory -Times 0 -Exactly -Because 'a -StatePath elsewhere is the caller''s folder'
        Mock -ModuleName DoctorDO.Collector Get-DDDefaultStatePath { $custom }
        $r = Invoke-DoctorDOCollector -Fleet -IngestUri 'https://ingest.contoso.example/v1/ingest'
        $r.ExitCode | Should -Be 7
        $r.Message | Should -Match 'and it could not be replaced \(access denied\)'
        Should -Invoke -ModuleName DoctorDO.Collector Reset-DDStateDirectory -Times 1 -Exactly
        Should -Invoke -ModuleName DoctorDO.Collector Read-DDState -Times 0 -Exactly
        Should -Invoke -ModuleName DoctorDO.Collector Send-DoctorDOReport -Times 0 -Exactly
    }

    It 'replaces the folder for real without following a link, and deletes nothing when anything there is not the collector''s' -Skip:([System.Environment]::OSVersion.Platform -ne 'Win32NT') {
        InModuleScope DoctorDO.Collector -Parameters @{ Root = $TestDrive } {
            param($Root)
            Mock Protect-DDPath { }   # the real ACL would lock the test runner out of TestDrive
            $outside = Join-Path $Root 'outside'; New-Item -ItemType Directory -Path $outside | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $outside 'keep.txt'), 'not the collector''s')
            $dir = Join-Path $Root 'DoctorDO'; New-Item -ItemType Directory -Path $dir | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $dir 'state.json'), '{}')
            New-Item -ItemType Junction -Path (Join-Path $dir 'geo.json') -Target $outside | Out-Null
            Reset-DDStateDirectory -Path $dir
            @([System.IO.Directory]::GetFileSystemEntries($dir)).Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $outside 'keep.txt') | Should -BeTrue -Because 'deleting the link removed the link, not its target'

            [System.IO.File]::WriteAllText((Join-Path $dir 'state.json'), '{}')
            [System.IO.File]::WriteAllText((Join-Path $dir 'notes.txt'), 'someone else''s')
            { Reset-DDStateDirectory -Path $dir } | Should -Throw '*a file the collector did not create*'
            @([System.IO.Directory]::GetFileSystemEntries($dir) | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Sort-Object) | Should -Be @('notes.txt', 'state.json') -Because 'everything is checked before anything is deleted'
        }
    }
}

Describe 'Redaction' {
    It 'reduces an address to its subnet' {
        InModuleScope DoctorDO.Collector {
            Get-DDSubnetString -Address '10.20.4.71' -PrefixLength 22 | Should -Be '10.20.4.0/22'
            Get-DDSubnetString -Address '192.168.1.200' -PrefixLength 24 | Should -Be '192.168.1.0/24'
            Get-DDSubnetString -Address '172.16.5.9' -PrefixLength 0 | Should -Be '0.0.0.0/0'
            Get-DDSubnetString -Address 'not-an-ip' -PrefixLength 24 | Should -BeNullOrEmpty
            Test-DDSameSubnet -Address '10.20.5.1' -LocalAddress '10.20.4.71' -PrefixLength 22 | Should -BeTrue
            Test-DDSameSubnet -Address '10.20.9.1' -LocalAddress '10.20.4.71' -PrefixLength 22 | Should -BeFalse
        }
    }

    It 'hashes with domain separation and a salt, deterministically' {
        InModuleScope DoctorDO.Collector {
            $a = Get-DDSaltedHash -Value 'x' -Salt 's1' -Domain 'peer'
            $a | Should -Match '^sha256:[0-9a-f]{64}$'
            Get-DDSaltedHash -Value 'x' -Salt 's1' -Domain 'peer' | Should -Be $a
            Get-DDSaltedHash -Value 'x' -Salt 's2' -Domain 'peer' | Should -Not -Be $a
            Get-DDSaltedHash -Value 'x' -Salt 's1' -Domain 'serial' | Should -Not -Be $a
        }
    }

    It 'scrubs user paths, URLs, e-mail addresses always; addresses and the machine name under -Anonymise' {
        InModuleScope DoctorDO.Collector {
            $t = 'fail C:\Users\alice\AppData\x https://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/0123abcd-0000-0000-0000-000000000000/part?sig=SECRET#f from 10.1.2.3 on PC-ALICE by bob@contoso.com'
            $base = Protect-DDLogText -Text $t
            $base | Should -Not -Match 'alice\\'
            $base | Should -Not -Match 'SECRET'
            $base | Should -Not -Match 'bob@contoso.com'
            $base | Should -Match 'https://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files'
            $base | Should -Match '10\.1\.2\.3'
            $machine = 'PC-ALICE'
            $anon = Protect-DDLogText -Text $t -Anonymise -Salt 'abc' -ComputerName $machine
            $anon | Should -Not -Match '10\.1\.2\.3'
            $anon | Should -Not -Match 'PC-ALICE'
            $anon | Should -Match '<ip:[0-9a-f]{8}>'
        }
    }

    # The forms the pre-launch audit's probe found unscrubbed (C-01), each with what the baseline scrub now sends.
    It 'scrubs the account in <In>' -ForEach @(
        @{ In = 'C:\Users\John Smith\AppData\Local\x.etl'; Out = 'C:\Users\<user>\AppData\Local\x.etl' }
        @{ In = 'C:\Users\jsmith\AppData\x'; Out = 'C:\Users\<user>\AppData\x' }
        @{ In = 'D:\Documents and Settings\jsmith\x'; Out = 'D:\Documents and Settings\<user>\x' }
        @{ In = 'C:/Users/jsmith/x'; Out = 'C:/Users/<user>/x' }
        @{ In = 'file:///C:/Users/jsmith/x.cab'; Out = 'file:///C:/Users/<user>/x.cab' }
        @{ In = '\\?\C:\Users\bob\x'; Out = '\\?\C:\Users\<user>\x' }
        @{ In = '\Device\HarddiskVolume3\Users\alice\y'; Out = '\Device\HarddiskVolume3\Users\<user>\y' }
        @{ In = '%SystemDrive%\Users\alice\y'; Out = '%SystemDrive%\Users\<user>\y' }
        @{ In = '{"ImagePath":"C:\\Users\\jsmith\\x.exe"}'; Out = '{"ImagePath":"C:\\Users\\<user>\\x.exe"}' }
        @{ In = 'CONTOSO\jsmith failed'; Out = 'CONTOSO\<user> failed' }
        @{ In = 'account AzureAD\JohnSmith'; Out = 'account AzureAD\<user>' }
        @{ In = 'azuread\johnsmith'; Out = 'azuread\<user>' }
        @{ In = 'DESKTOP-AB12\localadmin'; Out = 'DESKTOP-AB12\<user>' }
        @{ In = '\\fileserver\home$\jsmith\f.txt not found'; Out = '\\fileserver\<path> not found' }
        @{ In = '\\srv\Home Folders\John Smith\f.txt (0x80070002)'; Out = '\\srv\<path> (0x80070002)' }
        @{ In = '\\?\UNC\srv\users\jsmith\f.txt'; Out = '\\?\UNC\srv\<path>' }
        @{ In = 'sid S-1-5-21-1004336348-1177238915-682003330-1001'; Out = 'sid <sid>' }
        @{ In = 'sid S-1-12-1-1234567890-1234567890-1234567890-1234567890'; Out = 'sid <sid>' }
        @{ In = 'https://host.example/Users/jsmith/deep/path?sig=SECRET'; Out = 'https://host.example/Users/<user>' }
    ) {
        InModuleScope DoctorDO.Collector -Parameters @{ In = $In; Out = $Out } {
            param($In, $Out)
            Protect-DDLogText -Text $In | Should -BeExactly $Out
            Protect-DDLogText -Text $Out | Should -BeExactly $Out -Because 'the scrub is idempotent'
        }
    }

    It 'leaves text that is not an account alone: <In>' -ForEach @(
        @{ In = 'C:\Program Files\Foo\foo.exe and C:\Program Files\foo.exe' }
        @{ In = '%SystemRoot%\system32\svchost.exe' }
        @{ In = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' }
        @{ In = 'NT AUTHORITY\SYSTEM, NT SERVICE\DoSvc, BUILTIN\Administrators' }
        @{ In = 'domain SID S-1-5-21-1004336348-1177238915-682003330' }
        @{ In = 'FailurePeerConnect, hr: 8007274c, peerIp: [fe80::1c2d:3e4f:5a6b:7c8d%12]:7680' }
    ) {
        InModuleScope DoctorDO.Collector -Parameters @{ In = $In } {
            param($In)
            Protect-DDLogText -Text $In | Should -BeExactly $In
        }
    }

    It 'masks IPv6 addresses under -Anonymise as it does IPv4, and leaves times, MAC addresses and C++ scopes' {
        InModuleScope DoctorDO.Collector {
            $t = 'peerIp: [fe80::1c2d:3e4f:5a6b:7c8d%12]:7680, to 2001:db8:1::5 and ::ffff:10.1.2.3 then 10.0.0.1; CSwarmConn::Initiate at 10:20:30.123 mac 00:1a:2b:3c:4d:5e'
            $machine = 'PC-1'
            $anon = Protect-DDLogText -Text $t -Anonymise -Salt 'abc' -ComputerName $machine
            $anon | Should -Not -Match 'fe80|2001:db8|ffff|10\.1\.2\.3|10\.0\.0\.1'
            @([regex]::Matches($anon, '<ip:[0-9a-f]{8}>')).Count | Should -Be 4
            $anon | Should -Match 'CSwarmConn::Initiate at 10:20:30\.123 mac 00:1a:2b:3c:4d:5e'
            # One address, two spellings: one pseudonym.
            (Protect-DDLogText -Text '2001:db8::5' -Anonymise -Salt 'abc') | Should -Be (Protect-DDLogText -Text '2001:0db8:0:0::5' -Anonymise -Salt 'abc')
            (Protect-DDLogText -Text $t) | Should -Match 'fe80::1c2d' -Because 'without -Anonymise addresses stay, for IPv6 as for IPv4'
        }
    }

    It 'scrubs a firewall rule''s display name and program, always, and the machine name and addresses under -Anonymise' {
        InModuleScope DoctorDO.Collector {
            $rule = [pscustomobject]@{ DisplayName = 'Foo for CONTOSO\jsmith on PC-JS'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Private'; Protocol = 'TCP'; LocalPort = '7680'
                Program = 'C:\Users\John Smith\AppData\Local\Foo\foo.exe'; Service = $null }
            $plain = ConvertFrom-DDFirewallRaw -Rules @($rule)
            $plain[0].program | Should -BeExactly 'C:\Users\<user>\AppData\Local\Foo\foo.exe'
            $plain[0].displayName | Should -BeExactly 'Foo for CONTOSO\<user> on PC-JS'
            $machine = 'PC-JS'
            $ctx = New-DDContext -Salt 'aa' -TenantSalt 'bb' -Anonymise -ComputerName $machine
            $anon = ConvertFrom-DDFirewallRaw -Rules @($rule) -Context $ctx
            $anon[0].displayName | Should -BeExactly 'Foo for CONTOSO\<user> on <host>'
            $anon[0].program | Should -BeExactly 'C:\Users\<user>\AppData\Local\Foo\foo.exe'
            $do = [pscustomobject]@{ DisplayName = 'Delivery Optimization (TCP-In)'; Direction = 'Inbound'; Action = 'Allow'; Enabled = 'True'; Profile = 'Any'; Protocol = 'TCP'; LocalPort = '7680'
                Program = '%SystemRoot%\system32\svchost.exe'; Service = 'dosvc' }
            $kept = (ConvertFrom-DDFirewallRaw -Rules @($do) -Context $ctx)[0]
            $kept.program | Should -BeExactly '%SystemRoot%\system32\svchost.exe'
            $kept.displayName | Should -BeExactly 'Delivery Optimization (TCP-In)'
        }
    }

    It 'treats link-local peers as on the same link and compares IPv6 peers with the device''s own prefixes (A-14)' {
        InModuleScope DoctorDO.Collector {
            Test-DDSameSubnet -Address 'fe80::1c2d:3e4f:5a6b:7c8d' -LocalAddress '10.0.0.5' -PrefixLength 24 | Should -BeTrue
            Test-DDSameSubnet -Address '[fe80::1%12]' -LocalAddress '10.0.0.5' -PrefixLength 24 | Should -BeTrue
            Test-DDSameSubnet -Address '169.254.10.20' -LocalAddress '10.0.0.5' -PrefixLength 24 | Should -BeTrue
            Test-DDSameSubnet -Address '2001:db8:1:2::9' -LocalAddress '10.0.0.5' -PrefixLength 24 | Should -BeFalse -Because 'no IPv6 prefix of the device is known'
            Test-DDSameSubnet -Address '2001:db8:1:2::9' -LocalAddress '10.0.0.5' -PrefixLength 24 -LocalNetworks @('2001:db8:1:2::5/64') | Should -BeTrue
            Test-DDSameSubnet -Address '2001:db8:1:3::9' -LocalAddress '10.0.0.5' -PrefixLength 24 -LocalNetworks @('2001:db8:1:2::5/64') | Should -BeFalse
            Test-DDSameSubnet -Address '::ffff:10.0.0.9' -LocalAddress '10.0.0.5' -PrefixLength 24 | Should -BeTrue -Because 'an IPv4-mapped address is compared as IPv4'
            Test-DDSameSubnet -Address 'not-an-ip' -LocalAddress '10.0.0.5' -PrefixLength 24 | Should -BeFalse
        }
    }

    It 'hashes DOGroupId registry data under -Anonymise; keeps the cache host (ADR-0031) and other values' {
        InModuleScope DoctorDO.Collector {
            $vals = @([ordered]@{ name = 'DOGroupId'; type = 'REG_SZ'; data = 'secret-guid' }, [ordered]@{ name = 'DOCacheHost'; type = 'REG_SZ'; data = 'cache.corp' }, [ordered]@{ name = 'DOCacheHostSource'; type = 'REG_DWORD'; data = '1' }, [ordered]@{ name = 'DODownloadMode'; type = 'REG_DWORD'; data = '2' })
            $out = Protect-DDRegistryValues -Values $vals -Salt 'abc'
            $out[0].data | Should -Match '^redacted:[0-9a-f]{16}$'
            $out[1].data | Should -Be 'cache.corp'
            $out[2].data | Should -Be '1'
            $out[3].data | Should -Be '2'
        }
    }

    It 'prints the redaction profile as data (-WhatIfRedaction) and collects nothing' {
        Initialize-FakeDevice
        $r = Invoke-DoctorDOCollector -WhatIfRedaction
        $r.ExitCode | Should -Be 0
        $r.RedactionProfile['anonymise'].Count | Should -BeGreaterThan 5
        Should -Invoke -ModuleName DoctorDO.Collector Get-DDDsregStatusText -Times 0
    }

    It 'names everything the reports carry that a reviewer asks about: the ESP read and the provisioning section, the scrubbed forms, IPv6 (C-06, C-01)' {
        $p = Invoke-DoctorDOCollector -WhatIfRedaction | ForEach-Object RedactionProfile
        $always = ($p['alwaysApplied'] | ForEach-Object { '{0}: {1}' -f $_['field'], $_['treatment'] }) -join "`n"
        $always | Should -Match 'EnrollmentStatusTracking'
        $always | Should -Match 'provisioning section'
        $always | Should -Match 'Intune app ID'
        foreach ($form in 'AzureAD', 'UNC', '<sid>', '<upn>', 'firewall rule names and programs') { $always | Should -Match ([regex]::Escape($form)) }
        $always | Should -Match 'can get through' -Because 'the profile says what the patterns miss, not "never"'
        (($p['anonymise'] | ForEach-Object { $_['treatment'] }) -join ' ') | Should -Match 'IPv4 and IPv6'
    }
}

Describe 'Parsers of Windows output' {
    It 'dsregcmd /status: hybrid, Entra joined, domain only, registered, none' {
        InModuleScope DoctorDO.Collector {
            $mk = { param($aad, $dom, $wpj) @("             AzureAdJoined : $aad", "              DomainJoined : $dom", "                  DeviceId : 3f2c1a9e-5b7d-4c2e-9a41-0d6e8f7b1c20", "                  TenantId : 9B1E4D77-2C0A-4E55-8F1A-6A3C5D2E7B10", "           WorkplaceJoined : $wpj") }
            (ConvertFrom-DDDsregStatus -Lines (& $mk 'YES' 'YES' 'NO')).JoinType | Should -Be 'hybrid'
            (ConvertFrom-DDDsregStatus -Lines (& $mk 'YES' 'NO' 'NO')).JoinType | Should -Be 'entra'
            (ConvertFrom-DDDsregStatus -Lines (& $mk 'NO' 'YES' 'NO')).JoinType | Should -Be 'domain'
            (ConvertFrom-DDDsregStatus -Lines (& $mk 'NO' 'NO' 'YES')).JoinType | Should -Be 'registered'
            (ConvertFrom-DDDsregStatus -Lines (& $mk 'NO' 'NO' 'NO')).JoinType | Should -Be 'none'
            (ConvertFrom-DDDsregStatus -Lines (& $mk 'YES' 'NO' 'NO')).TenantId | Should -Be '9b1e4d77-2c0a-4e55-8f1a-6a3c5d2e7b10'
            (ConvertFrom-DDDsregStatus -Lines @('garbage', 'nothing')).Parsed | Should -BeFalse
        }
    }

    It 'proxy scope: device-wide, per-user only, netsh only, none (docs/17 section 4.3)' {
        InModuleScope DoctorDO.Collector {
            $set = { param($pairs) @{ Present = $true; Values = @($pairs.GetEnumerator() | ForEach-Object { [ordered]@{ name = $_.Key; type = 'REG_SZ'; data = $_.Value } }) } }
            $direct = @('Current WinHTTP proxy settings:', '', '    Direct access (no proxy server).')
            $via = @('Current WinHTTP proxy settings:', '', '    Proxy Server(s) :  proxy.corp:8080', '    Bypass List     :  <local>')
            $none = ConvertFrom-DDProxyState -Internet ([pscustomobject]@{ User = (& $set @{}); Machine = (& $set @{}); ProxySettingsPerUser = $null; DefaultConnectionSettings = $null }) -Netsh $direct
            $none.configured | Should -BeFalse; $none.wininetScope | Should -Be 'none'
            $perUser = ConvertFrom-DDProxyState -Internet ([pscustomobject]@{ User = (& $set @{ ProxyEnable = '1'; ProxyServer = 'p:80' }); Machine = (& $set @{}); ProxySettingsPerUser = $null; DefaultConnectionSettings = $null }) -Netsh $direct
            $perUser.wininetScope | Should -Be 'per-user'; $perUser.configured | Should -BeTrue
            $dev = ConvertFrom-DDProxyState -Internet ([pscustomobject]@{ User = (& $set @{}); Machine = (& $set @{ ProxyEnable = '1'; ProxyServer = 'p:80'; AutoConfigURL = 'http://wpad.corp/proxy.pac' }); ProxySettingsPerUser = 0; DefaultConnectionSettings = $null }) -Netsh $direct
            $dev.wininetScope | Should -Be 'device-wide'; $dev.pacUrlHost | Should -Be 'wpad.corp'
            $ns = ConvertFrom-DDProxyState -Internet ([pscustomobject]@{ User = (& $set @{}); Machine = (& $set @{}); ProxySettingsPerUser = $null; DefaultConnectionSettings = $null }) -Netsh $via
            $ns.netshConfigured | Should -BeTrue; $ns.wininetScope | Should -Be 'none'; $ns.configured | Should -BeTrue
            $sys = ConvertFrom-DDProxyState -Internet ([pscustomobject]@{ User = (& $set @{ ProxyEnable = '1'; ProxyServer = 'p:80' }); Machine = (& $set @{}); ProxySettingsPerUser = $null; DefaultConnectionSettings = $null }) -Netsh $direct -IsSystem
            $sys.wininetScope | Should -Be 'none' -Because 'HKCU under SYSTEM is not a user setting'
        }
    }

    It 'PAC: reads the setup script from the connection blob only with its flag set, and keeps the scope in force (ADR-0038)' {
        InModuleScope DoctorDO.Collector {
            $blob = {
                param([int] $flags, [string] $url)
                $b = New-Object 'System.Collections.Generic.List[byte]'
                foreach ($i in 0x46, 7, $flags, 0, 0) { $b.AddRange([BitConverter]::GetBytes([int]$i)) }
                $b.AddRange([BitConverter]::GetBytes([int]$url.Length)); $b.AddRange([System.Text.Encoding]::ASCII.GetBytes($url)); $b.AddRange((New-Object byte[] 32))
                ($b | ForEach-Object { $_.ToString('x2') }) -join ''
            }
            $c = ConvertFrom-DDConnectionSettings -Hex (& $blob 5 'http://pac.contoso.example/proxy.pac')
            $c.Flags | Should -Be 5; $c.AutoConfigUrl | Should -Be 'http://pac.contoso.example/proxy.pac'
            ConvertFrom-DDConnectionSettings -Hex 'zz' | Should -BeNullOrEmpty
            ConvertFrom-DDConnectionSettings -Hex '46000000ff' | Should -BeNullOrEmpty

            $e = { param($scope, $url, $conn) [pscustomobject]@{ Scope = $scope; AutoConfigUrl = $url; Connections = $conn } }
            $perUser = [pscustomobject]@{ PerMachine = $false; Entries = @((& $e 'device' 'http://device.example/d.pac' $null), (& $e 'user' $null (& $blob 5 'http://pac.contoso.example/a.pac')), (& $e 'user' $null (& $blob 1 'http://pac.contoso.example/unticked.pac')), (& $e 'service' ' http://pac.contoso.example/s.pac ' $null)) }
            $s = @(Get-DDPacSources -Raw $perUser)
            ($s | ForEach-Object { "$($_.Scope)=$($_.Url)" }) | Should -Be @('user=http://pac.contoso.example/a.pac', 'service=http://pac.contoso.example/s.pac') -Because 'the device store is not in force without the per-machine policy, and an unticked setup script does not count'
            $perMachine = [pscustomobject]@{ PerMachine = $true; Entries = $perUser.Entries }
            (@(Get-DDPacSources -Raw $perMachine) | ForEach-Object { $_.Scope }) | Should -Be @('device')
            @(Get-DDPacSources -Raw $null).Count | Should -Be 0
        }
    }

    It 'PAC: finds DO endpoints by whole DNS name, including parent domains down to three labels, never microsoft.com' {
        InModuleScope DoctorDO.Collector {
            @(Get-DDPacDomainNames -Pattern '*.do.dsp.mp.microsoft.com') | Should -Be @('do.dsp.mp.microsoft.com', 'dsp.mp.microsoft.com', 'mp.microsoft.com')
            @(Get-DDPacDomainNames -Pattern 'array*.prod.do.dsp.mp.microsoft.com')[0] | Should -Be 'prod.do.dsp.mp.microsoft.com'
            @(Get-DDPacDomainNames -Pattern '*.windowsupdate.com') | Should -Be @('windowsupdate.com')
            $m = Get-DDEndpointManifest
            Get-DDPacDoReferences -Text 'if (dnsDomainIs(host, ".do.dsp.mp.microsoft.com")) return "DIRECT";' -Manifest $m | Should -Be @('do-cloud')
            Get-DDPacDoReferences -Text 'shExpMatch(host, "*.mp.microsoft.com") || shExpMatch(host, "*.windowsupdate.com")' -Manifest $m | Should -Be @('do-cloud', 'do-content', 'wu-content')
            Get-DDPacDoReferences -Text 'shExpMatch(host, "array*.prod.do.dsp.mp.microsoft.com") || host == "foo.mp.microsoft.com"' -Manifest $m | Should -Be @('do-cloud')
            @(Get-DDPacDoReferences -Text 'dnsDomainIs(host, ".microsoft.com") || dnsDomainIs(host, "xmp.microsoft.com") || dnsDomainIs(host, "notwindowsupdate.com")' -Manifest $m).Count | Should -Be 0
            @(Get-DDPacDoReferences -Text $null -Manifest $m).Count | Should -Be 0
        }
    }

    It 'PAC check: not applicable without a PAC; warns on more than one version; fails only when DO is failing and the PAC proxies the DO cloud' {
        InModuleScope DoctorDO.Collector {
            $item = { param($id, $scopes, $refs, $cloud, $fetch = 'ok') [ordered]@{ id = $id; basis = 'content'; scopes = $scopes; userProfiles = 0; fetch = $fetch; doReferences = $refs; routes = [ordered]@{ doCloud = $cloud; doContent = $cloud } } }
            $net = { param($pac) [ordered]@{ proxy = [ordered]@{ configured = $true; pac = $pac } } }
            $failing = @([ordered]@{ checkId = 'do-cloud-tls'; result = 'fail' })

            (Get-DDPacCheck -Network ([ordered]@{ proxy = [ordered]@{ configured = $false } })).result | Should -Be 'not-collected'
            (Get-DDPacCheck -Network (& $net ([ordered]@{ configured = $false; versions = 0; referencesDo = $null; userProfiles = 1; items = @() }))).result | Should -Be 'not-applicable'

            $one = & $net ([ordered]@{ configured = $true; versions = 1; referencesDo = $true; userProfiles = 0; items = @((& $item 'pac:1' @('device') @('do-cloud', 'do-content') 'direct')) })
            $c = Get-DDPacCheck -Network $one
            $c.result | Should -Be 'pass'
            $c.detail | Should -Match 'device-wide.*names DO endpoints \(do-cloud, do-content\); 1 version \(DO-NET-025\)'
            (Get-DDPacCheck -Network $one -Checks $failing).detail | Should -Match 'names or proxies DO endpoints that are failing.*check the PAC'

            $two = & $net ([ordered]@{ configured = $true; versions = 2; referencesDo = $true; userProfiles = 2; items = @((& $item 'pac:1' @('user') @('do-cloud') 'direct'), (& $item 'pac:2' @('user') @() 'direct')) })
            $w = Get-DDPacCheck -Network $two
            $w.result | Should -Be 'warn'; $w.detail | Should -Match '2 versions: different PACs apply'

            $proxied = & $net ([ordered]@{ configured = $true; versions = 1; referencesDo = $false; userProfiles = 0; items = @((& $item 'pac:3' @('device') @() 'proxy')) })
            (Get-DDPacCheck -Network $proxied).result | Should -Be 'warn'
            $f = Get-DDPacCheck -Network $proxied -Checks $failing
            $f.result | Should -Be 'fail'; $f.detail | Should -Match 'DO cloud service .* through a proxy.*check the PAC'
            $f.evidence | Should -Be 'versions=1 scopes=device names=none doCloud=proxy doContent=proxy'

            $file = & $net ([ordered]@{ configured = $true; versions = 1; referencesDo = $null; userProfiles = 1; items = @((& $item 'pac:4' @('user') @() $null 'unsupported')) })
            $x = Get-DDPacCheck -Network $file
            $x.result | Should -Be 'warn'; $x.detail | Should -Match 'could not be read.*file:// PAC'

            $big = & $net ([ordered]@{ configured = $true; versions = 1; referencesDo = $true; userProfiles = 0; items = @((& $item 'pac:5' @('device') @('do-cloud') 'direct' 'too-large')) })
            (Get-DDPacCheck -Network $big).detail | Should -Match 'larger than 1 MB, which WinHTTP rejects'
            $skip = & $net ([ordered]@{ configured = $true; versions = 1; referencesDo = $null; userProfiles = 0; items = @((& $item 'pac:6' @('device') @() $null 'skipped')) })
            $k = Get-DDPacCheck -Network $skip
            $k.result | Should -Be 'pass'; $k.detail | Should -Match 'not downloaded \(connectivity checks skipped\)'
        }
    }

    It 'maps firewall rules and expands profile lists' {
        InModuleScope DoctorDO.Collector {
            $r = ConvertFrom-DDFirewallRaw -Rules @([pscustomobject]@{ DisplayName = 'x'; Direction = 'Inbound'; Action = 'Block'; Enabled = 'False'; Profile = 'Domain, Public'; Protocol = 'TCP'; LocalPort = 'Any'; Program = $null; Service = $null })
            $r[0].action | Should -Be 'Block'; $r[0].enabled | Should -BeFalse; $r[0].profiles | Should -Be @('Domain', 'Public')
        }
    }

    It 'maps Delivery Optimization status, peers, perf, errors, connections tolerantly' {
        InModuleScope DoctorDO.Collector {
            $ctx = New-DDContext -Salt 'aa' -TenantSalt 'bb' -Anonymise
            $row = ConvertTo-DDStatusRow -Context $ctx -Item ([pscustomobject]@{ FileId = 'f1'; FileSize = 100; TotalBytesDownloaded = 100; BytesFromHttp = 60; BytesFromLanPeers = 40; DownloadMode = 'Lan'; Status = 'Caching'; Priority = 'Foreground'; SourceURL = 'http://a.example/x/y/z?q=1'; PredefinedCallerApplication = 'Edge' })
            $row.downloadMode | Should -Be 1; $row.priority | Should -Be 'Foreground'; $row.bytesFromLanPeers | Should -Be '40'; $row.sourceUrlPathHint | Should -Be '/x/y'
            $row.sourceUrlHost | Should -Match '^host:[0-9a-f]{16}$' -Because 'a non-Microsoft source host is pseudonymised under -Anonymise'
            (ConvertTo-DDStatusRow -Context $ctx -Item ([pscustomobject]@{ FileId = 'f2'; SourceURL = 'http://1D.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/x'; CacheHost = [uri]'198.51.100.203' })).sourceUrlHost | Should -Be '1d.tlu.dl.delivery.mp.microsoft.com'
            (ConvertTo-DDStatusRow -Context $ctx -Item ([pscustomobject]@{ FileId = 'f2'; CacheHost = [uri]'198.51.100.203' })).cacheHost | Should -Be '198.51.100.203' -Because 'the cache server is infrastructure and stays in clear (ADR-0031)'
            $peers = ConvertTo-DDPeerRows -Context $ctx -LocalAddress '10.0.0.5' -PrefixLength 24 -Items @([pscustomobject]@{ FileId = 'f1'; IP = '10.0.0.9'; PeerType = 'LAN'; BytesSent = 5; BytesReceived = 6 }, [pscustomobject]@{ FileId = 'f1'; IP = '10.9.0.9'; PeerType = 'Internet'; BytesSent = 1; BytesReceived = 2 })
            $peers[0].sameSubnet | Should -BeTrue; $peers[1].sameSubnet | Should -BeFalse
            $peers[0].peerHash | Should -Match '^sha256:[0-9a-f]{64}$'
            (ConvertTo-DDPerfSnap -Item $null) | Should -BeNullOrEmpty
            $errs = ConvertTo-DDErrorRows -Context $ctx -Entries @([pscustomobject]@{ TimeCreated = [datetime]::UtcNow; Function = 'F'; Message = 'bad 0x80d0000a here' }, [pscustomobject]@{ TimeCreated = [datetime]::UtcNow; Function = 'F'; Message = 'fine' })
            $errs.Count | Should -Be 1; $errs[0].hresult | Should -Be '0x80D0000A'
            $old = ConvertTo-DDErrorRows -Context $ctx -Since ([datetime]::UtcNow.AddHours(1)) -Entries @([pscustomobject]@{ TimeCreated = [datetime]::UtcNow; Function = 'F'; Message = 'bad 0x80d0000a' })
            @($old).Count | Should -Be 0
            $conns = ConvertTo-DDConnectionRows -Context $ctx -Items @([pscustomobject]@{ Nonsense = 1 })
            @($conns).Count | Should -Be 0
            ($ctx.NotCollected | Where-Object field -eq 'connections').reason | Should -Be 'error'
        }
    }

    It 'reads an HRESULT in each shape the DO log writes it, normalised, and keeps those lines in the excerpt (A-07)' {
        InModuleScope DoctorDO.Collector {
            $ctx = New-DDContext -Salt 'aa' -TenantSalt 'bb'
            $now = [datetime]::UtcNow
            $lines = @(
                'FailurePeerConnect, hr: 8007274c, msg: Socket connect error, peerIp: [10.100.0.74]:7680, peerId: , peerType: 1'
                'Download job failed, errorCode = 0x80D02002, fileId = abc'
                'Download job failed, errorCode = 80d05011'
                'HRESULT=0x80070005 opening the cache'
                'all fine, hr: 00000000'
                'build 22631.4317 took 80000000 ms'
            )
            $errs = ConvertTo-DDErrorRows -Context $ctx -Entries @($lines | ForEach-Object { [pscustomobject]@{ TimeCreated = $now; Function = 'F'; Message = $_ } })
            @($errs | ForEach-Object { $_['hresult'] }) | Should -Be @('0x8007274C', '0x80D02002', '0x80D05011', '0x80070005')
            $p = Get-DDRedactionProfile
            Test-DDRetainedLogLine -Line $lines[0] -RedactionProfile $p | Should -BeTrue -Because 'the peer-connect failure has no 0x'
            Test-DDRetainedLogLine -Line $lines[2] -RedactionProfile $p | Should -BeTrue
            Test-DDRetainedLogLine -Line $lines[5] -RedactionProfile $p | Should -BeFalse
        }
    }

    It 'Get-DOConfig output: documented property names map to CSP names, providers come from the documented verbose text' {
        InModuleScope DoctorDO.Collector {
            $cfg = [pscustomobject]@{ DownloadMode = 'Simple'; MinTotalRAM = 4; MinTotalDiskSize = 32; BatteryPctToSeed = 60; VpnPeerCachingAllowed = $true; DownBackLimitBps = 5000; DownBackLimitPct = 45
                WorkingDirectory = 'C:\DOCache'; VpnKeywords = 'vpn,tunnel'; SomethingNew = 'x'; MaxUploadRatePct = 20; UploadLimitMonthlyGB = 500 }
            $verbose = @('DownloadMode:Simple DownloadModeProvider:Mdm Provider', 'MinTotalRAM:4 MinTotalRAMProvider:Default Provider', 'BatteryPctToSeed:60 BatteryPctToSeedProvider:GroupPolicy Provider')
            $r = ConvertFrom-DDDoConfig -Config $cfg -VerboseLines $verbose
            $e = $r.Effective
            $e['DODownloadMode'].value | Should -Be 99 -Because 'Simple is mode 99'
            $e['DODownloadMode'].provider | Should -Be 'Mdm'
            $e['DOMinRAMAllowedToPeer'].value | Should -Be 4; $e['DOMinRAMAllowedToPeer'].provider | Should -Be 'Default'
            $e['DOMinBatteryPercentageAllowedToUpload'].provider | Should -Be 'GroupPolicy'
            $e['DOMinDiskSizeAllowedToPeer'].provider | Should -Be 'Unknown' -Because 'no provider stated, none guessed'
            $e['DOAllowVPNPeerCaching'].value | Should -Be 1
            $e['DOPercentageMaxBackgroundBandwidth'].value | Should -Be 45
            $e['DOMaxUploadBandwidth'].value | Should -Be 20
            $e['DOMonthlyUploadDataCap'].value | Should -Be 500
            $e.Contains('DownBackLimitBps') | Should -BeTrue -Because 'the Bps limits keep their own name: the unit is not stated, so they are not folded into the KB/s policy'
            $e.Contains('DOMaxBackgroundDownloadBandwidth') | Should -BeFalse
            $e['DOSomethingNew'].provider | Should -Be 'Unknown'
            $e.Contains('DOWorkingDirectory') | Should -BeFalse
            $r.WorkingDirectory | Should -Be 'C:\DOCache'
            $r.VpnKeywords | Should -Be 'vpn,tunnel'
        }
    }

    It 'Get-DOConfig verbose-only fallback still yields values and providers' {
        InModuleScope DoctorDO.Collector {
            $r = ConvertFrom-DDDoConfig -Config $null -VerboseLines @('DownloadMode:Lan DownloadModeProvider:Mdm Provider')
            $r.Effective['DODownloadMode'].value | Should -Be 1
            $r.Effective['DODownloadMode'].provider | Should -Be 'Mdm'
        }
    }

    It 'status rows take cache-server bytes out of BytesFromHTTP so the five sources are disjoint' {
        InModuleScope DoctorDO.Collector {
            $ctx = New-DDContext -Salt 'aa'
            $row = ConvertTo-DDStatusRow -Context $ctx -Item ([pscustomobject]@{ FileId = 'f'; BytesFromHttp = 100; BytesFromCacheServer = 30 })
            $row.bytesFromHttp | Should -Be '70'; $row.bytesFromCacheServer | Should -Be '30'
            (ConvertTo-DDStatusRow -Context $ctx -Item ([pscustomobject]@{ FileId = 'f'; BytesFromHttp = 10; BytesFromCacheServer = 30 })).bytesFromHttp | Should -Be '0' -Because 'never negative, and the cache bytes are not counted twice (A-18)'
        }
    }

    It 'reads the make and model from the documented DevDetail class, MDM_DevDetail, not MDM_DevDetail_Ext01 (A-12)' {
        InModuleScope DoctorDO.Collector {
            Mock Get-DDCim { @([pscustomobject]@{ InstanceID = 'DevDetail'; OEM = 'Contoso'; DevTyp = 'Laptop 14' }) } -ParameterFilter { $ClassName -eq 'MDM_DevDetail' }
            Mock Get-DDCim { @() }
            (Get-DDDevDetail).DevTyp | Should -Be 'Laptop 14'
            Should -Invoke Get-DDCim -Times 1 -Exactly -ParameterFilter { $ClassName -eq 'MDM_DevDetail' -and $Namespace -eq 'root/cimv2/mdm/dmmap' }
        }
    }

    It 'numeric and date edge cases: a digit-string duration, a counter above 2^63 - 1, an unknown mode name, the install date (A-18)' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDDownloadMs '172' | Should -Be 172000 -Because 'a plain number is seconds, as documented, not 172 days'
            ConvertTo-DDDownloadMs '1.5' | Should -Be 1500
            ConvertTo-DDDownloadMs '00:02:52' | Should -Be 172000
            ConvertTo-DDDownloadMs ([timespan]::FromSeconds(3)) | Should -Be 3000
            ConvertTo-DDDownloadMs 'soon' | Should -BeNullOrEmpty
            (ConvertTo-DDBigInt ([uint64]::MaxValue)).ToString() | Should -Be '18446744073709551615'
            (ConvertTo-DDBigInt ([double]::NaN)).ToString() | Should -Be '0'
            $ctx = New-DDContext -Salt 'aa'
            $row = ConvertTo-DDStatusRow -Context $ctx -Item ([pscustomobject]@{ FileId = 'f'; FileSize = [uint64]::MaxValue; TotalBytesDownloaded = [uint64]9223372036854775808; BytesFromHttp = [uint64]::MaxValue; DownloadMode = 'Turbo' })
            $row.fileSize | Should -Be '18446744073709551615'
            $row.totalBytesDownloaded | Should -Be '9223372036854775808'
            $row.downloadMode | Should -Be -1
            ($ctx.NotCollected | Where-Object { $_['field'] -eq 'status.downloadMode' }).detail | Should -Match "'Turbo' is not a known mode"
            (ConvertTo-DDStatusRow -Context $ctx -Item ([pscustomobject]@{ FileId = 'g'; DownloadMode = 'Group' })).downloadMode | Should -Be 2
            (ConvertTo-DDStatusRow -Context (New-DDContext -Salt 'aa') -Item ([pscustomobject]@{ FileId = 'h' })).downloadMode | Should -Be -1
            Mock Get-DDRegistryValue { if ($Name -eq 'CurrentBuild') { '26100' } elseif ($Name -eq 'InstallDate') { 1698710399 } else { $null } }
            (Get-DDOsFacts -Context (New-DDContext -Salt 'aa')).Os['installDate'] | Should -Be '2023-10-30' -Because 'one second before midnight UTC is still the 30th, whatever the local zone'
            Mock Get-DDRegistryValue { if ($Name -eq 'CurrentBuild') { '26100' } elseif ($Name -eq 'InstallDate') { 1698710400 } else { $null } }
            (Get-DDOsFacts -Context (New-DDContext -Salt 'aa')).Os['installDate'] | Should -Be '2023-10-31'
        }
    }

    It 'perf snapshot: the documented readings, and the byte counters of the jobs in the cache, uploads by peer type included (A-02, A-03)' {
        InModuleScope DoctorDO.Collector {
            $snap = [pscustomobject]@{ NumberOfPeers = 7; CacheHostConnections = 2; DownlinkUsageBps = 2048000 }
            $rows = @([ordered]@{ priority = 'Foreground'; totalBytesDownloaded = '50'; bytesFromHttp = '10'; bytesFromLanPeers = '40'; bytesFromGroupPeers = '0'; bytesFromInternetPeers = '0'; bytesFromCacheServer = '0'; bytesToLanPeers = '9'; bytesToGroupPeers = '3'; bytesToInternetPeers = '1' },
                [ordered]@{ priority = 'Background'; totalBytesDownloaded = '70'; bytesFromHttp = '70'; bytesFromLanPeers = '0'; bytesFromGroupPeers = '0'; bytesFromInternetPeers = '0'; bytesFromCacheServer = '0' })
            $d = ConvertTo-DDPerfSnap -Item $snap -StatusRows $rows
            $d.downloadHttpBytes | Should -Be '80'; $d.downloadLanBytes | Should -Be '40'; $d.foregroundDownloadBytes | Should -Be '50'; $d.backgroundDownloadBytes | Should -Be '70'
            $d.uploadLanBytes | Should -Be '9'; $d.uploadGroupBytes | Should -Be '3'; $d.uploadInternetBytes | Should -Be '1'
            $d.numberOfPeers | Should -Be 7; $d.cacheHostConnections | Should -Be 2; $d.averageDownloadKBps | Should -Be 2000
        }
    }

    It 'month totals: the service''s own counters for the calendar month, as Get-DeliveryOptimizationPerfSnapThisMonth returns them (19 Oct 2026)' {
        InModuleScope DoctorDO.Collector {
            # The reading the product owner compared with Get-AutopilotDiagnostics, Windows 11 26H2.
            $snap = [pscustomobject]@{ UploadLanBytes = 0; UploadInternetBytes = 0; DownloadHttpBytes = 18440031483; DownloadCacheHostBytes = 2628549676; DownloadLanBytes = 0
                DownloadInternetBytes = 0; DownloadFgRateKbps = 62115; DownloadBgRateKbps = 27588; UploadLimitReached = $false; MonthStartDate = [datetime]::new(2026, 10, 1) }
            $m = ConvertTo-DDMonthTotals -Item $snap
            $m.monthStart | Should -Be '2026-10-01'
            $m.httpBytes | Should -Be '18440031483'; $m.cacheBytes | Should -Be '2628549676'; $m.lanBytes | Should -Be '0'; $m.internetBytes | Should -Be '0'
            $m.groupBytes | Should -BeNullOrEmpty -Because 'that build has no group counter: not reported, never 0'
            $m.uploadLanBytes | Should -Be '0'; $m.uploadInternetBytes | Should -Be '0'
            @($m.Keys) -join ',' | Should -Be 'monthStart,httpBytes,cacheBytes,lanBytes,internetBytes,groupBytes,uploadLanBytes,uploadInternetBytes'
            # A build that has the group counter, an unsigned counter above 2^63 - 1, a negative value and no start date.
            $m = ConvertTo-DDMonthTotals -Item ([pscustomobject]@{ DownloadHttpBytes = [uint64]::MaxValue; DownloadGroupBytes = 5; DownloadLanBytes = -3 })
            $m.httpBytes | Should -Be '18446744073709551615'; $m.groupBytes | Should -Be '5'; $m.lanBytes | Should -Be '0'; $m.monthStart | Should -BeNullOrEmpty
            # No snapshot, or a shape without DownloadHttpBytes: nothing, so the caller records doMonth as not collected.
            ConvertTo-DDMonthTotals -Item $null | Should -BeNullOrEmpty
            ConvertTo-DDMonthTotals -Item ([pscustomobject]@{ NumberOfPeers = 3 }) | Should -BeNullOrEmpty
        }
    }

    It 'month totals travel in telemetry as read, not in a baseline, and are absent when not read' {
        InModuleScope DoctorDO.Collector {
            $raw = [ordered]@{ collector = [ordered]@{ name = 'DoctorDO.Collector'; version = '0.6.0' }; collectedAt = '2026-10-19T09:00:00Z'; anonymised = $false
                device = [ordered]@{ onBattery = $false; batteryPercent = $null; systemDiskFreeGB = 100; cacheUsedBytes = '0' }
                network = [ordered]@{ isVpnActive = $false; adapterType = 'Ethernet'; localSubnet = $null; publicEgressHash = $null }
                status = @(); peerInfo = @(); connections = @(); perfSnap = $null; connectivity = @(); errors = @(); notCollected = @()
                doMonth = [ordered]@{ monthStart = '2026-10-01'; httpBytes = '18440031483'; cacheBytes = '2628549676'; lanBytes = '0'; internetBytes = '0'; groupBytes = $null; uploadLanBytes = '0'; uploadInternetBytes = '9007199254740993' } }
            $args2 = @{ Raw = $raw; Seq = 1; InventoryHash = ('sha256:' + ('a' * 64)); PeriodFrom = '2026-10-19T08:00:00Z'; PeriodTo = '2026-10-19T09:00:00Z' }
            $b = ConvertTo-DDTelemetry @args2 -PreviousCounters $null
            $b['counters'] | Should -Be 'baseline'
            $b.Contains('month') | Should -BeFalse -Because 'a baseline sends no byte counters'
            $t = ConvertTo-DDTelemetry @args2
            $t['counters'] | Should -Be 'snapshot'
            $t['month']['httpBytes'] | Should -Be 18440031483; $t['month']['cacheBytes'] | Should -Be 2628549676
            $t['month']['uploadInternetBytes'] | Should -Be '9007199254740993' -Because 'above 2^53 a counter travels as a decimal string'
            $t['month']['groupBytes'] | Should -BeNullOrEmpty; $t['month']['monthStart'] | Should -Be '2026-10-01'
            $raw.Remove('doMonth')
            (ConvertTo-DDTelemetry @args2).Contains('month') | Should -BeFalse
        }
    }

    It 'a status row carries what the job uploaded to LAN, Group and Internet peers' {
        InModuleScope DoctorDO.Collector {
            $row = ConvertTo-DDStatusRow -Context (New-DDContext -Salt 'aa') -Item ([pscustomobject]@{ FileId = 'f'; BytesToLanPeers = 12; BytesToGroupPeers = 4; BytesToInternetPeers = 0 })
            $row.bytesToLanPeers | Should -Be '12'; $row.bytesToGroupPeers | Should -Be '4'; $row.bytesToInternetPeers | Should -Be '0'
            (ConvertTo-DDStatusRow -Context (New-DDContext -Salt 'aa') -Item ([pscustomobject]@{ FileId = 'f' })).bytesToGroupPeers | Should -Be '0'
        }
    }

    It 'teredo state text' {
        InModuleScope DoctorDO.Collector {
            # netsh interface teredo show state on Windows 11 (read on a lab device, 19 Oct 2026).
            $t = ConvertFrom-DDTeredoState -Lines @('Teredo Parameters', '---------------------------------------------', 'Type                    : disabled', 'Server Name             : win1910.ipv6.microsoft.com.', 'Client Refresh Interval : 30 seconds', 'Client Port             : unspecified', 'State                   : offline', 'Error                   : none')
            $t.Type | Should -Be 'disabled'
            $t.State | Should -Be 'offline'
            $t.Error | Should -BeNullOrEmpty -Because '"none" is no error'
            $t.ServerName | Should -Be 'win1910.ipv6.microsoft.com'
            $t.Source | Should -Be 'netsh'
            (ConvertFrom-DDTeredoState -Lines @('Type : client', 'State : probe(primary server)', 'Error : none')).State | Should -Be 'probe'
            (ConvertFrom-DDTeredoState -Lines @('Type : client')).State | Should -BeNullOrEmpty -Because 'a text without a State line does not say whether Teredo is active'
            ConvertFrom-DDTeredoState -Lines @('nothing') | Should -BeNullOrEmpty
        }
    }

    It 'teredo state from the classes behind Get-NetTeredoState (language independent)' {
        InModuleScope DoctorDO.Collector {
            $q = ConvertFrom-DDTeredoRaw -Raw ([pscustomobject]@{ Type = [uint32]2; ServerName = 'win1910.ipv6.microsoft.com.'; StatePresent = $true; State = 'Qualified'; Error = 'none' })
            $q.Type | Should -Be 'client'; $q.State | Should -Be 'qualified'; $q.Error | Should -BeNullOrEmpty; $q.Source | Should -Be 'cim'
            # Microsoft: "If Teredo is not active, then this cmdlet does not return an object."
            (ConvertFrom-DDTeredoRaw -Raw ([pscustomobject]@{ Type = [uint32]0; ServerName = $null; StatePresent = $false; State = $null; Error = $null })).State | Should -Be 'inactive'
            (ConvertFrom-DDTeredoRaw -Raw ([pscustomobject]@{ Type = [uint32]4; ServerName = $null; StatePresent = $false; State = $null; Error = $null })).Type | Should -Be 'disabled'
            (ConvertFrom-DDTeredoRaw -Raw ([pscustomobject]@{ Type = [uint32]6; ServerName = $null; StatePresent = $true; State = 'offline'; Error = 'client is in a managed network' })).Error | Should -Be 'client is in a managed network'
            ConvertFrom-DDTeredoRaw -Raw $null | Should -BeNullOrEmpty
        }
    }
}

Describe 'Retry-After' {
    It 'accepts seconds and HTTP dates, and caps at 24 hours' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDRetryAfterSeconds -Value '120' | Should -Be 120
            ConvertTo-DDRetryAfterSeconds -Value '999999' | Should -Be 86400
            ConvertTo-DDRetryAfterSeconds -Value 'Mon, 12 Oct 2026 08:10:00 GMT' -Now ([datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)) | Should -Be 600
            ConvertTo-DDRetryAfterSeconds -Value $null | Should -BeNullOrEmpty
            ConvertTo-DDRetryAfterSeconds -Value 'soon' | Should -BeNullOrEmpty
        }
    }
}
