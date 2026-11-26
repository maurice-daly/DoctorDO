#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# The remediation's module install (ADR-0041): CMTrace log, the checks run before every import, the two update policies,
# install failure, rollback. Install-Module, Find-Module, Install-PackageProvider, Get-PackageProvider, Get-Module,
# Import-Module, Get-AuthenticodeSignature, Invoke-WebRequest and the permission reader are mocked; the files are real
# (a fake module in the test drive), so hashing, listing and removal are exercised for real.
BeforeAll {
    $script:Intune = (Resolve-Path (Join-Path $PSScriptRoot '../intune')).Path
    $script:Tools = (Resolve-Path (Join-Path $PSScriptRoot '../tools')).Path
    $script:RealModule = (Resolve-Path (Join-Path $PSScriptRoot '../DoctorDO.Collector')).Path
    . (Join-Path $script:Intune 'Detect-DoctorDO.ps1')
    . (Join-Path $script:Intune 'Remediate-DoctorDO.ps1')
    . (Join-Path $script:Tools 'package-collector.ps1')
    $script:StubbedSignature = $false
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        function global:Get-AuthenticodeSignature { param([string] $FilePath) throw 'Get-AuthenticodeSignature is not available here' }
        $script:StubbedSignature = $true
    }
    $script:LineRegex = '^<!\[LOG\[(?<msg>.*)\]LOG\]!><time="(?<time>\d\d:\d\d:\d\d\.\d{3})(?<bias>[+-]\d{3})" date="(?<date>\d\d-\d\d-\d{4})" component="(?<comp>[^"]*)" context="" type="(?<type>[123])" thread="(?<thread>\d+)" file="(?<file>[^"]*)">$'
    $script:FakeGuid = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa'

    function New-FakeRelease {
        # A release "on the repository": <Source>\<Version>\ with a manifest, a root module and one script.
        param([string] $Source, [string] $Version, [string] $Guid = $script:FakeGuid, [string] $Author = 'Maurice Daly', [string[]] $Functions = @('Get-Thing'), [string] $OmitFromFileList = '')
        $dir = Join-Path $Source $Version
        [void](New-Item -ItemType Directory -Path (Join-Path $dir 'Public') -Force)
        [System.IO.File]::WriteAllText((Join-Path $dir 'DoctorDO.Collector.psm1'), "Set-StrictMode -Version Latest`nfunction Get-Thing { 'thing $Version' }`n")
        [System.IO.File]::WriteAllText((Join-Path $dir 'Public/Get-Thing.ps1'), "function Get-Thing { 'thing' }`n")
        $fnList = ($Functions | ForEach-Object { "'$_'" }) -join ', '
        $listed = (@('DoctorDO.Collector.psd1', 'DoctorDO.Collector.psm1', 'Public/Get-Thing.ps1') | Where-Object { $_ -ne $OmitFromFileList } | ForEach-Object { "'$_'" }) -join ', '
        $psd1 = "@{`n RootModule = 'DoctorDO.Collector.psm1'`n ModuleVersion = '$Version'`n GUID = '$Guid'`n Author = '$Author'`n FunctionsToExport = @($fnList)`n" +
        " FileList = @($listed)`n}`n"
        [System.IO.File]::WriteAllText((Join-Path $dir 'DoctorDO.Collector.psd1'), $psd1)
        $dir
    }
    function Get-FakeSpec {
        param([string] $Dir, [string] $Version, [string] $Guid = $script:FakeGuid, [string] $Author = 'Maurice Daly', [string[]] $Functions = @('Get-Thing'))
        $files = [ordered]@{}
        foreach ($r in (Get-CollectorFileHashes -ModulePath $Dir)) { $files[$r.path] = $r.sha256 }
        New-DoctorDOSpec -ModuleName 'DoctorDO.Collector' -Version $Version -Guid $Guid -Author $Author -Functions $Functions -Files $files -Source 'test'
    }
    function Get-FakeManifestJson {
        param($Spec)
        $facts = [pscustomobject]@{ Name = 'DoctorDO.Collector'; Version = $Spec.Version; Guid = $Spec.Guid; Author = $Spec.Author; Functions = $Spec.Functions
            Files = @($Spec.Files.Keys | Sort-Object | ForEach-Object { [pscustomobject]@{ path = $_; sha256 = $Spec.Files[$_] } }) }
        ConvertTo-CollectorManifestJson -Facts $facts
    }
    function Install-Fake {
        # Puts a copy of a release in the AllUsers folder, as Install-Module (or the old Win32 app) would.
        param([string] $Version, [switch] $WithInfoFile)
        $dest = Join-Path (Join-Path $global:RT.Root 'DoctorDO.Collector') $Version
        [void](New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force)
        Copy-Item -LiteralPath (Join-Path $global:RT.Source $Version) -Destination $dest -Recurse
        if ($WithInfoFile) { [System.IO.File]::WriteAllText((Join-Path $dest 'PSGetModuleInfo.xml'), '<Objs />') }
        $dest
    }
    function Get-LogEntries {
        param([string] $Path = $global:RT.Log)
        if (-not (Test-Path -LiteralPath $Path)) { return @() }
        @([System.IO.File]::ReadAllLines($Path) | ForEach-Object { $m = [regex]::Match($_, $script:LineRegex); if (-not $m.Success) { throw "not a CMTrace line: $_" }; [pscustomobject]@{ Message = $m.Groups['msg'].Value; Type = [int]$m.Groups['type'].Value; Component = $m.Groups['comp'].Value } })
    }
    function Invoke-Init {
        param([string] $Policy = 'LatestVerified', [string] $Min = '0.5.0', [string] $Max = '', [string] $Thumbprint = '')
        Initialize-DoctorDOModule -ModuleName 'DoctorDO.Collector' -Repository 'PSGallery' -UpdatePolicy $Policy -MinimumVersion $Min -MaximumVersion $Max -ModulesPath $global:RT.Root `
            -PinnedSpec $global:RT.Pinned -ManifestUrlTemplate 'https://example.test/{owner}/{repo}/{version}/collector-manifest.json' -GitHubOwner 'o' -GitHubRepo 'r' -ExpectedSignerThumbprint $Thumbprint
    }
}

AfterAll {
    if ($script:StubbedSignature) { Remove-Item Function:\Get-AuthenticodeSignature -ErrorAction SilentlyContinue }
}

Describe 'CMTrace log' {
    It 'writes the CMTrace line format, and a regex reads every part back' {
        $t = [datetime]::new(2026, 10, 18, 14, 5, 9, 42)
        $line = Format-DoctorDOLogLine -Message 'Installing DoctorDO.Collector 0.5.0' -Level Warning -Component 'Remediate-DoctorDO' -File 'Remediate-DoctorDO.ps1' -Time $t -BiasMinutes 420
        $m = [regex]::Match($line, $script:LineRegex)
        $m.Success | Should -BeTrue -Because $line
        $m.Groups['msg'].Value | Should -Be 'Installing DoctorDO.Collector 0.5.0'
        $m.Groups['time'].Value | Should -Be '14:05:09.042'
        $m.Groups['date'].Value | Should -Be '10-18-2026'
        $m.Groups['bias'].Value | Should -Be '+420'
        $m.Groups['comp'].Value | Should -Be 'Remediate-DoctorDO'
        $m.Groups['type'].Value | Should -Be '2'
        $m.Groups['file'].Value | Should -Be 'Remediate-DoctorDO.ps1'
        $line | Should -Match '^<!\[LOG\[.*\]LOG\]!><time="\d\d:\d\d:\d\d\.\d{3}[+-]\d{3}" date="\d\d-\d\d-\d{4}" component="[^"]+" context="" type="[123]" thread="\d+" file="[^"]*">$'
    }

    It 'type is 1 for information, 2 for a warning and 3 for an error' {
        $t = [datetime]::new(2026, 1, 2, 3, 4, 5)
        foreach ($case in @(@('Info', '1'), @('Warning', '2'), @('Error', '3'))) {
            (Format-DoctorDOLogLine -Message 'x' -Level $case[0] -Component 'c' -Time $t -BiasMinutes 0) | Should -Match ('type="' + $case[1] + '"')
        }
    }

    It 'the bias is the Windows time-zone bias in minutes: UTC+1 is -060, UTC-7 is +420, UTC is +000' {
        $t = [datetime]::new(2026, 1, 2, 3, 4, 5)
        (Format-DoctorDOLogLine -Message 'x' -Component 'c' -Time $t -BiasMinutes -60) | Should -Match 'time="03:04:05\.000-060"'
        (Format-DoctorDOLogLine -Message 'x' -Component 'c' -Time $t -BiasMinutes 420) | Should -Match 'time="03:04:05\.000\+420"'
        (Format-DoctorDOLogLine -Message 'x' -Component 'c' -Time $t -BiasMinutes 0) | Should -Match 'time="03:04:05\.000\+000"'
        (Format-DoctorDOLogLine -Message 'x' -Component 'c' -Time $t -BiasMinutes -345) | Should -Match 'time="03:04:05\.000-345"'
        # Left to itself it is the machine's: UTC = local + bias.
        $local = [datetime]::Now
        $b = Get-DoctorDOLogBias -Time $local
        ($local.ToUniversalTime() - $local).TotalMinutes | Should -Be $b
    }

    It 'one printable-ASCII line: line breaks, other characters and a closing marker cannot break the format' {
        $line = Format-DoctorDOLogLine -Message ("first`r`nsecond`tthird caf" + [char]0xE9 + ' ]LOG]!> end') -Component 'c"x' -File 'a"b.ps1' -Time ([datetime]::Now)
        $line | Should -Not -Match '[\r\n]'
        $line | Should -Match $script:LineRegex
        $m = [regex]::Match($line, $script:LineRegex)
        $m.Groups['msg'].Value | Should -Be 'first second third caf? ]LOG] !> end'
        $m.Groups['comp'].Value | Should -Be 'c_x'
        @($line.ToCharArray() | Where-Object { [int]$_ -gt 126 -or [int]$_ -lt 32 }).Count | Should -Be 0
    }

    It 'never writes a credential: URL user info, sas and token query values, and an Authorization header are replaced' {
        $text = 'GET https://user:hunter2@h.example/x?sig=AbCd&token=T0k&ok=1 failed; Authorization: Basic ZZZZ; https://h.example/y?code=123'
        $line = Format-DoctorDOLogLine -Message $text -Component 'c' -Time ([datetime]::Now)
        foreach ($s in 'hunter2', 'AbCd', 'T0k', 'ZZZZ', '123') { $line | Should -Not -Match ([regex]::Escape($s)) }
        $line | Should -Match 'ok=1'
        $line | Should -Match '<hidden>'
    }

    It 'appends CRLF-terminated lines, creates the folder, and every line parses' {
        $p = Join-Path $TestDrive 'logs/a/DoctorDO-Remediation.log'
        Initialize-DoctorDOLog -Path $p -Component 'Remediate-DoctorDO' -File 'Remediate-DoctorDO.ps1'
        Write-DoctorDOLog 'one'
        Write-DoctorDOLog 'two' -Level Warning
        Write-DoctorDOLog 'three' -Level Error
        $raw = [System.IO.File]::ReadAllText($p)
        $raw | Should -Match "\r\n$"
        $e = Get-LogEntries -Path $p
        @($e).Count | Should -Be 3
        @($e | ForEach-Object { $_.Type }) | Should -Be @(1, 2, 3)
        $e[0].Component | Should -Be 'Remediate-DoctorDO'
        [System.IO.File]::ReadAllBytes($p) | Where-Object { $_ -gt 127 } | Should -BeNullOrEmpty
    }

    It 'does nothing until a path is set, and never throws when the log cannot be written' {
        Initialize-DoctorDOLog -Path '' -Component 'c' -File 'f'
        { Write-DoctorDOLog 'x' } | Should -Not -Throw
        $blocker = Join-Path $TestDrive 'a-file'
        [System.IO.File]::WriteAllText($blocker, 'x')
        Initialize-DoctorDOLog -Path (Join-Path $blocker 'sub/x.log') -Component 'c' -File 'f'
        { Write-DoctorDOLog 'x' } | Should -Not -Throw
        $script:DDLog.Failed | Should -BeTrue
    }

    It 'rotates at the limit: the log becomes .lo_ (replacing the previous one) and a new log starts' {
        $p = Join-Path $TestDrive 'rot/DoctorDO-Remediation.log'
        Initialize-DoctorDOLog -Path $p -Component 'c' -File 'f' -MaxBytes 1500
        1..30 | ForEach-Object { Write-DoctorDOLog ('line number {0:00} ' -f $_ + ('x' * 40)) }
        $old = Join-Path $TestDrive 'rot/DoctorDO-Remediation.lo_'
        Test-Path -LiteralPath $old | Should -BeTrue
        (Get-Item -LiteralPath $p).Length | Should -BeLessOrEqual 1500
        (Get-Item -LiteralPath $old).Length | Should -BeLessOrEqual 1500
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'rot')).Count | Should -Be 2 -Because 'one previous file only'
        $first = [System.IO.File]::ReadAllText($old)
        1..30 | ForEach-Object { Write-DoctorDOLog ('later {0:00} ' -f $_ + ('y' * 40)) }
        [System.IO.File]::ReadAllText($old) | Should -Not -Be $first -Because 'the previous .lo_ is replaced'
        @(Get-ChildItem -LiteralPath (Join-Path $TestDrive 'rot')).Count | Should -Be 2
        @(Get-LogEntries -Path $p).Count | Should -BeGreaterThan 0
        @(Get-LogEntries -Path $old).Count | Should -BeGreaterThan 0
    }

    It 'rotates at about 1 MB by default and logs in the Intune Management Extension folder' {
        Initialize-DoctorDOLog -Path (Join-Path $TestDrive 'x.log') -Component 'c' -File 'f'
        $script:DDLog.MaxBytes | Should -Be 1048576
        Get-DoctorDODefaultLogPath | Should -Match 'Microsoft[\\/]IntuneManagementExtension[\\/]Logs[\\/]DoctorDO-Remediation\.log$'
    }

    It 'the detection script and the remediation script write the same format with the same code' {
        $get = {
            param($file)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Intune $file), [ref]$null, [ref]$null)
            $names = 'Get-DoctorDODefaultLogPath', 'Initialize-DoctorDOLog', 'Get-DoctorDOLogBias', 'Hide-DoctorDOCredential', 'ConvertTo-DoctorDOLogText', 'Format-DoctorDOLogLine', 'Invoke-DoctorDOLogRotation', 'Write-DoctorDOLog', 'Get-DoctorDOAllUsersModulesPath', 'Get-DoctorDOInstalledVersions'
            $h = @{}
            foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $names }, $true)) { $h[$f.Name] = $f.Extent.Text }
            $h
        }
        $a = & $get 'Detect-DoctorDO.ps1'
        $b = & $get 'Remediate-DoctorDO.ps1'
        $a.Count | Should -Be 10
        foreach ($k in $a.Keys) { $a[$k] | Should -BeExactly $b[$k] -Because $k }
    }
}

Describe 'Module checks (Test-DoctorDOModuleFolder)' {
    BeforeEach {
        $global:RT = @{ Source = (Join-Path $TestDrive ('src-' + [guid]::NewGuid().ToString('N'))); Root = (Join-Path $TestDrive ('mods-' + [guid]::NewGuid().ToString('N'))); Unsafe = $null }
        [void](New-Item -ItemType Directory -Path $global:RT.Source -Force)
        [void](New-FakeRelease -Source $global:RT.Source -Version '0.5.0')
        $global:RT.Spec = Get-FakeSpec -Dir (Join-Path $global:RT.Source '0.5.0') -Version '0.5.0'
        $global:RT.Folder = Install-Fake -Version '0.5.0'
        Mock Get-DoctorDOPathSecurityRaw {
            $users = if ($global:RT.Unsafe -and $Path -like $global:RT.Unsafe) { @([pscustomobject]@{ Sid = 'S-1-5-32-545'; Type = 'Allow'; Rights = [int64]0x1301BF }) } else { @() }
            [pscustomobject]@{ Exists = $true; ReparsePoint = $false; Owner = 'S-1-5-32-544'; Error = $null
                Rules = @([pscustomobject]@{ Sid = 'S-1-5-18'; Type = 'Allow'; Rights = [int64]0x1F01FF }, [pscustomobject]@{ Sid = 'S-1-5-32-544'; Type = 'Allow'; Rights = [int64]0x1F01FF },
                    [pscustomobject]@{ Sid = 'S-1-5-32-545'; Type = 'Allow'; Rights = [int64]0x1200A9 }) + $users }
        }
    }

    It 'accepts the release: permissions, files, SHA-256 and identity all match' {
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Valid | Should -BeTrue -Because $r.Reason
    }

    # PowerShellGet 1.x/2.x (Windows PowerShell 5.1's Install-Module) writes a hidden PSGetModuleInfo.xml into the version
    # folder; PSResourceGet's Save-PSResource writes none. TO VERIFY on a device: Microsoft Learn does not document the file
    # (observed by the packaging test with Publish-PSResource and Save-PSResource, and by the integrator on Install-Module).
    It 'installed by PowerShellGet with PSGetModuleInfo.xml (hidden) present: passes, and without it also passes' {
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec).Valid | Should -BeTrue -Because 'Save-PSResource writes none'
        $info = Join-Path $global:RT.Folder 'PSGetModuleInfo.xml'
        [System.IO.File]::WriteAllText($info, '<Objs>whatever PowerShellGet writes: its content is not hashed</Objs>')
        [System.IO.File]::SetAttributes($info, [System.IO.FileAttributes]::Hidden)
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Valid | Should -BeTrue -Because $r.Reason
    }

    It 'the PSGetModuleInfo.xml is still under the permission check' {
        [System.IO.File]::WriteAllText((Join-Path $global:RT.Folder 'PSGetModuleInfo.xml'), '<Objs />')
        $global:RT.Unsafe = '*PSGetModuleInfo.xml'
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Valid | Should -BeFalse
        $r.Check | Should -Be 'permissions'
        $r.Reason | Should -Match 'PSGetModuleInfo.xml'
    }

    It 'an unexpected extra file fails, and the one name allowed is allowed only at the top of the folder' {
        [System.IO.File]::WriteAllText((Join-Path $global:RT.Folder 'Public/extra.ps1'), 'x')
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Valid | Should -BeFalse
        $r.Check | Should -Be 'contents'
        $r.Reason | Should -Match 'unexpected file Public/extra.ps1'
        Remove-Item -LiteralPath (Join-Path $global:RT.Folder 'Public/extra.ps1')
        [System.IO.File]::WriteAllText((Join-Path $global:RT.Folder 'Public/PSGetModuleInfo.xml'), '<Objs />')
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec).Reason | Should -Match 'unexpected file Public/PSGetModuleInfo.xml'
        Remove-Item -LiteralPath (Join-Path $global:RT.Folder 'Public/PSGetModuleInfo.xml')
        [System.IO.File]::WriteAllText((Join-Path $global:RT.Folder 'PSGetModuleInfo.xml.bak'), 'x')
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec).Reason | Should -Match 'unexpected file PSGetModuleInfo.xml.bak'
        Remove-Item -LiteralPath (Join-Path $global:RT.Folder 'PSGetModuleInfo.xml.bak')
        [System.IO.File]::WriteAllText((Join-Path $global:RT.Folder 'Data.dll'), 'x')
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec).Check | Should -Be 'contents'
    }

    It 'rejects a missing file' {
        Remove-Item -LiteralPath (Join-Path $global:RT.Folder 'Public/Get-Thing.ps1')
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Check | Should -Be 'contents'
        $r.Reason | Should -Match 'missing file'
    }

    It 'rejects a tampered file by its SHA-256, in a script and in the manifest' {
        Add-Content -LiteralPath (Join-Path $global:RT.Folder 'DoctorDO.Collector.psm1') -Value 'Invoke-Evil'
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Valid | Should -BeFalse
        $r.Check | Should -Be 'hashes'
        $r.Reason | Should -Match 'DoctorDO.Collector.psm1'
        Remove-Item -LiteralPath $global:RT.Folder -Recurse -Force
        $global:RT.Folder = Install-Fake -Version '0.5.0'
        Add-Content -LiteralPath (Join-Path $global:RT.Folder 'DoctorDO.Collector.psd1') -Value '# changed'
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec).Check | Should -Be 'hashes'
    }

    It 'rejects a wrong module GUID (the files are the release''s, the identity is not)' {
        $other = New-FakeRelease -Source $global:RT.Source -Version '0.5.1' -Guid 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb'
        $spec = Get-FakeSpec -Dir $other -Version '0.5.1' -Guid 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb'
        $dest = Install-Fake -Version '0.5.1'
        (Test-DoctorDOModuleFolder -Path $dest -Spec $spec).Valid | Should -BeTrue -Because 'consistent with its own list'
        $expected = $spec.PSObject.Copy(); $expected.Guid = $script:FakeGuid
        $r = Test-DoctorDOModuleFolder -Path $dest -Spec $expected
        $r.Valid | Should -BeFalse
        $r.Check | Should -Be 'identity'
        $r.Reason | Should -Match 'GUID'
    }

    It 'rejects a wrong author, other exported functions, a wrong version and a FileList that does not match' {
        $s = $global:RT.Spec.PSObject.Copy(); $s.Author = 'Someone Else'
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $s).Reason | Should -Match 'author'
        $s = $global:RT.Spec.PSObject.Copy(); $s.Functions = @('Get-Thing', 'Get-Other')
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $s).Reason | Should -Match 'exported functions'
        $s = $global:RT.Spec.PSObject.Copy(); $s.Version = '0.5.1'
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $s).Check | Should -Be 'identity'
        $odd = New-FakeRelease -Source $global:RT.Source -Version '0.5.2' -OmitFromFileList 'Public/Get-Thing.ps1'
        $dest = Install-Fake -Version '0.5.2'
        $r = Test-DoctorDOModuleFolder -Path $dest -Spec (Get-FakeSpec -Dir $odd -Version '0.5.2')
        $r.Check | Should -Be 'identity'
        $r.Reason | Should -Match 'FileList lacks|manifest FileList lacks'
    }

    It 'rejects a folder that others can write to: the version folder, the module folder above it, or a file' {
        foreach ($pattern in @("$($global:RT.Folder)", (Split-Path $global:RT.Folder -Parent), (Join-Path $global:RT.Folder 'Public/Get-Thing.ps1'))) {
            $global:RT.Unsafe = $pattern
            $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
            $r.Valid | Should -BeFalse -Because $pattern
            $r.Check | Should -Be 'permissions'
            $r.Reason | Should -Match 'can change it'
            $r.Reason | Should -Not -Match 'S-1-5'
        }
    }

    It 'rejects a link in the tree' {
        $link = Join-Path $global:RT.Folder 'Data'
        try { [void](New-Item -ItemType SymbolicLink -Path $link -Target $global:RT.Source -ErrorAction Stop) } catch { Set-ItResult -Skipped -Because "no symbolic links here: $($_.Exception.Message)"; return }
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Valid | Should -BeFalse
        $r.Check | Should -Be 'permissions'
        $r.Reason | Should -Match 'link'
    }

    It 'fails closed when the permissions cannot be read or the check itself fails' {
        Mock Get-DoctorDOPathSecurityRaw { $null }
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec).Check | Should -Be 'permissions'
        Mock Get-DoctorDOPathSecurityRaw { throw 'boom' }
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec
        $r.Valid | Should -BeFalse
        $r.Check | Should -Be 'error'
    }

    It 'with a signer thumbprint every script and manifest needs a Valid signature by it; without one the signature is not asked for' {
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Thumbprint = 'AABBCCDD' } } }
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec -ExpectedSignerThumbprint 'aa bb cc dd').Valid | Should -BeTrue
        Should -Invoke Get-AuthenticodeSignature -Times 3 -Exactly -Because 'psd1, psm1 and the one .ps1'
        $r = Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec -ExpectedSignerThumbprint 'EEEE'
        $r.Check | Should -Be 'signature'
        Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'NotSigned'; SignerCertificate = $null } }
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec -ExpectedSignerThumbprint 'AABBCCDD').Reason | Should -Match 'no valid signature'
        Mock Get-AuthenticodeSignature { throw 'not asked' }
        (Test-DoctorDOModuleFolder -Path $global:RT.Folder -Spec $global:RT.Spec).Valid | Should -BeTrue
    }

    It 'the real module folder passes against the release stamped into the remediation script' {
        $dest = Join-Path (Join-Path $global:RT.Root 'DoctorDO.Collector') $DoctorDOPinnedVersion
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
        Copy-Item -LiteralPath $script:RealModule -Destination $dest -Recurse
        $pinned = New-DoctorDOSpec -ModuleName 'DoctorDO.Collector' -Version $DoctorDOPinnedVersion -Guid $DoctorDOExpectedGuid -Author $DoctorDOExpectedAuthor -Functions $DoctorDOExpectedFunctions -Files $DoctorDOPinnedFiles -Source 'script'
        $r = Test-DoctorDOModuleFolder -Path $dest -Spec $pinned
        $r.Valid | Should -BeTrue -Because $r.Reason
    }
}

Describe 'Permission judgement (Test-DoctorDOPathSecurity)' {
    BeforeAll {
        function New-Raw { param([string] $Owner = 'S-1-5-32-544', $Rules = @(), [switch] $Link, [switch] $Missing, [string] $Err)
            [pscustomobject]@{ Exists = -not $Missing; ReparsePoint = [bool]$Link; Owner = $Owner; Rules = @($Rules); Error = $Err } }
        function New-Rule { param([string] $Sid, [int64] $Rights, [string] $Type = 'Allow') [pscustomobject]@{ Sid = $Sid; Type = $Type; Rights = $Rights } }
    }
    It 'SYSTEM, Administrators, TrustedInstaller and CREATOR OWNER may write; read and execute for Users is fine' {
        $rules = @((New-Rule 'S-1-5-18' 0x1F01FF), (New-Rule 'S-1-5-32-544' 0x1F01FF), (New-Rule 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' 0x1F01FF),
            (New-Rule 'S-1-3-0' 0x1F01FF), (New-Rule 'S-1-5-32-545' 0x1200A9), (New-Rule 'S-1-15-2-1' 0x1200A9))
        Test-DoctorDOPathSecurity -Raw (New-Raw -Rules $rules) | Should -BeNullOrEmpty
    }
    It 'Users, Authenticated Users, Everyone or any other account with any write-type right make it unsafe' {
        foreach ($sid in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-21-1-2-3-1001') {
            foreach ($right in 0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x1301BF, 0x1F01FF, 0x10000000, 0x40000000) {
                Test-DoctorDOPathSecurity -Raw (New-Raw -Rules @((New-Rule 'S-1-5-18' 0x1F01FF), (New-Rule $sid $right))) | Should -Match 'can change it' -Because "$sid $right"
            }
        }
    }
    It 'a Deny rule is not a grant; an owner that is a user, a link, a missing path and an unreadable one are unsafe' {
        Test-DoctorDOPathSecurity -Raw (New-Raw -Rules @((New-Rule 'S-1-5-32-545' 0x1F01FF 'Deny'))) | Should -BeNullOrEmpty
        Test-DoctorDOPathSecurity -Raw (New-Raw -Owner 'S-1-5-21-1-2-3-1001') | Should -Match 'owned by'
        Test-DoctorDOPathSecurity -Raw (New-Raw -Link) | Should -Match 'link'
        Test-DoctorDOPathSecurity -Raw (New-Raw -Missing) | Should -Match 'missing'
        Test-DoctorDOPathSecurity -Raw (New-Raw -Err 'denied') | Should -Match 'could not be read'
        Test-DoctorDOPathSecurity -Raw $null | Should -Match 'could not be read'
    }
}

Describe 'The release manifest' {
    BeforeAll {
        $script:Hex = 'a' * 64
        function New-ManifestText { param([hashtable] $Override = @{})
            $m = [ordered]@{ schema = 'doctordo-collector-manifest/1'; module = 'DoctorDO.Collector'; version = '0.6.0'; guid = $script:FakeGuid; author = 'Maurice Daly'; exports = @('Get-Thing')
                files = @([ordered]@{ path = 'DoctorDO.Collector.psd1'; sha256 = $script:Hex }, [ordered]@{ path = 'Public/Get-Thing.ps1'; sha256 = $script:Hex.ToUpper() }) }
            foreach ($k in $Override.Keys) { $m[$k] = $Override[$k] }
            $m | ConvertTo-Json -Depth 5
        }
        function Read-Manifest { param([string] $Text) ConvertTo-DoctorDOSpecFromManifest -Json $Text -ModuleName 'DoctorDO.Collector' -Version '0.6.0' -ExpectedGuid $script:FakeGuid -ExpectedAuthor 'Maurice Daly' }
    }
    It 'reads a good manifest into the files and the identity to check' {
        $s = Read-Manifest (New-ManifestText)
        $s.Version | Should -Be '0.6.0'
        $s.Files.Count | Should -Be 2
        $s.Files['public/get-thing.ps1'] | Should -Be $script:Hex
        $s.Functions | Should -Be @('Get-Thing')
        $s.Source | Should -Be 'release manifest'
    }
    It 'refuses another version, module, GUID, author, schema, and anything that is not JSON' {
        { Read-Manifest (New-ManifestText @{ version = '0.6.1' }) } | Should -Throw '*version 0.6.1*'
        { Read-Manifest (New-ManifestText @{ module = 'Other' }) } | Should -Throw '*another module*'
        { Read-Manifest (New-ManifestText @{ guid = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb' }) } | Should -Throw '*GUID*'
        { Read-Manifest (New-ManifestText @{ author = 'Mallory' }) } | Should -Throw '*author*'
        { Read-Manifest (New-ManifestText @{ schema = 'x/2' }) } | Should -Throw '*schema*'
        { Read-Manifest '<html>404</html>' } | Should -Throw '*not valid JSON*'
    }
    It 'refuses unsafe paths, malformed hashes, duplicates, and empty lists' {
        foreach ($bad in '../evil.ps1', '/abs.ps1', 'a\b.ps1', 'C:x.ps1', 'a//b.ps1', './a.ps1') {
            { Read-Manifest (New-ManifestText @{ files = @([ordered]@{ path = $bad; sha256 = $script:Hex }) }) } | Should -Throw '*unsafe file path*' -Because $bad
        }
        { Read-Manifest (New-ManifestText @{ files = @([ordered]@{ path = 'a.ps1'; sha256 = 'zz' }) }) } | Should -Throw '*invalid SHA-256*'
        { Read-Manifest (New-ManifestText @{ files = @([ordered]@{ path = 'a.ps1'; sha256 = $script:Hex }, [ordered]@{ path = 'A.ps1'; sha256 = $script:Hex }) }) } | Should -Throw '*twice*'
        { Read-Manifest (New-ManifestText @{ files = @() }) } | Should -Throw '*no files*'
        { Read-Manifest (New-ManifestText @{ exports = @() }) } | Should -Throw '*no exported functions*'
    }
    It 'builds the URL from the template and accepts https only' {
        Get-DoctorDOManifestUrl -Template 'https://github.com/{owner}/{repo}/releases/download/collector-v{version}/collector-manifest.json' -Owner 'maurice-daly' -Repo 'doctordo' -Version '0.5.0' |
            Should -Be 'https://github.com/maurice-daly/doctordo/releases/download/collector-v0.5.0/collector-manifest.json'
        { Get-DoctorDOManifestUrl -Template 'http://x/{version}' -Owner 'o' -Repo 'r' -Version '1.0.0' } | Should -Throw '*https*'
        { Get-DoctorDOManifestUrl -Template 'https://u:p@x/{version}' -Owner 'o' -Repo 'r' -Version '1.0.0' } | Should -Throw '*https*'
    }
    It 'reads the text of a response whether the content is a string or bytes (GitHub serves octet-stream)' {
        Mock Invoke-WebRequest { [pscustomobject]@{ Content = [byte[]](0xEF, 0xBB, 0xBF, 0x7B, 0x7D) } }
        Get-DoctorDOReleaseManifestText -Url 'https://x.example/m.json' | Should -Be '{}'
        Mock Invoke-WebRequest { [pscustomobject]@{ Content = '{"a":1}' } }
        Get-DoctorDOReleaseManifestText -Url 'https://x.example/m.json' | Should -Be '{"a":1}'
        Mock Invoke-WebRequest { [pscustomobject]@{ Content = ('x' * 300000) } }
        { Get-DoctorDOReleaseManifestText -Url 'https://x.example/m.json' } | Should -Throw '*larger than*'
    }
}

Describe 'Initialize-DoctorDOModule' {
    BeforeEach {
        $global:RT = @{
            Source = (Join-Path $TestDrive ('src-' + [guid]::NewGuid().ToString('N'))); Root = (Join-Path $TestDrive ('mods-' + [guid]::NewGuid().ToString('N')))
            Log = (Join-Path $TestDrive ('log-' + [guid]::NewGuid().ToString('N') + '.log'))
            Available = @('0.5.0'); Manifests = @{}; Unsafe = $null; Installs = @(); WebFail = $false; FindFail = $false; InstallFail = $false; NoProvider = $false
            ImportFails = @(); Imports = @(); Loaded = $null; FindArgs = @()
        }
        [void](New-Item -ItemType Directory -Path $global:RT.Source -Force)
        foreach ($v in '0.4.0', '0.5.0', '0.6.0', '0.7.0') {
            $d = New-FakeRelease -Source $global:RT.Source -Version $v
            $spec = Get-FakeSpec -Dir $d -Version $v
            $global:RT.Manifests[$v] = Get-FakeManifestJson -Spec $spec
            if ($v -eq '0.5.0') { $global:RT.Pinned = $spec }
        }
        Initialize-DoctorDOLog -Path $global:RT.Log -Component 'Remediate-DoctorDO' -File 'Remediate-DoctorDO.ps1'

        Mock Get-DoctorDOPathSecurityRaw {
            $users = if ($global:RT.Unsafe -and $Path -like $global:RT.Unsafe) { @([pscustomobject]@{ Sid = 'S-1-5-32-545'; Type = 'Allow'; Rights = [int64]0x1301BF }) } else { @() }
            [pscustomobject]@{ Exists = $true; ReparsePoint = $false; Owner = 'S-1-5-18'; Error = $null; Rules = @([pscustomobject]@{ Sid = 'S-1-5-18'; Type = 'Allow'; Rights = [int64]0x1F01FF }) + $users }
        }
        Mock Get-PackageProvider { if (-not $global:RT.NoProvider) { [pscustomobject]@{ Name = 'NuGet'; Version = [version]'2.8.5.208' } } }
        Mock Install-PackageProvider { }
        Mock Find-Module {
            $global:RT.FindArgs += , @{ MaximumVersion = $MaximumVersion }
            if ($global:RT.FindFail) { throw 'No match was found for the specified search criteria' }
            $c = @($global:RT.Available | ForEach-Object { [version]$_ } | Where-Object { -not $MaximumVersion -or $_ -le [version]$MaximumVersion } | Sort-Object -Descending)
            if ($c.Count -eq 0) { throw 'No match was found' }
            [pscustomobject]@{ Name = $Name; Version = $c[0].ToString(); Repository = $Repository }
        }
        Mock Install-Module {
            if ($global:RT.InstallFail) { throw 'Unable to download from URI' }
            $global:RT.Installs += $RequiredVersion
            # -Name is [string[]] in Windows PowerShell 5.1's PowerShellGet, and its Join-Path takes no array for -ChildPath.
            $dest = Join-Path (Join-Path $global:RT.Root ([string]@($Name)[0])) ([string]$RequiredVersion)
            [void](New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force)
            Copy-Item -LiteralPath (Join-Path $global:RT.Source $RequiredVersion) -Destination $dest -Recurse
            [System.IO.File]::WriteAllText((Join-Path $dest 'PSGetModuleInfo.xml'), '<Objs />')
        }
        Mock Invoke-WebRequest {
            if ($global:RT.WebFail) { throw 'The remote server returned an error: (404) Not Found.' }
            $v = [regex]::Match([string]$Uri, '/(\d+\.\d+\.\d+)/').Groups[1].Value
            if (-not $global:RT.Manifests.ContainsKey($v)) { throw 'The remote server returned an error: (404) Not Found.' }
            [pscustomobject]@{ Content = $global:RT.Manifests[$v] }
        }
        Mock Get-Module { if ($global:RT.Loaded) { $global:RT.Loaded } }
        Mock Remove-Module { }
        Mock Import-Module {
            $global:RT.Imports += $Name
            $base = Split-Path $Name -Parent
            if ($global:RT.ImportFails -contains (Split-Path $base -Leaf)) { throw 'The module could not be loaded' }
            [pscustomobject]@{ ModuleBase = $base; Version = [version](Split-Path $base -Leaf) }
        }
    }
    AfterAll { Remove-Variable -Name RT -Scope Global -ErrorAction SilentlyContinue }

    Context 'already installed' {
        It 'verifies it, imports it by the full path of its .psd1, and installs and downloads nothing' {
            $dir = Install-Fake -Version '0.5.0' -WithInfoFile
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            $r.Summary | Should -Be 'module 0.5.0 verified'
            Should -Invoke Install-Module -Times 0 -Exactly
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly -Because 'this version is the one stamped into the script'
            Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter { $Name -eq (Join-Path $dir 'DoctorDO.Collector.psd1') -and $Force -and $ErrorAction -eq 'Stop' }
            $global:RT.Imports[0] | Should -Match '\.psd1$'
            $global:RT.Imports[0] | Should -Not -Be 'DoctorDO.Collector'
            (Get-LogEntries | ForEach-Object { $_.Message }) -join "`n" | Should -Match 'Imported DoctorDO.Collector 0.5.0'
        }
        It 'enforces TLS 1.2 and leaves the repository''s trust setting alone' {
            [void](Install-Fake -Version '0.5.0')
            [void](Invoke-Init)
            ([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls12) | Should -Not -Be 0
            $text = Get-Content (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Raw
            $text | Should -Not -Match 'Set-PSRepository|InstallationPolicy|Register-PSRepository'
            $text | Should -Not -Match 'CurrentUser|SkipPublisherCheck|Invoke-Expression|DownloadString'
            $text | Should -Match 'Install-Module -Name \$ModuleName -RequiredVersion \$target\.ToString\(\) -Repository \$Repository -Scope AllUsers -Force'
        }
    }

    Context 'not installed' {
        It 'bootstraps nothing when the NuGet provider is there, then installs the newest version for all users, verifies and imports it' {
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Summary | Should -Be 'module 0.5.0 installed'
            Should -Invoke Install-PackageProvider -Times 0 -Exactly
            Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter { $Name -eq 'DoctorDO.Collector' -and $RequiredVersion -eq '0.5.0' -and $Repository -eq 'PSGallery' -and $Scope -eq 'AllUsers' -and $Force }
            Should -Invoke Import-Module -Times 1 -Exactly
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.5.0/DoctorDO.Collector.psd1') | Should -BeTrue
            (Get-LogEntries | ForEach-Object { $_.Message }) -join "`n" | Should -Match 'Installing DoctorDO.Collector 0.5.0 from PSGallery for all users'
        }
        It 'installs the NuGet provider first when it is missing (once, with -MinimumVersion 2.8.5.201 -Force)' {
            $global:RT.NoProvider = $true
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            Should -Invoke Install-PackageProvider -ParameterFilter { $Name -eq 'NuGet' -and [version]$MinimumVersion -eq [version]'2.8.5.201' -and $Force } -Times 2 -Exactly -Because 'once before the search and once before the install, each only when still missing'
        }
        It 'a failed provider install is caught, logged, and ends the run with exit 8 and nothing imported' {
            $global:RT.NoProvider = $true
            Mock Install-PackageProvider { throw 'Unable to download the NuGet provider' }
            $r = Invoke-Init
            $r.ExitCode | Should -Be 8
            Should -Invoke Import-Module -Times 0 -Exactly
            (Get-LogEntries | Where-Object { $_.Type -ge 2 } | ForEach-Object { $_.Message }) -join "`n" | Should -Match 'Unable to download the NuGet provider'
        }
    }

    Context 'too old, and upgraded' {
        It 'a newer version in the repository: verified against the release manifest, imported, one previous kept and older ones removed' {
            [void](Install-Fake -Version '0.4.0'); [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0')
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.6.0'
            $r.Summary | Should -Be 'module 0.6.0 installed'
            Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://example.test/o/r/0.6.0/collector-manifest.json' }
            Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter { $Name -like '*0.6.0*' }
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.6.0') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.5.0') | Should -BeTrue -Because 'the previous version is kept for rollback'
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.4.0') | Should -BeFalse
        }
        It 'only a version below the minimum is installed: the minimum is installed, the old one stays as the previous version' {
            [void](Install-Fake -Version '0.4.0')
            $r = Invoke-Init
            $r.Version | Should -Be '0.5.0'
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.4.0') | Should -BeTrue
            Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -like '*0.4.0*' }
        }
        It 'a repository that has nothing at or above the minimum installs nothing (exit 8)' {
            $global:RT.Available = @('0.4.0')
            $r = Invoke-Init
            $r.ExitCode | Should -Be 8
            Should -Invoke Install-Module -Times 0 -Exactly
            Should -Invoke Import-Module -Times 0 -Exactly
        }
    }

    Context 'the install fails' {
        It 'with nothing installed: exit 8, the error is logged, nothing is imported' {
            $global:RT.InstallFail = $true
            $r = Invoke-Init
            $r.ExitCode | Should -Be 8
            $r.Message | Should -Match 'not installed and could not be'
            Should -Invoke Import-Module -Times 0 -Exactly
            (Get-LogEntries | Where-Object { $_.Type -eq 3 } | ForEach-Object { $_.Message }) -join "`n" | Should -Match 'Install failed: Unable to download'
        }
        It 'with a verified version installed: it keeps being used, and the summary says the update was not made' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0'); $global:RT.InstallFail = $true
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            $r.Summary | Should -Match 'install of 0.6.0 failed'
        }
        It 'success reported but nothing left in the folder is an install failure' {
            Mock Install-Module { }
            (Invoke-Init).ExitCode | Should -Be 8
        }
    }

    Context 'a release that does not verify' {
        It 'files that do not match the release''s SHA-256: removed, not imported, the previous version used' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0')
            Add-Content -LiteralPath (Join-Path $global:RT.Source '0.6.0/DoctorDO.Collector.psm1') -Value 'Invoke-Evil'
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            $r.Summary | Should -Match 'rejected \(hashes\)'
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.6.0') | Should -BeFalse -Because 'what was just installed is removed'
            Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -like '*0.6.0*' }
            (Get-LogEntries | Where-Object { $_.Type -eq 3 } | ForEach-Object { $_.Message }) -join "`n" | Should -Match 'failed the hashes check'
        }
        It 'and with no earlier version: exit 9, nothing imported, nothing left behind' {
            Add-Content -LiteralPath (Join-Path $global:RT.Source '0.5.0/Public/Get-Thing.ps1') -Value 'Invoke-Evil'
            $r = Invoke-Init
            $r.ExitCode | Should -Be 9
            $r.Message | Should -Match 'failed verification'
            Should -Invoke Import-Module -Times 0 -Exactly
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.5.0') | Should -BeFalse
        }
        It 'a manifest whose hashes differ from the files: removed, the previous version used' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0')
            $global:RT.Manifests['0.6.0'] = $global:RT.Manifests['0.6.0'] -replace '("path": "DoctorDO.Collector.psm1", "sha256": ")[0-9a-f]{3}', '${1}000'
            $r = Invoke-Init
            $r.Version | Should -Be '0.5.0'
            $r.Summary | Should -Match 'rejected'
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.6.0') | Should -BeFalse
            Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -like '*0.6.0*' }
        }
        It 'a different module GUID in the manifest: nothing is installed at all, the previous version used (exit 0), exit 11 without one' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0')
            $global:RT.Manifests['0.6.0'] = $global:RT.Manifests['0.6.0'] -replace [regex]::Escape($script:FakeGuid), 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb'
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            $r.Summary | Should -Match 'update to 0.6.0 skipped'
            Should -Invoke Install-Module -Times 0 -Exactly
            Remove-Item -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector') -Recurse -Force
            $global:RT.Available = @('0.6.0')
            $r2 = Invoke-Init
            $r2.ExitCode | Should -Be 11
            Should -Invoke Import-Module -Times 1 -Exactly -Because 'only the first run imported'
        }
        It 'the module''s own GUID differs from the one expected (a repackaged module with matching file list): rejected and removed' {
            $d = New-FakeRelease -Source $global:RT.Source -Version '0.6.0' -Guid 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb'
            $global:RT.Manifests['0.6.0'] = Get-FakeManifestJson -Spec (Get-FakeSpec -Dir $d -Version '0.6.0')
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0')
            $r = Invoke-Init
            $r.Version | Should -Be '0.5.0'
            $r.Summary | Should -Match 'rejected \(identity\)'
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.6.0') | Should -BeFalse
        }
        It 'a folder that others can write to: just-installed is removed; an existing one is left in place and not used' {
            $global:RT.Unsafe = '*0.5.0*'
            $r = Invoke-Init
            $r.ExitCode | Should -Be 9
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.5.0') | Should -BeFalse
            Should -Invoke Import-Module -Times 0 -Exactly
            $global:RT.Unsafe = $null
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $global:RT.Unsafe = '*0.5.0*'
            $r = Invoke-Init
            $r.ExitCode | Should -Be 9
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.5.0') | Should -BeTrue
            (Get-LogEntries | ForEach-Object { $_.Message }) -join "`n" | Should -Match 'left in place'
        }
        It 'an installed copy that was changed since: removed, installed again in the same run, verified' {
            $dir = Install-Fake -Version '0.5.0'
            Add-Content -LiteralPath (Join-Path $dir 'DoctorDO.Collector.psm1') -Value 'Invoke-Evil'
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Summary | Should -Be 'module 0.5.0 installed'
            Should -Invoke Install-Module -Times 1 -Exactly
            (Get-Content (Join-Path $dir 'DoctorDO.Collector.psm1') -Raw) | Should -Not -Match 'Invoke-Evil'
            Should -Invoke Import-Module -Times 1 -Exactly
        }
        It 'with a signer thumbprint set, an invalid signature removes what was installed and nothing is imported' {
            Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'HashMismatch'; SignerCertificate = $null } }
            $r = Invoke-Init -Thumbprint 'AABBCCDD'
            $r.ExitCode | Should -Be 9
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.5.0') | Should -BeFalse
            Should -Invoke Import-Module -Times 0 -Exactly
            Mock Get-AuthenticodeSignature { [pscustomobject]@{ Status = 'Valid'; SignerCertificate = [pscustomobject]@{ Thumbprint = 'AABBCCDD' } } }
            $r = Invoke-Init -Thumbprint 'AABBCCDD'
            $r.ExitCode | Should -Be 0
        }
    }

    Context 'the release manifest cannot be read' {
        It 'unreachable: no update, the verified version stays in use (exit 0, a warning); with nothing installed exit 11' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0'); $global:RT.WebFail = $true
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            $r.Summary | Should -Match 'update to 0.6.0 skipped: the release manifest for 0.6.0 could not be used'
            Should -Invoke Install-Module -Times 0 -Exactly
            @(Get-LogEntries | Where-Object { $_.Type -eq 2 }).Count | Should -BeGreaterThan 0
            Remove-Item -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector') -Recurse -Force
            $global:RT.Available = @('0.6.0')
            (Invoke-Init).ExitCode | Should -Be 11
        }
        It 'an installed version newer than this script''s release cannot be verified offline, but the stamped one can' {
            [void](Install-Fake -Version '0.5.0'); [void](Install-Fake -Version '0.6.0')
            $global:RT.Available = @('0.6.0'); $global:RT.WebFail = $true
            $r = Invoke-Init
            $r.Version | Should -Be '0.5.0' -Because '0.6.0 has no list to check against while the manifest is unreachable'
            Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -like '*0.6.0*' }
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.6.0') | Should -BeTrue -Because 'unverifiable is not the same as bad: it is not removed'
        }
        It 'the repository cannot be searched: the installed version is used (exit 0); with nothing installed exit 8' {
            $global:RT.FindFail = $true
            (Invoke-Init).ExitCode | Should -Be 8
            [void](Install-Fake -Version '0.5.0')
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Summary | Should -Match 'could not query PSGallery'
        }
    }

    Context 'the Pinned policy' {
        It 'installs the stamped version even when the repository has a newer one, and never downloads a manifest or searches' {
            $global:RT.Available = @('0.5.0', '0.7.0')
            $r = Invoke-Init -Policy Pinned
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            Should -Invoke Install-Module -Times 1 -Exactly -ParameterFilter { $RequiredVersion -eq '0.5.0' }
            Should -Invoke Find-Module -Times 0 -Exactly
            Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        }
        It 'ignores a newer installed version it has no hashes for' {
            [void](Install-Fake -Version '0.6.0')
            $r = Invoke-Init -Policy Pinned
            $r.Version | Should -Be '0.5.0'
            Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -like '*0.6.0*' }
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.6.0') | Should -BeTrue
        }
        It 'a stamped version that fails: exit 9, removed, nothing imported' {
            Add-Content -LiteralPath (Join-Path $global:RT.Source '0.5.0/Public/Get-Thing.ps1') -Value 'x'
            (Invoke-Init -Policy Pinned).ExitCode | Should -Be 9
            Should -Invoke Import-Module -Times 0 -Exactly
        }
    }

    Context 'MinimumVersion and MaximumVersion' {
        It 'a cap is passed to the search, and a newer installed version is not used' {
            [void](Install-Fake -Version '0.7.0'); [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0', '0.7.0')
            $r = Invoke-Init -Max '0.6.0'
            $r.Version | Should -Be '0.6.0'
            $global:RT.FindArgs[0].MaximumVersion | Should -Be '0.6.0'
            Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -like '*0.7.0*' }
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.7.0') | Should -BeTrue
        }
        It 'a setting that is not a version is a configuration error (exit 3)' {
            (Invoke-Init -Min 'latest').ExitCode | Should -Be 3
            (Invoke-Init -Max 'x').ExitCode | Should -Be 3
        }
    }

    Context 'how often the repository is searched (-UpdateCheckHours)' {
        BeforeEach {
            $global:RT.LastCheck = $null; $global:RT.Recorded = @()
            Mock Get-DoctorDOLastUpdateCheck { $global:RT.LastCheck }
            Mock Set-DoctorDOLastUpdateCheck { $global:RT.Recorded += $At }
        }
        BeforeAll {
            $script:now = [datetime]::new(2026, 10, 19, 9, 0, 0, [System.DateTimeKind]::Utc)
            $script:init = {
                param($hours, $at)
                Initialize-DoctorDOModule -ModuleName 'DoctorDO.Collector' -Repository 'PSGallery' -UpdatePolicy 'LatestVerified' -MinimumVersion '0.5.0' -ModulesPath $global:RT.Root `
                    -PinnedSpec $global:RT.Pinned -ManifestUrlTemplate 'https://example.test/{owner}/{repo}/{version}/collector-manifest.json' -GitHubOwner 'o' -GitHubRepo 'r' `
                    -UpdateCheckHours $hours -UpdateCheckRegistryPath 'HKLM:\SOFTWARE\DoctorDO-test' -Now $at
            }
        }
        It 'does not search within 24 hours of the last search while a version that meets the minimum is installed' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0')
            $global:RT.LastCheck = $now.AddHours(-3)
            $r = & $init 24 $now
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            @($global:RT.FindArgs).Count | Should -Be 0
            @($global:RT.Recorded).Count | Should -Be 0
        }
        It 'searches once 24 hours have passed, allowing 30 minutes for the schedule''s jitter, and records the time' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0')
            $global:RT.LastCheck = $now.AddHours(-23.6)
            $r = & $init 24 $now
            $r.Version | Should -Be '0.6.0'
            @($global:RT.FindArgs).Count | Should -Be 1
            $global:RT.Recorded | Should -Be @($now)
        }
        It 'always searches when nothing usable is installed, or with -UpdateCheckHours 0; a failed search records nothing' {
            $global:RT.Available = @('0.5.0')
            $global:RT.LastCheck = $now.AddHours(-1)
            (& $init 24 $now).Version | Should -Be '0.5.0'
            @($global:RT.FindArgs).Count | Should -Be 1
            & $init 0 $now | Out-Null
            @($global:RT.FindArgs).Count | Should -Be 2
            @($global:RT.Recorded).Count | Should -Be 1 -Because '-UpdateCheckHours 0 keeps no time'
            $global:RT.FindFail = $true
            $global:RT.LastCheck = $now.AddHours(-30)
            & $init 24 $now | Out-Null
            @($global:RT.Recorded).Count | Should -Be 1 -Because 'an unreachable repository is looked at again next run'
        }
        It 'the script passes its -UpdateCheckHours (default 24) to the module check' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Intune 'Remediate-DoctorDO.ps1'), [ref]$null, [ref]$null)
            ($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'UpdateCheckHours' }).DefaultValue.Value | Should -Be 24
            $text = Get-Content -LiteralPath (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Raw
            $text | Should -Match 'UpdateCheckHours = \$UpdateCheckHours \}'
            $text | Should -Match "'-UpdateCheckHours', \[string\]\`$UpdateCheckHours"
        }
    }

    Context 'importing' {
        It 'a verified version that will not import: removed when just installed, the previous one is used; with none, exit 10' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Available = @('0.5.0', '0.6.0'); $global:RT.ImportFails = @('0.6.0')
            $r = Invoke-Init
            $r.ExitCode | Should -Be 0
            $r.Version | Should -Be '0.5.0'
            Test-Path -LiteralPath (Join-Path $global:RT.Root 'DoctorDO.Collector/0.6.0') | Should -BeFalse
            $global:RT.ImportFails = @('0.5.0', '0.6.0')
            (Invoke-Init).ExitCode | Should -Be 10
        }
        It 'another copy already loaded in the session is unloaded first' {
            [void](Install-Fake -Version '0.5.0')
            $global:RT.Loaded = [pscustomobject]@{ Name = 'DoctorDO.Collector'; ModuleBase = '/somewhere/else/DoctorDO.Collector/0.1.0'; Version = [version]'0.1.0' }
            [void](Invoke-Init)
            Should -Invoke Remove-Module -Times 1 -Exactly
        }
        It 'refuses what loaded when it is not the folder that was verified' {
            [void](Install-Fake -Version '0.5.0')
            Mock Import-Module { [pscustomobject]@{ ModuleBase = '/elsewhere/0.5.0'; Version = [version]'0.5.0' } }
            (Invoke-Init).ExitCode | Should -Be 10
        }
    }

    Context 'never removes outside the module''s version folders' {
        It 'refuses a path that is not a version folder of the module' {
            [void](Install-Fake -Version '0.5.0')
            { Remove-DoctorDOModuleVersion -Path $global:RT.Root -ModulesPath $global:RT.Root -ModuleName 'DoctorDO.Collector' } | Should -Throw '*refusing*'
            { Remove-DoctorDOModuleVersion -Path (Join-Path $global:RT.Root 'DoctorDO.Collector/0.5.0/Public') -ModulesPath $global:RT.Root -ModuleName 'DoctorDO.Collector' } | Should -Throw '*refusing*'
            { Remove-DoctorDOModuleVersion -Path (Join-Path $global:RT.Root 'Other/0.5.0') -ModulesPath $global:RT.Root -ModuleName 'DoctorDO.Collector' } | Should -Throw '*refusing*'
        }
        It 'removing a tree with a link inside removes the link, not what it points to' {
            $dir = Install-Fake -Version '0.5.0'
            $keep = Join-Path $TestDrive ('keep-' + [guid]::NewGuid().ToString('N'))
            [void](New-Item -ItemType Directory -Path $keep)
            [System.IO.File]::WriteAllText((Join-Path $keep 'precious.txt'), 'x')
            try { [void](New-Item -ItemType SymbolicLink -Path (Join-Path $dir 'Link') -Target $keep -ErrorAction Stop) } catch { Set-ItResult -Skipped -Because "no symbolic links here: $($_.Exception.Message)"; return }
            Remove-DoctorDOModuleVersion -Path $dir -ModulesPath $global:RT.Root -ModuleName 'DoctorDO.Collector'
            Test-Path -LiteralPath $dir | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $keep 'precious.txt') | Should -BeTrue
        }
    }
}

Describe 'Invoke-DoctorDORemediation with the module step' {
    BeforeEach {
        $global:RT2 = @{ Prepared = 0; Collected = 0 }
        Initialize-DoctorDOLog -Path (Join-Path $TestDrive ('log-' + [guid]::NewGuid().ToString('N') + '.log')) -Component 'Remediate-DoctorDO' -File 'Remediate-DoctorDO.ps1'
    }
    AfterAll { Remove-Variable -Name RT2 -Scope Global -ErrorAction SilentlyContinue }

    It 'runs the module step after the jitter and before the collector, and adds the module note to the message' {
        $global:RT2.Order = @()
        $r = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' `
            -PrepareModule { param($a) $global:RT2.Order += 'module'; [pscustomobject]@{ ExitCode = 0; Message = ''; Summary = "module 0.5.0 installed $($a.Marker)" } } -PrepareArguments @{ Marker = 'm' } `
            -Collector { param($u, $a) $global:RT2.Order += 'collect'; [pscustomobject]@{ ExitCode = 0; Message = 'sent' } }
        $global:RT2.Order | Should -Be @('module', 'collect')
        $r.ExitCode | Should -Be 0
        $r.Message | Should -Be 'sent [module 0.5.0 installed m]'
    }
    It 'stops with the module step''s exit code and message, and does not collect' {
        $r = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' `
            -PrepareModule { param($a) [pscustomobject]@{ ExitCode = 9; Message = 'module failed verification'; Summary = '' } } `
            -Collector { $global:RT2.Collected++; [pscustomobject]@{ ExitCode = 0 } }
        $r.ExitCode | Should -Be 9
        $r.Message | Should -Be 'module failed verification'
        $global:RT2.Collected | Should -Be 0
    }
    It 'a module step that throws is caught: exit 8' {
        $r = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri 'https://ingest.example/v1/ingest' -ConfiguredIngestUri '' `
            -PrepareModule { throw 'unexpected' } -Collector { $global:RT2.Collected++; [pscustomobject]@{ ExitCode = 0 } }
        $r.ExitCode | Should -Be 8
        $global:RT2.Collected | Should -Be 0
    }
    It 'a configuration error comes first: no module is installed for a script that cannot report' {
        $r = Invoke-DoctorDORemediation -MaxJitterSeconds 0 -IngestUri '' -ConfiguredIngestUri 'https://REPLACE-WITH-YOUR-INGEST-HOST/v1/ingest' `
            -PrepareModule { $global:RT2.Prepared++; [pscustomobject]@{ ExitCode = 0 } } -Collector { [pscustomobject]@{ ExitCode = 0 } }
        $r.ExitCode | Should -Be 3
        $global:RT2.Prepared | Should -Be 0
    }
    It 'the summary for Intune is one short line' {
        $long = "first line`r`nsecond " + ('x' * 3000) + ' https://h.example/p?sig=ABC'
        $s = Format-DoctorDOSummary -Text $long
        $s | Should -Not -Match '[\r\n]'
        $s.Length | Should -BeLessOrEqual 400
        $s | Should -Not -Match 'sig=ABC'
        (Format-DoctorDOSummary -Text "DoctorDO run finished. [module 0.5.0 verified]") | Should -Be 'DoctorDO run finished. [module 0.5.0 verified]'
    }
    It 'the exit codes of the module step are the ones the README lists' {
        $script:ExitModuleInstall | Should -Be 8
        $script:ExitModuleIntegrity | Should -Be 9
        $script:ExitModuleImport | Should -Be 10
        $script:ExitModuleUnverified | Should -Be 11
        $readme = Get-Content (Join-Path $script:Intune 'README.md') -Raw
        foreach ($code in 8, 9, 10, 11) { $readme | Should -Match "(?m)^\| $code \|" }
    }
}

Describe 'The script as Intune runs it' {
    It 'unconfigured: exit 3, one summary line last, and a CMTrace log with the run in it' {
        $pwsh = (Get-Process -Id $PID).Path
        $log = Join-Path $TestDrive 'run/DoctorDO-Remediation.log'
        $out = @(& $pwsh -NoProfile -File (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -MaxJitterSeconds 0 -LogPath $log -ModulesPath (Join-Path $TestDrive 'run/mods') 2>&1)
        $LASTEXITCODE | Should -Be 3
        $out[-1] | Should -Match '^DoctorDO is not configured'
        @($out | Where-Object { "$_" -ne '' }).Count | Should -Be 1 -Because 'the only output is the summary line'
        $entries = @(Get-LogEntries -Path $log)
        $entries.Count | Should -BeGreaterThan 1
        ($entries | ForEach-Object { $_.Message }) -join "`n" | Should -Match 'Started \(PowerShell'
        $entries[-1].Type | Should -Be 3
        $entries[0].Component | Should -Be 'Remediate-DoctorDO'
    }
}

Describe 'Detection script' {
    BeforeEach {
        $global:RT3 = @{ Source = (Join-Path $TestDrive ('src-' + [guid]::NewGuid().ToString('N'))); Root = (Join-Path $TestDrive ('mods-' + [guid]::NewGuid().ToString('N'))) }
        [void](New-Item -ItemType Directory -Path $global:RT3.Source -Force)
        Initialize-DoctorDOLog -Path (Join-Path $TestDrive ('log-' + [guid]::NewGuid().ToString('N') + '.log')) -Component 'Detect-DoctorDO' -File 'Detect-DoctorDO.ps1'
        $global:RT3.Log = $script:DDLog.Path
    }
    AfterAll { Remove-Variable -Name RT3 -Scope Global -ErrorAction SilentlyContinue }

    It 'is non-compliant (exit 1) when the module is not installed, or only an older version is' {
        $r = Test-DoctorDOModuleInstalled -ModulesPath $global:RT3.Root -ModuleName 'DoctorDO.Collector' -MinimumVersion '0.5.0'
        $r.Present | Should -BeFalse
        $r.Message | Should -Be 'Non-compliant: the DoctorDO.Collector module 0.5.0 or later is not installed for all users.'
        [void](New-FakeRelease -Source $global:RT3.Source -Version '0.4.0')
        [void](New-Item -ItemType Directory -Path (Join-Path $global:RT3.Root 'DoctorDO.Collector') -Force)
        Copy-Item -LiteralPath (Join-Path $global:RT3.Source '0.4.0') -Destination (Join-Path $global:RT3.Root 'DoctorDO.Collector/0.4.0') -Recurse
        (Test-DoctorDOModuleInstalled -ModulesPath $global:RT3.Root -ModuleName 'DoctorDO.Collector' -MinimumVersion '0.5.0').Present | Should -BeFalse
        (Test-DoctorDOModuleInstalled -ModulesPath $global:RT3.Root -ModuleName 'DoctorDO.Collector' -MinimumVersion '0.4.0').Present | Should -BeTrue
    }
    It 'a folder whose manifest says another version, or has no manifest, does not count' {
        [void](New-FakeRelease -Source $global:RT3.Source -Version '0.5.0')
        $dest = Join-Path $global:RT3.Root 'DoctorDO.Collector/0.6.0'
        [void](New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force)
        Copy-Item -LiteralPath (Join-Path $global:RT3.Source '0.5.0') -Destination $dest -Recurse
        (Test-DoctorDOModuleInstalled -ModulesPath $global:RT3.Root -ModuleName 'DoctorDO.Collector' -MinimumVersion '0.5.0').Present | Should -BeFalse
        Remove-Item -LiteralPath (Join-Path $dest 'DoctorDO.Collector.psd1')
        (Test-DoctorDOModuleInstalled -ModulesPath $global:RT3.Root -ModuleName 'DoctorDO.Collector' -MinimumVersion '0.5.0').Present | Should -BeFalse
    }
    It 'the module comes first, then the freshness of the last collection; both are logged under the detection''s own component' {
        Mock Get-ItemProperty { [pscustomobject]@{ LastSuccessfulCollection = '2026-10-12T06:00:00Z' } }
        $now = [datetime]::new(2026, 10, 12, 8, 0, 0, [System.DateTimeKind]::Utc)
        $r = Get-DoctorDODetection -MaxAgeHours 22 -RegistryPath 'HKLM:\x' -ModulesPath $global:RT3.Root -ModuleName 'DoctorDO.Collector' -MinimumVersion '0.5.0' -Now $now
        $r.Compliant | Should -BeFalse
        $r.Message | Should -Match 'is not installed'
        Should -Invoke Get-ItemProperty -Times 0 -Exactly
        [void](New-FakeRelease -Source $global:RT3.Source -Version '0.5.0')
        [void](New-Item -ItemType Directory -Path (Join-Path $global:RT3.Root 'DoctorDO.Collector') -Force)
        Copy-Item -LiteralPath (Join-Path $global:RT3.Source '0.5.0') -Destination (Join-Path $global:RT3.Root 'DoctorDO.Collector/0.5.0') -Recurse
        $r = Get-DoctorDODetection -MaxAgeHours 22 -RegistryPath 'HKLM:\x' -ModulesPath $global:RT3.Root -ModuleName 'DoctorDO.Collector' -MinimumVersion '0.5.0' -Now $now
        $r.Compliant | Should -BeTrue
        $r.Message | Should -Match '^Compliant'
        $e = @(Get-LogEntries -Path $global:RT3.Log)
        $e.Count | Should -BeGreaterThan 1
        @($e | Where-Object { $_.Component -ne 'Detect-DoctorDO' }).Count | Should -Be 0
    }
    It 'run as a script with the module in place: exit 1 and the message of the missing collection, with a log' {
        $pwsh = (Get-Process -Id $PID).Path
        # The module's own version, so the script's default -MinimumVersion (kept equal to it) is met whatever the release (19 Oct 2026).
        $v = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot '../DoctorDO.Collector/DoctorDO.Collector.psd1')).ModuleVersion
        [void](New-FakeRelease -Source $global:RT3.Source -Version $v)
        [void](New-Item -ItemType Directory -Path (Join-Path $global:RT3.Root 'DoctorDO.Collector') -Force)
        Copy-Item -LiteralPath (Join-Path $global:RT3.Source $v) -Destination (Join-Path $global:RT3.Root "DoctorDO.Collector/$v") -Recurse
        $log = Join-Path $TestDrive 'det/DoctorDO-Remediation.log'
        $out = @(& $pwsh -NoProfile -File (Join-Path $script:Intune 'Detect-DoctorDO.ps1') -RegistryPath 'HKLM:\SOFTWARE\DoctorDO-does-not-exist' -ModulesPath $global:RT3.Root -LogPath $log)
        $LASTEXITCODE | Should -Be 1
        ($out -join ' ') | Should -Match 'no successful'
        @(Get-LogEntries -Path $log).Count | Should -BeGreaterThan 0
    }
}

Describe 'Packaging: collector-manifest.json, the stamped script and the FileList' {
    It 'the module manifest''s FileList is exactly the files in the module folder' {
        $facts = Get-CollectorFacts -ModulePath $script:RealModule
        $facts.FileListProblems | Should -BeNullOrEmpty
        $facts.Files.Count | Should -BeGreaterThan 30
        # Ordinal order, whatever order the file system lists them in, so every machine stamps the same block.
        $paths = [string[]]@($facts.Files | ForEach-Object { $_.path })
        $sorted = [string[]]$paths.Clone()
        [Array]::Sort($sorted, [System.StringComparer]::Ordinal)
        $paths | Should -Be $sorted
    }
    It 'reads the same files when the module folder is given by its 8.3 short name, as $env:TEMP often is' {
        $copy = Join-Path $TestDrive 'module-short-name'
        Copy-Item -LiteralPath $script:RealModule -Destination $copy -Recurse
        $short = $null
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            try { $short = (New-Object -ComObject Scripting.FileSystemObject).GetFolder($copy).ShortPath } catch { $short = $null }
        }
        if (-not $short -or $short.Length -eq $copy.Length) { Set-ItResult -Skipped -Because 'this volume gives the test drive no shorter 8.3 name'; return }
        $facts = Get-CollectorFacts -ModulePath $short
        $facts.FileListProblems | Should -BeNullOrEmpty
        @($facts.Files | ForEach-Object { $_.path }) | Should -Be @((Get-CollectorFacts -ModulePath $copy).Files | ForEach-Object { $_.path })
    }
    It 'the committed remediation script pins the module as it is now (run: pnpm --dir collector run package:stamp)' {
        $facts = Get-CollectorFacts -ModulePath $script:RealModule
        Test-RemediationStamp -ScriptPath (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Facts $facts | Should -BeNullOrEmpty
    }
    It 'the stamp changes with any file of the module, and stamping a copy fixes it' {
        $copy = Join-Path $TestDrive 'module-copy'
        Copy-Item -LiteralPath $script:RealModule -Destination $copy -Recurse
        $script2 = Join-Path $TestDrive 'Remediate-copy.ps1'
        Copy-Item -LiteralPath (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Destination $script2
        Add-Content -LiteralPath (Join-Path $copy 'Private/Json.ps1') -Value '# changed'
        $facts = Get-CollectorFacts -ModulePath $copy
        Test-RemediationStamp -ScriptPath $script2 -Facts $facts | Should -Match 'pins a different release'
        Set-RemediationStamp -ScriptPath $script2 -Facts $facts
        Test-RemediationStamp -ScriptPath $script2 -Facts $facts | Should -BeNullOrEmpty
        $after = Get-Content $script2 -Raw
        $after | Should -Match ([regex]::Escape($facts.Files[0].sha256))
        # Nothing outside the generated block changed.
        $a = (Get-Content (Join-Path $script:Intune 'Remediate-DoctorDO.ps1') -Raw) -split '# BEGIN GENERATED PINNED RELEASE'
        $b = $after -split '# BEGIN GENERATED PINNED RELEASE'
        $b[0] | Should -BeExactly $a[0]
        ($b[1] -split '# END GENERATED PINNED RELEASE')[1] | Should -BeExactly ($a[1] -split '# END GENERATED PINNED RELEASE')[1]
    }
    It 'the stamp is the identity the module has: GUID, author, exports, version' {
        $d = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RealModule 'DoctorDO.Collector.psd1')
        $DoctorDOExpectedGuid | Should -Be $d.GUID
        $DoctorDOExpectedAuthor | Should -Be $d.Author
        $DoctorDOPinnedVersion | Should -Be $d.ModuleVersion
        @($DoctorDOExpectedFunctions | Sort-Object) | Should -Be @($d.FunctionsToExport | Sort-Object)
        $DoctorDOPinnedFiles.Count | Should -Be @($d.FileList).Count
        # The default minimum is the release the script was built with.
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Intune 'Remediate-DoctorDO.ps1'), [ref]$null, [ref]$null)
        ($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MinimumVersion' }).DefaultValue.Value | Should -Be $d.ModuleVersion
        ($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'UpdatePolicy' }).DefaultValue.Value | Should -Be 'LatestVerified'
        ($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Repository' }).DefaultValue.Value | Should -Be 'PSGallery'
    }
    It 'collector-manifest.json lists every file with its SHA-256 and is read back by the remediation''s own parser' {
        $facts = Get-CollectorFacts -ModulePath $script:RealModule
        $json = ConvertTo-CollectorManifestJson -Facts $facts
        $json | Should -Match "\n$"
        $json | Should -Not -Match "`r"
        $spec = ConvertTo-DoctorDOSpecFromManifest -Json $json -ModuleName 'DoctorDO.Collector' -Version $facts.Version -ExpectedGuid $facts.Guid -ExpectedAuthor $facts.Author
        $spec.Files.Count | Should -Be $facts.Files.Count
        foreach ($f in $facts.Files) { $spec.Files[$f.path.ToLowerInvariant()] | Should -Be $f.sha256 }
        foreach ($f in $facts.Files) { (Get-FileHash -LiteralPath (Join-Path $script:RealModule $f.path) -Algorithm SHA256).Hash.ToLowerInvariant() | Should -Be $f.sha256 }
        $parsed = $json | ConvertFrom-Json
        $parsed.schema | Should -Be 'doctordo-collector-manifest/1'
        @($parsed.exports).Count | Should -Be 7
    }
    It 'the tool writes the manifest and checks the stamp when run' {
        $pwsh = (Get-Process -Id $PID).Path
        $out = Join-Path $TestDrive 'pkg-out'
        $null = @(& $pwsh -NoProfile -File (Join-Path $script:Tools 'package-collector.ps1') -OutputPath $out)
        $LASTEXITCODE | Should -Be 0
        Test-Path -LiteralPath (Join-Path $out 'collector-manifest.json') | Should -BeTrue
        $c = @(& $pwsh -NoProfile -File (Join-Path $script:Tools 'package-collector.ps1') -Check)
        $LASTEXITCODE | Should -Be 0
        "$c" | Should -Match 'up to date'
    }
}
