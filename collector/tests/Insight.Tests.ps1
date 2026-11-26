#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Configuration source attribution and endpoint discovery (ADR-0031).
#
# Fixture provenance. Every shape below was read on a real device, not invented:
#  - Get-DOConfig -Verbose: Windows 11 26H2 (this repository's lab machine) returns DOExtendedConfig with "<Name>Provider"
#    properties of the enum ConfigProvider (RegistryProvider 5, MdmProvider 7, SettingsProvider 8, AdminProvider 9,
#    DefaultProvider 99); an Intune-managed device's Format-List of the same object shows "MdmProvider" (a support bundle).
#  - PolicyManager\current\device\<Area>: "<Name>", "<Name>_ProviderSet" = 1, "<Name>_WinningProvider" = GUID without
#    braces; Enrollments\<GUID>\ProviderID "MS DM Server" (Intune), "WMI_Bridge_SCCM_Server" (ConfigMgr co-management);
#    ControlPolicyConflict\MDMWinsOverGP = 1.
#  - DO log lines: copied from a real Get-DeliveryOptimizationLog export (DO client 10.1.0.15), shortened only where noted.
#  - MSFT_DeliveryOptimizationFile.CacheHost "198.51.100.203"; MSFT_DeliveryOptimizationFilePeerInfo IPs/PeerTypes arrays.
#  - Get-NetTCPConnection -OwningProcess <DoSvc PID>: Listen on :: 7680, Established to remote 443.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-DDModule
}

Describe 'Get-DOConfig providers' {
    It 'reads the per-setting Provider properties as providers, never as settings (the "28 by another source" bug)' {
        InModuleScope DoctorDO.Collector {
            # A DOExtendedConfig as a managed device returns it: providers are enum values (string form here, as they
            # format), MaxUploadRatePct is paired with MaxUploadRateProvider, and an unset business-hours window is ''.
            $cfg = [pscustomobject]@{
                DownloadMode = 'Group'; DownloadModeProvider = 'MdmProvider'; DownBackLimitPct = 45; DownBackLimitPctProvider = 'DefaultProvider'
                MaxUploadRatePct = 50; MaxUploadRateProvider = 'DefaultProvider'; MinTotalRAM = 1; MinTotalRAMProvider = 'MdmProvider'
                VpnPeerCachingAllowed = $false; VpnPeerCachingAllowedProvider = 'MdmProvider'; SetHoursToLimitDownloadBackground = ''
                SetHoursToLimitDownloadBackgroundProvider = 'DefaultProvider'; WorkingDirectory = 'C:\x'; WorkingDirectoryProvider = 'DefaultProvider'
                VpnKeywords = 'VPN;Secure;'; VpnKeywordsProvider = 'DefaultProvider'; UploadLimitMonthlyGB = 5120; UploadLimitMonthlyGBProvider = 7
            }
            $r = ConvertFrom-DDDoConfig -Config $cfg
            $e = $r.Effective
            @($e.Keys | Where-Object { $_ -match 'Provider$' }) | Should -BeNullOrEmpty
            $e.Count | Should -Be 7
            $e['DODownloadMode'].value | Should -Be 2
            $e['DODownloadMode'].provider | Should -Be 'Mdm'
            $r.Kinds['DODownloadMode'] | Should -Be 'mdm'
            $e['DOMaxUploadBandwidth'].provider | Should -Be 'Default' -Because 'MaxUploadRateProvider belongs to MaxUploadRatePct'
            $e['DOMonthlyUploadDataCap'].provider | Should -Be 'Mdm' -Because 'the CIM class reports the provider as a number (7)'
            $e['DOSetHoursToLimitBackgroundDownloadBandwidth'].value | Should -Be ''
            $r.VpnKeywords | Should -Be 'VPN;Secure;'
        }
    }

    It 'maps every ConfigProvider value, as a name, a number or the documented text' {
        InModuleScope DoctorDO.Collector {
            @('RegistryProvider', 'MdmProvider', 'SettingsProvider', 'AdminProvider', 'DefaultProvider', 5, 7, 8, 9, 99, 'Mdm Provider', 'Default Provider', 'Nonsense', $null) |
                ForEach-Object { ConvertTo-DDProviderKind -Value $_ } |
                Should -Be @('gp', 'mdm', 'local', 'admin', 'default', 'gp', 'mdm', 'local', 'admin', 'default', 'mdm', 'default', 'unknown', 'unknown')
        }
    }
}

Describe 'Resolve-DDSettingSources' {
    BeforeAll {
        $script:Guid = 'C834B271-E12C-4B38-89CC-B5A7062BACAD'
        $script:Enrol = @(
            [pscustomobject]@{ EnrollmentId = 'C834B271-E12C-4B38-89CC-B5A7062BACAD'; ProviderId = 'MS DM Server' },
            [pscustomobject]@{ EnrollmentId = '9E1255FB-1BE1-4F78-8E0A-9B6FB62D504A'; ProviderId = 'WMI_Bridge_SCCM_Server' })
        $script:Mdm = @{ Present = $true; Values = @(
                [ordered]@{ name = 'DODownloadMode'; type = 'REG_DWORD'; data = '2' }, [ordered]@{ name = 'DODownloadMode_ProviderSet'; type = 'REG_DWORD'; data = '1' },
                [ordered]@{ name = 'DODownloadMode_WinningProvider'; type = 'REG_SZ'; data = 'C834B271-E12C-4B38-89CC-B5A7062BACAD' },
                [ordered]@{ name = 'DOCacheHost'; type = 'REG_SZ'; data = 'mcc01.contoso.example' }, [ordered]@{ name = 'DOCacheHost_ProviderSet'; type = 'REG_DWORD'; data = '1' },
                [ordered]@{ name = 'DOCacheHost_WinningProvider'; type = 'REG_SZ'; data = '9E1255FB-1BE1-4F78-8E0A-9B6FB62D504A' },
                [ordered]@{ name = 'DOMaxCacheAge'; type = 'REG_DWORD'; data = '604800' }, [ordered]@{ name = 'DOMaxCacheAge_WinningProvider'; type = 'REG_SZ'; data = 'C834B271-E12C-4B38-89CC-B5A7062BACAD' }) }
        $script:Gp = @{ Present = $true; Values = @([ordered]@{ name = 'DOMaxCacheAge'; type = 'REG_DWORD'; data = '86400' }, [ordered]@{ name = 'DOGroupId'; type = 'REG_SZ'; data = 'grp' }) }
        $script:Local = @{ Present = $true; Values = @([ordered]@{ name = 'DownloadMode'; type = 'REG_DWORD'; data = '1' }) }
    }

    It 'attributes MDM to the winning enrolment (Intune or other), adds policy-only settings, and keeps DO''s own provider first' {
        InModuleScope DoctorDO.Collector -Parameters @{ M = $script:Mdm; G = $script:Gp; L = $script:Local; E = $script:Enrol } {
            param($M, $G, $L, $E)
            $eff = [ordered]@{ DODownloadMode = [ordered]@{ value = 2; provider = 'Mdm' }; DOMinRAMAllowedToPeer = [ordered]@{ value = 4; provider = 'Default' } }
            $r = Resolve-DDSettingSources -Effective $eff -Kinds @{ DODownloadMode = 'mdm'; DOMinRAMAllowedToPeer = 'default' } -MdmStore $M -PolicyStore $G -LocalStore $L -Enrollments $E -MdmWinsOverGp $true
            $r['DODownloadMode'].source.kind | Should -Be 'mdm'
            $r['DODownloadMode'].source.basis | Should -Be 'do-service'
            $r['DODownloadMode'].source.mdm.provider | Should -Be 'intune'
            $r['DODownloadMode'].source.mdm.providerId | Should -Be 'MS DM Server'
            $r['DODownloadMode'].source.setIn | Should -Be @('mdm', 'local') -Because 'the Settings app value is matched without the DO prefix'
            ($r['DODownloadMode'].source.alt | Where-Object store -eq 'local').value | Should -Be 1
            $r['DOMinRAMAllowedToPeer'].source.kind | Should -Be 'default'
            $r['DOCacheHost'].value | Should -Be 'mcc01.contoso.example' -Because 'Get-DOConfig does not report it; the policy store does'
            $r['DOCacheHost'].source.mdm.provider | Should -Be 'other'
            $r['DOCacheHost'].source.mdm.providerId | Should -Be 'WMI_Bridge_SCCM_Server'
            $r['DOCacheHost'].provider | Should -Be 'Mdm'
            $r['DOGroupId'].source.kind | Should -Be 'gp'
            $r['DOGroupId'].source.basis | Should -Be 'registry'
            $r.Contains('DODownloadMode_WinningProvider') | Should -BeFalse
        }
    }

    It 'MDM and Group Policy both set it: MDM wins only under MDMWinsOverGP = 1; otherwise no winner is claimed' {
        InModuleScope DoctorDO.Collector -Parameters @{ M = $script:Mdm; G = $script:Gp; E = $script:Enrol } {
            param($M, $G, $E)
            $won = Resolve-DDSettingSources -Effective ([ordered]@{}) -MdmStore $M -PolicyStore $G -Enrollments $E -MdmWinsOverGp $true
            $won['DOMaxCacheAge'].source.kind | Should -Be 'mdm'
            $won['DOMaxCacheAge'].source.basis | Should -Be 'mdm-wins-over-gp'
            $won['DOMaxCacheAge'].value | Should -Be 604800
            ($won['DOMaxCacheAge'].source.alt | Where-Object store -eq 'gp').value | Should -Be 86400
            $race = Resolve-DDSettingSources -Effective ([ordered]@{}) -MdmStore $M -PolicyStore $G -Enrollments $E -MdmWinsOverGp $false
            $race['DOMaxCacheAge'].source.kind | Should -Be 'unknown'
            $race['DOMaxCacheAge'].source.basis | Should -Be 'unresolved'
            $race['DOMaxCacheAge'].source.setIn | Should -Be @('mdm', 'gp')
            $race['DOMaxCacheAge'].provider | Should -Be 'Unknown'
        }
    }

    It 'keeps DOGroupId hashed and the cache host in clear under -Anonymise, through Get-DOInventory' {
        Initialize-FakeDevice -CacheHost 'cache.contoso.example'
        $inv = Get-DOInventory -StatePath (Join-Path $TestDrive 'state.json') -Anonymise
        $inv.doConfig.effective.DOGroupId.value | Should -Match '^redacted:[0-9a-f]{16}$'
        $inv.doConfig.effective.DOCacheHost.value | Should -Be 'cache.contoso.example'
        $inv.doConfig.effective.DODownloadMode.source.kind | Should -Be 'gp'
    }

    It 'hashes the group ID, DHCP option 234 and an internal source host with the tenant salt: equal on two devices, different in another tenant; the gateway stays per device (A-17, C-35)' {
        InModuleScope DoctorDO.Collector {
            $a = New-DDContext -Salt ('a' * 64) -TenantSalt ('t' * 64) -Anonymise
            $b = New-DDContext -Salt ('b' * 64) -TenantSalt ('t' * 64) -Anonymise
            $other = New-DDContext -Salt ('a' * 64) -TenantSalt ('u' * 64) -Anonymise
            $dumps = { [ordered]@{ policy = @{ Key = 'K'; Present = $true; Confidence = 'documented'; Values = @([ordered]@{ name = 'DOGroupId'; type = 'REG_SZ'; data = 'A1B2C3D4-AAAA-BBBB-CCCC-0123456789AB' }) } } }
            $gid = { param($c) (Get-DDDoStores -Context $c -Dumps (& $dumps))['policy']['values'][0]['data'] }
            (& $gid $a) | Should -Match '^redacted:[0-9a-f]{16}$'
            (& $gid $a) | Should -Be (& $gid $b) -Because 'one group ID set on two devices of a tenant is one value the console can compare'
            (& $gid $a) | Should -Not -Be (& $gid $other)
            $row = { param($c) (ConvertTo-DDStatusRow -Context $c -Item ([pscustomobject]@{ FileId = 'f1'; SourceURL = 'http://wsus01.corp.contoso.example:8530/Content/x.cab' }))['sourceUrlHost'] }
            (& $row $a) | Should -Match '^host:[0-9a-f]{16}$'
            (& $row $a) | Should -Be (& $row $b)
            (& $row $a) | Should -Not -Be (& $row $other)
        }
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDRegistryValues {
            if ($Path -match 'Policies\\Microsoft\\Windows\\DeliveryOptimization$') { @{ Present = $true; Values = @([ordered]@{ name = 'DODownloadMode'; type = 'REG_DWORD'; data = '2' }, [ordered]@{ name = 'DOGroupIdSource'; type = 'REG_DWORD'; data = '3' }) } }
            else { @{ Present = $false; Values = @() } }
        }
        Mock -ModuleName DoctorDO.Collector Get-DDDhcpOptionsRaw {
            [pscustomobject]@{ Attempted = $true; TimedOut = $false; Win32Error = 0; Options = @(foreach ($id in $OptionIds) { [pscustomobject]@{ OptionId = $id; Present = $true; Data = $(if ($id -eq 1) { [byte[]](255, 255, 252, 0) } else { [System.Text.Encoding]::ASCII.GetBytes('a1b2c3d4-0000-4000-8000-0000000000aa') }) } }) }
        }
        # Two devices of one tenant: each state file holds its own random device salt.
        $one = Get-DOInventory -StatePath (Join-Path $TestDrive 'one.json') -Anonymise
        $two = Get-DOInventory -StatePath (Join-Path $TestDrive 'two.json') -Anonymise
        $one.network.dhcpOption234 | Should -Match '^redacted:[0-9a-f]{16}$'
        $one.network.dhcpOption234 | Should -Be $two.network.dhcpOption234
        $one.doConfig.effective.DOGroupId.value | Should -Be $two.doConfig.effective.DOGroupId.value
        $one.network.defaultGateway | Should -Not -Be $two.network.defaultGateway -Because 'the gateway stays hashed with the device salt'
    }
}

Describe 'Endpoints' {
    It 'normalises a cache host from the job list, the log and policy' {
        InModuleScope DoctorDO.Collector {
            ConvertTo-DDCacheHostName ([uri]'198.51.100.203') | Should -Be '198.51.100.203'
            ConvertTo-DDCacheHostName 'http://user:pw@MCC01.Contoso.Example:8080/path?x=1' | Should -Be 'mcc01.contoso.example'
            ConvertTo-DDCacheHostName '[2001:db8::5]:80' | Should -Be '2001:db8::5'
            ConvertTo-DDCacheHostName 'not a host' | Should -BeNullOrEmpty
        }
    }

    It 'reads the real DO log formats: CDN and cache bytes, the cache origin, HTTP and peer connections, failures' {
        InModuleScope DoctorDO.Collector {
            $t = [datetime]::new(2026, 9, 9, 12, 42, 42, [System.DateTimeKind]::Utc)
            $e = @(
                [pscustomobject]@{ TimeCreated = $t; Function = 'CServiceConfigProvider::_CallService'; Message = 'GEO response: {"ExternalIpAddress":"203.0.113.18","CountryCode":"IE","CacheHost":"198.51.100.202","CacheId":"7"}' },
                [pscustomobject]@{ TimeCreated = $t; Function = 'CHttpPeerConn::Initiate'; Message = 'Swarm: c7b6993f752a7d9dffcd8015cb6ded537114c3994ae6fa6b7035f109acb6b2c1, initiating HTTP connection, IP: 198.51.100.202' },
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(3); Function = 'CHttpPeerConn::Initiate'; Message = 'Swarm: c7b6993f752a7d9dffcd8015cb6ded537114c3994ae6fa6b7035f109acb6b2c1, initiating HTTP connection, IP: 150.171.109.244' },
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(3); Function = 'CHttpPeerConn::_OnComplete'; Message = 'Swarm: c7b6993f752a7d9dffcd8015cb6ded537114c3994ae6fa6b7035f109acb6b2c1, HTTP connection: [150.171.109.244]:443, rLEDBAT? 0' },
                # TraceDownloadCompletedImpl, shortened after the conns list
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(4); Function = 'CTelemetryLogger::TraceDownloadCompletedImpl'; Message = 'jobId: 79baace7-0757-44ee-bfed-6c0ff9e05389, fileId: c7b6993f752a7d9dffcd8015cb6ded537114c3994ae6fa6b7035f109acb6b2c1, sessionId: 8cb9aaba-820a-4067-bb38-0d41bcb4c862, updateId: , caller: MDM EDAM Job, cdnUrl = https://imeswdb-afd-hotfix.manage.microsoft.com/IntuneWindowsAgent.msi, cdnIp = [150.171.109.244]:443;, cacheHost = Services:198.51.100.202, bytes: [File: 13754368, CDN: 13754368, DOINC: 0, rledbat: 0, LAN: 0, LinkLocal: 0, Group: 0, inet: 0, lcache: 0, req: 0, total: 2:13754368;], peers: 0 (local 0), conns: [CDN: 1, DOINC: 1, LAN: 0, LinkLocal: 0, Group: 0, inet: 0]' },
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(40); Function = 'CTelemetryLogger::TraceDownloadCompletedImpl'; Message = 'jobId: 583f667e-f459-41fd-94e4-b69e068112f1, fileId: 95D2EE60-C9D3-45E4-876D-BAE16D758A87_16_0_20326_20142_I640_CAB, caller: Microsoft Office Click-to-Run, cdnUrl = http://f.c2r.ts.cdn.office.net/pr/x/i640.cab, cdnIp = [198.51.100.202]:80;X-CCC:cf76886c-0f1e-4665-ace2-6cdc177fc6bc;X-CID:10006;, cacheHost = Services:198.51.100.202, bytes: [File: 32761464, CDN: 31712888, DOINC: 31712888, rledbat: 0, LAN: 0, LinkLocal: 0, Group: 0, inet: 0, lcache: 1048576, req: 0, total: 5:32761464;], peers: 0 (local 0)' },
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(170); Function = 'CSwarmConn::Initiate'; Message = 'Swarm: 95D2EE60-C9D3-45E4-876D-BAE16D758A87_16_0_20326_20142_STREAM_X64_X_NONE, initiating peer connection: [10.100.0.74]:7680' },
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(193); Function = 'CTelemetryLogger::TraceErrorPeerComm'; Message = 'FailurePeerConnect, hr: 8007274c, msg: Socket connect error, fileId: 95D2EE60-C9D3-45E4-876D-BAE16D758A87_16_0_20326_20142_STREAM_X64_X_NONE, sessionId: a728e318-7d62-4692-b7a7-dd578eda8047, peerIp: [10.100.0.74]:7680, peerId: , peerType: 1' },
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(171); Function = 'CHttpDownloader::_DoSendRequest'; Message = 'Unresponsive cache host 198.51.100.202' },
                [pscustomobject]@{ TimeCreated = $t.AddSeconds(206); Function = 'CConnMan::_StartNewHttpConns'; Message = 'Connecting to banned cache host 198.51.100.202. Time until fallback: 49731 ms.' })
            $obs = ConvertFrom-DDDoLogEndpoints -Entries $e -LocalAddress '10.100.0.20' -PrefixLength 24
            $ctx = New-DDContext -Salt 's'
            $rows = Merge-DDEndpoints -Observations $obs -Context $ctx
            $cache = $rows | Where-Object role -eq 'cache'
            $cache.addr | Should -Be '198.51.100.202'
            $cache.origin | Should -Be 'service' -Because 'the log says "cacheHost = Services:..." and the GEO response names it'
            $cache.rx | Should -Be '31712888'
            $cache.fails | Should -Be 2
            $cache.conns | Should -Be 1
            $cdn = $rows | Where-Object role -eq 'cdn'
            $cdn.addr | Should -Be '150.171.109.244'
            $cdn.rx | Should -Be '13754368' -Because 'CDN bytes include DOINC; only the remainder came from the CDN node'
            $cdn.ok | Should -Be 1
            $peer = $rows | Where-Object role -eq 'lan'
            $peer.addr | Should -Be '10.100.0.74'
            $peer.conns | Should -Be 1; $peer.fails | Should -Be 1
            $peer.first | Should -Be '2026-09-09T12:45:32Z'
            ($rows | ConvertTo-Json -Depth 5) | Should -Not -Match '86\.45\.209' -Because 'the GEO response''s public address is never read'
        }
    }

    It 'takes the cache host and its bytes from the job list, and peers from the CIM peer list (numbers) or the cmdlet (names)' {
        InModuleScope DoctorDO.Collector {
            $st = ConvertFrom-DDStatusEndpoints -Items @(
                [pscustomobject]@{ FileId = 'a'; CacheHost = [uri]'198.51.100.203'; BytesFromCacheServer = 910919; CacheServerConnectionCount = 1 },
                [pscustomobject]@{ FileId = 'b'; CacheHost = [uri]'198.51.100.204'; BytesFromCacheServer = 0; CacheServerConnectionCount = 1 },
                [pscustomobject]@{ FileId = 'c'; CacheHost = $null })
            $pe = ConvertFrom-DDPeerEndpoints -Items @(
                [pscustomobject]@{ FileId = 'a'; Peers = @([pscustomobject]@{ IP = '10.100.0.74'; PeerType = 1; ConnectionEstablished = $true; BytesSent = 10; BytesReceived = 5000 },
                        [pscustomobject]@{ IP = '203.0.113.9'; PeerType = 'PeerType_Internet'; ConnectionEstablished = $false; BytesSent = 0; BytesReceived = 0 },
                        [pscustomobject]@{ IP = '10.30.0.5'; PeerType = 4; ConnectionEstablished = $true; BytesSent = 0; BytesReceived = 70 }) })
            $rows = Merge-DDEndpoints -Observations (@($st) + @($pe)) -Context (New-DDContext -Salt 's')
            ($rows | Select-Object -First 2 | ForEach-Object { $_.addr }) | Should -Be @('198.51.100.203', '198.51.100.204') -Because 'cache servers lead, most bytes first'
            ($rows | Where-Object addr -eq '198.51.100.204').rx | Should -Be '0' -Because 'paired with a file but served nothing: offered, not used'
            ($rows | Where-Object role -eq 'lan').rx | Should -Be '5000'
            ($rows | Where-Object role -eq 'group').addr | Should -Be '10.30.0.5'
            ($rows | Where-Object role -eq 'internet').addr | Should -Be '203.0.113.0/24' -Because 'an internet peer is someone else''s device: always a prefix'
        }
    }

    It 'reduces LAN and group peers to a /24 or /48 under -Anonymise and folds them, keeping the infrastructure in clear' {
        InModuleScope DoctorDO.Collector {
            $o = @(
                (New-DDEndpointObservation -Role lan -Address '10.20.4.55' -Via peers -Rx 100 -Attempts 1 -Ok 1),
                (New-DDEndpointObservation -Role lan -Address '10.20.4.56' -Via peers -Rx 50 -Attempts 1 -Ok 1),
                (New-DDEndpointObservation -Role group -Address '2001:db8:1:2::5' -Via peers -Rx 7),
                (New-DDEndpointObservation -Role cache -Address 'mcc01.contoso.example' -Via status -Rx 9),
                (New-DDEndpointObservation -Role cdn -Address '150.171.109.244' -Via log -Rx 1),
                (New-DDEndpointObservation -Role peer -Address '127.0.0.1' -Via tcp))
            $rows = Merge-DDEndpoints -Observations $o -Context (New-DDContext -Salt 's' -Anonymise)
            $lan = $rows | Where-Object role -eq 'lan'
            $lan.addr | Should -Be '10.20.4.0/24'
            $lan.n | Should -Be 2
            $lan.rx | Should -Be '150' -Because 'two peers in one prefix: their bytes add up within one source'
            ($rows | Where-Object role -eq 'group').addr | Should -Be '2001:db8:1::/48'
            ($rows | Where-Object role -eq 'cache').addr | Should -Be 'mcc01.contoso.example'
            ($rows | Where-Object role -eq 'cdn').addr | Should -Be '150.171.109.244'
            @($rows | Where-Object role -eq 'peer') | Should -BeNullOrEmpty -Because 'loopback is never an endpoint'
            ($rows | ConvertTo-Json -Depth 5) | Should -Not -Match '10\.20\.4\.5[56]'
        }
    }

    It 'takes peers on TCP 7680 and known cache hosts from DoSvc''s connections, ignoring listeners and other HTTPS' {
        InModuleScope DoctorDO.Collector {
            $when = [datetime]::new(2026, 10, 13, 14, 49, 40, [System.DateTimeKind]::Utc)
            $tcp = @(
                [pscustomobject]@{ LocalAddress = '::'; LocalPort = 7680; RemoteAddress = '::'; RemotePort = 0; State = 'Listen'; CreationTime = $when },
                [pscustomobject]@{ LocalAddress = '192.168.7.19'; LocalPort = 63265; RemoteAddress = '72.154.7.98'; RemotePort = 443; State = 'Established'; CreationTime = $when },
                [pscustomobject]@{ LocalAddress = '192.168.7.19'; LocalPort = 7680; RemoteAddress = '192.168.7.40'; RemotePort = 50123; State = 'Established'; CreationTime = $when },
                [pscustomobject]@{ LocalAddress = '192.168.7.19'; LocalPort = 63300; RemoteAddress = '198.51.100.203'; RemotePort = 80; State = 'Established'; CreationTime = $when })
            $o = ConvertFrom-DDTcpEndpoints -Items $tcp -CacheHosts @('198.51.100.203') -LocalAddress '192.168.7.19' -PrefixLength 24
            @($o).Count | Should -Be 2
            ($o | Where-Object Role -eq 'lan').Address | Should -Be '192.168.7.40'
            ($o | Where-Object Role -eq 'cache').Ok | Should -Be 1
        }
    }

    It 'counts an IPv6 peer on 7680 as LAN when it is link-local or inside one of the device''s IPv6 prefixes (A-14)' {
        InModuleScope DoctorDO.Collector {
            $when = [datetime]::new(2026, 10, 13, 14, 49, 40, [System.DateTimeKind]::Utc)
            $tcp = @(
                [pscustomobject]@{ LocalAddress = 'fe80::5'; LocalPort = 7680; RemoteAddress = 'fe80::1c2d:3e4f:5a6b:7c8d'; RemotePort = 50123; State = 'Established'; CreationTime = $when },
                [pscustomobject]@{ LocalAddress = '2001:db8:1:2::5'; LocalPort = 7680; RemoteAddress = '2001:db8:1:2::9'; RemotePort = 50124; State = 'Established'; CreationTime = $when },
                [pscustomobject]@{ LocalAddress = '2001:db8:1:2::5'; LocalPort = 50125; RemoteAddress = '2001:db8:9:9::9'; RemotePort = 7680; State = 'Established'; CreationTime = $when })
            $o = ConvertFrom-DDTcpEndpoints -Items $tcp -LocalAddress '192.168.7.19' -PrefixLength 24 -LocalNetworks @('2001:db8:1:2::5/64')
            @($o | Where-Object Role -eq 'lan' | ForEach-Object Address) | Should -Be @('fe80::1c2d:3e4f:5a6b:7c8d', '2001:db8:1:2::9')
            @($o | Where-Object Role -eq 'peer' | ForEach-Object Address) | Should -Be @('2001:db8:9:9::9')
            $entries = @([pscustomobject]@{ TimeCreated = $when; Function = 'CSwarmConn::Initiate'; Message = 'Swarm: x, initiating peer connection: [2001:db8:1:2::9]:7680' })
            (ConvertFrom-DDDoLogEndpoints -Entries $entries -LocalAddress '192.168.7.19' -PrefixLength 24 -LocalNetworks @('2001:db8:1:2::5/64'))[0].Role | Should -Be 'lan'
            (ConvertFrom-DDDoLogEndpoints -Entries $entries -LocalAddress '192.168.7.19' -PrefixLength 24)[0].Role | Should -Be 'peer'
        }
    }

    It 'sends endpoints and the per-file cache host in telemetry, cache first and capped' {
        Initialize-FakeDevice
        Mock -ModuleName DoctorDO.Collector Get-DDDOStatusRaw {
            @([pscustomobject]@{ FileId = ('{0:x40}' -f 1); FileSize = 2000; TotalBytesDownloaded = 2000; BytesFromHttp = 2000; BytesFromCacheServer = 1500; BytesFromLanPeers = 0; DownloadMode = 1; Status = 'Caching'; Priority = 'Background'
                    SourceURL = 'http://1D.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/x'; CacheHost = [uri]'198.51.100.203'; PredefinedCallerApplication = 'WU Client Download' })
        }
        Mock -ModuleName DoctorDO.Collector Get-DDDoSvcTcpConnections {
            @([pscustomobject]@{ LocalAddress = '10.20.4.71'; LocalPort = 7680; RemoteAddress = '10.20.4.90'; RemotePort = 51000; State = 'Established'; CreationTime = [datetime]::new(2026, 10, 12, 7, 59, 0, [System.DateTimeKind]::Utc) })
        }
        # The last accepted report had no jobs, so the one job listed now is new since then and is sent.
        InModuleScope DoctorDO.Collector -Parameters @{ P = (Join-Path $TestDrive 'state.json') } {
            param($P)
            $st = New-DDState
            $st['counters'] = Get-DDNextCounters -Raw ([ordered]@{ status = @(); peerInfo = @(); connections = @(); notCollected = @() }) -Previous $null
            Save-DDState -Path $P -State $st
        }
        $t = Get-DOTelemetry -StatePath (Join-Path $TestDrive 'state.json') -Anonymise
        $t.endpoints[0].role | Should -Be 'cache'
        $t.endpoints[0].addr | Should -Be '198.51.100.203'
        $t.endpoints[0].rx | Should -Be 1500
        $t.files[0].ch | Should -Be '198.51.100.203'
        ($t.endpoints | Where-Object role -eq 'lan').addr | Should -Be '10.20.4.0/24'
        @($t.endpoints).Count | Should -BeLessOrEqual 24
        Assert-ValidAgainstSchema -Object $t -SchemaFile (Get-ContractPath 'telemetry-v1.schema.json')
    }
}
