function Get-DOInventory {
    <#
    .SYNOPSIS
        Collects this device's Delivery Optimization inventory (InventoryV1) and returns it as a dictionary, without
        sending or writing anything.
    .DESCRIPTION
        Get-DOInventory collects the on-device inventory that fleet mode sends as its full report: identity and
        management (join type, Microsoft Entra device and tenant IDs, MDM enrolment, Intune device ID, ConfigMgr
        client), hardware, operating system, static device facts, network (adapter, VPN, proxy and PAC, DHCP options
        234 and 235), the complete Delivery Optimization configuration with the provider that set each value
        (Intune, Group Policy, the Settings app or the default), the Windows Firewall rules that matter to Delivery
        Optimization, and the connectivity matrix (see Get-DOConnectivityMatrix). On a device that showed the
        Autopilot Enrollment Status Page it adds a provisioning section, read from
        HKLM\SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking: for up to 30 Win32 apps the Intune app ID,
        installation state, reboot flag and status times, and, once within 7 days of provisioning, a summary of
        Delivery Optimization's jobs of that time (the 10 largest with their calling application, up to 64
        characters).

        Every fact that cannot be read is listed in notCollected with a reason (insufficient-rights, cmdlet-missing,
        unsupported-os, timeout, skipped-by-flag or error); nothing is silently left out or invented. The result
        follows DoctorDO's InventoryV1 schema.

        The command is read-only. It reads the collector's state file only for the per-device salt that keeps hashed
        identifiers stable, and never writes it; it does not flush the Delivery Optimization log, so DoSvc is not
        stopped; nothing is uploaded. It makes no call to Microsoft Graph. Unless -SkipConnectivityChecks is given it
        probes the Microsoft endpoints Delivery Optimization uses, as Test-DOConnectivity does.
    .PARAMETER Anonymise
        Remove the host name and reduce or hash the values that identify the device or the network (local subnet,
        default gateway, peer grouping ID, adapter name, PAC host, internal content hosts). Run
        Invoke-DoctorDOCollector -WhatIfRedaction for the full list. The management section's Entra device, tenant
        and Intune device IDs stay in the inventory either way.
    .PARAMETER SkipConnectivityChecks
        Do not probe the network (for air-gapped or change-frozen environments). The connectivity checks are reported
        as not-collected.
    .PARAMETER StatePath
        Where the per-device salt is read from. Default: %ProgramData%\DoctorDO\state.json. The file is read, never
        changed. When it does not exist, or the folder is not one the collector trusts, a new random salt is used for
        this run only, so hashed identifiers such as deviceId differ from run to run.
    .PARAMETER PublicIpProbeUri
        Optional https URL of a service you trust that returns the caller's public IP address as plain text, used
        only when the Delivery Optimization geo answer gives no address. Supplying it turns on the public egress
        hash. The address is hashed at once and never stored.
    .PARAMETER CollectPublicEgress
        Add a salted hash of the public egress address read from the Delivery Optimization geo service's answer (no
        third-party service is called). Off by default.
    .PARAMETER RangeProbeUri
        Optional extra object for the HTTP byte-range check, used only when its host is a Microsoft content host in
        Data\endpoints.json. Normally not needed: a file the device itself downloaded is used.
    .EXAMPLE
        Get-DOInventory -Anonymise | ConvertTo-Json -Depth 32 | Set-Content -Path C:\Temp\inventory.json -Encoding UTF8

        Collects an anonymised inventory and saves it as JSON, for example to compare two devices or to attach to a
        support request. Run it from an elevated prompt for the full picture.
    .EXAMPLE
        $inv = Get-DOInventory -SkipConnectivityChecks
        $inv['doConfig']['effective'].GetEnumerator() | ForEach-Object { '{0} = {1} ({2})' -f $_.Key, $_.Value['value'], $_.Value['provider'] }

        Lists every Delivery Optimization setting in force on the device with the provider that set it, without
        touching the network. For example: DODownloadMode = 2 (Mdm).
    .EXAMPLE
        (Get-DOInventory)['notCollected'] | ForEach-Object { [pscustomobject]$_ } | Format-Table field, reason, detail -Wrap

        Shows what could not be read on this device and why. Running without elevation lists the facts that need
        administrator rights as insufficient-rights.
    .INPUTS
        None. You cannot pipe objects to Get-DOInventory.
    .OUTPUTS
        System.Collections.Specialized.OrderedDictionary. One InventoryV1 report (kind 'inventory', schemaVersion 1).
        Convert it with ConvertTo-Json -Depth 32.
    .NOTES
        Runs on Windows. Elevation is not required, but without it the Delivery Optimization logs and some registry
        keys cannot be read and are listed in notCollected. Takes about as long as one collector run (typically under
        a minute; endpoint probes are capped at 40 seconds in total).

        Read-only: no file, registry value or service is changed, and no report is sent (the connectivity checks
        still contact the endpoints they test, unless -SkipConnectivityChecks). To send the
        inventory, use Invoke-DoctorDOCollector -Fleet, which decides when an inventory is due.
    .LINK
        https://www.doctor-do.com/data/
    .LINK
        about_DoctorDO.Collector
    .LINK
        Get-DOTelemetry
    .LINK
        Get-DOConnectivityMatrix
    .LINK
        Invoke-DoctorDOCollector
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [switch] $Anonymise,
        [switch] $SkipConnectivityChecks,
        [string] $StatePath,
        [string] $PublicIpProbeUri,
        [switch] $CollectPublicEgress,
        [string] $RangeProbeUri
    )
    if (-not $StatePath) { $StatePath = Get-DDDefaultStatePath }
    $st = (Read-DDState -Path $StatePath).State
    $collection = Get-DDRawCollection -Salt $st['salt'] -Anonymise:$Anonymise -SkipConnectivityChecks:$SkipConnectivityChecks -PublicIpProbeUri $PublicIpProbeUri -CollectPublicEgress:$CollectPublicEgress -RangeProbeUri $RangeProbeUri
    $collection.Provisioning = Resolve-DDProvisioning -Fresh $collection.Provisioning -Stored $st['provisioning']
    ConvertTo-DDInventory -Collection $collection
}
