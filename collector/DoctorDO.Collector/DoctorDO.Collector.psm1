#Requires -Version 5.1
# DoctorDO.Collector root module: dot-sources Private/*.ps1 then Public/*.ps1. Public functions are
# exported explicitly (see the manifest) and nothing is exported implicitly.
Set-StrictMode -Version Latest

try { Add-Type -Verbose:$false -AssemblyName System.Numerics -ErrorAction Stop } catch { Write-Verbose "System.Numerics already loaded: $($_.Exception.Message)" }

$script:ModuleRoot = $PSScriptRoot
$script:CollectorVersion = '1.2.3'
foreach ($dir in 'Private', 'Public') {
    $path = Join-Path -Path $PSScriptRoot -ChildPath $dir
    if (Test-Path -LiteralPath $path) {
        foreach ($file in (Get-ChildItem -LiteralPath $path -Filter '*.ps1' -File | Sort-Object -Property Name)) {
            . $file.FullName
        }
    }
}
