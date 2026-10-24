#Requires -Version 5.1
<#
.SYNOPSIS
  Stops and removes the Leaf Vault service and its program files. Run from an elevated PowerShell.

.DESCRIPTION
  Without -RemoveData the encrypted store in C:\ProgramData\Leaf Vault\ and the service profile
  (which holds the DPAPI keys and the badge signing key) are kept, so a reinstall picks up every
  secret again. With -RemoveData both are deleted: every stored secret is gone and every badge the
  vault signed stops verifying.
#>
[CmdletBinding()]
param(
    [switch]$RemoveData,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Leaf Vault must be uninstalled from an elevated PowerShell (Run as administrator).'
}

$serviceName = 'LeafVault'
$installDir = Join-Path $env:ProgramFiles 'Leaf Vault'
$dataDir = Join-Path $env:ProgramData 'Leaf Vault'
$profileDir = Join-Path $env:SystemRoot "ServiceProfiles\$serviceName"
$serviceSid = (((sc.exe showsid $serviceName) -match 'SERVICE SID:' | Select-Object -First 1) -replace '.*SERVICE SID:\s*', '').Trim()

if ($RemoveData -and -not $Yes) {
    $answer = Read-Host "Delete every secret in $dataDir and the vault's signing key? This cannot be undone. [y/N]"
    if ($answer -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; return }
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc delete $serviceName failed (exit $LASTEXITCODE)." }
    Write-Host "Removed service $serviceName."
}
if (Test-Path -LiteralPath $installDir) {
    Remove-Item -LiteralPath $installDir -Recurse -Force
    Write-Host "Removed $installDir."
}
$eventSource = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Leaf Vault'
if (Test-Path $eventSource) { Remove-Item -Path $eventSource -Recurse -Force }

if (-not $RemoveData) {
    Write-Host "Kept $dataDir and the service profile (encrypted; readable only by NT SERVICE\$serviceName)."
    Write-Host 'Reinstalling reuses them. Pass -RemoveData to delete them.'
    return
}

function Remove-OwnedTree([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    # The tree is owned by and only readable to the service account: take it back first.
    takeown /F $Path /R /A /D Y | Out-Null
    icacls $Path /reset /T /C /Q | Out-Null
    Remove-Item -LiteralPath $Path -Recurse -Force
    Write-Host "Removed $Path."
}

Remove-OwnedTree $dataDir
$userProfile = if ($serviceSid -match '^S-1-5-80-') { Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $serviceSid } } else { $null }
if ($userProfile) {
    $userProfile | Remove-CimInstance
    Write-Host "Removed the service profile of NT SERVICE\$serviceName."
}
Remove-OwnedTree $profileDir
Write-Host 'All Leaf Vault secrets and the badge signing key are deleted.'
