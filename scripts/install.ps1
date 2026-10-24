#Requires -Version 5.1
<#
.SYNOPSIS
  Installs or updates Leaf Vault as a Windows service. Run from an elevated PowerShell.

.DESCRIPTION
  1. Refuses to run unelevated, or from a working tree with uncommitted changes (unless -AllowDirty).
  2. Publishes src/Leaf.Vault (Release, locked NuGet restore) to a temp folder and shows the version,
     the git commit and the SHA-256 of Leaf.Vault.dll, then asks for confirmation (-Yes skips it).
  3. Stops the service if it exists and replaces C:\Program Files\Leaf Vault\ (ACL reset to inherit
     from Program Files: administrators write, everyone else read).
  4. Writes leaf-vault.json there: the pipe owner SID (default: the account running this script),
     the proxy port and the data directory.
  5. Creates the service once: virtual account NT SERVICE\LeafVault, automatic start, restart on failure.
  6. Creates C:\ProgramData\Leaf Vault\ with inheritance disabled and an ACL of exactly
     NT SERVICE\LeafVault (Modify) + SYSTEM (Full), owner Administrators. The owner's normal,
     non-elevated session has no access to it at all.
  7. Starts the service and prints GET /health.

.PARAMETER OwnerSid
  The account allowed on \\.\pipe\leaf-vault besides SYSTEM. Defaults to the user running this
  script; pass it explicitly if you elevate with a different administrator account.
#>
[CmdletBinding()]
param(
    [string]$OwnerSid,
    [ValidateRange(1024, 65535)][int]$Port = 18810,
    [switch]$AllowDirty,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Leaf Vault must be installed from an elevated PowerShell (Run as administrator).'
}

$serviceName = 'LeafVault'
$repo = Split-Path -Parent $PSScriptRoot
$installDir = Join-Path $env:ProgramFiles 'Leaf Vault'
$dataDir = Join-Path $env:ProgramData 'Leaf Vault'
$exe = Join-Path $installDir 'Leaf.Vault.exe'

function Invoke-Native([string]$What, [scriptblock]$Command) {
    # Windows PowerShell turns redirected native stderr into errors; judge by exit code instead.
    $ErrorActionPreference = 'Continue'
    $output = & $Command 2>&1
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE): $output" }
    $output
}

# --- Owner -------------------------------------------------------------------------------------
if (-not $OwnerSid) { $OwnerSid = $identity.User.Value }
$owner = New-Object Security.Principal.SecurityIdentifier($OwnerSid)
if (-not ($owner.IsAccountSid() -or $OwnerSid.StartsWith('S-1-12-1-'))) { throw "OwnerSid $OwnerSid is not a user account SID." }
try { $ownerName = $owner.Translate([Security.Principal.NTAccount]).Value } catch { $ownerName = '(unresolved account)' }

# --- What is being installed -------------------------------------------------------------------
$gitRepo = $repo -replace '\\', '/'
$commit = (Invoke-Native 'git rev-parse' { git -c "safe.directory=$gitRepo" -C $repo rev-parse HEAD }).Trim()
$dirty = Invoke-Native 'git status' { git -c "safe.directory=$gitRepo" -C $repo status --porcelain }
if ($dirty -and -not $AllowDirty) { throw "The working tree has uncommitted changes; commit them first (or pass -AllowDirty).`n$dirty" }

$stage = Join-Path ([IO.Path]::GetTempPath()) ('leaf-vault-publish-' + [guid]::NewGuid().ToString('N'))
Write-Host "Publishing Leaf Vault from $repo ..."
Invoke-Native 'dotnet publish' {
    dotnet publish (Join-Path $repo 'src\Leaf.Vault\Leaf.Vault.csproj') -c Release -p:RestoreLockedMode=true `
        "-p:SourceRevisionId=$commit" -o $stage --nologo -v quiet
} | Out-Null

$version = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $stage 'Leaf.Vault.dll')).ProductVersion
$hash = (Get-FileHash (Join-Path $stage 'Leaf.Vault.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ''
Write-Host "  Leaf Vault   $version"
Write-Host "  Commit       $commit$(if ($dirty) { ' (with uncommitted changes)' })"
Write-Host "  Leaf.Vault.dll SHA-256  $hash"
Write-Host "  Pipe owner   $ownerName ($OwnerSid)"
Write-Host "  Install to   $installDir"
Write-Host "  Data in      $dataDir"
Write-Host "  Proxy        http://127.0.0.1:$Port"
Write-Host ''
if (-not $Yes) {
    $answer = Read-Host 'Install this build? [y/N]'
    if ($answer -notmatch '^(y|yes)$') { Remove-Item -Recurse -Force $stage; Write-Host 'Cancelled.'; return }
}

# --- Program files -----------------------------------------------------------------------------
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($service) {
    $cim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($cim.PathName -ne "`"$exe`"") { throw "Service $serviceName exists with another binary ($($cim.PathName)); run uninstall.ps1 first." }
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Get-ChildItem -LiteralPath $installDir -Force | Remove-Item -Recurse -Force
Copy-Item -Path (Join-Path $stage '*') -Destination $installDir -Recurse -Force
Remove-Item -Recurse -Force $stage
Invoke-Native 'icacls reset' { icacls $installDir /reset /T /C /Q } | Out-Null

$config = [ordered]@{ Vault = [ordered]@{ OwnerSid = $OwnerSid; ProxyPort = $Port; DataDirectory = $dataDir } }
[IO.File]::WriteAllText((Join-Path $installDir 'leaf-vault.json'), ($config | ConvertTo-Json -Depth 3), (New-Object Text.UTF8Encoding($false)))

# --- Service -----------------------------------------------------------------------------------
if (-not $service) {
    New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName 'Leaf Vault' -StartupType Automatic `
        -Description 'Holds every Leaf secret and never returns one. Control pipe \\.\pipe\leaf-vault; egress proxy on 127.0.0.1.' | Out-Null
}
Invoke-Native 'sc config' { sc.exe config $serviceName obj= "NT SERVICE\$serviceName" start= auto } | Out-Null
Invoke-Native 'sc sidtype' { sc.exe sidtype $serviceName unrestricted } | Out-Null
Invoke-Native 'sc failure' { sc.exe failure $serviceName reset= 86400 actions= restart/5000/restart/5000/restart/30000 } | Out-Null
Invoke-Native 'sc failureflag' { sc.exe failureflag $serviceName 1 } | Out-Null
$serviceSid = ((Invoke-Native 'sc showsid' { sc.exe showsid $serviceName }) -match 'SERVICE SID:' | Select-Object -First 1) -replace '.*SERVICE SID:\s*', ''
$serviceSid = $serviceSid.Trim()
if ($serviceSid -notmatch '^S-1-5-80-') { throw "Could not read the service SID for $serviceName." }
Invoke-Native 'icacls program files' { icacls $installDir /grant "*${serviceSid}:(OI)(CI)RX" /Q } | Out-Null

$eventSource = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Leaf Vault'
if (-not (Test-Path $eventSource)) {
    New-Item -Path $eventSource | Out-Null
    New-ItemProperty -Path $eventSource -Name EventMessageFile -PropertyType ExpandString `
        -Value '%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll' | Out-Null
}

# --- Data directory: LeafVault + SYSTEM only -----------------------------------------------------
function Test-DataAcl {
    $acl = Get-Acl -LiteralPath $dataDir
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $expected = @{ 'S-1-5-18' = 'FullControl'; $serviceSid = 'Modify, Synchronize' }
    if (-not $acl.AreAccessRulesProtected -or $rules.Count -ne 2) { return $false }
    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if (-not $expected.ContainsKey($sid) -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited) { return $false }
        if ($rule.FileSystemRights.ToString() -ne $expected[$sid]) { return $false }
    }
    return $true
}
if (-not (Test-Path -LiteralPath $dataDir)) { New-Item -ItemType Directory -Path $dataDir | Out-Null }
if (-not (Test-DataAcl)) {
    Invoke-Native 'icacls data' { icacls $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' "*${serviceSid}:(OI)(CI)M" /Q } | Out-Null
    # Remove anything else that was granted explicitly (for example by an earlier manual attempt).
    $acl = Get-Acl -LiteralPath $dataDir
    foreach ($rule in @($acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]))) {
        if ($rule.IdentityReference.Value -notin @('S-1-5-18', $serviceSid)) { [void]$acl.RemoveAccessRuleAll($rule) }
    }
    Set-Acl -LiteralPath $dataDir -AclObject $acl
}
Invoke-Native 'icacls owner' { icacls $dataDir /setowner '*S-1-5-32-544' /Q } | Out-Null
if (-not (Test-DataAcl)) { throw "The ACL on $dataDir is not LeafVault + SYSTEM only; refusing to start the service." }

# --- Start -------------------------------------------------------------------------------------
Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
$health = $null
for ($i = 0; $i -lt 30 -and -not $health; $i++) {
    try { $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 2 } catch { Start-Sleep -Seconds 1 }
}
if (-not $health) { throw "The service is running but http://127.0.0.1:$Port/health did not answer; see the Application event log (source 'Leaf Vault')." }

Write-Host ''
Write-Host "Installed Leaf Vault $version ($commit) as NT SERVICE\$serviceName."
Write-Host "Data directory ACL:"
icacls $dataDir
Write-Host 'Health:'
$health | Format-List | Out-String | Write-Host
