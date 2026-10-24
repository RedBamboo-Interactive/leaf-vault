#Requires -Version 5.1
<#
.SYNOPSIS
  Installs or updates Leaf Vault as a Windows service. Run from an elevated PowerShell.

.DESCRIPTION
  The checkout this script sits in is writable by the owner's normal session, and so by agents.
  Nothing executable is taken from it or from the user's environment except this script itself:

  1. The commit to install is read as text from the checkout's .git/HEAD (git is never run), or
     given with -Commit. It must be pushed: the source is that commit's archive from GitHub
     (-Repository), downloaded over HTTPS into an administrators-only folder under Program Files.
  2. It is built there with dotnet from Program Files (checked to be writable by administrators
     only) and a whitelisted environment: no user PATH, user environment variables, user NuGet
     configuration or cache, or MSBuild user extensions. The NuGet restore is locked to
     packages.lock.json.
  3. Shows the version, commit and SHA-256 of Leaf.Vault.dll and asks for confirmation (-Yes skips it).
  4. Stops the service if it exists and replaces C:\Program Files\Leaf Vault\ (inherited Program
     Files ACL: administrators write, everyone else read), then writes leaf-vault.json there with the
     pipe owner SID (default: the account running this script), the proxy port and the data directory.
  5. Creates the service once: virtual account NT SERVICE\LeafVault, automatic start, restart on failure.
  6. Creates C:\ProgramData\Leaf Vault\ already locked (inheritance disabled; NT SERVICE\LeafVault
     Modify + SYSTEM Full; owner Administrators). A folder that exists before the first install is
     refused, and an existing one must already have exactly that ACL. The vault re-checks at start.
  7. Starts the service and prints GET /health.

.PARAMETER OwnerSid
  The account allowed on \\.\pipe\leaf-vault besides SYSTEM. Defaults to the user running this
  script; pass it explicitly if you elevate with a different administrator account.

.PARAMETER Commit
  Full commit hash to install. Defaults to the checkout's current HEAD commit.
#>
[CmdletBinding()]
param(
    [string]$OwnerSid,
    [ValidateRange(1024, 65535)][int]$Port = 18810,
    [ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [ValidatePattern('^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$')][string]$Repository = 'RedBamboo-Interactive/leaf-vault',
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Leaf Vault must be installed from an elevated PowerShell (Run as administrator).'
}

# Known folders from the system, not from (user-overridable) environment variables.
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
$programData = [Environment]::GetFolderPath('CommonApplicationData')
$windows = [Environment]::GetFolderPath('Windows')
$serviceName = 'LeafVault'
$repo = Split-Path -Parent $PSScriptRoot
$installDir = Join-Path $programFiles 'Leaf Vault'
$dataDir = Join-Path $programData 'Leaf Vault'
$exe = Join-Path $installDir 'Leaf.Vault.exe'
$dotnet = Join-Path $programFiles 'dotnet\dotnet.exe'
$icacls = Join-Path $windows 'System32\icacls.exe'
if (-not (Test-Path -LiteralPath $dotnet)) { throw "$dotnet not found (install the .NET SDK machine-wide)." }

# Anything run elevated must not be replaceable by the owner's normal session.
function Assert-AdminOnlyWritable([string]$Path) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464', 'S-1-3-0')
    $writeMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
    $item = Get-Item -LiteralPath $Path
    $root = [IO.Path]::GetPathRoot($item.FullName)
    # The file and every folder above it, except the drive root (whose "create folders" grant cannot touch them).
    while ($item -and $item.FullName -ne $root) {
        foreach ($rule in (Get-Acl -LiteralPath $item.FullName).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow' -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            if ($trusted -contains $rule.IdentityReference.Value) { continue }
            if (([int]$rule.FileSystemRights -band $writeMask) -ne 0) {
                throw "$($item.FullName) is writable by $($rule.IdentityReference.Value); a non-elevated process could replace what this script runs as administrator. Fix that ACL first."
            }
        }
        $item = if ($item -is [IO.DirectoryInfo]) { $item.Parent } else { $item.Directory }
    }
}
Assert-AdminOnlyWritable $dotnet

# --- Owner -------------------------------------------------------------------------------------
if (-not $OwnerSid) { $OwnerSid = $identity.User.Value }
$owner = New-Object Security.Principal.SecurityIdentifier($OwnerSid)
if (-not ($owner.IsAccountSid() -or $OwnerSid.StartsWith('S-1-12-1-'))) { throw "OwnerSid $OwnerSid is not a user account SID." }
try { $ownerName = $owner.Translate([Security.Principal.NTAccount]).Value } catch { $ownerName = '(unresolved account)' }

# --- Which commit: read as data, never by running git ----------------------------------------------
if (-not $Commit) {
    $gitDir = Join-Path $repo '.git'
    if (-not (Test-Path -LiteralPath $gitDir -PathType Container)) { throw "No .git folder in $repo; pass -Commit." }
    $head = (Get-Content -LiteralPath (Join-Path $gitDir 'HEAD') -Raw).Trim()
    if ($head -match '^ref: (refs/[A-Za-z0-9._/-]+)$') {
        $ref = $Matches[1]
        $refFile = Join-Path $gitDir ($ref -replace '/', '\')
        if (Test-Path -LiteralPath $refFile) { $head = (Get-Content -LiteralPath $refFile -Raw).Trim() }
        else {
            $packed = Join-Path $gitDir 'packed-refs'
            $line = if (Test-Path -LiteralPath $packed) { Get-Content -LiteralPath $packed | Where-Object { $_ -match " $([regex]::Escape($ref))$" } | Select-Object -First 1 }
            if (-not $line) { throw "Cannot resolve $ref; pass -Commit." }
            $head = ($line -split ' ')[0]
        }
    }
    if ($head -notmatch '^[0-9a-f]{40}$') { throw 'Cannot read the HEAD commit; pass -Commit.' }
    $Commit = $head
}

# --- Build in an administrators-only folder with a whitelisted environment -----------------------
$buildRoot = Join-Path $programFiles 'Leaf Vault Build'
$work = Join-Path $buildRoot ([guid]::NewGuid().ToString('N'))
$buildHome = Join-Path $work 'home'
$tmp = Join-Path $work 'tmp'
foreach ($d in @($buildRoot, $work, $buildHome, $tmp, (Join-Path $buildHome 'AppData\Roaming'), (Join-Path $buildHome 'AppData\Local'))) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

function Invoke-Clean([string]$Exe, [string[]]$Arguments, [string]$WorkDir) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($Arguments | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join ' '
    $psi.WorkingDirectory = $WorkDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.EnvironmentVariables.Clear()
    $vars = [ordered]@{
        SystemRoot = $windows; windir = $windows; ComSpec = (Join-Path $windows 'System32\cmd.exe')
        PATH = "$(Join-Path $windows 'System32');$windows;$(Split-Path -Parent $Exe)"
        TEMP = $tmp; TMP = $tmp; USERPROFILE = $buildHome; HOME = $buildHome
        APPDATA = (Join-Path $buildHome 'AppData\Roaming'); LOCALAPPDATA = (Join-Path $buildHome 'AppData\Local')
        ProgramFiles = $programFiles; ProgramData = $programData
        NUGET_PACKAGES = (Join-Path $work 'nuget'); DOTNET_CLI_HOME = $buildHome
        DOTNET_NOLOGO = '1'; DOTNET_CLI_TELEMETRY_OPTOUT = '1'; DOTNET_SKIP_FIRST_TIME_EXPERIENCE = '1'
        DOTNET_CLI_USE_MSBUILD_SERVER = '0'; MSBUILDDISABLENODEREUSE = '1'
    }
    foreach ($k in $vars.Keys) { $psi.EnvironmentVariables[$k] = $vars[$k] }
    $process = [Diagnostics.Process]::Start($psi)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "$(Split-Path -Leaf $Exe) $($Arguments[0]) failed (exit $($process.ExitCode)):`n$($stdout.Result)`n$stderr" }
    $stdout.Result
}

try {
    $out = Join-Path $work 'out'
    $archive = Join-Path $work 'source.zip'
    $url = "https://github.com/$Repository/archive/$Commit.zip"
    Write-Host "Downloading $url ..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    # No proxy: the per-user proxy setting is the owner's normal session's to change.
    $client = New-Object Net.WebClient
    $client.Proxy = $null
    try { $client.DownloadFile($url, $archive) }
    catch { throw "Could not download $Commit from github.com/$Repository; push the reviewed commit first, or pass -Commit. ($($_.Exception.Message))" }
    finally { $client.Dispose() }
    Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $work 'x')
    $src = @(Get-ChildItem -LiteralPath (Join-Path $work 'x') -Directory)
    if ($src.Count -ne 1) { throw 'Unexpected archive layout.' }
    $src = $src[0].FullName
    Write-Host 'Building (locked restore) ...'
    Invoke-Clean $dotnet @('publish', (Join-Path $src 'src\Leaf.Vault\Leaf.Vault.csproj'), '-c', 'Release',
        '-p:RestoreLockedMode=true', "-p:SourceRevisionId=$Commit", '-o', $out, '--nologo', '-nodeReuse:false',
        '--disable-build-servers') $src | Out-Null

    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $out 'Leaf.Vault.dll')).ProductVersion
    $hash = (Get-FileHash (Join-Path $out 'Leaf.Vault.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ''
    Write-Host "  Leaf Vault     $version"
    Write-Host "  Commit         $Commit (github.com/$Repository)"
    Write-Host "  Leaf.Vault.dll SHA-256 $hash"
    Write-Host "  Pipe owner     $ownerName ($OwnerSid)"
    Write-Host "  Install to     $installDir"
    Write-Host "  Data in        $dataDir"
    Write-Host "  Proxy          http://127.0.0.1:$Port"
    Write-Host ''
    if (-not $Yes) {
        $answer = Read-Host 'Install this build? [y/N]'
        if ($answer -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; return }
    }

    # --- Program files -------------------------------------------------------------------------
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service -and (Test-Path -LiteralPath $dataDir)) {
        throw "$dataDir exists but the $serviceName service is not installed, so this installer did not create it. Inspect and delete it, then run install.ps1 again."
    }
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
    Copy-Item -Path (Join-Path $out '*') -Destination $installDir -Recurse -Force
    & $icacls $installDir /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /reset on $installDir failed." }

    $config = [ordered]@{ Vault = [ordered]@{ OwnerSid = $OwnerSid; ProxyPort = $Port; DataDirectory = $dataDir } }
    [IO.File]::WriteAllText((Join-Path $installDir 'leaf-vault.json'), ($config | ConvertTo-Json -Depth 3), (New-Object Text.UTF8Encoding($false)))

    # --- Service -------------------------------------------------------------------------------
    if (-not $service) {
        New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName 'Leaf Vault' -StartupType Automatic `
            -Description 'Holds every Leaf secret and never returns one. Control pipe \\.\pipe\leaf-vault; egress proxy on 127.0.0.1.' | Out-Null
    }
    $sc = Join-Path $windows 'System32\sc.exe'
    foreach ($scArgs in @(
            @('config', $serviceName, 'obj=', "NT SERVICE\$serviceName", 'start=', 'auto'),
            @('sidtype', $serviceName, 'unrestricted'),
            @('failure', $serviceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000/restart/30000'),
            @('failureflag', $serviceName, '1'))) {
        & $sc @scArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe $($scArgs -join ' ') failed (exit $LASTEXITCODE)." }
    }
    $serviceSid = ((& $sc showsid $serviceName) -match 'SERVICE SID:' | Select-Object -First 1) -replace '.*SERVICE SID:\s*', ''
    $serviceSid = $serviceSid.Trim()
    if ($serviceSid -notmatch '^S-1-5-80-') { throw "Could not read the service SID for $serviceName." }
    & $icacls $installDir /grant "*${serviceSid}:(OI)(CI)RX" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls /grant on $installDir failed." }

    $eventSource = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Leaf Vault'
    if (-not (Test-Path $eventSource)) {
        New-Item -Path $eventSource | Out-Null
        New-ItemProperty -Path $eventSource -Name EventMessageFile -PropertyType ExpandString `
            -Value '%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll' | Out-Null
    }

    # --- Data directory: LeafVault + SYSTEM only, owner Administrators, from the moment it exists --
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $vaultSid = New-Object Security.Principal.SecurityIdentifier($serviceSid)
    function Test-DataAcl {
        $acl = Get-Acl -LiteralPath $dataDir
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $admins.Value) { return $false }
        if (-not $acl.AreAccessRulesProtected) { return $false }
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        $expected = @{ $system.Value = 'FullControl'; $vaultSid.Value = 'Modify, Synchronize' }
        if ($rules.Count -ne 2) { return $false }
        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value
            if (-not $expected.ContainsKey($sid) -or $rule.AccessControlType -ne 'Allow' -or $rule.IsInherited) { return $false }
            if ($rule.FileSystemRights.ToString() -ne $expected[$sid]) { return $false }
        }
        return $true
    }
    if (-not (Test-Path -LiteralPath $dataDir)) {
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $none = [Security.AccessControl.PropagationFlags]::None
        $security = New-Object Security.AccessControl.DirectorySecurity
        $security.SetAccessRuleProtection($true, $false)
        $security.SetOwner($admins)
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system, 'FullControl', $inherit, $none, 'Allow')))
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($vaultSid, 'Modify', $inherit, $none, 'Allow')))
        # Created with this security descriptor in one call: there is no moment with inherited access.
        # No emptiness check afterwards: Administrators deliberately have no ACE on this folder, so even this
        # elevated session cannot list it. Nothing else can have written into it either.
        if ($PSVersionTable.PSEdition -eq 'Desktop') { [void][IO.Directory]::CreateDirectory($dataDir, $security) }
        else { [IO.FileSystemAclExtensions]::Create((New-Object IO.DirectoryInfo($dataDir)), $security) }
    }
    if (-not (Test-DataAcl)) {
        throw "The ACL or owner of $dataDir is not exactly LeafVault (Modify) + SYSTEM (Full), owner Administrators. Refusing to start the service; inspect the folder."
    }

    # --- Start ---------------------------------------------------------------------------------
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    $health = $null
    for ($i = 0; $i -lt 30 -and -not $health; $i++) {
        try { $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health" -UseBasicParsing -TimeoutSec 2 } catch { Start-Sleep -Seconds 1 }
    }
    if (-not $health) { throw "The service is running but http://127.0.0.1:$Port/health did not answer; see the Application event log (source 'Leaf Vault')." }

    Write-Host ''
    Write-Host "Installed Leaf Vault $version ($Commit) as NT SERVICE\$serviceName."
    Write-Host 'Data directory ACL:'
    & $icacls $dataDir
    Write-Host 'Health:'
    $health | Format-List | Out-String | Write-Host
}
finally {
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
