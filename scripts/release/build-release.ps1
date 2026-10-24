#Requires -Version 7.2
<#
.SYNOPSIS
  Builds the Leaf Vault release artifact: one self-contained, single-file win-x64 Leaf.Vault.exe
  that is both the service and its own installer (`Leaf.Vault.exe setup install`).

.DESCRIPTION
  Run by Release Manager's leaf-vault recipe from a fresh clone of an exact commit. Nothing here
  signs or publishes: the release signing binds the artifact's SHA-256 in a signed feed record.

  1. Locked restore, then the full test suite (Release).
  2. Deterministic publish (-p:Version=<version>, SourceRevisionId=<commit>) of src/Leaf.Vault.
     The output must be exactly one file, Leaf.Vault.exe.
  3. Smoke: the exe starts and its setup entrypoint refuses an incomplete command line (exit 11)
     without changing anything.
  4. Writes leaf-vault-<version>-win-x64.exe and leaf-vault-release.v1.json (version, commit,
     SHA-256, size) to -OutputDirectory.

  The developer path (scripts/install.ps1) builds from source on the owner's machine instead.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Invoke-Checked([string]$What, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$What failed (exit $LASTEXITCODE)." }
}

$head = (& git -C $repo rev-parse HEAD).Trim()
if ($head -cne $SourceCommit) { throw "The checkout is at $head, not $SourceCommit." }
if (@(& git -C $repo status --porcelain=v1).Count -ne 0) { throw 'The checkout is not clean.' }

$output = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null
$publish = Join-Path $output 'publish'
if (Test-Path -LiteralPath $publish) { throw "$publish must not exist yet." }

$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$env:DOTNET_NOLOGO = '1'
Push-Location $repo
try {
    Invoke-Checked 'restore' { dotnet restore leaf-vault.sln --locked-mode --nologo }
    if (-not $SkipTests) {
        Invoke-Checked 'tests' { dotnet test leaf-vault.sln --configuration Release --no-restore --nologo }
    }
    Invoke-Checked 'publish' {
        dotnet publish src/Leaf.Vault/Leaf.Vault.csproj --configuration Release --runtime win-x64 --self-contained true `
            --output $publish --nologo -p:RestoreLockedMode=true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
            -p:DebugType=none -p:DebugSymbols=false -p:Version=$Version -p:SourceRevisionId=$SourceCommit `
            -p:ContinuousIntegrationBuild=true -p:Deterministic=true
    }
}
finally { Pop-Location }

$files = @(Get-ChildItem -LiteralPath $publish -Recurse -File)
if ($files.Count -ne 1 -or $files[0].Name -cne 'Leaf.Vault.exe') {
    throw "The publish output must be exactly Leaf.Vault.exe; found: $($files.Name -join ', ')."
}
$exe = $files[0].FullName
$informational = [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductVersion
if ($informational -cne "$Version+$SourceCommit") { throw "Leaf.Vault.exe reports $informational, not $Version+$SourceCommit." }

# The setup entrypoint exists and refuses an incomplete command line before touching anything.
& $exe setup | Out-Null
if ($LASTEXITCODE -ne 11) { throw "Leaf.Vault.exe setup answered $LASTEXITCODE, expected 11 (invalid arguments)." }

$fileName = "leaf-vault-$Version-win-x64.exe"
$artifact = Join-Path $output $fileName
Move-Item -LiteralPath $exe -Destination $artifact
Remove-Item -LiteralPath $publish -Recurse -Force
$item = Get-Item -LiteralPath $artifact
$metadata = [ordered]@{
    schemaVersion = 1
    componentId = 'leaf-vault'
    version = $Version
    sourceCommit = $SourceCommit
    informationalVersion = $informational
    artifact = [ordered]@{
        fileName = $fileName
        sha256 = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
        sizeBytes = $item.Length
    }
}
$metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output 'leaf-vault-release.v1.json') -Encoding utf8NoBOM
Write-Output "Leaf Vault $Version ($SourceCommit): $fileName $($metadata.artifact.sha256) $($metadata.artifact.sizeBytes) bytes"
