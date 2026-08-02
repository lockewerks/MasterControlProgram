#Requires -Version 7.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Build and install MasterControlProgram.

.DESCRIPTION
    Idempotent. Re-run it as often as you like; each run rebuilds, stops any
    running instance, and replaces the installed binary in place.

    Installing to Program Files rather than running out of target\release
    matters for two reasons: cargo cannot overwrite the exe while a client has
    it running, and a stable path means MCP registrations do not break every
    time you rebuild.

    This does not sign anything. Release binaries are signed by CI, see
    .github\workflows\release.yml. If you build from source you are on the
    hook for your own signature, and scripts\sign.ps1 is there if you have a
    Trusted Signing account of your own.

.PARAMETER InstallDir
    Where the binary lands. Defaults to %ProgramFiles%\MasterControlProgram.

.PARAMETER SkipBuild
    Install whatever is already in target\, without invoking cargo.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -SkipBuild
#>
[CmdletBinding()]
param(
    [string]$InstallDir    = (Join-Path $env:ProgramFiles 'MasterControlProgram'),
    [ValidateSet('release', 'debug')]
    [string]$Configuration = 'release',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ExeName   = 'MasterControlProgram.exe'
$RepoRoot  = $PSScriptRoot
$BuiltExe  = Join-Path $RepoRoot "target\$Configuration\$ExeName"
$TargetExe = Join-Path $InstallDir $ExeName

function Write-Step { param([string]$m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Note { param([string]$m) Write-Host "    $m" -ForegroundColor DarkGray }

# ---------------------------------------------------------------- build ----
if ($SkipBuild) {
    Write-Step "Skipping build"
} else {
    Write-Step "Building ($Configuration)"
    Push-Location $RepoRoot
    try {
        $cargoArgs = @('build')
        if ($Configuration -eq 'release') { $cargoArgs += '--release' }
        & cargo @cargoArgs
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $BuiltExe)) {
    throw "Built binary not found at $BuiltExe. Drop -SkipBuild, or build first."
}
Write-Note "built: $BuiltExe ($([math]::Round((Get-Item $BuiltExe).Length / 1MB, 2)) MB)"

# -------------------------------------------------------- stop instances ----
# Only ever kill pwsh whose PARENT is one of our own processes. A blanket
# "kill all pwsh" would take out the caller's shell, and every other PowerShell
# on the box, which is a genuinely terrible day.
Write-Step "Stopping running instances"

$ours = @(Get-CimInstance Win32_Process -Filter "Name='$ExeName'" -ErrorAction SilentlyContinue)
if ($ours.Count -eq 0) {
    Write-Note "none running"
} else {
    foreach ($proc in $ours) {
        $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.ProcessId)" -ErrorAction SilentlyContinue)
        foreach ($child in $children) {
            if ($child.Name -in @('pwsh.exe', 'powershell.exe')) {
                Write-Note "killing orphaned worker $($child.Name) pid $($child.ProcessId) (parent $($proc.ProcessId))"
                Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Note "killing $ExeName pid $($proc.ProcessId)"
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

# --------------------------------------------------------------- install ----
Write-Step "Installing to $InstallDir"

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Write-Note "created $InstallDir"
}

# The exe can stay locked for a beat after the process dies. Retry rather than
# failing a reinstall on a race.
$copied = $false
foreach ($attempt in 1..10) {
    try {
        Copy-Item $BuiltExe $TargetExe -Force
        $copied = $true
        break
    } catch {
        if ($attempt -eq 10) { throw "Could not write $TargetExe after 10 attempts: $_" }
        Start-Sleep -Milliseconds 300
    }
}
if ($copied) { Write-Note "copied to $TargetExe" }

# ---------------------------------------------------------------- verify ----
Write-Step "Verifying"

$installed = Get-Item $TargetExe
Write-Note "path:     $($installed.FullName)"
Write-Note "size:     $([math]::Round($installed.Length / 1MB, 2)) MB"
Write-Note "modified: $($installed.LastWriteTime)"

$sig = Get-AuthenticodeSignature $TargetExe
Write-Note "signature: $($sig.Status)"

$sudoMode = try {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Sudo' -ErrorAction Stop).Enabled
} catch { $null }

$sudoLabel = switch ($sudoMode) {
    3       { 'Inline (good)' }
    2       { 'DisableInput (BREAKS stdio, run: sudo config --enable normal)' }
    1       { 'ForceNewWindow (BREAKS stdio, run: sudo config --enable normal)' }
    0       { 'disabled (run: sudo config --enable normal)' }
    default { 'not configured (run: sudo config --enable normal)' }
}
Write-Note "sudo mode: $sudoLabel"

Write-Host ""
Write-Host "Installed." -ForegroundColor Green
Write-Host "Register with an MCP client using this path:"
Write-Host "  $TargetExe" -ForegroundColor Yellow
Write-Host ""
Write-Host "It elevates itself on launch, so the client does not need to be elevated."
