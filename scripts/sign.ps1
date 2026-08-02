<#
.SYNOPSIS
    Signs a Windows binary with Azure Trusted Signing. Requires
    AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET in the
    environment.

.PARAMETER FilePath
    The file to sign (.exe, .msi, .dll).

.NOTES
    Set MCP_SKIP_SIGN=1 to no-op (unsigned local test builds).
    The Trusted Signing client lands in LOCALAPPDATA via:
      Invoke-WebRequest https://www.nuget.org/api/v2/package/Microsoft.Trusted.Signing.Client
      then extract bin/x64 to %LOCALAPPDATA%\Microsoft\MicrosoftArtifactSigningClientTools

    Signing account and certificate profile live in signing\metadata.json.
#>

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$FilePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:MCP_SKIP_SIGN -eq '1') {
    Write-Host "MCP_SKIP_SIGN=1: skipping signature for $FilePath" -ForegroundColor Yellow
    exit 0
}

$RepoRoot     = Split-Path -Parent $PSScriptRoot
$MetadataJson = Join-Path $RepoRoot 'signing\metadata.json'
$Dlib         = if ($env:AZURE_CODESIGN_DLIB) { $env:AZURE_CODESIGN_DLIB } else {
    Join-Path $env:LOCALAPPDATA 'Microsoft\MicrosoftArtifactSigningClientTools\Azure.CodeSigning.Dlib.dll'
}
$SignTool = if ($env:SIGNTOOL_PATH) { $env:SIGNTOOL_PATH } else {
    Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' -ErrorAction SilentlyContinue |
        Sort-Object FullName | Select-Object -Last 1 -ExpandProperty FullName
}

foreach ($envVar in @('AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET')) {
    if (-not [Environment]::GetEnvironmentVariable($envVar)) {
        Write-Error "ERROR: Environment variable $envVar is not set."
        exit 1
    }
}

foreach ($path in @($FilePath, $Dlib, $SignTool, $MetadataJson)) {
    if (-not ($path -and (Test-Path $path))) {
        Write-Error "ERROR: Not found: $path"
        exit 1
    }
}

$resolvedFile = Resolve-Path $FilePath
Write-Host "--- Signing $resolvedFile ---" -ForegroundColor Cyan

& $SignTool sign /v /fd SHA256 /tr http://timestamp.acs.microsoft.com /td SHA256 /dlib $Dlib /dmdf $MetadataJson $resolvedFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "ERROR: signtool sign failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "`n--- Verifying signature ---" -ForegroundColor Cyan
& $SignTool verify /pa /v $resolvedFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "ERROR: signtool verify failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "`nSigned and verified: $resolvedFile" -ForegroundColor Green
