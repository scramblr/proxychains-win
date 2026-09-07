<#
.SYNOPSIS
    Builds and packages proxychains-win for release distribution.
.DESCRIPTION
    Compiles both 64-bit and 32-bit release targets, verifies all unit tests,
    and bundles the distribution binaries, configuration, and documentation
    into a versioned zip package with SHA256 checksums.
.PARAMETER Version
    The release version tag (defaults to "0.5.1alpha").
.PARAMETER SkipBuild
    Skip CMake compilation and test steps, packaging existing binaries.
#>

param (
    [string]$Version = "0.5.1alpha",
    [switch]$SkipBuild = $false
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " proxychains-win Release Packaging Script (v$Version)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if (-not $SkipBuild) {
    Write-Host "`n[1/5] Building 64-bit Release Target..." -ForegroundColor Yellow
    cmake -B build -A x64
    cmake --build build --config Release --parallel

    Write-Host "`n[2/5] Building 32-bit (Win32/WoW64) Release Target..." -ForegroundColor Yellow
    cmake -B build32 -A Win32
    cmake --build build32 --config Release --parallel

    Write-Host "`n[3/5] Running Automated Test Suites..." -ForegroundColor Yellow
    Write-Host "  -> Running 64-bit tests..." -ForegroundColor Gray
    ctest --test-dir build -C Release --output-on-failure
    Write-Host "  -> Running 32-bit tests..." -ForegroundColor Gray
    ctest --test-dir build32 -C Release --output-on-failure
} else {
    Write-Host "`n[Skipping build & test steps as requested]" -ForegroundColor Gray
}

Write-Host "`n[4/5] Staging Distribution Artifacts..." -ForegroundColor Yellow
$DistDir = Join-Path $RepoRoot "dist"
$StageDir = Join-Path $DistDir "proxychains-win-v$Version"

if (Test-Path $StageDir) {
    Remove-Item -Recurse -Force $StageDir
}
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null

$FilesToBundle = @(
    @{ Src = "build\bin\Release\proxychains-win.exe"; Dest = "proxychains-win.exe" },
    @{ Src = "build\bin\Release\proxychains.exe"; Dest = "proxychains.exe" },
    @{ Src = "build\bin\Release\proxychains64.dll"; Dest = "proxychains64.dll" },
    @{ Src = "build32\bin\Release\proxychains32.dll"; Dest = "proxychains32.dll" },
    @{ Src = "proxychains.conf"; Dest = "proxychains.conf" },
    @{ Src = "README.md"; Dest = "README.md" }
)

foreach ($item in $FilesToBundle) {
    $srcPath = Join-Path $RepoRoot $item.Src
    if (-not (Test-Path $srcPath)) {
        throw "Required artifact missing: $srcPath"
    }
    $destPath = Join-Path $StageDir $item.Dest
    Copy-Item $srcPath $destPath -Force
    Write-Host "  + Staged: $($item.Dest)" -ForegroundColor Green
}

Write-Host "`n[5/5] Creating Release Archive & Checksums..." -ForegroundColor Yellow
$ZipPath = Join-Path $DistDir "proxychains-win-v$Version.zip"
$ShaPath = Join-Path $DistDir "proxychains-win-v$Version.zip.sha256"

if (Test-Path $ZipPath) {
    Remove-Item -Force $ZipPath
}
if (Test-Path $ShaPath) {
    Remove-Item -Force $ShaPath
}

Compress-Archive -Path "$StageDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal
$Hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash
"$Hash  proxychains-win-v$Version.zip" | Out-File -FilePath $ShaPath -Encoding utf8

$ZipSize = (Get-Item $ZipPath).Length / 1KB

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " Release Packaging Succeeded!" -ForegroundColor Green
Write-Host " Archive:  $ZipPath ($([Math]::Round($ZipSize, 2)) KB)" -ForegroundColor Green
Write-Host " SHA256:   $Hash" -ForegroundColor Green
Write-Host " Checksum: $ShaPath" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
