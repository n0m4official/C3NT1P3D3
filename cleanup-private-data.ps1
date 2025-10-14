# C3NT1P3D3 Privacy Cleanup Script
# Removes build artifacts, binaries, and files containing personal information

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "C3NT1P3D3 Privacy Cleanup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to safely remove items
function Remove-SafeItem {
    param(
        [string]$Path,
        [string]$Description
    )
    
    if (Test-Path $Path) {
        Write-Host "Removing: $Description" -ForegroundColor Yellow
        Write-Host "  Path: $Path" -ForegroundColor Gray
        try {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
            Write-Host "  Success: Removed" -ForegroundColor Green
        }
        catch {
            Write-Host "  Failed: $_" -ForegroundColor Red
        }
        Write-Host ""
    }
    else {
        Write-Host "Skipping: $Description (not found)" -ForegroundColor Gray
        Write-Host ""
    }
}

Write-Host "This script will remove:" -ForegroundColor White
Write-Host "  - Build directory (contains personal paths)" -ForegroundColor White
Write-Host "  - Visual Studio cache (.vs)" -ForegroundColor White
Write-Host "  - Compiled executables" -ForegroundColor White
Write-Host "  - Release packages" -ForegroundColor White
Write-Host ""

$confirmation = Read-Host "Continue? (y/n)"
if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
    Write-Host "Cleanup cancelled." -ForegroundColor Yellow
    exit
}

Write-Host ""
Write-Host "Starting cleanup..." -ForegroundColor Cyan
Write-Host ""

# Remove build directory (contains personal username paths)
Remove-SafeItem -Path "build" -Description "Build directory (CMake artifacts with personal paths)"

# Remove Visual Studio directory
Remove-SafeItem -Path ".vs" -Description "Visual Studio cache directory"

# Remove release directory
Remove-SafeItem -Path "release" -Description "Release directory (compiled binaries)"

# Remove ZIP archives
Remove-SafeItem -Path "C3NT1P3D3-v2.0.0-beta.zip" -Description "Old release ZIP archive"

# Remove any stray executables in root
$exeFiles = Get-ChildItem -Path "." -Filter "*.exe" -File -ErrorAction SilentlyContinue
if ($exeFiles) {
    foreach ($exe in $exeFiles) {
        Remove-SafeItem -Path $exe.FullName -Description "Executable: $($exe.Name)"
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cleanup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check git status
Write-Host "Checking git status..." -ForegroundColor Cyan
Write-Host ""

if (Get-Command git -ErrorAction SilentlyContinue) {
    # Check if any deleted files were tracked by git
    $gitStatus = git status --short 2>$null
    
    if ($gitStatus) {
        Write-Host "Git detected changes:" -ForegroundColor Yellow
        git status --short
        Write-Host ""
        Write-Host "If these files were previously committed to git, run:" -ForegroundColor Yellow
        Write-Host "  git add -A" -ForegroundColor White
        Write-Host "  git commit -m 'Remove build artifacts and personal data'" -ForegroundColor White
    }
    else {
        Write-Host "No git-tracked files affected (good!)" -ForegroundColor Green
    }
}
else {
    Write-Host "Git not found - skipping git check" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Your source code, documentation, and configuration files are safe." -ForegroundColor Green
Write-Host "The repository is now clean for public sharing." -ForegroundColor Green
Write-Host ""
