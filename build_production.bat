@echo off
echo Building C3NT1P3D3 Production Executable...
echo.

REM Collect all core source files
set CORE_FILES=^
src\core\ConfigurationManager.cpp ^
src\core\ProductionScanner.cpp ^
src\simulation\SimulationEngine.cpp ^
src\IPRangeValidator.cpp ^
src\VulnerabilityDatabase.cpp

REM Build the production executable
cl.exe /EHsc /std:c++17 /Fe:C3NT1P3D3-Comprehensive.exe ^
    /I"include" ^
    src\C3NT1P3D3-Production.cpp ^
    %CORE_FILES% ^
    /link

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Build successful!
    echo Executable: C3NT1P3D3-Comprehensive.exe
    echo.
    echo Try running:
    echo   C3NT1P3D3-Comprehensive.exe --help
    echo   C3NT1P3D3-Comprehensive.exe 192.168.1.0/24 --simulation
) else (
    echo.
    echo ✗ Build failed with error code %ERRORLEVEL%
)

pause
