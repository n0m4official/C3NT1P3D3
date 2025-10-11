@echo off
echo Testing compilation...
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl /std:c++20 /EHsc /I"include" /Zs "src\MockTarget.cpp" 2>&1
