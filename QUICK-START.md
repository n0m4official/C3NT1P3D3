# 🚀 Quick Start - C3NT1P3D3 v3.0.0-legendary

## ✅ Build is Running Now!

The executables are currently being compiled. This will take 2-5 minutes.

---

## 📋 What to Do Next (In Order)

### **Step 1: Wait for Build to Complete** ⏳
The build is running in the background. You'll know it's done when you see "Build succeeded" in the terminal.

### **Step 2: Copy Executables to Release Folder** 📦
Once build completes, run:
```powershell
.\copy-to-release.ps1
```

This will copy all 3 executables to `release\C3NT1P3D3-v3.0.0-legendary\bin\`

### **Step 3: Verify the Files** ✅
Check that executables are in place:
```powershell
dir release\C3NT1P3D3-v3.0.0-legendary\bin\
```

You should see:
- ✅ `C3NT1P3D3-Comprehensive.exe` (Main scanner - 30 modules)
- ✅ `C3NT1P3D3.exe` (Development build)
- ✅ `test_ip_validator.exe` (IP validator)

### **Step 4: Test the Scanner** 🧪
```powershell
# Test help
.\release\C3NT1P3D3-v3.0.0-legendary\bin\C3NT1P3D3-Comprehensive.exe --help

# Test IP validator
.\release\C3NT1P3D3-v3.0.0-legendary\bin\test_ip_validator.exe
```

### **Step 5: Create ZIP Archive** 📦
```powershell
Compress-Archive -Path "release\C3NT1P3D3-v3.0.0-legendary" -DestinationPath "release\C3NT1P3D3-v3.0.0-legendary-windows-x64.zip" -Force
```

### **Step 6: Generate Checksum** 🔐
```powershell
$hash = (Get-FileHash -Path "release\C3NT1P3D3-v3.0.0-legendary-windows-x64.zip" -Algorithm SHA256).Hash
"$hash  C3NT1P3D3-v3.0.0-legendary-windows-x64.zip" | Out-File "release\C3NT1P3D3-v3.0.0-legendary-SHA256.txt" -Encoding ASCII
Write-Host "SHA256: $hash" -ForegroundColor Green
```

---

## 🎉 You're Done!

Your release package is ready:
- 📦 `release\C3NT1P3D3-v3.0.0-legendary-windows-x64.zip`
- 🔐 `release\C3NT1P3D3-v3.0.0-legendary-SHA256.txt`

Upload these to GitHub Releases!

---

## 🆘 Troubleshooting

### **If Build Fails:**
```powershell
# Check build output
cmake --build build --config Release --verbose
```

### **If Executables Missing:**
```powershell
# Check if they were built
dir build\Release\*.exe

# If not there, rebuild
cmake --build build --config Release --target C3NT1P3D3-Comprehensive
```

### **If Copy Script Fails:**
```powershell
# Manually copy
Copy-Item build\Release\*.exe release\C3NT1P3D3-v3.0.0-legendary\bin\ -Force
```

---

## 📊 What You're Building

**30 Legendary Modules:**
- Network: EternalBlue, BlueKeep, SSH Brute Force, FTP Anonymous
- Web: SQL Injection, XSS, XXE, SSRF, SSTI, NoSQL, and 16 more
- Cloud: Metadata Exploitation, Container Escape
- SSL/TLS: Heartbleed, Weak Ciphers
- System: Shellshock

**MITRE ATT&CK:** 17 techniques, 11 tactics

---

**Made with ❤️ by n0m4official**
