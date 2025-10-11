# 🎨 Adding Icon to C3NT1P3D3 Executable

## Step 1: Convert Image to ICO Format

1. **Save your centipede image** as PNG first
2. **Convert to ICO** using one of these methods:

### Option A: Online Converter (Easiest)
- Go to: https://convertio.co/png-ico/
- Upload your centipede image
- Select sizes: 16x16, 32x32, 48x48, 256x256
- Download as `centipede.ico`
- Save to: `c:\Users\ba55d\source\repos\C3NT1P3D3\resources\centipede.ico`

### Option B: Using ImageMagick
```powershell
# Install ImageMagick first, then:
magick convert centipede.png -define icon:auto-resize=256,128,64,48,32,16 centipede.ico
```

---

## Step 2: Files Already Created ✅

I've already created these files for you:
- ✅ `resources/app.rc` - Resource script
- ✅ `resources/resource.h` - Resource header

---

## Step 3: Update CMakeLists.txt

Add these lines to your `CMakeLists.txt` for the C3NT1P3D3-Comprehensive target:

```cmake
# Add this near the top
if(WIN32)
    enable_language(RC)
endif()

# Find your C3NT1P3D3-Comprehensive target and modify it:
add_executable(C3NT1P3D3-Comprehensive
    src/C3NT1P3D3-Production.cpp
    # ... other source files ...
)

# Add this right after the add_executable for C3NT1P3D3-Comprehensive:
if(WIN32)
    target_sources(C3NT1P3D3-Comprehensive PRIVATE
        ${CMAKE_SOURCE_DIR}/resources/app.rc
    )
endif()
```

---

## Step 4: Rebuild

```powershell
# Reconfigure CMake
cmake -S . -B build -G "Visual Studio 17 2022" -A x64

# Rebuild
cmake --build build --config Debug --target C3NT1P3D3-Comprehensive

# Your exe will now have the icon!
```

---

## Alternative: Quick Manual Method (Visual Studio)

If you're using Visual Studio directly:

1. Open the project in Visual Studio
2. Right-click on `C3NT1P3D3-Comprehensive` project
3. Select "Add" → "Resource"
4. Select "Icon" → "Import"
5. Browse to your `centipede.ico` file
6. Rebuild the project

---

## Verify Icon Was Added

```powershell
# Check the exe properties
Get-Item "build\Debug\C3NT1P3D3-Comprehensive.exe" | Select-Object *

# Or just right-click the exe in Windows Explorer and check properties
```

---

## Quick Reference: File Locations

```
C3NT1P3D3/
├── resources/
│   ├── centipede.ico          ← PUT YOUR ICO FILE HERE
│   ├── app.rc                 ← Already created ✅
│   └── resource.h             ← Already created ✅
├── CMakeLists.txt             ← Need to update this
└── build/
    └── Debug/
        └── C3NT1P3D3-Comprehensive.exe  ← Will have icon after rebuild
```

---

## Troubleshooting

### Icon doesn't show after rebuild?
- Clear icon cache: Delete `IconCache.db` from `%LOCALAPPDATA%`
- Restart Windows Explorer: `taskkill /f /im explorer.exe && start explorer.exe`

### Build error about RC file?
- Make sure `centipede.ico` exists in `resources/` folder
- Check that CMakeLists.txt has `enable_language(RC)` for Windows

### Icon looks blurry?
- Make sure your ICO file has multiple sizes (16, 32, 48, 256)
- Use a high-quality source image

---

## 🎯 Summary

1. ✅ Resource files created (`app.rc`, `resource.h`)
2. ⏳ Convert your image to `resources/centipede.ico`
3. ⏳ Update `CMakeLists.txt` to include the RC file
4. ⏳ Rebuild the project
5. ✅ Your exe will have the awesome centipede icon!

---

**Once you have the ICO file, let me know and I can help update CMakeLists.txt!**
