; NekoSlop Installer Script (NSIS)
; Build with: makensis installer.nsi

!include "MUI2.nsh"
!include "FileFunc.nsh"

; === General ===
Name "NekoSlop"
OutFile "NekoSlopSetup.exe"
InstallDir "$PROGRAMFILES64\NekoSlop"
InstallDirRegKey HKLM "Software\NekoSlop" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; === Version ===
VIProductVersion "4.0.1.0"
VIAddVersionKey "ProductName" "NekoSlop"
VIAddVersionKey "FileDescription" "NekoSlop Installer"
VIAddVersionKey "FileVersion" "4.0.1"
VIAddVersionKey "ProductVersion" "4.0.1"
VIAddVersionKey "CompanyName" "NekoSlop"
VIAddVersionKey "LegalCopyright" "GPL-3.0"

; === MUI Settings ===
!define MUI_ABORTWARNING
!define MUI_ICON "..\res\nekoslop.ico"
!define MUI_UNICON "..\res\nekoslop.ico"
!define MUI_HEADERIMAGE
!define MUI_BGCOLOR "1e1e2e"
!define MUI_TEXTCOLOR "cdd6f4"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

; Uninstall Pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Languages
!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

; === Sections ===
Section "NekoSlop (required)" SecMain
    SectionIn RO
    SetOutPath "$INSTDIR"

    ; Main binaries
    File "..\build\nekoslop.exe"
    File "..\build\nekoslop_core.exe"

    ; Qt DLLs
    File "..\build\Qt6Core.dll"
    File "..\build\Qt6Gui.dll"
    File "..\build\Qt6Network.dll"
    File "..\build\Qt6Widgets.dll"
    File "..\build\Qt6Svg.dll"
    File "..\build\Qt6Pdf.dll"

    ; OpenSSL
    File "..\build\libcrypto-3-x64.dll"
    File "..\build\libssl-3-x64.dll"

    ; D3D (Qt WebGL fallback)
    File /nonfatal "..\build\d3dcompiler_47.dll"

    ; Geo databases
    File "..\build\geoip.db"
    File "..\build\geosite.db"

    ; Qt platform plugins
    SetOutPath "$INSTDIR\platforms"
    File "..\build\platforms\qwindows.dll"

    SetOutPath "$INSTDIR\styles"
    File /r /x ".svn" "..\build\styles\*"

    SetOutPath "$INSTDIR\imageformats"
    File /r /x ".svn" "..\build\imageformats\*"

    SetOutPath "$INSTDIR\iconengines"
    File /r /x ".svn" "..\build\iconengines\*"

    SetOutPath "$INSTDIR\tls"
    File /r /x ".svn" "..\build\tls\*"

    SetOutPath "$INSTDIR\networkinformation"
    File /nonfatal /r "..\build\networkinformation\*"

    SetOutPath "$INSTDIR\generic"
    File /nonfatal /r "..\build\generic\*"

    ; Translations
    SetOutPath "$INSTDIR"
    File /nonfatal "..\build\ru_RU.qm"
    File /nonfatal "..\build\zh_CN.qm"
    File /nonfatal "..\build\fa_IR.qm"

    ; VC++ Redist (silent)
    SetOutPath "$INSTDIR"
    File /nonfatal "..\build\vc_redist.x64.exe"
    ExecWait '"$INSTDIR\vc_redist.x64.exe" /install /quiet /norestart'

    ; Registry
    WriteRegStr HKLM "Software\NekoSlop" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "Software\NekoSlop" "Version" "4.0.1"

    ; Uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Add/Remove Programs entry
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop" \
        "DisplayName" "NekoSlop"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop" \
        "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop" \
        "DisplayIcon" '"$INSTDIR\nekoslop.exe"'
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop" \
        "Publisher" "NekoSlop"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop" \
        "DisplayVersion" "4.0.1"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop" \
        "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop" \
        "NoRepair" 1

    ; Start Menu shortcut
    CreateDirectory "$SMPROGRAMS\NekoSlop"
    CreateShortCut "$SMPROGRAMS\NekoSlop\NekoSlop.lnk" \
        "$INSTDIR\nekoslop.exe" "" "$INSTDIR\nekoslop.exe" 0
    CreateShortCut "$SMPROGRAMS\NekoSlop\Uninstall.lnk" \
        "$INSTDIR\Uninstall.exe"

    ; Desktop shortcut
    CreateShortCut "$DESKTOP\NekoSlop.lnk" \
        "$INSTDIR\nekoslop.exe" "" "$INSTDIR\nekoslop.exe" 0

SectionEnd

; === Uninstall ===
Section "Uninstall"
    ; Kill running processes
    ExecWait 'taskkill /F /IM nekoslop.exe'
    ExecWait 'taskkill /F /IM nekoslop_core.exe'
    Sleep 500

    ; Remove files
    RMDir /r "$INSTDIR\platforms"
    RMDir /r "$INSTDIR\styles"
    RMDir /r "$INSTDIR\imageformats"
    RMDir /r "$INSTDIR\iconengines"
    RMDir /r "$INSTDIR\tls"
    RMDir /r "$INSTDIR\networkinformation"
    RMDir /r "$INSTDIR\generic"

    Delete "$INSTDIR\nekoslop.exe"
    Delete "$INSTDIR\nekoslop_core.exe"
    Delete "$INSTDIR\Qt6*.dll"
    Delete "$INSTDIR\libcrypto-3-x64.dll"
    Delete "$INSTDIR\libssl-3-x64.dll"
    Delete "$INSTDIR\d3dcompiler_47.dll"
    Delete "$INSTDIR\geoip.db"
    Delete "$INSTDIR\geosite.db"
    Delete "$INSTDIR\*.qm"
    Delete "$INSTDIR\vc_redist.x64.exe"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"

    ; Shortcuts
    Delete "$SMPROGRAMS\NekoSlop\NekoSlop.lnk"
    Delete "$SMPROGRAMS\NekoSlop\Uninstall.lnk"
    RMDir "$SMPROGRAMS\NekoSlop"
    Delete "$DESKTOP\NekoSlop.lnk"

    ; Registry
    DeleteRegKey HKLM "Software\NekoSlop"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NekoSlop"

SectionEnd
