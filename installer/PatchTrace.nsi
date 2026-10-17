!include "MUI2.nsh"

!define APP_NAME "PatchTrace"
!define APP_EXE "PatchTrace.exe"
!ifndef APP_VERSION
  !define APP_VERSION "0.1.0"
!endif

Unicode true
Name "${APP_NAME}"
OutFile "dist\\PatchTrace-Windows-x64-Setup.exe"
InstallDir "$LOCALAPPDATA\\Programs\\PatchTrace"
InstallDirRegKey HKCU "Software\\PatchTrace" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID zlib
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${APP_VERSION}.0"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "ProductVersion" "${APP_VERSION}"
VIAddVersionKey "FileDescription" "PatchTrace Windows x64 Setup"
VIAddVersionKey "LegalCopyright" "Copyright PatchTrace contributors"

!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  File /r "dist\\PatchTrace\\*"
  SetOutPath "$INSTDIR\\licenses\\installer"
  File "third_party\\notices\\nsis-3.13\\COPYING"
  WriteUninstaller "$INSTDIR\\Uninstall.exe"
  WriteRegStr HKCU "Software\\PatchTrace" "InstallDir" "$INSTDIR"
  CreateDirectory "$SMPROGRAMS\\PatchTrace"
  CreateShortcut "$SMPROGRAMS\\PatchTrace\\PatchTrace.lnk" "$INSTDIR\\${APP_EXE}" "" "$INSTDIR\\${APP_EXE}" 0
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  Delete "$SMPROGRAMS\\PatchTrace\\PatchTrace.lnk"
  RMDir "$SMPROGRAMS\\PatchTrace"
  DeleteRegKey HKCU "Software\\PatchTrace"
  RMDir /r "$INSTDIR"
SectionEnd
