; TailConnect-SSH setup.exe: a one-click installer (and upgrader).
;
; Built by build.sh: makensis -DVERSION=X.Y.Z -DSRC=<package folder> -DOUT=<setup.exe>
;
; It asks for administrator rights once, unpacks the package to a temporary
; folder and runs `tcd install` from there, which does the work (files to
; Program Files\TailConnect-SSH, the service, PATH, firewall, Start menu,
; sign-in, Settings > Apps, whose Uninstall runs `tcd uninstall`). The
; Finish page opens the app, as the signed-in user.

Unicode true
ManifestDPIAware true
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WinVer.nsh"

Name "TailConnect-SSH"
OutFile "${OUT}"
BrandingText "TailConnect-SSH ${VERSION}"
ShowInstDetails show

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "TailConnect-SSH"
VIAddVersionKey "FileDescription" "TailConnect-SSH Setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "TailConnect-SSH"

!define MUI_ICON "TailConnectSSH.ico"
!define MUI_UNICON "TailConnectSSH.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "installer-side.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "installer-header.bmp"
!define MUI_ABORTWARNING

!define MUI_WELCOMEPAGE_TITLE "Welcome to TailConnect-SSH"
!define MUI_WELCOMEPAGE_TEXT "This puts your PC on your private TailConnect-SSH network: it gets an address and a name, reaches your other machines directly or through your hub, and finds them by name.$\r$\n$\r$\nSetup installs the TailConnectSSH service, the TailConnect-SSH app by the clock, and the tcs command.$\r$\n$\r$\nIf TailConnect-SSH is already installed, it's upgraded and stays logged in."
!insertmacro MUI_PAGE_WELCOME

!define MUI_PAGE_HEADER_TEXT "Installing"
!define MUI_PAGE_HEADER_SUBTEXT "Setting up the service, the app and the network adapter."
!insertmacro MUI_PAGE_INSTFILES

!define MUI_FINISHPAGE_TITLE "TailConnect-SSH is ready"
!define MUI_FINISHPAGE_TEXT "Open the app and choose Log in... to join your network with your hub's address and an auth key from its web portal.$\r$\n$\r$\nThe app lives by the clock; it starts when you sign in."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open TailConnect-SSH"
!define MUI_FINISHPAGE_RUN_FUNCTION OpenApp
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "TailConnect-SSH needs 64-bit Windows."
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "TailConnect-SSH needs Windows 10 or 11."
    Abort
  ${EndIf}
FunctionEnd

; Open the app unelevated, as the signed-in user (explorer.exe starts it).
Function OpenApp
  Exec '"$WINDIR\explorer.exe" "$PROGRAMFILES64\TailConnect-SSH\TailConnectSSH.exe"'
FunctionEnd

Section "TailConnect-SSH"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR\pkg"
  File "${SRC}\tcd.exe"
  File "${SRC}\tcs.exe"
  File "${SRC}\TailConnectSSH.exe"
  File "${SRC}\wintun.dll"
  File "${SRC}\TailConnectSSH.ico"
  File "${SRC}\README.txt"
  File "${SRC}\LICENSE-wintun.txt"
  ; The Finish page opens the app (silent installs: the next sign-in does).
  System::Call 'Kernel32::SetEnvironmentVariable(t "TCS_NO_APP", t "1")i'
  DetailPrint "Installing TailConnect-SSH ${VERSION}..."
  nsExec::ExecToLog '"$PLUGINSDIR\pkg\tcd.exe" install'
  Pop $0
  ${If} $0 != 0
    DetailPrint "tcd install failed ($0)."
    MessageBox MB_ICONSTOP "TailConnect-SSH couldn't be installed (see the details above)."
    SetOutPath "$TEMP"
    Abort
  ${EndIf}
  SetOutPath "$TEMP"
SectionEnd
