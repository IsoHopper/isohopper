; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 S33G
;
; Tauri CLI 2.12.4 includes hooks before all installer Sections. A Section here
; therefore runs before its SetOutPath (which would create an insecure default
; owner directory before NSIS_HOOK_PREINSTALL). NSIS executes Sections in order.
; https://nsis.sourceforge.io/Docs/Chapter4.html#sections
; https://nsis.sourceforge.io/Docs/System/System.html
;
; SECURITY_ATTRIBUTES below is the 12-byte x86 ABI of the NSIS process, not the
; architecture of the installed application. Refuse another installer ABI.
!if ${NSIS_PTR_SIZE} != 4
  !error "IsoHopper protected installation requires the x86 NSIS installer ABI"
!endif

Var IsoHopperInstallHandle

; The template's maintenance page can execute a registered uninstaller before
; any Section, including in /P mode. MUI calls this before its first page.
; /S has no pages; the same check is called by our first Section below.
!ifdef MUI_CUSTOMFUNCTION_GUIINIT
  !error "IsoHopper requires the pre-page fresh-install guard"
!endif
!define MUI_CUSTOMFUNCTION_GUIINIT IsoHopperRequireFreshInstall

Function IsoHopperInstallFailed
  ${If} $IsoHopperInstallHandle != ""
    System::Call 'kernel32::CloseHandle(p $IsoHopperInstallHandle) i'
    StrCpy $IsoHopperInstallHandle ""
  ${EndIf}
  SetErrorLevel 3
  DetailPrint "Fresh protected installation required; no existing installation is reused."
  ; Do not leave a passive installer waiting on an invisible modal prompt.
  IfSilent isohopper_no_prompt
  ClearErrors
  ${GetOptions} $CMDLINE "/P" $0
  ${If} ${Errors}
    MessageBox MB_OK|MB_ICONSTOP "Installation requires a fresh Program Files\IsoHopper directory on the Windows system drive. Existing directories are not reused or reset. Uninstall an earlier version first. A failed new installation may require administrator cleanup."
  ${EndIf}
  isohopper_no_prompt:
  Quit
FunctionEnd

Function IsoHopperRequireFreshInstall
  System::Store "s"
  ${IfNot} ${RunningX64}
    Call IsoHopperInstallFailed
  ${EndIf}
  ${If} $INSTDIR != "$PROGRAMFILES64\IsoHopper"
    Call IsoHopperInstallFailed
  ${EndIf}
  ; Only explicit absence passes. An empty directory, file, reparse point,
  ; inaccessible path or another metadata error must stop before maintenance.
  System::Call 'kernel32::GetFileAttributesW(w "$PROGRAMFILES64\IsoHopper") i.r0 ?e'
  Pop $1
  ${If} $0 != -1
    Call IsoHopperInstallFailed
  ${EndIf}
  ${If} $1 != 2 ; ERROR_FILE_NOT_FOUND
  ${AndIf} $1 != 3 ; ERROR_PATH_NOT_FOUND
    Call IsoHopperInstallFailed
  ${EndIf}
  ; Match both old-install sources consumed by this pinned template, including
  ; registrations pointing somewhere other than the supported fixed directory.
  ; Product defines follow this include, so the NSIS key is deliberately fixed.
  Call FindWixInstall
  ${If} $R6 != ""
    Call IsoHopperInstallFailed
  ${EndIf}
  ReadRegStr $0 SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\IsoHopper" ""
  ReadRegStr $1 SHCTX "Software\Microsoft\Windows\CurrentVersion\Uninstall\IsoHopper" "UninstallString"
  ${If} "$0$1" != ""
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Store "l"
FunctionEnd

; Hidden, always selected, and read-only in any component selection UI.
Section "-IsoHopper protected directory"
  SectionIn RO
  Call IsoHopperRequireFreshInstall
  System::Store "s"
  ${IfNot} ${RunningX64}
    Call IsoHopperInstallFailed
  ${EndIf}
  ${If} $INSTDIR != "$PROGRAMFILES64\IsoHopper"
    DetailPrint "Unsupported installation location."
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Call 'kernel32::GetSystemWindowsDirectoryW(w .r2, i ${NSIS_MAX_STRLEN}) i.r3'
  ${If} $3 == 0
  ${OrIf} $3 >= ${NSIS_MAX_STRLEN}
    Call IsoHopperInstallFailed
  ${EndIf}
  StrCpy $2 $2 3
  StrCpy $3 "$PROGRAMFILES64" 3
  ${If} $2 != $3
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Call 'kernel32::GetVolumeInformationW(w r3, p 0, i 0, p 0, p 0, *i .r4, p 0, i 0) i.r5'
  IntOp $4 $4 & 8 ; FILE_PERSISTENT_ACLS
  ${If} $5 == 0
  ${OrIf} $4 == 0
    Call IsoHopperInstallFailed
  ${EndIf}

  ; Create with the owner and ACL already protected. OWNER_RIGHTS suppresses
  ; implicit owner WRITE_DAC on newly extracted files until their owner is BA.
  ; No CREATOR_OWNER write grant and no recursive change of an existing tree.
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;RC;;;OW)", i 1, *p .r0, p 0) i.r2'
  ${If} $2 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Call '*(i 12, p r0, i 0) p.r1'
  ${If} $1 == 0
    System::Call 'kernel32::LocalFree(p r0) p'
    Call IsoHopperInstallFailed
  ${EndIf}
  ; Atomic existing-directory refusal, including empty dirs and reparse points.
  System::Call 'kernel32::CreateDirectoryW(w "$INSTDIR", p r1) i.r2'
  System::Free $1
  System::Call 'kernel32::LocalFree(p r0) p'
  ${If} $2 == 0
    DetailPrint "Protected directory creation failed; existing paths are untouched."
    Call IsoHopperInstallFailed
  ${EndIf}
  ; Keep the new directory open without delete sharing through extraction.
  System::Call 'kernel32::CreateFileW(w "$INSTDIR", i 0x20080, i 3, p 0, i 3, i 0x02200000, p 0) p.r0'
  ${If} $0 == -1
  ${OrIf} $0 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  StrCpy $IsoHopperInstallHandle $0
  System::Store "l"
SectionEnd

!macro IsoHopperSetNewFileOwner FILE_NAME
  System::Call 'advapi32::SetNamedSecurityInfoW(w "$INSTDIR\${FILE_NAME}", i 1, i 1, p r0, p 0, p 0, p 0) i.r1'
  ${If} $1 != 0
    System::Call 'kernel32::LocalFree(p r0) p'
    DetailPrint "Could not establish protected ownership of a newly installed file."
    Call IsoHopperInstallFailed
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  System::Store "s"
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-32-544", *p .r0) i.r1'
  ${If} $1 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  ; The fixed directory was created above. All three files were created by
  ; this installer; the inherited OWNER_RIGHTS ACE protected them from birth.
  !insertmacro IsoHopperSetNewFileOwner "${MAINBINARYNAME}.exe"
  !insertmacro IsoHopperSetNewFileOwner "isohopper-helper.exe"
  !insertmacro IsoHopperSetNewFileOwner "uninstall.exe"
  System::Call 'kernel32::LocalFree(p r0) p'
  System::Call 'kernel32::CloseHandle(p $IsoHopperInstallHandle) i'
  StrCpy $IsoHopperInstallHandle ""
  System::Store "l"
!macroend
