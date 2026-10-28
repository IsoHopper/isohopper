; SPDX-License-Identifier: GPL-3.0-or-later
; Copyright (C) 2026 S33G
;
; Included by the pinned custom template after its product definitions.
; SECURITY_ATTRIBUTES is the 12-byte x86 ABI of the NSIS process.
!if ${NSIS_PTR_SIZE} != 4
  !error "IsoHopper protected installation requires the x86 NSIS installer ABI"
!endif
!define ISOHOPPER_PAYLOAD_SD "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;RC;;;OW)"

Var IsoHopperStageDirectory
Var IsoHopperStageHandle
Var IsoHopperParentHandle
Var IsoHopperFailureCode
Var IsoHopperFailureText
Var IsoHopperFailureStage
Var IsoHopperHelperOutput
Var IsoHopperUninstallStudio
Var IsoHopperUninstallHelper
Var IsoHopperUninstallSelf

!define MUI_CUSTOMFUNCTION_ABORT IsoHopperCleanup

Function IsoHopperCleanup
  ; Leave the staging directory before removing it. Never recurse into either
  ; the installed tree or the payload directory, including on failed apply.
  ${If} $IsoHopperStageDirectory != ""
    SetOutPath "$PROGRAMFILES64"
    Delete "$IsoHopperStageDirectory\isohopper-studio.exe"
    Delete "$IsoHopperStageDirectory\isohopper-helper.exe"
    Delete "$IsoHopperStageDirectory\uninstall.exe"
  ${EndIf}
  ${If} $IsoHopperStageHandle != ""
    System::Call 'kernel32::CloseHandle(p $IsoHopperStageHandle) i'
    StrCpy $IsoHopperStageHandle ""
  ${EndIf}
  ${If} $IsoHopperStageDirectory != ""
    RMDir "$IsoHopperStageDirectory"
    StrCpy $IsoHopperStageDirectory ""
  ${EndIf}
  ${If} $IsoHopperParentHandle != ""
    System::Call 'kernel32::CloseHandle(p $IsoHopperParentHandle) i'
    StrCpy $IsoHopperParentHandle ""
  ${EndIf}
FunctionEnd

Function .onInstFailed
  Call IsoHopperCleanup
FunctionEnd

Function .onGUIEnd
  Call IsoHopperCleanup
FunctionEnd

Function IsoHopperInstallFailed
  ; The template reports extraction errors as 12. Keep native helper code 12
  ; distinct from failures before the helper has started.
  ${If} $IsoHopperFailureStage == "extract"
  ${AndIf} $IsoHopperFailureCode == 12
    StrCpy $IsoHopperFailureCode 130
  ${EndIf}
  ${If} $IsoHopperFailureStage == "helper"
  ${AndIf} $IsoHopperHelperOutput != ""
    StrCpy $IsoHopperFailureText "$IsoHopperFailureText$\r$\n$IsoHopperHelperOutput"
  ${EndIf}
  Call IsoHopperCleanup
  Call IsoHopperWriteFailure
  SetErrorLevel $IsoHopperFailureCode
  DetailPrint "IsoHopper setup failed ($IsoHopperFailureCode): $IsoHopperFailureText"
  IfSilent isohopper_no_prompt
  ${If} $PassiveMode != 1
    MessageBox MB_OK|MB_ICONSTOP "$IsoHopperFailureText"
  ${EndIf}
  isohopper_no_prompt:
  Quit
FunctionEnd

Function IsoHopperWriteFailure
  ; Best-effort diagnostics only: use the inherited stderr handle, never open
  ; a privileged log path. Conversion or write failures do not change status.
  System::Store "s"
  StrCpy $0 $IsoHopperFailureText 900
  StrCpy $0 "IsoHopper setup failed ($IsoHopperFailureCode): $0$\r$\n"
  System::Call 'kernel32::GetStdHandle(i -12) p.r1'
  ${If} $1 == -1
  ${OrIf} $1 == 0
    Goto isohopper_stderr_done
  ${EndIf}
  StrLen $2 $0
  System::Call 'kernel32::WideCharToMultiByte(i 65001, i 0, w r0, i r2, p 0, i 0, p 0, p 0) i.r3'
  ${If} $3 <= 0
    Goto isohopper_stderr_done
  ${EndIf}
  System::Alloc $3
  Pop $4
  ${If} $4 == 0
    Goto isohopper_stderr_done
  ${EndIf}
  System::Call 'kernel32::WideCharToMultiByte(i 65001, i 0, w r0, i r2, p r4, i r3, p 0, p 0) i.r5'
  ${If} $5 > 0
    System::Call 'kernel32::WriteFile(p r1, p r4, i r5, *i .r6, p 0) i'
  ${EndIf}
  System::Free $4
  isohopper_stderr_done:
  System::Store "l"
FunctionEnd

Function IsoHopperInitialize
  System::Store "s"
  StrCpy $IsoHopperFailureCode 11
  StrCpy $IsoHopperFailureText "IsoHopper requires the protected Program Files location on the Windows system drive."
  ${IfNot} ${RunningX64}
    Call IsoHopperInstallFailed
  ${EndIf}
  ; /D cannot select another destination. Registry values never supply a path.
  ${If} $INSTDIR != "${PLACEHOLDER_INSTALL_DIR}"
  ${AndIf} $INSTDIR != "$PROGRAMFILES64\IsoHopper"
    Call IsoHopperInstallFailed
  ${EndIf}
  StrCpy $INSTDIR "$PROGRAMFILES64\IsoHopper"
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
  System::Store "l"
FunctionEnd

Function IsoHopperCreatePayload
  System::Store "s"
  StrCpy $IsoHopperFailureStage "stage"
  StrCpy $IsoHopperFailureCode 120 ; Parent open
  StrCpy $IsoHopperFailureText "Could not create a protected setup directory. Close other setup windows and run this installer again."
  ; Include FILE_TRAVERSE so the guard participates in sharing checks. Metadata
  ; access alone does not enforce no-delete sharing. Permit child-name writes.
  System::Call 'kernel32::CreateFileW(w "$PROGRAMFILES64", i 0x200a0, i 3, p 0, i 3, i 0x02200000, p 0) p.r0'
  ${If} $0 == -1
  ${OrIf} $0 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  StrCpy $IsoHopperParentHandle $0
  StrCpy $IsoHopperFailureCode 121 ; Parent type
  System::Call 'kernel32::GetFileAttributesW(w "$PROGRAMFILES64") i.r0'
  IntOp $1 $0 & 0x410 ; DIRECTORY | REPARSE_POINT
  ${If} $0 == -1
  ${OrIf} $1 != 0x10
    Call IsoHopperInstallFailed
  ${EndIf}

  StrCpy $IsoHopperFailureCode 122 ; Unique GUID
  System::Alloc 16
  Pop $0
  ${If} $0 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Call 'ole32::CoCreateGuid(p r0) i.r1'
  ${If} $1 != 0
    System::Free $0
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Call 'ole32::StringFromGUID2(p r0, w .r5, i 39) i.r1'
  System::Free $0
  ${If} $1 != 39
    Call IsoHopperInstallFailed
  ${EndIf}
  StrCpy $8 "$PROGRAMFILES64\.IsoHopper-setup-$5"

  ; Protect the new directory at creation. OWNER_RIGHTS suppresses the
  ; extractor owner's implicit WRITE_DAC until each file is owned by BA.
  StrCpy $IsoHopperFailureCode 123 ; Protected directory creation
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${ISOHOPPER_PAYLOAD_SD}", i 1, *p .r0, p 0) i.r2'
  ${If} $2 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Call '*(i 12, p r0, i 0) p.r1'
  ${If} $1 == 0
    System::Call 'kernel32::LocalFree(p r0) p'
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Call 'kernel32::CreateDirectoryW(w r8, p r1) i.r2'
  System::Free $1
  System::Call 'kernel32::LocalFree(p r0) p'
  ${If} $2 == 0
    ; The path was not created by us. Do not open or clean it up.
    Call IsoHopperInstallFailed
  ${EndIf}
  StrCpy $IsoHopperFailureCode 124 ; Retained stage open
  System::Call 'kernel32::CreateFileW(w r8, i 0x200a0, i 3, p 0, i 3, i 0x02200000, p 0) p.r0'
  ${If} $0 == -1
  ${OrIf} $0 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  StrCpy $IsoHopperStageHandle $0
  Call IsoHopperCheckRetainedPayload
  ; Only a verified retained object may be used for extraction or cleanup.
  StrCpy $IsoHopperStageDirectory $8
  StrCpy $IsoHopperFailureStage "extract"
  System::Store "l"
FunctionEnd

Function IsoHopperCheckRetainedPayload
  System::Store "s"
  StrCpy $IsoHopperFailureCode 125 ; Retained stage type
  StrCpy $IsoHopperFailureText "The setup directory failed its protection check. Setup did not extract or run its payload."
  StrCpy $0 0 ; Expected descriptor
  StrCpy $1 0 ; Expected canonical string
  StrCpy $2 0 ; Observed descriptor
  StrCpy $3 0 ; Observed canonical string
  StrCpy $7 0 ; Verification result
  System::Alloc 8 ; FILE_ATTRIBUTE_TAG_INFO
  Pop $4
  ${If} $4 == 0
    Goto isohopper_stage_check_done
  ${EndIf}
  System::Call 'kernel32::GetFileInformationByHandleEx(p $IsoHopperStageHandle, i 9, p r4, i 8) i.r5'
  ${If} $5 == 0
    Goto isohopper_stage_check_done
  ${EndIf}
  System::Call '*$4(i .r5, i .r6)'
  IntOp $5 $5 & 0x410 ; DIRECTORY | REPARSE_POINT
  ${If} $5 != 0x10
    Goto isohopper_stage_check_done
  ${EndIf}

  ; Compare API-normalized OWNER/GROUP/DACL strings, not binary ACL layouts.
  ; Exact protected DACL and BA owner prevent an attacker-created replacement
  ; from being accepted even if the parent was misconfigured as writable.
  StrCpy $IsoHopperFailureCode 126 ; Expected security descriptor
  System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "${ISOHOPPER_PAYLOAD_SD}", i 1, *p .r0, p 0) i.r5'
  ${If} $5 == 0
    Goto isohopper_stage_check_done
  ${EndIf}
  System::Call 'advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorW(p r0, i 1, i 7, *p .r1, p 0) i.r5'
  ${If} $5 == 0
    Goto isohopper_stage_check_done
  ${EndIf}
  StrCpy $IsoHopperFailureCode 127 ; Observed security descriptor
  System::Call 'advapi32::GetSecurityInfo(p $IsoHopperStageHandle, i 1, i 7, p 0, p 0, p 0, p 0, *p .r2) i.r5'
  ${If} $5 != 0
    Goto isohopper_stage_check_done
  ${EndIf}
  ; Windows may mark a created DACL auto-inherited. Clear only that bookkeeping
  ; bit in our local descriptor, never on the directory. The expected D:P
  ; descriptor already has it clear. Protection, all ACEs, owner and group stay.
  StrCpy $IsoHopperFailureCode 128 ; Descriptor normalization
  System::Call 'advapi32::SetSecurityDescriptorControl(p r2, i 0x0400, i 0) i.r5'
  ${If} $5 == 0
    Goto isohopper_stage_check_done
  ${EndIf}
  System::Call 'advapi32::ConvertSecurityDescriptorToStringSecurityDescriptorW(p r2, i 1, i 7, *p .r3, p 0) i.r5'
  ${If} $5 == 0
    Goto isohopper_stage_check_done
  ${EndIf}
  StrCpy $IsoHopperFailureCode 129 ; Exact descriptor comparison
  System::Call 'kernel32::CompareStringOrdinal(p r1, i -1, p r3, i -1, i 0) i.r5'
  ${If} $5 == 2 ; CSTR_EQUAL, with case-sensitive ordinal comparison
    StrCpy $7 1
  ${Else}
    ; Both canonical strings exist here. Copy only bounded, terminated text
    ; before freeing them; earlier API failures never read these pointers.
    StrCpy $8 $5
    StrCpy $6 ""
    StrCpy $9 ""
    System::Call 'kernel32::lstrcpynW(w .r6, p r1, i 256) p'
    System::Call 'kernel32::lstrcpynW(w .r9, p r3, i 256) p'
    StrCpy $IsoHopperFailureText "$IsoHopperFailureText$\r$\nCompareStringOrdinal=$8; expected=$6; observed=$9"
  ${EndIf}

  isohopper_stage_check_done:
  ${If} $0 != 0
    System::Call 'kernel32::LocalFree(p r0) p'
  ${EndIf}
  ${If} $1 != 0
    System::Call 'kernel32::LocalFree(p r1) p'
  ${EndIf}
  ${If} $2 != 0
    System::Call 'kernel32::LocalFree(p r2) p'
  ${EndIf}
  ${If} $3 != 0
    System::Call 'kernel32::LocalFree(p r3) p'
  ${EndIf}
  ${If} $4 != 0
    System::Free $4
  ${EndIf}
  ${If} $7 != 1
    Call IsoHopperInstallFailed
  ${EndIf}
  System::Store "l"
FunctionEnd

!macro IsoHopperSetPayloadOwner FILE_NAME FAILURE_CODE
  StrCpy $IsoHopperFailureCode ${FAILURE_CODE}
  System::Call 'advapi32::SetNamedSecurityInfoW(w "$IsoHopperStageDirectory\${FILE_NAME}", i 1, i 1, p r0, p 0, p 0, p 0) i.r1'
  ${If} $1 != 0
    System::Call 'kernel32::LocalFree(p r0) p'
    Call IsoHopperInstallFailed
  ${EndIf}
!macroend

Function IsoHopperApplyPayload
  System::Store "s"
  StrCpy $IsoHopperFailureStage "owner"
  StrCpy $IsoHopperFailureCode 131 ; Administrators SID
  StrCpy $IsoHopperFailureText "Could not verify the protected setup payload. Run this installer again."
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-32-544", *p .r0) i.r1'
  ${If} $1 == 0
    Call IsoHopperInstallFailed
  ${EndIf}
  !insertmacro IsoHopperSetPayloadOwner "isohopper-studio.exe" 132
  !insertmacro IsoHopperSetPayloadOwner "isohopper-helper.exe" 133
  !insertmacro IsoHopperSetPayloadOwner "uninstall.exe" 134
  System::Call 'kernel32::LocalFree(p r0) p'

  isohopper_apply_retry:
  StrCpy $IsoHopperFailureStage "helper"
  ; nsExec hides the console and captures at most NSIS_MAX_STRLEN characters.
  ; Do not set a timeout: killing a file transaction can interrupt rollback.
  nsExec::ExecToStack '"$IsoHopperStageDirectory\isohopper-helper.exe" --installer-apply-v1 "$IsoHopperStageDirectory"'
  Pop $IsoHopperFailureCode
  Pop $IsoHopperHelperOutput
  StrCpy $IsoHopperHelperOutput $IsoHopperHelperOutput 512
  ${If} $IsoHopperHelperOutput != ""
    DetailPrint "$IsoHopperHelperOutput"
  ${EndIf}
  ${If} $IsoHopperFailureCode == "error"
  ${OrIf} $IsoHopperFailureCode == "timeout"
  ${OrIf} $IsoHopperFailureCode == ""
    StrCpy $IsoHopperFailureCode 13
    StrCpy $IsoHopperFailureText "Could not complete communication with the protected installer helper. Run this installer again to check and repair the installation."
    Call IsoHopperInstallFailed
  ${EndIf}
  ${If} $IsoHopperFailureCode == 10
    IfSilent isohopper_apply_no_retry
    ${If} $PassiveMode != 1
      MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Close IsoHopper after any active preparation finishes, then retry." IDRETRY isohopper_apply_retry
      Call IsoHopperCleanup
      SetErrorLevel 10
      Quit
    ${EndIf}
  ${EndIf}
  isohopper_apply_no_retry:
  ${If} $IsoHopperFailureCode != 0
    StrCpy $IsoHopperFailureText "Installation did not complete. Close IsoHopper and its helper, then run this installer again."
    ${If} $IsoHopperFailureCode == 10
      StrCpy $IsoHopperFailureText "Close IsoHopper after any active preparation finishes, then retry. Setup did not stop it."
    ${ElseIf} $IsoHopperFailureCode == 11
      StrCpy $IsoHopperFailureText "The existing installation has unsafe permissions or links. Setup left it unchanged."
    ${ElseIf} $IsoHopperFailureCode == 12
      StrCpy $IsoHopperFailureText "The setup payload did not pass verification. Download the installer again."
    ${ElseIf} $IsoHopperFailureCode == 13
      StrCpy $IsoHopperFailureText "Installation failed and changes were rolled back. Close IsoHopper and run this installer again."
    ${ElseIf} $IsoHopperFailureCode == 14
      StrCpy $IsoHopperFailureText "Installation could not finish restoring the previous files. Run this installer again to repair the installation before opening IsoHopper."
    ${ElseIf} $IsoHopperFailureCode == 3
      StrCpy $IsoHopperFailureText "The installer helper rejected its arguments. Download the installer again."
    ${Else}
      DetailPrint "Unexpected installer helper exit code: $IsoHopperFailureCode"
      StrCpy $IsoHopperFailureCode 13
      StrCpy $IsoHopperFailureText "The installer helper ended unexpectedly. Run this installer again to check and repair the installation."
    ${EndIf}
    Call IsoHopperInstallFailed
  ${EndIf}
  Call IsoHopperCleanup
  SetErrorLevel 0
  System::Store "l"
FunctionEnd

; Standalone uninstall keeps the existing explicit data-deletion checkbox.
; Hold write handles (without write sharing) across all deletes: an active
; image/retained helper blocks us, and a new launch cannot start in between.
!macro IsoHopperUninstallGuard FILE_NAME HANDLE_VAR
  ClearErrors
  System::Call 'kernel32::GetFileAttributesW(w "$INSTDIR\${FILE_NAME}") i.r0 ?e'
  Pop $1
  ${If} $0 == -1
    ${If} $1 != 2
    ${AndIf} $1 != 3
      Call un.IsoHopperBusy
    ${EndIf}
  ${Else}
    System::Call 'kernel32::CreateFileW(w "$INSTDIR\${FILE_NAME}", i 0x40000000, i 5, p 0, i 3, i 0x00200000, p 0) p.r0'
    ${If} $0 == -1
    ${OrIf} $0 == 0
      Call un.IsoHopperBusy
    ${EndIf}
    StrCpy ${HANDLE_VAR} $0
  ${EndIf}
!macroend

Function un.IsoHopperCheckBusy
  !insertmacro IsoHopperUninstallGuard "isohopper-studio.exe" $IsoHopperUninstallStudio
  !insertmacro IsoHopperUninstallGuard "isohopper-helper.exe" $IsoHopperUninstallHelper
  !insertmacro IsoHopperUninstallGuard "uninstall.exe" $IsoHopperUninstallSelf
FunctionEnd

Function un.IsoHopperRelease
  ${If} $IsoHopperUninstallStudio != ""
    System::Call 'kernel32::CloseHandle(p $IsoHopperUninstallStudio) i'
    StrCpy $IsoHopperUninstallStudio ""
  ${EndIf}
  ${If} $IsoHopperUninstallHelper != ""
    System::Call 'kernel32::CloseHandle(p $IsoHopperUninstallHelper) i'
    StrCpy $IsoHopperUninstallHelper ""
  ${EndIf}
  ${If} $IsoHopperUninstallSelf != ""
    System::Call 'kernel32::CloseHandle(p $IsoHopperUninstallSelf) i'
    StrCpy $IsoHopperUninstallSelf ""
  ${EndIf}
FunctionEnd

Function un.IsoHopperBusy
  Call un.IsoHopperRelease
  SetErrorLevel 10
  DetailPrint "Close IsoHopper and its helper before uninstalling."
  IfSilent isohopper_uninstall_no_prompt
  ${If} $PassiveMode != 1
    MessageBox MB_OK|MB_ICONSTOP "Finish or cancel the current operation, then close IsoHopper and its helper before uninstalling."
  ${EndIf}
  isohopper_uninstall_no_prompt:
  Quit
FunctionEnd
