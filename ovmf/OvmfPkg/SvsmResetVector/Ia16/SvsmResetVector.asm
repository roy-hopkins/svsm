;------------------------------------------------------------------------------
; @file
; Implements a reset vector that launches an SVSM module.
;
; Copyright (c) 2022-2023 SUSE LLC
; SPDX-License-Identifier: MIT OR Apache-2.0
; Author: Roy Hopkins <rhopkins@suse.de>
;
;------------------------------------------------------------------------------

ALIGN 16

SvsmSevGuidedStructureStart:

SvsmSevMetadataGuid:

_DescriptorSev:
  DB 'A','S','E','V'                                        ; Signature
  DD SvsmSevGuidedStructureEnd - _DescriptorSev             ; Length
  DD SVSM_SEV_METADATA_VERSION                              ; Version
  DD (SvsmSevGuidedStructureEnd - _DescriptorSev - 16) / 12 ; Number of sections

; Region need to be pre-validated by the hypervisor
PreValidate1:
  DD  SVSM_SEC_MEM_BASE
  DD  SVSM_SEC_MEM_SIZE
  DD  SVSM_SECTION_TYPE_SNP_SEC_MEM

; SEV-SNP Secrets page
SevSnpSecrets:
  DD  SVSM_SECRETS_BASE
  DD  SVSM_SECRETS_SIZE
  DD  SVSM_SECTION_TYPE_SNP_SECRETS

; CPUID values
CpuidSec:
  DD  SVSM_CPUID_BASE
  DD  SVSM_CPUID_SIZE
  DD  SVSM_SECTION_TYPE_CPUID

SvsmSevGuidedStructureEnd:

BITS    16

to_pm_mode:
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    mov     eax, cr0
    and     eax, ~((1 << 30) | (1 << 29))
    or      al, 1
    mov     cr0, eax

o32 lgdt    [word cs:ADDR16_OF(gdt32_descr)]
    jmp     8:dword ADDR_OF(protected_mode)

BITS    32
protected_mode:
    mov     ax, 16
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax
    jmp     8:SVSM_BASE_ADDR

gdt32:
    dq      0
    dq      0x00cf9b000000ffff
    dq      0x00cf93000000ffff
gdt32_end:

gdt32_descr:
    dw      gdt32_end - gdt32 - 1
    dd      ADDR_OF(gdt32)


BITS 16
ALIGN   16

;
; Padding to ensure first guid starts at 0xffffffd0
;
TIMES (0xf40 - (guidedStructureEnd - guidedStructureStart) - ($ - SvsmSevGuidedStructureStart)) DB 0

; GUIDed structure.  To traverse this you should first verify the
; presence of the table footer guid
; (96b582de-1fb2-45f7-baea-a366c55a082d) at 0xffffffd0.  If that
; is found, the two bytes at 0xffffffce are the entire table length.
;
; The table is composed of structures with the form:
;
; Data (arbitrary bytes identified by guid)
; length from start of data to end of guid (2 bytes)
; guid (16 bytes)
;
; so work back from the footer using the length to traverse until you
; either find the guid you're looking for or run off the beginning of
; the table.
;
guidedStructureStart:

;
; SEV metadata descriptor
;
; Provide the start offset of the metadata blob within the OVMF binary.

; GUID : dc886566-984a-4798-A75e-5585a7bf67cc
;
SvsmSevMetadataOffsetStart:
  DD      (fourGigabytes - SvsmSevMetadataGuid)
  DW      SvsmSevMetadataOffsetEnd - SvsmSevMetadataOffsetStart
  DB      0x66, 0x65, 0x88, 0xdc, 0x4a, 0x98, 0x98, 0x47
  DB      0xA7, 0x5e, 0x55, 0x85, 0xa7, 0xbf, 0x67, 0xcc
SvsmSevMetadataOffsetEnd:

; SEV Secret block
;
; This describes the guest ram area where the hypervisor should
; inject the secret.  The data format is:
;
; base physical address (32 bit word)
; table length (32 bit word)
;
; GUID (SEV secret block): 4c2eb361-7d9b-4cc3-8081-127c90d3d294
;
sevSecretBlockStart:
    DD      SVSM_SECRETS_BASE
    DD      SVSM_SECRETS_SIZE
    DW      sevSecretBlockEnd - sevSecretBlockStart
    DB      0x61, 0xB3, 0x2E, 0x4C, 0x9B, 0x7D, 0xC3, 0x4C
    DB      0x80, 0x81, 0x12, 0x7C, 0x90, 0xD3, 0xD2, 0x94
sevSecretBlockEnd:

;
; SEV-ES Processor Reset support
;
; sevEsResetBlock:
;   For the initial boot of an AP under SEV-ES, the "reset" RIP must be
;   programmed to the RAM area defined by SEV_ES_AP_RESET_IP. The data
;   format is:
;
;   IP value [0:15]
;   CS segment base [31:16]
;
;   GUID (SEV-ES reset block): 00f771de-1a7e-4fcb-890e-68c77e2fb44e
;
;   A hypervisor reads the CS segement base and IP value. The CS segment base
;   value represents the high order 16-bits of the CS segment base, so the
;   hypervisor must left shift the value of the CS segement base by 16 bits to
;   form the full CS segment base for the CS segment register. It would then
;   program the EIP register with the IP value as read.
;

sevEsResetBlockStart:
    DD      SEV_ES_AP_RESET_IP
    DW      sevEsResetBlockEnd - sevEsResetBlockStart
    DB      0xDE, 0x71, 0xF7, 0x00, 0x7E, 0x1A, 0xCB, 0x4F
    DB      0x89, 0x0E, 0x68, 0xC7, 0x7E, 0x2F, 0xB4, 0x4E
sevEsResetBlockEnd:

;
; SEV-SNP SVSM Info
;
; SVM Info:
;   Information about the location of any SVSM region within the firmware.
;   The SVSM region is optional but if present, provides the entry point for
;   the AP in 32-bit protected mode. The hypervisor will detect the presence
;   of the SVSM region and will configure the entry point of the guest
;   accordingly. The structure format is:
;
;   Launch offset of entry point of SVSM from start of firmware (32-bit word)
;
;   GUID (SVSM Info): a789a612-0597-4c4b-a49f-cbb1fe9d1ddd
;
;   A hypervisor reads the CS segement base and IP value. The CS segment base
;   value represents the high order 16-bits of the CS segment base, so the
;   hypervisor must left shift the value of the CS segement base by 16 bits to
;   form the full CS segment base for the CS segment register. It would then
;   program the EIP register with the IP value as read.
;

sevSnpSvsmInfoStart:
    DD      SVSM_OFFSET
    DW      sevSnpSvsmInfoEnd - sevSnpSvsmInfoStart
    DB      0x12, 0xA6, 0x89, 0xA7, 0x97, 0x05, 0x4B, 0x4C
    DB      0xA4, 0x9F, 0xCB, 0xB1, 0xFE, 0x9D, 0x1D, 0xDD
sevSnpSvsmInfoEnd:

;
; Table footer:
;
; length of whole table (16 bit word)
; GUID (table footer): 96b582de-1fb2-45f7-baea-a366c55a082d
;
    DW      guidedStructureEnd - guidedStructureStart
    DB      0xDE, 0x82, 0xB5, 0x96, 0xB2, 0x1F, 0xF7, 0x45
    DB      0xBA, 0xEA, 0xA3, 0x66, 0xC5, 0x5A, 0x08, 0x2D

guidedStructureEnd:

ALIGN   16

applicationProcessorEntryPoint:
;
; Application Processors entry point
;
; GenFv generates code aligned on a 4k boundary which will jump to this
; location.  (0xffffffe0)  This allows the Local APIC Startup IPI to be
; used to wake up the application processors.
;
;    jmp     EarlyApInitReal16
;
; FIXME
jmp     $

ALIGN   8

    DD      0

;
; The VTF signature
;
; VTF-0 means that the VTF (Volume Top File) code does not require
; any fixups.
;
vtfSignature:
    DB      'V', 'T', 'F', 0

ALIGN   16

resetVector:
;
; Reset Vector
;
; This is where the processor will begin execution
;
; In IA32 we follow the standard reset vector flow. While in X64, Td guest
; may be supported. Td guest requires the startup mode to be 32-bit
; protected mode but the legacy VM startup mode is 16-bit real mode.
; To make NASM generate such shared entry code that behaves correctly in
; both 16-bit and 32-bit mode, more BITS directives are added.
;
    jmp     to_pm_mode

ALIGN   16

fourGigabytes:

