/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Roy Hopkins <roy.hopkins@suse.com>
 */

OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
	.stext = ALIGN(.sdata  - SIZEOF(.text) - 4095, 4096);
	. = .stext;
	.text : { *(.startup.*) *(.text) *(.text.*) }

	.sdata = ALIGN(.sovmf - SIZEOF(.data) - 4095, 4096);
	. = .sdata;
	.data : { *(.data) }

	/*
	 * The OVMF section must be aligned up to 0xfffff000 followed by the
	 * SVSM reset vector. The OVMF firmware image has been truncated so the
	 * ResetVector module containing the OVMF metadata starts at
	 * 0xffffe000.
	 */
	.sovmf = ALIGN(.sinit - SIZEOF(.ovmf) - 4095, 4096);
	. = .sovmf;
	.ovmf : { *(.ovmf) }

	. = 0xfffffe00;
	.sinit = .;
	.init . : {
		*(.init);
		. = 512 - 32 - 256;
		*(.sevmeta);
		. = 512 - 16;
		*(.resetvector);
		. = 512;
	}
	einit = .;

	/DISCARD/ : {*(.*)}
}

