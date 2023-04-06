/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Roy Hopkins <rhopkins@suse.com>
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

	. = 0xfffff000;
	ovmfgdt = .;
	.sinit = .;
	.init . : {
		/*
		 * OVMF GDT is expected to be at 0xfffff000
		 */
		*(.ovmfgdt);
		. = 4096 - 512;
		*(.init);
		. = 4096 - 32 - 256;
		*(.sevmeta);
		. = 4096 - 16;
		*(.resetvector);
		. = 4096;
	}
	einit = .;

	/DISCARD/ : {*(.*)}
}

