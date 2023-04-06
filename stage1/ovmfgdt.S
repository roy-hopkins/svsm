/* SPDX-License-Identifier: MIT OR Apache-2.0 */

/*
 * Copyright (c) 2022-2023 SUSE LLC
 *
 * Author: Roy Hopkins <roy.hopkins@suse.com>
 */

/*
 * GDT that is compatible with the OVMF SEC entry point.
 */
.section .ovmfgdt
.quad	0					// NULL				[0x00]
.quad	0					// Spare            [0x08]
.quad	0x00cf9b000000ffff	// Code segment     [0x10]
.quad	0x00cf93000000ffff	// Data segment     [0x18]
.quad	0					// Spare            [0x20]
.quad	0x008f9b000000ffff	// 16-bit code      [0x28]
.quad	0x000093000000ffff	// 16-bit data      [0x30]
.quad	0x00af9b000000ffff	// 64-bit code      [0x38]

