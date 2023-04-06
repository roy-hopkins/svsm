// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use core::str::FromStr;

use crate::error::SvsmError;
use crate::ovmf::ffs::EFI_FV_FILETYPE_SECURITY_CORE;
use crate::types::{PhysAddr, PAGE_SIZE};
use crate::utils::Uuid;
use crate::mm::{SIZE_1G, PerCPUPageMappingGuard};

use super::ffs::FirmwareFileSystem;

const FFS3_GUID: &str = "8c8ce578-8a3d-4f1c-9935-896185c32dd3";
const FFS2_GUID: &str = "8c8ce578-3dcb-4dca-bd6f-1e9689e7349a";

pub fn find_bfv_base() -> Result<(PhysAddr, usize), SvsmError> {
    // Search down 16MB from 4GB looking for the boot firmware volume header.
    // Start a page lower to skip the SVSM boot volume.
    let mut paddr: PhysAddr = (4 * SIZE_1G) - (2 * PAGE_SIZE);
    let pend: PhysAddr = (4 * SIZE_1G) - 0x1000000;
    let ffs3_uuid = Uuid::from_str(FFS3_GUID).map_err(|()| SvsmError::Firmware)?;
    let ffs2_uuid = Uuid::from_str(FFS2_GUID).map_err(|()| SvsmError::Firmware)?;

    let mut result: Result<(PhysAddr, usize), SvsmError> = Err(SvsmError::Firmware);

    while paddr >= pend {
        let guard = PerCPUPageMappingGuard::create(paddr, 0, false)?;
        let vaddr = guard.virt_addr();

        unsafe {
            // Check to see if there is an FFS3 or FFS2 GUID at this location.
            let uuid = Uuid::from_mem((vaddr + 0x10) as *const u8);
            if uuid == ffs3_uuid || uuid == ffs2_uuid {
                // Check the FV length.
                let length_check = ((vaddr + 0x20) as *const u64).read();
                if (paddr as u64 + length_check) <= (4 * SIZE_1G) as u64 {
                    log::info!("Found a valid FFS at addr {:#018x}, length {:#x}", paddr, length_check);
                    // Found the header
                    result = Ok((paddr, length_check as usize));
                    break;
                }
            }
            paddr -= PAGE_SIZE;
        }
    }
    if result.is_err() {
        panic!("The boot firmware volume could not be located.");
    }
    result
}

pub fn find_sec_entry() -> Result<(PhysAddr, PhysAddr), SvsmError> {
    // The SEC section is stored as a PE32+ file within the BFV.
    let bfv_base = find_bfv_base();
    if bfv_base.is_err() {
        log::error!("Boot firmware volume not found");
        return Err(SvsmError::Firmware);
    }
    let (bfv_addr, bfv_size) = bfv_base.unwrap();
    let mut ffs = FirmwareFileSystem::new(bfv_addr, bfv_size);
    let mut file = ffs.get_next_file();
    while file.is_ok() {
        let cur_file = file.unwrap();
        if cur_file.file_type == EFI_FV_FILETYPE_SECURITY_CORE {
            match cur_file.find_pe_entry() {
                Ok(pe) => {
                    log::info!("SEC entry point found at {:#x}", pe);
                    return Ok((pe, bfv_addr));
                }
                Err(_) => {
                    log::error!("SEC entry point not found");
                    return Err(SvsmError::Firmware);
                },
            }
        }
        file = ffs.get_next_file();
    }
    return Err(SvsmError::Firmware);
}