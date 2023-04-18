// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::cpu::percpu::this_cpu_mut;
use crate::error::SvsmError;
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::SIZE_1G;
use crate::sev::ghcb::PageStateChangeOp;
use crate::sev::{pvalidate, rmp_adjust, RMPFlags};
use crate::types::{PhysAddr, VirtAddr, PAGE_SIZE};
use crate::utils::Uuid;
use crate::utils::{overlap, zero_mem_region};
use alloc::vec::Vec;

use core::cmp;
use core::mem;
use core::str::FromStr;

/*
 * First page below 4GB contains SVSM metadata. Second page
 * below 4GB contains OVMF metadata.
 */
const OVMF_METADATA_PHYS: PhysAddr = (4 * SIZE_1G) - (2 * PAGE_SIZE);

#[derive(Copy, Clone)]
pub struct SevPreValidMem {
    base: PhysAddr,
    length: usize,
}

impl SevPreValidMem {
    fn new(base: PhysAddr, length: usize) -> Self {
        Self { base, length }
    }

    fn new_4k(base: PhysAddr) -> Self {
        Self::new(base, PAGE_SIZE)
    }

    #[inline]
    fn end(&self) -> PhysAddr {
        self.base + self.length
    }

    fn overlap(&self, other: &Self) -> bool {
        overlap(self.base, self.end(), other.base, other.end())
    }

    fn merge(self, other: Self) -> Self {
        let base = cmp::min(self.base, other.base);
        let length = cmp::max(self.end(), other.end()) - base;
        Self::new(base, length)
    }
}

pub struct SevOVMFMetaData {
    pub reset_ip: Option<PhysAddr>,
    pub cpuid_page: Option<PhysAddr>,
    pub secrets_page: Option<PhysAddr>,
    pub caa_page: Option<PhysAddr>,
    pub valid_mem: Vec<SevPreValidMem>,
}

impl SevOVMFMetaData {
    pub const fn new() -> Self {
        SevOVMFMetaData {
            reset_ip: None,
            cpuid_page: None,
            secrets_page: None,
            caa_page: None,
            valid_mem: Vec::new(),
        }
    }

    pub fn add_valid_mem(&mut self, base: PhysAddr, len: usize) {
        self.valid_mem.push(SevPreValidMem::new(base, len));
    }
}

const OVMF_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const OVMF_SEV_META_DATA_GUID: &str = "dc886566-984a-4798-a75e-5585a7bf67cc";
const SEV_INFO_BLOCK_GUID: &str = "00f771de-1a7e-4fcb-890e-68c77e2fb44e";
const SVSM_INFO_GUID: &str = "a789a612-0597-4c4b-a49f-cbb1fe9d1ddd";

unsafe fn find_table(uuid: &Uuid, start: VirtAddr, len: VirtAddr) -> Option<(VirtAddr, usize)> {
    let mut curr = start;
    let end = start - len;

    while curr >= end {
        curr -= mem::size_of::<Uuid>();

        let ptr = curr as *const u8;
        let curr_uuid = Uuid::from_mem(ptr);

        curr -= mem::size_of::<u16>();
        if curr < end {
            break;
        }

        let len_ptr = curr as *const u16;
        let orig_len = len_ptr.read() as usize;

        if len < mem::size_of::<Uuid>() + mem::size_of::<u16>() {
            break;
        }
        let len = orig_len - (mem::size_of::<Uuid>() + mem::size_of::<u16>());

        curr -= len;

        if *uuid == curr_uuid {
            return Some((curr, len));
        }
    }

    None
}

#[repr(C, packed)]
struct SevMetaDataHeader {
    signature: [u8; 4],
    len: u32,
    version: u32,
    num_desc: u32,
}

#[repr(C, packed)]
struct SevMetaDataDesc {
    base: u32,
    len: u32,
    t: u32,
}

const SEV_META_DESC_TYPE_MEM: u32 = 1;
const SEV_META_DESC_TYPE_SECRETS: u32 = 2;
const SEV_META_DESC_TYPE_CPUID: u32 = 3;
const SEV_META_DESC_TYPE_CAA: u32 = 4;

pub fn parse_ovmf_meta_data() -> Result<SevOVMFMetaData, SvsmError> {
    let pstart: PhysAddr = OVMF_METADATA_PHYS;
    let mut meta_data = SevOVMFMetaData::new();

    // Map meta-data location, it starts at 32 bytes below 4GiB
    let guard = PerCPUPageMappingGuard::create_4k(pstart)?;
    let vstart = guard.virt_addr();
    let vend: VirtAddr = vstart + PAGE_SIZE;

    let mut curr = vend - 32;

    let meta_uuid = Uuid::from_str(OVMF_TABLE_FOOTER_GUID).map_err(|()| SvsmError::Firmware)?;

    curr -= mem::size_of::<Uuid>();
    let ptr = curr as *const u8;

    unsafe {
        let uuid = Uuid::from_mem(ptr);

        if uuid != meta_uuid {
            return Err(SvsmError::Firmware);
        }

        curr -= mem::size_of::<u16>();
        let ptr = curr as *const u16;

        let full_len = ptr.read() as usize;
        let len = full_len - mem::size_of::<u16>() + mem::size_of::<Uuid>();

        // First check if this is the SVSM itself instead of OVMF
        let svsm_info_uuid = Uuid::from_str(SVSM_INFO_GUID).map_err(|()| SvsmError::Firmware)?;
        if let Some(_v) = find_table(&svsm_info_uuid, curr, len) {
            return Err(SvsmError::Firmware);
        }

        // Search SEV_INFO_BLOCK_GUID
        let sev_info_uuid =
            Uuid::from_str(SEV_INFO_BLOCK_GUID).map_err(|()| SvsmError::Firmware)?;
        let ret = find_table(&sev_info_uuid, curr, len);
        if let Some(tbl) = ret {
            let (base, len) = tbl;
            if len != mem::size_of::<u32>() {
                return Err(SvsmError::Firmware);
            }
            let info_ptr = base as *const u32;
            meta_data.reset_ip = Some(info_ptr.read() as PhysAddr);
        }

        // Search and parse Meta Data
        let sev_meta_uuid =
            Uuid::from_str(OVMF_SEV_META_DATA_GUID).map_err(|()| SvsmError::Firmware)?;
        let ret = find_table(&sev_meta_uuid, curr, len);
        if let Some(tbl) = ret {
            let (base, _len) = tbl;
            let off_ptr = base as *const u32;
            let offset = off_ptr.read_unaligned() as usize;

            let meta_ptr = (vend - offset) as *const SevMetaDataHeader;
            //let len = meta_ptr.read().len;
            let num_descs = meta_ptr.read().num_desc as isize;
            let desc_ptr = meta_ptr.offset(1).cast::<SevMetaDataDesc>();

            for i in 0..num_descs {
                let desc = desc_ptr.offset(i).read();
                let t = desc.t;
                let base = desc.base as PhysAddr;
                let len = desc.len as usize;
                match t {
                    SEV_META_DESC_TYPE_MEM => meta_data.add_valid_mem(base, len),
                    SEV_META_DESC_TYPE_SECRETS => {
                        if len != PAGE_SIZE {
                            return Err(SvsmError::Firmware);
                        }
                        meta_data.secrets_page = Some(base);
                    }
                    SEV_META_DESC_TYPE_CPUID => {
                        if len != PAGE_SIZE {
                            return Err(SvsmError::Firmware);
                        }
                        meta_data.cpuid_page = Some(base);
                    }
                    SEV_META_DESC_TYPE_CAA => {
                        if len != PAGE_SIZE {
                            return Err(SvsmError::Firmware);
                        }
                        meta_data.caa_page = Some(base);
                    }
                    _ => log::info!("Unknown metadata item type: {}", t),
                }
            }
        }
    }

    Ok(meta_data)
}

fn validate_ovmf_mem_region(region: SevPreValidMem) -> Result<(), SvsmError> {
    let pstart: PhysAddr = region.base;
    let pend: PhysAddr = region.end();

    log::info!("Validating {:#018x}-{:#018x}", pstart, pend);

    this_cpu_mut()
        .ghcb()
        .page_state_change(pstart, pend, false, PageStateChangeOp::PscPrivate)
        .expect("GHCB PSC call failed to validate firmware memory");

    for paddr in (pstart..pend).step_by(PAGE_SIZE) {
        let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
        let vaddr = guard.virt_addr();

        pvalidate(vaddr, false, true)?;

        // Make page accessible to guest VMPL
        rmp_adjust(vaddr, RMPFlags::GUEST_VMPL | RMPFlags::RWX, false)?;

        zero_mem_region(vaddr, vaddr + PAGE_SIZE);
    }

    Ok(())
}

fn validate_ovmf_memory_vec(regions: Vec<SevPreValidMem>) -> Result<(), SvsmError> {
    if regions.is_empty() {
        return Ok(());
    }

    let mut next_vec: Vec<SevPreValidMem> = Vec::new();
    let mut region = regions[0];

    for next in regions.into_iter().skip(1) {
        if region.overlap(&next) {
            region = region.merge(next);
        } else {
            next_vec.push(next);
        }
    }

    validate_ovmf_mem_region(region)?;
    validate_ovmf_memory_vec(next_vec)
}

pub fn validate_ovmf_memory(ovmf_meta: &SevOVMFMetaData) -> Result<(), SvsmError> {
    // Initalize vector with regions from the OVMF FW
    let mut regions = ovmf_meta.valid_mem.clone();

    // Add region for CPUID page if present
    if let Some(cpuid_paddr) = ovmf_meta.cpuid_page {
        regions.push(SevPreValidMem::new_4k(cpuid_paddr));
    }

    // Add region for Secrets page if present
    if let Some(secrets_paddr) = ovmf_meta.secrets_page {
        regions.push(SevPreValidMem::new_4k(secrets_paddr));
    }

    // Add region for CAA page if present
    if let Some(caa_paddr) = ovmf_meta.caa_page {
        regions.push(SevPreValidMem::new_4k(caa_paddr));
    }

    // Sort regions by base address
    regions.sort_unstable_by(|a, b| a.base.cmp(&b.base));

    validate_ovmf_memory_vec(regions)
}

pub fn print_ovmf_meta(ovmf_meta: &SevOVMFMetaData) {
    log::info!("OVMF FW Meta Data");

    match ovmf_meta.reset_ip {
        Some(ip) => log::info!("  Reset RIP    : {:#010x}", ip),
        None => log::info!("  Reset RIP    : None"),
    };

    match ovmf_meta.cpuid_page {
        Some(addr) => log::info!("  CPUID Page   : {:#010x}", addr),
        None => log::info!("  CPUID Page   : None"),
    };

    match ovmf_meta.secrets_page {
        Some(addr) => log::info!("  Secrets Page : {:#010x}", addr),
        None => log::info!("  Secrets Page : None"),
    };

    match ovmf_meta.caa_page {
        Some(addr) => log::info!("  CAA Page     : {:#010x}", addr),
        None => log::info!("  CAA Page     : None"),
    };

    for region in &ovmf_meta.valid_mem {
        log::info!(
            "  Pre-Validated Region {:#018x}-{:#018x}",
            region.base,
            region.end()
        );
    }
}
