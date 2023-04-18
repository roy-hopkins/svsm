// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use core::mem;

use crate::cpu::efer::read_efer;
use crate::cpu::msr::read_msr;
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::pagetable::{PTEntryFlags, set_c_bit};
use crate::sev::vmsa::{VMSASegment, VMSA};
use crate::types::{PhysAddr, GUEST_VMPL, PAGE_SIZE};
use crate::cpu::percpu::this_cpu_mut;
use crate::requests::update_mappings;
use crate::error::SvsmError;
use crate::utils::zero_mem_region;

use super::sec::find_sec_entry;
use super::{SevOVMFMetaData, parse_ovmf_meta_data, print_ovmf_meta, validate_ovmf_memory};

// From OvmfPkgDefines.fdf.inc
const MEMFD_BASE_ADDRESS: PhysAddr = 0x800000;
const GHCB_PT_ADDR: PhysAddr = 0x808000;
const GHCB_BASE: PhysAddr = 0x809000;
const WORK_AREA: PhysAddr = 0x80b000;
const PAGE_TABLE_SIZE: usize = 0x6000;

// FIXME: This should be passed in from stage 1
const OVMF_GDT: PhysAddr = 0xfffff000;

#[repr(C, packed)]
struct OvmfWorkArea {
    sev_enabled: u8,
    reserved: [u8; 3],
    sev_status: u64,
    random_data: u64,
    encryption_mask: u64,
}

pub struct OvmfFw {
    ovmf_meta: SevOVMFMetaData
}

impl OvmfFw {
    pub fn new() -> Self {
        let ovmf_meta = parse_ovmf_meta_data()
            .unwrap_or_else(|e| panic!("Failed to parse OVMF FW SEV meta-data: {:#?}", e));
        print_ovmf_meta(&ovmf_meta);

        if let Err(e) = validate_ovmf_memory(&ovmf_meta) {
            panic!("Failed to validate firmware memory: {:#?}", e);
        }
        
        Self { 
            ovmf_meta
        }
    }

    pub fn tables(self: &Self) -> (PhysAddr, PhysAddr, PhysAddr) {
        let cpuid_page = match self.ovmf_meta.cpuid_page {
            Some(addr) => addr,
            None => panic!("OVMF FW does not specify CPUID_PAGE location"),
        };
    
        let secrets_page = match self.ovmf_meta.secrets_page {
            Some(addr) => addr,
            None => panic!("OVMF FW does not specify SECRETS_PAGE location"),
        };
    
        let caa_page = match self.ovmf_meta.caa_page {
            Some(addr) => addr,
            None => panic!("OVMF FW does not specify CAA_PAGE location"),
        };
        (cpuid_page, secrets_page, caa_page)
    }

    pub fn prepare_launch(self: &Self) -> Result<(), SvsmError> {
        let caa = self.ovmf_meta.caa_page.unwrap();
        let cpu = this_cpu_mut();
    
        let (entry, bfv_base) = find_sec_entry().expect("Failed to find SEC entry");

        if let Err(e) = OvmfFw::create_pagetable() {
            panic!("Failed to create OVMF pagetable: {:#?}", e);
        }
        if let Err(e) = OvmfFw::clear_page_enc_mask_for_ghcb() {
            panic!("Failed to clear encrypted mask for OVMF GHCB: {:#?}", e);
        }
        if let Err(e) = OvmfFw::prepare_work_area() {
            panic!("Failed to prepare OVMF work area: {:#?}", e);
        }
    
        let vmsa = VMSA::from_virt_addr(cpu.alloc_guest_vmsa()?);
        init_sec_vmsa(vmsa, entry as u64, true, bfv_base);

        cpu.update_guest_caa(caa);
        update_mappings()?;

        Ok(())
    }

    pub fn launch(self: &Self) -> Result<(), SvsmError> {
        let vmsa_pa = this_cpu_mut().guest_vmsa_ref().vmsa_phys().unwrap();
        let vmsa = this_cpu_mut().guest_vmsa();
    
        log::info!("VMSA PA: {:#x}", vmsa_pa);
    
        vmsa.enable();
        let sev_features = vmsa.sev_features;
    
        log::info!("Launching Firmware");
        this_cpu_mut()
            .ghcb()
            .ap_create(vmsa_pa, 0, GUEST_VMPL as u64, sev_features)?;
    
        Ok(())
    }

    /*
     * Creates an identity-mapped page table at a fixed location in memory.
     * This code is a translation of edk2/OvmfPkg/ResetVector/Ia32/PageTables64.asm
     */
    fn create_pagetable() -> Result<(), SvsmError> {
        let page_pdp_attr = PTEntryFlags::ACCESSED 
                                | PTEntryFlags::WRITABLE 
                                | PTEntryFlags::PRESENT;
        let page_2m_pde_attr = PTEntryFlags::ACCESSED 
                                | PTEntryFlags::WRITABLE 
                                | PTEntryFlags::PRESENT 
                                | PTEntryFlags::DIRTY 
                                | PTEntryFlags::HUGE;
    
        // Clear the page table memory.
        for pt_page in 0..(PAGE_TABLE_SIZE / PAGE_SIZE) {
            let guard = PerCPUPageMappingGuard::create_4k(MEMFD_BASE_ADDRESS + (pt_page * PAGE_SIZE))?;
            let vaddr = guard.virt_addr();
            zero_mem_region(vaddr, vaddr + PAGE_SIZE);
        }
    
        // Top level page directory pointers (1 * 512GB entry)
        unsafe {
            let guard = PerCPUPageMappingGuard::create_4k(MEMFD_BASE_ADDRESS)?;
            let p = guard.virt_addr() as *mut u64;
            p.write((set_c_bit(MEMFD_BASE_ADDRESS + 0x1000) + page_pdp_attr.bits() as PhysAddr) as u64);
        }
    
        // Next level page directory pointers (4 * 1GB entries => 4GB)
        unsafe {
            let guard = PerCPUPageMappingGuard::create_4k(MEMFD_BASE_ADDRESS + 0x1000)?;
            let p = guard.virt_addr() as *mut u64;
            for offset in 0..4 {
                p.offset(offset).write(
                    (set_c_bit(MEMFD_BASE_ADDRESS + 0x2000 + (0x1000 * offset as PhysAddr)) 
                    + page_pdp_attr.bits() as PhysAddr) as u64);
            }
        }
    
        // Page table entries (2048 * 2MB entries => 4GB)
        unsafe {
            for page in 0..4 {
                let guard = PerCPUPageMappingGuard::create_4k(
                    MEMFD_BASE_ADDRESS + 0x2000 + (page as PhysAddr * 0x1000))?;
                let p = guard.virt_addr() as *mut u64;

                for entry in 0..0x200 {
                    let addr = set_c_bit(((entry + (page * 0x200)) as PhysAddr) << 21);
                    p.offset(entry).write((addr + page_2m_pde_attr.bits() as PhysAddr) as u64);
                }
            }
        }    
        Ok(())
    }

    /*
     * Modifies the identity-mapped OVMF page table to clear the encrypted bit
     * for the GHCB memory range.
     */    
    pub fn clear_page_enc_mask_for_ghcb() -> Result<(), SvsmError> {
        let page_pdp_attr = PTEntryFlags::ACCESSED 
                            | PTEntryFlags::WRITABLE 
                            | PTEntryFlags::PRESENT;
        let page_4k_pde_attr = PTEntryFlags::ACCESSED 
                            | PTEntryFlags::WRITABLE 
                            | PTEntryFlags::PRESENT 
                            | PTEntryFlags::DIRTY;
    
        unsafe {
            // Switch from 2MB to 4K pages for the range containing the GHCB
            let guard = PerCPUPageMappingGuard::create_4k(MEMFD_BASE_ADDRESS + 0x2000)?;
            let p = guard.virt_addr() as *mut u64;
            let addr = set_c_bit(GHCB_PT_ADDR);
            p.offset((GHCB_BASE as isize) >> 21).write((addr + page_pdp_attr.bits() as PhysAddr) as u64);
        }
        unsafe {
            // Create the 4K entries
            let guard = PerCPUPageMappingGuard::create_4k(GHCB_PT_ADDR as PhysAddr)?;
            let p = guard.virt_addr() as *mut u64;
            for entry in 0..0x200 {
                let addr = ((entry as PhysAddr) << 12) + (GHCB_BASE & 0xffe0_0000) as PhysAddr;
                // Skip setting the encrypted bit for the GHCB page
                let phys_addr = if addr == GHCB_BASE as PhysAddr { addr } else { set_c_bit(addr) };
                p.offset(entry).write((phys_addr + page_4k_pde_attr.bits() as PhysAddr) as u64);
            }
        }
        Ok(())
    }
    
    /*
     * The work area tells SEC what SEV features are enabled. This must match the
     * structure defined in edk2/OvmfPkg/Include/WorkArea.h
     */
    pub fn prepare_work_area()  -> Result<(), SvsmError> {
        let work_area_phys: PhysAddr = WORK_AREA;
        let guard = PerCPUPageMappingGuard::create_4k(work_area_phys)?;
        let work_area = guard.virt_addr();
    
        zero_mem_region(work_area, work_area + 0x1000);

        unsafe {
            let work_area_data = work_area as *mut OvmfWorkArea;
            *work_area_data = OvmfWorkArea {
                sev_enabled: 1,
                reserved: [0, 0, 0],
                sev_status: read_msr(0xc0010131),
                random_data: 0,
                encryption_mask: set_c_bit(0) as u64,
            };
        }

        Ok(())
    }
       
}

fn ovmf_gdt_segment() -> VMSASegment {
    let limit = ((mem::size_of::<u64>() * 8) - 1) as u32;
    VMSASegment {
        selector: 0,
        flags: 0,
        limit: limit,
        base: OVMF_GDT as u64,
    }
}

fn ovmf_code_segment() -> VMSASegment {
    VMSASegment {
        selector: 0x38,
        flags: 0xa9b,
        limit: 0xffff_ffff,
        base: 0,
    }
}

fn ovmf_data_segment() -> VMSASegment {
    VMSASegment {
        selector: 0x18,
        flags: 0xc93,
        limit: 0xffff_ffff,
        base: 0,
    }
}

pub fn init_sec_vmsa(vmsa: *mut VMSA, rip: u64, ap: bool, bfv_addr: PhysAddr) {
    let v = unsafe { vmsa.as_mut().unwrap() };
    v.es = ovmf_data_segment();
    v.cs = ovmf_code_segment();
    v.ss = ovmf_data_segment();
    v.ds = ovmf_data_segment();
    v.fs = ovmf_data_segment();
    v.gs = ovmf_data_segment();
    v.gdt = ovmf_gdt_segment();
    v.cr3 = MEMFD_BASE_ADDRESS as u64;
    v.cr0 = 0xc0000023;
    v.cr4 = 0x660;

    v.rbp = bfv_addr as u64;
    v.rdi = if ap { 0x4150 } else { 0x4250 };       // AP or BP

    v.efer = read_efer().bits() | 0x100;

    v.rflags = 0x2;
    v.dr6 = 0xffff0ff0;
    v.dr7 = 0x400;
    v.g_pat = 0x0007040600070406u64;
    v.xcr0 = 1;
    v.mxcsr = 0x1f80;
    v.x87_ftw = 0x5555;
    v.x87_fcw = 0x0040;
    v.vmpl = 1;
    v.rip = rip;
    v.sev_features = read_msr(0xc0010131) >> 2;
}
