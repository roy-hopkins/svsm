// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>
//
// vim: ts=4 sw=4 et
use core::mem::size_of;

use crate::error::SvsmError;
use crate::utils::Uuid;
use crate::types::PhysAddr;
use crate::mm::{PerCPUPageMappingGuard, PAGE_SIZE, PAGE_SIZE_2M};

pub struct FirmwareVolumeHeader {
    pub zero_vector: [u8; 16],
    pub file_system_guid: Uuid,
    pub fv_length: u64,
    pub signature: u32,
    pub attributes: u32,
    pub header_length: u16,
    pub checksum: u16,
    pub ext_header_offset: u16,
    pub reserved: u8,
    pub revision: u8,
}

pub struct FirmwareFileIntegrityCheck {
    pub header: u8,
    pub file:   u8,
}

pub struct FirmwareFileHeader {
    pub name: [u8; 16],
    pub integrity_check: FirmwareFileIntegrityCheck,
    pub file_type: u8,
    pub attributes: u8,
    pub size: [u8; 3],
    pub state: u8,
}

pub struct FirmwareFileHeader2 {
    pub header: FirmwareFileHeader,
    pub extended_size: u64,
}

pub struct SectionHeader {
    pub size: [u8; 3],
    pub section_type: u8,
}

pub struct Pe32SectionHeader {
    // COFF header
    pub signature: u32,
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_data_stamp: u32,
    pub ptr_to_symbols: u32,
    pub num_symbol_table: u32,
    pub size_opt_header: u16,
    // Standard COFF
    pub characteristics: u16,
    pub magic: u16,
    pub major_link_version: u8,
    pub minor_link_version: u8,
    pub size_of_code: u32,
    pub size_of_init_data: u32,
    pub size_of_uninit_data: u32,
    pub addr_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    // Additional COFF (UEFI)
    pub image_base: u32,
}

// Helper for generically working with files that use either FirmwareFileHeader
// or FirmwareFileHeader2
pub struct FirmwareFile {
    pub size: usize,                                // Validated size of file contents including header.
    pub phys_data: Option<PhysAddr>,                // Physical address of file contents.
    pub data_length: usize,                         // Length of file data.
    pub file_type: u8,                              // File type from file header.
}

pub struct FirmwareFileSystem {
    phys_fv: PhysAddr,
    fv_length: usize,
    first_file: Option<PhysAddr>,
    next_file: Option<PhysAddr>
}

const FVH_SIGNATURE: u32 = 0x4856465f;      // _FVH
const MSDOS_SIGNATURE: u16 = 0x5a4d;        // MZ
const PE_SIGNATURE: u32 = 0x00004550;       // PE..
const FFS_ATTRIB_LARGE_FILE: u8 = 0x01;
const FFS_ATTRIB_CHECKSUM: u8 = 0x40;

pub const EFI_FV_FILETYPE_SECURITY_CORE: u8 = 0x03;
pub const EFI_SECTION_PE32: u8 = 0x10;

unsafe fn calculate_sum8(buffer: *const u8, length: usize) -> u8 {
    let mut sum: u8 = 0;
    for count in 0..length {
        sum = ((sum as u16 + buffer.offset(count as isize).read() as u16) & 0x00ff) as u8;
    }
    sum
}

unsafe fn calculate_sum16(buffer: *const u8, length: usize) -> u16 {
    // Check for 16 bit alignment.
    assert!(((buffer as usize) & 0x1) == 0);
    assert!((length & 0x1) == 0);

    let mut sum: u16 = 0;
    let buffer16 = buffer as *const u16;
    for count in 0..(length / 2) {
        sum = ((sum as u32 + buffer16.offset(count as isize).read() as u32) & 0x0000ffff) as u16;
    }
    sum
}

impl FirmwareFileSystem {
    pub fn new(fv_base: PhysAddr, fv_length: usize) -> Self {
        if fv_length < size_of::<FirmwareVolumeHeader>() {
            panic!("Firmware volume is too small to contain a volume header");
        }
        Self {
            phys_fv: fv_base,
            fv_length,
            next_file: None,
            first_file: None
        }
    }

    pub fn valid(self: &mut Self) -> Result<(), SvsmError> {
        let guard = PerCPUPageMappingGuard::create(self.phys_fv, 0, false)?;
        let vaddr = guard.virt_addr();
        let volume = vaddr as *const FirmwareVolumeHeader;

        unsafe {
            if (*volume).signature != FVH_SIGNATURE {
                return Err(SvsmError::Firmware);
            }
            let checksum = calculate_sum16(volume as *const u8, (*volume).header_length as usize);
            match checksum {
                0 => {
                    self.first_file = Some(self.phys_fv + (*volume).header_length as PhysAddr);
                    Ok(())
                },
                _ => Err(SvsmError::Firmware)
            }
        }
    }

    pub fn get_first_file(self: &mut Self) -> Result<FirmwareFile, ()> {
        // Make sure the volume is valid and the first file lies within the volume.
        if self.valid().is_err() {
            return Err(());
        }
        let phys_file = self.first_file.unwrap();
        let file = match FirmwareFile::new(self, phys_file) {
            Ok(file) => file,
            Err(_) => return Err(()),
        };

        // next_file keeps track of the start location of the file after this one. This must be
        // aligned to the next 8 byte boundary.
        self.next_file = Some((phys_file + file.size + 7) & !0x7);
        Ok(file)
    }

    pub fn get_next_file(self: &mut Self) -> Result<FirmwareFile, ()> {
        if self.next_file.is_none() {
            return self.get_first_file();
        }

        let phys_file = self.next_file.unwrap();
        let file = match FirmwareFile::new(self, phys_file) {
            Ok(file) => file,
            Err(_) => return Err(()),
        };

        // next_file keeps track of the start location of the file after this one. This must be
        // aligned to the next 8 byte boundary.
        self.next_file = Some((phys_file + file.size + 7) & !0x7);
        Ok(file)
    }

    pub fn within(self: &Self, phys_addr: PhysAddr) -> Result<(), ()> {
        match (phys_addr >= self.phys_fv) && (phys_addr < (self.phys_fv + self.fv_length)) {
            true => Ok(()),
            false => Err(()),
        }
    }
}


impl FirmwareFile {
    pub fn new(fv: &FirmwareFileSystem, phys_addr: usize) -> Result<Self, SvsmError> {
        // Make sure the file start and subsequently the entire file fit within the
        // firmware volume.
        let ffh_size = size_of::<FirmwareFileHeader>();
        let ffh2_size = size_of::<FirmwareFileHeader2>();

        if fv.within(phys_addr + ffh_size).is_err() {
            return Err(SvsmError::Firmware);
        }
        // FIXME: The (extended) file header might traverse a page boundary. This will _always_
        // cause a panic on startup if the OVMF image does generate a file that traverses the
        // boundary so it will be apparent if this is the case. Use a 2M page to minimise the likelihood.
        let page = phys_addr & !(PAGE_SIZE_2M - 1);
        let guard = PerCPUPageMappingGuard::create(page, 0, true)?;
        let mut vaddr = guard.virt_addr();
        vaddr += phys_addr - page;

        unsafe {
            let file_ptr = vaddr as *const FirmwareFileHeader;
            // Long files use the same structure but have an extended field on the end.
            let (file_size, header_size) = match ((*file_ptr).attributes & FFS_ATTRIB_LARGE_FILE) == FFS_ATTRIB_LARGE_FILE {
                true => {
                    if fv.within(phys_addr + ffh2_size).is_err() {
                        return Err(SvsmError::Firmware);
                    }
                    let extended_file_ptr = file_ptr as *const FirmwareFileHeader2;
                    let size = (*extended_file_ptr).extended_size;
                    if (size > 0xffffffff) || fv.within(phys_addr + size as usize).is_err() {
                        return Err(SvsmError::Firmware);
                    }
                    (size as usize, ffh2_size)
                },
                false => {
                    let size = (*file_ptr).size[0] as u32 + 
                                    (((*file_ptr).size[1] as u32) << 8) + 
                                    (((*file_ptr).size[2] as u32) << 16);
                    if fv.within(phys_addr + size as usize).is_err() {
                        return Err(SvsmError::Firmware);
                    }
                    (size as usize, ffh_size)
                },
            };

            // There are potentially two checksums to check: the header and the file contents.
            let mut header_checksum = calculate_sum8(file_ptr as *const u8, header_size);
            // Two fields in the header should not be included in the checksum so subtract them out.
            let checksum_correction = (0xff - (*file_ptr).state + 1) as u16 + (0xff - (*file_ptr).integrity_check.file + 1) as u16;
            header_checksum = (((header_checksum as u16) + checksum_correction) & 0xff) as u8;
            let file_checksum = match ((*file_ptr).attributes & FFS_ATTRIB_CHECKSUM) == 0 {
                true => 0,
                false => {
                    // TODO: Perform file checksum calculation.
                    //calculate_sum8(fv.fv.offset((offset + header_size) as isize), file_size - header_size)
                    0
                },
            };
            let (data, data_length) = match (file_size - header_size) == 0 {
                true => (None, 0),
                false => (Some(phys_addr + header_size), file_size - header_size),
            };
            match (header_checksum == 0) && (file_checksum == 0) {
                true => Ok(Self { size: file_size, phys_data: data, data_length, file_type: (*file_ptr).file_type }),
                false => Err(SvsmError::Firmware)
            }
        }
    }

    fn find_section(self: &Self, section_type: u8) -> Result<(PhysAddr, usize), SvsmError> {
        let section_header_size = size_of::<SectionHeader>();
        assert!(section_header_size == 4);

        let mut result = Err(SvsmError::Firmware);
        let phys_data = self.phys_data.unwrap();
        let mut phys_section = phys_data;
        while (phys_section + section_header_size) < (phys_data + self.size) {
            // Section headers must be 4 byte aligned and are 4 bytes long so will not
            // traverse a page boundary.
            assert!((phys_section & 0x3) == 0);
            let page = phys_section & !(PAGE_SIZE-1);
            let guard = PerCPUPageMappingGuard::create(page, 0, false)?;
            let vaddr = guard.virt_addr();
    
            let section_header = (vaddr + (phys_section - page)) as *const SectionHeader;
            // Validate the size. If the file is using an extended size (greater
            // than 24 bits) then the size will contain 0xffffff. This code
            // doesn't support large files at the moment so the check below will
            // exit.
            unsafe {
                let size = (*section_header).size[0] as usize + 
                                (((*section_header).size[1] as usize) << 8) + 
                                (((*section_header).size[2] as usize) << 16);
                if size > self.size {
                    break;
                }
                if (*section_header).section_type == section_type {
                    result = Ok((phys_section + section_header_size, size - section_header_size));
                    break;
                }
                // Advance to the next section
                phys_section += size;
            }
        }
        result
    }

    pub fn find_pe_entry(self: &Self) -> Result<PhysAddr, SvsmError> {
        // Start by finding the PE32 section within the file.
        let (phys_section, section_size) = self.find_section(EFI_SECTION_PE32)?;
        if section_size < 0x40 {
            return Err(SvsmError::Firmware);
        }

        // FIXME: There is no guarantee that the header will be completely contained in a single page. We
        // use a 2M page to minimise the likelihood of page traversal but it is not guaranteed. It is 
        // dependent purely on the OVMF build and will be detected by a panic during startup if a page
        // boundary is traversed.
        let page = phys_section & !(PAGE_SIZE_2M - 1);
        let guard = PerCPUPageMappingGuard::create(page, 0, true)?;
        let vaddr = guard.virt_addr();

        let virt_section = vaddr + (phys_section - page);
        
        // Check for the MSDOS header.
        unsafe {
            let sh_size = size_of::<Pe32SectionHeader>();
            let msdos_sig = (virt_section as *const u16).read();
            if msdos_sig != MSDOS_SIGNATURE {
                return Err(SvsmError::Firmware);
            }
            // The PE header is always at offset 0x3c
            let pe_header_offset = ((virt_section + 0x3c) as *const u32).read();
            if (pe_header_offset as usize + sh_size) > section_size {
                return Err(SvsmError::Firmware);
            }
            // Check that the offset fits in our page range.
            let phys_pe_section_header = phys_section + pe_header_offset as usize;
            if (phys_pe_section_header + sh_size) > (page + PAGE_SIZE_2M) {
                panic!("SEC PE32+ file contains a Pe32SectionHeader that exceeds the mapped page limit.");
            }

            //log::info!("section {:#x}, pe section {:#x}, diff {:#x}", virt_section, phys_pe_section_header);

            let pe_header = (virt_section + pe_header_offset as usize) as *const Pe32SectionHeader;
            if ((*pe_header).signature != PE_SIGNATURE) || ((*pe_header).image_base as usize >= section_size) {
                return Err(SvsmError::Firmware);
            }
            Ok(phys_section + (*pe_header).image_base as PhysAddr)
        }
    }
}
