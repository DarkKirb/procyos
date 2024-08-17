//! Module for loading the kernel ELF file and executing it.

use core::{
    alloc::{Allocator, Layout, LayoutError},
    ptr,
};

use alloc::vec::Vec;
use elf::{
    abi::{PF_W, PF_X, PT_LOAD, SHT_RELA},
    endian::AnyEndian,
    file::Class,
    ElfBytes,
};
use kernel_arch_x86_64::paging::PageFault;
use log::{debug, info};
use miniser::Serialize;
use rand::Rng;
use startup_info::{KernelStartInfo, MemoryMapEntry};
use sys::{jump_thunk, Pager, PAGE_SIZE};
use thiserror::Error;
use uefi::table::{boot::MemoryType, Boot, SystemTable};

use crate::bump_alloc::BumpAllocator;

mod sys {
    #[cfg(target_arch = "x86_64")]
    mod x86_64;

    pub use x86_64::*;
}

#[derive(Debug, Error)]
pub enum ElfLoadError {
    #[error("Invalid ELF file: {0}")]
    ElfParsingError(#[from] elf::ParseError),
    #[error("Invalid ELF Class: {0:?} (expected {1:?})")]
    InvalidElfClass(Class, Class),
    #[error("Invalid big-endianness: {0} (expected {1})")]
    InvalidEndian(bool, bool),
    #[error("Invalid ELF File Type: {0} (expected {1})")]
    InvalidElfType(u16, u16),
    #[error("Invalid Architecture: {0} (expected {1})")]
    InvalidArchitecture(u16, u16),
    #[error("ELF file is missing segment headers!")]
    NoSegmentsFound,
    #[error("Layout error preparing an allocation: {0}")]
    LayoutError(#[from] LayoutError),
    #[error("Invalid segment size: {0}")]
    InvalidSegmentSize(u64),
    #[error("Allocation error: {0}")]
    AllocationError(#[from] alloc::alloc::AllocError),
    #[error("Expected section headers in the ELF file")]
    ExpectedShdrs,
    #[error("Expected string table in the ELF file")]
    ExpectedStrtab,
    #[error("Couldn’t access virtual memory space: {0}")]
    VirtualMemoryError(#[from] PageFault),
}

/// Loads an ELF file into memory and executes it.
pub fn load(
    elf_bin: &[u8],
    rand: &mut impl Rng,
    system_table: SystemTable<Boot>,
) -> Result<!, ElfLoadError> {
    let bump = BumpAllocator::new(8 * 1024 * 1024); // Reserve 8MiB for the bump allocator
    let elf = ElfBytes::<AnyEndian>::minimal_parse(elf_bin)?;
    // Sanity check that the ELF file is supported.
    sys::verify_header(&elf.ehdr)?;

    #[cfg(not(debug_assertions))]
    let mut kernel_addr: usize =
        rand.gen_range(sys::kernelspace_code_start()..sys::kernelspace_end() - 16 * 1024 * 1024);
    #[cfg(debug_assertions)]
    let mut kernel_addr: usize = 0xFFFF_FFFF_8000_0000; // Use a fixed address for testing
    let mut boot_info_addr: usize =
        rand.gen_range(sys::kernelspace_start()..sys::kernelspace_end());
    let mut cma_addr: usize = rand.gen_range(sys::kernelspace_start()..sys::kernelspace_end());

    kernel_addr &= !(sys::KERNELSPACE_ALIGN - 1); // align to the native address boundary
    boot_info_addr &= !(sys::PAGE_SIZE - 1); // align to the native address boundary
    cma_addr &= !(sys::PAGE_SIZE - 1); // align to the native address boundary

    let mut page_table = Pager::new(&bump)?;
    let recursive_map_addr = page_table.recursive_map();

    info!("Loading kernel at 0x{:x}...", kernel_addr);

    let mut og_load_address = usize::MAX;

    for segment in elf.segments().ok_or(ElfLoadError::NoSegmentsFound)? {
        debug!("Segment Type: {:?}", segment.p_type);
        if segment.p_type != PT_LOAD {
            debug!("Non LOAD-segment. skipping");
            continue;
        }
        if og_load_address == usize::MAX {
            og_load_address = segment.p_vaddr as usize;
        }
        let layout = Layout::from_size_align(segment.p_memsz as usize, segment.p_align as usize)?;
        debug!("Layout: {:?}", layout);
        if segment.p_memsz == 0 {
            return Err(ElfLoadError::InvalidSegmentSize(segment.p_memsz));
        }
        // SAFE: The allocation size is guaranteed to not be 0
        let buffer = bump.allocate_zeroed(layout)?.as_mut_ptr().cast::<u8>();
        debug!("Allocated buffer at 0x{:x}", buffer as usize);

        // Precondition check: the segment is fully in the file
        if (segment.p_offset as usize).saturating_add(segment.p_filesz as usize) > elf_bin.len() {
            return Err(ElfLoadError::InvalidSegmentSize(segment.p_filesz));
        }
        if segment.p_memsz < segment.p_filesz {
            return Err(ElfLoadError::InvalidSegmentSize(segment.p_filesz));
        }
        // Copy the segment data from the ELF file to the allocated buffer
        // SAFE: The buffer points to valid memory, not overlapping, the source and destination buffers all have the correct size, and the alignment is correct.
        unsafe {
            buffer.copy_from_nonoverlapping(
                ptr::from_ref::<u8>(&elf_bin[segment.p_offset as usize]),
                segment.p_filesz as usize,
            );
        }
        let vaddr = kernel_addr + (segment.p_vaddr as usize - og_load_address);
        debug!(
            "Loaded segment from {}..{} to 0x{:X}..0x{:X} (P0x{:X}..0x{:X})",
            segment.p_offset,
            segment.p_offset + segment.p_filesz,
            vaddr,
            vaddr + segment.p_filesz as usize,
            buffer as usize,
            buffer as usize + segment.p_filesz as usize
        );
        let mut current_vaddr = vaddr;
        // create mappings
        for i in 0..((segment.p_memsz as usize + PAGE_SIZE - 1) / PAGE_SIZE) {
            page_table.map(
                current_vaddr,
                buffer as usize + i * PAGE_SIZE,
                (segment.p_flags & PF_W) != 0,
                (segment.p_flags & PF_X) != 0,
            )?;
            current_vaddr += PAGE_SIZE;
        }
    }

    // find relocation table

    let shdrs = elf.section_headers().ok_or(ElfLoadError::ExpectedShdrs)?;

    for shdr in shdrs {
        if shdr.sh_type == SHT_RELA {
            info!("Found relocation table at 0x{:x}...", shdr.sh_offset);
            let relas = elf.section_data_as_relas(&shdr)?;
            for rela in relas {
                sys::relocate(og_load_address, rela, kernel_addr, &page_table);
            }
        }
    }

    // Ensure that the thunk is mapped
    page_table.map(
        jump_thunk as *const () as usize,
        jump_thunk as *const () as usize,
        false,
        true,
    )?;

    info!("Allocating the CMA area");
    let cma_ptr = bump
        .allocate_zeroed(Layout::from_size_align(1024 * 1024, 4096).unwrap())
        .unwrap();

    let cma_paddr = cma_ptr.as_ptr().cast::<u8>() as usize;

    info!(
        "CMA area allocated at 0x{:x} (P0x{:x})",
        cma_addr, cma_paddr
    );

    for i in 0..(1024 * 1024 / PAGE_SIZE) {
        page_table.map(
            cma_addr + i * PAGE_SIZE,
            cma_paddr + i * PAGE_SIZE,
            true,
            false,
        )?;
    }

    info!("Gathering some system information");

    let graphics_info = crate::gop_info::gather_gop_info(system_table.boot_services()).ok();

    let mut info_memory_map = Vec::with_capacity(1024); // Hope we don’t need more!

    info!("Graphics Information: {:?}", graphics_info);

    let (_system_table, mut memory_map) =
        unsafe { system_table.exit_boot_services(MemoryType::LOADER_DATA) };

    memory_map.sort();
    for entry in memory_map.entries() {
        let entry_type = if entry.ty == MemoryType::LOADER_CODE
            || entry.ty == MemoryType::LOADER_DATA
            || entry.ty == MemoryType::BOOT_SERVICES_CODE
            || entry.ty == MemoryType::BOOT_SERVICES_DATA
            || entry.ty == MemoryType::CONVENTIONAL
        {
            startup_info::MemoryType::Free
        } else {
            startup_info::MemoryType::Reserved
        };

        info_memory_map.push(MemoryMapEntry::new(
            entry.phys_start as usize,
            entry.page_count as usize * PAGE_SIZE,
            entry_type,
        ));
    }

    info_memory_map.reverse(); // Reverse the order for potential initialization optimizations

    let mut seed = [0u8; 32];
    rand.fill_bytes(&mut seed);

    let startup_info = KernelStartInfo::new(
        info_memory_map,
        graphics_info,
        recursive_map_addr,
        cma_addr,
        seed,
    );

    let mut buf_owned = [0u8; 4096];
    let buf = &mut buf_owned[..startup_info.bytes_required()];
    startup_info.serialize(buf).unwrap();

    let final_info = bump
        .allocate_zeroed(Layout::from_size_align(buf.len(), PAGE_SIZE).unwrap())
        .unwrap();
    unsafe {
        final_info
            .cast::<u8>()
            .as_ptr()
            .copy_from_nonoverlapping(buf.as_mut_ptr(), buf.len());
        page_table.map(
            boot_info_addr,
            final_info.as_ptr().cast::<u8>() as usize,
            false,
            false,
        )?;
    }

    // All bets are off.
    unsafe {
        jump_thunk(
            page_table.get_base_address(),
            (elf.ehdr.e_entry as usize - og_load_address) + kernel_addr,
            boot_info_addr,
            buf.len(),
        );
    }
}
