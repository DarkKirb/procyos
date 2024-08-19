//! Special x86-64 loader bits

use core::{
    alloc::{AllocError, Allocator, Layout},
    arch::asm,
    ptr::{self, NonNull},
};

use super::super::ElfLoadError;
use elf::{
    abi::{EM_X86_64, ET_DYN, R_X86_64_RELATIVE},
    endian::EndianParse,
    file::{Class, FileHeader},
    relocation::Rela,
};

pub const KERNELSPACE_ALIGN: usize = 0x1000; // 4KiB
pub const PAGE_SIZE: usize = 4096; // 4KiB

use kernel_arch_x86_64::paging::{PageAllocator, PageFault, PageOracle, PML4, PML5};
use raw_cpuid::{CpuId, ExtendedFeatures};

#[derive(Debug, PartialEq, Eq)]
pub enum PageBase {
    Level5(&'static mut PML5),
    Level4(&'static mut PML4),
}

#[derive(Debug, Copy, Clone)]
struct IdentityOracle;

unsafe impl PageOracle for IdentityOracle {
    fn resolve_pml4(&self, paddr: usize, _: usize) -> Result<NonNull<PML4>, PageFault> {
        NonNull::new(paddr as *mut _).ok_or(PageFault::InvalidMapping(0))
    }

    fn resolve_pdpt(
        &self,
        paddr: usize,
        _: usize,
    ) -> Result<NonNull<kernel_arch_x86_64::paging::PDPT>, PageFault> {
        NonNull::new(paddr as *mut _).ok_or(PageFault::InvalidMapping(0))
    }

    fn resolve_pd(
        &self,
        paddr: usize,
        _: usize,
    ) -> Result<NonNull<kernel_arch_x86_64::paging::PD>, PageFault> {
        NonNull::new(paddr as *mut _).ok_or(PageFault::InvalidMapping(0))
    }

    fn resolve_pt(
        &self,
        paddr: usize,
        _: usize,
    ) -> Result<NonNull<kernel_arch_x86_64::paging::PT>, PageFault> {
        NonNull::new(paddr as *mut _).ok_or(PageFault::InvalidMapping(0))
    }

    fn resolve_page(&self, paddr: usize, _: usize) -> Result<NonNull<u8>, PageFault> {
        NonNull::new(paddr as *mut _).ok_or(PageFault::InvalidMapping(0))
    }
}

#[derive(Copy, Clone, Debug)]
struct AllocatorPageAlloc<'a, A: Allocator>(&'a A);

unsafe impl<'a, A: Allocator> PageAllocator for AllocatorPageAlloc<'a, A> {
    fn allocate(&mut self) -> Result<usize, AllocError> {
        let layout = Layout::from_size_align(4096, 4096).map_err(|_| AllocError)?;
        let page = self.0.allocate(layout)?;
        Ok(page.addr().into())
    }

    fn deallocate(&mut self, _: usize) {
        // unsupported
    }
}

impl PageBase {
    #[allow(clippy::cast_ptr_alignment, reason = "We check the alignment")]
    pub fn new(allocator: &impl Allocator) -> Result<Self, AllocError> {
        let page = allocator
            .allocate_zeroed(Layout::from_size_align(4096, 4096).unwrap())?
            .as_mut_ptr();
        let cpuid = CpuId::new();
        // This is 'static as we are leaking the memory and allocated it using an allocator that can’t deallocate.
        if cpuid
            .get_extended_feature_info()
            .as_ref()
            .is_some_and(ExtendedFeatures::has_la57)
        {
            assert_eq!(size_of::<PML5>(), 4096);
            assert!(align_of::<PML5>() <= 4096);
            Ok(Self::Level5(unsafe { &mut *page.cast::<PML5>() }))
        } else {
            assert_eq!(size_of::<PML4>(), 4096);
            assert!(align_of::<PML4>() <= 4096);
            Ok(Self::Level4(unsafe { &mut *page.cast::<PML4>() }))
        }
    }
    /// Attempts to create a mapping for the given virtual address to a physical address.
    pub fn map(
        &mut self,
        virtual_addr: usize,
        physical_addr: usize,
        page_allocator: &mut impl PageAllocator,
        page_oracle: &impl PageOracle,
        write: bool,
        execute: bool,
    ) -> Result<(), PageFault> {
        match self {
            Self::Level5(pm) => pm.map(
                virtual_addr,
                physical_addr,
                page_allocator,
                page_oracle,
                write,
                execute,
            ),
            Self::Level4(pm) => pm.map(
                virtual_addr,
                physical_addr,
                page_allocator,
                page_oracle,
                write,
                execute,
            ),
        }
    }
    pub fn recursive_map(&mut self) -> usize {
        let phys_addr = self.get_base_address();
        match self {
            Self::Level5(pm) => pm.map_recursive(phys_addr),
            Self::Level4(pm) => pm.map_recursive(phys_addr),
        }
    }
    pub unsafe fn resolve(
        &self,
        addr: usize,
        page_oracle: &impl PageOracle,
    ) -> Result<NonNull<u8>, PageFault> {
        match self {
            Self::Level5(pt) => pt.resolve(addr, page_oracle),
            Self::Level4(pt) => pt.resolve(addr, page_oracle),
        }
    }
    pub fn get_base_address(&self) -> usize {
        match self {
            Self::Level5(pt) => ptr::from_ref::<PML5>(*pt).addr(),
            Self::Level4(pt) => ptr::from_ref::<PML4>(*pt).addr(),
        }
    }
}

#[derive(Debug)]
pub struct Pager<'alloc, A: Allocator> {
    allocator: AllocatorPageAlloc<'alloc, A>,
    oracle: IdentityOracle,
    table: PageBase,
}

impl<'alloc, A: Allocator> Pager<'alloc, A> {
    pub fn new(allocator: &'alloc A) -> Result<Self, AllocError> {
        let table = PageBase::new(allocator)?;
        Ok(Pager {
            allocator: AllocatorPageAlloc(allocator),
            oracle: IdentityOracle,
            table,
        })
    }
    /// Attempts to create a mapping for the given virtual address to a physical address.
    pub fn map(
        &mut self,
        virtual_addr: usize,
        physical_addr: usize,
        write: bool,
        execute: bool,
    ) -> Result<(), PageFault> {
        self.table.map(
            virtual_addr,
            physical_addr,
            &mut self.allocator,
            &self.oracle,
            write,
            execute,
        )
    }
    pub fn recursive_map(&mut self) -> usize {
        self.table.recursive_map()
    }
    pub unsafe fn resolve(&self, addr: usize) -> Result<NonNull<u8>, PageFault> {
        self.table.resolve(addr, &self.oracle)
    }
    pub fn get_base_address(&self) -> usize {
        self.table.get_base_address()
    }
}

pub fn verify_header<E: EndianParse>(file_header: &FileHeader<E>) -> Result<(), ElfLoadError> {
    if file_header.class != Class::ELF64 {
        return Err(ElfLoadError::InvalidElfClass(
            file_header.class,
            Class::ELF64,
        ));
    }
    if file_header.endianness.is_big() {
        return Err(ElfLoadError::InvalidEndian(
            file_header.endianness.is_big(),
            false,
        ));
    }
    if file_header.e_type != ET_DYN {
        return Err(ElfLoadError::InvalidElfType(file_header.e_type, ET_DYN));
    }
    if file_header.e_machine != EM_X86_64 {
        return Err(ElfLoadError::InvalidArchitecture(
            file_header.e_machine,
            EM_X86_64,
        ));
    }
    Ok(())
}

pub fn kernelspace_start() -> usize {
    let cpuid = CpuId::new();
    // This is 'static as we are leaking the memory and allocated it using an allocator that can’t deallocate.
    if cpuid
        .get_extended_feature_info()
        .as_ref()
        .is_some_and(ExtendedFeatures::has_la57)
    {
        0xFF00_0000_0000_0000
    } else {
        0xFFFF_8000_0000_0000
    }
}

pub const fn kernelspace_end() -> usize {
    usize::MAX
}

pub const fn kernelspace_code_start() -> usize {
    0xFFFF_FFFF_8000_0000
}

pub fn relocate(
    og_load_addr: usize,
    relocation: Rela,
    kernel_addr: usize,
    page_table: &Pager<'_, impl Allocator>,
) {
    assert_eq!(relocation.r_sym, 0); // Only support null symbols
    match relocation.r_type {
        const { R_X86_64_RELATIVE } => {
            let vaddr = kernel_addr + (relocation.r_offset as usize - og_load_addr);
            let page_base = unsafe { page_table.resolve(vaddr).expect("Unable to resolve page") };
            let paddr = unsafe { page_base.add(vaddr & 0xfff) }.cast::<usize>();
            unsafe {
                paddr.write(
                    (kernel_addr - og_load_addr).wrapping_add_signed(relocation.r_addend as isize),
                );
            }
        }
        _ => todo!(),
    }
}

#[naked]
pub unsafe extern "C" fn jump_thunk(
    page_map: usize,
    target_addr: usize,
    startup_info: usize,
    startup_info_size: usize,
) -> ! {
    // looks wrong but that’s just the efi calling convention for you
    asm!(
        "mov rdi, r8",
        "mov rsi, r9",
        "cli",
        "mov cr3, rcx",
        "jmp rdx",
        options(noreturn)
    );
}
