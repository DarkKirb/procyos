//! Paging related definitions

use core::{alloc::AllocError, ptr::NonNull};

use bitfield_struct::bitfield;
use thiserror::Error;

#[derive(Debug, Copy, Clone, Error)]
pub enum PageFault {
    #[error("Page {0:x} not present")]
    NotPresent(usize),
    #[error("Page {0:x} is an invalid mapping")]
    InvalidMapping(usize),
    #[error("Page Oracle mapped {0:x} to invalid {1:x}")]
    BrokenPageOracle(usize, usize),
    #[error("Failed to allocate a new page")]
    FailedAllocation(#[from] AllocError),
}

/// Converts a paging-related physical address to a virtual address
///
/// # Safety
///
/// This function is unsafe as the implementor needs to return a pointer to a Page Table structure, well aligned to 4096 bytes.
pub unsafe trait PageOracle {
    /// Returns a virtual address that corresponds to the given physical address for a paging-related function
    ///
    /// # Errors
    /// This function may return an error if the given physical address is not mapped to a valid virtual address.
    fn physical_to_virtual(&self, physical: usize) -> Result<NonNull<u8>, PageFault>;
}

/// Reserves a page for use for paging-related functions
///
/// # Safety
///
/// This function is unsafe as similar requirements exist for the allocator functions
pub unsafe trait PageAllocator {
    /// Allocates a new page for the given virtual address and returns the physical address
    ///
    /// # Errors
    ///
    /// This function returns an error if the allocation fails
    fn allocate(&mut self) -> Result<usize, AllocError>;

    /// Deallocates a specific page
    fn deallocate(&mut self, physical: usize);
}

/// A single Page Map Level 5 Entry (PML5E)
#[bitfield(u64)]
#[derive(PartialEq, Eq)]
pub struct PML5Entry {
    /// Present; must be `true` to reference a PML4 table
    pub present: bool,
    /// Read/write; if 0, writes may not be allowed to the 256 TiB region controlled by this entry (see Section 4.6)
    pub write_enable: bool,
    /// User/supervisor; if 0, user-mode accesses are not allowed to the 256 TiB region controlled by this entry (see Section 4.6)
    pub user_mode_access: bool,
    /// Page-level write-through; indirectly determines the memory type used to access the PML4 table referenced by this entry (see Section 4.9.2)
    pub page_level_write_through: bool,
    /// Page-level cache disable; indirectly determines the memory type used to access the PML4 table referenced by this entry (see Section 4.9.2)
    pub page_level_cache_disable: bool,
    /// Accessed; indicates whether this entry has been used for linear-address translation (see Section 4.8)
    pub accessed: bool,
    _ign1: bool,
    /// Must be false
    reserved1: bool,
    #[bits(3)]
    _ign2: u8,
    /// For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging
    pub hlat_restart: bool,
    /// Physical address of 4-KByte aligned PML4 table referenced by this entry
    #[bits(40)]
    pub page_addr: usize,
    #[bits(11)]
    _ign3: u16,
    /// If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 256 TiB region controlled by this entry; see Section 4.6); otherwise, reserved (must be 0)
    pub disable_execution: bool,
}

impl PML5Entry {
    /// Returns the PML4 table referenced by this entry, if present.
    ///
    /// # Errors
    /// This function returns an error if the entry is not present, or is inaccessible, or
    #[allow(clippy::cast_ptr_alignment, reason = "We check alignment manually")]
    pub fn get_pml4(&self, page_oracle: &impl PageOracle) -> Result<&'static mut PML4, PageFault> {
        if self.present() {
            let ptr = page_oracle.physical_to_virtual(self.phys_addr())?;
            if ptr.is_aligned_to(align_of::<PML4>()) {
                Ok(unsafe { ptr.cast::<PML4>().as_mut() })
            } else {
                Err(PageFault::BrokenPageOracle(
                    self.phys_addr(),
                    ptr.as_ptr() as usize,
                ))
            }
        } else {
            Err(PageFault::NotPresent(self.phys_addr()))
        }
    }

    #[must_use]
    pub const fn phys_addr(self) -> usize {
        self.page_addr() << 12
    }
}

/// A single Page Map Level 5
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(align(4096))]
pub struct PML5([PML5Entry; 512]);

impl PML5 {
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<&PML5Entry> {
        if index < self.0.len() && self.0[index].present() {
            Some(&self.0[index])
        } else {
            None
        }
    }
    pub fn set(&mut self, index: usize, entry: PML5Entry) {
        if index < self.0.len() {
            self.0[index] = entry.with_present(true);
        }
    }
    pub fn delete(&mut self, index: usize) {
        if index < self.0.len() {
            self.0[index].set_present(false);
        }
    }

    /// Attempts to create a mapping for the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if the mapping fails, for example because there is not enough physical memory or because the page oracle fails to provide a valid virtual address.
    pub fn map(
        &mut self,
        virtual_addr: usize,
        physical_addr: usize,
        page_allocator: &mut impl PageAllocator,
        page_oracle: &impl PageOracle,
        write: bool,
        execute: bool,
    ) -> Result<(), PageFault> {
        let index = (virtual_addr >> 48) % 512;
        let pml4 = if let Some(idx) = self.get(index) {
            idx.get_pml4(page_oracle)?
        } else {
            let page = page_allocator.allocate()?;
            let entry = PML5Entry::new()
                .with_present(true)
                .with_write_enable(true)
                .with_page_addr(page >> 12);
            self.set(index, entry);
            entry.get_pml4(page_oracle)?
        };
        pml4.map(
            virtual_addr,
            physical_addr,
            page_allocator,
            page_oracle,
            write,
            execute,
        )?;
        Ok(())
    }

    /// Attempts to resolve the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    pub fn resolve(
        &self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
    ) -> Result<NonNull<u8>, PageFault> {
        let idx = (virtual_addr >> 48) % 512;
        let pml4 = match self.get(idx) {
            Some(idx) => idx.get_pml4(page_oracle)?,
            None => return Err(PageFault::NotPresent(virtual_addr)),
        };
        pml4.resolve(virtual_addr, page_oracle)
    }

    /// Maps a recursive page table mapping
    pub fn map_recursive(&mut self, phys_addr: usize) -> usize {
        self.0[510] = PML5Entry::new()
            .with_present(true)
            .with_write_enable(true)
            .with_user_mode_access(false)
            .with_disable_execution(true)
            .with_page_addr(phys_addr >> 12);
        0xFFFE_0000_0000_0000
    }

    /// Removes the mapping for the given virtual address, if it exists. It deallocates page table tables as necessary.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    pub fn unmap(
        &mut self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
        page_allocator: &mut impl PageAllocator,
    ) -> Result<(), PageFault> {
        let idx = (virtual_addr >> 48) % 512;
        let (pml4, physical) = match self.get(idx) {
            Some(idx) => (idx.get_pml4(page_oracle)?, idx.phys_addr()),
            None => return Ok(()),
        };
        let empty = pml4.unmap(virtual_addr, page_oracle, page_allocator)?;
        if empty {
            self.0[idx].set_present(false);
            page_allocator.deallocate(physical);
        }
        Ok(())
    }
}

/// A single Page Map Level 4 Entry (PML4E)
#[bitfield(u64)]
#[derive(PartialEq, Eq)]
pub struct PML4Entry {
    /// Present; must be `true` to reference a page-directory-pointer table
    pub present: bool,
    /// Read/write; if 0, writes may not be allowed to the 512 GiB region controlled by this entry (see Section 4.6)
    pub write_enable: bool,
    /// User/supervisor; if 0, user-mode accesses are not allowed to the 512 GiB region controlled by this entry (see Section 4.6)
    pub user_mode_access: bool,
    /// Page-level write-through; indirectly determines the memory type used to access the page-directory-pointer table table referenced by this entry (see Section 4.9.2)
    pub page_level_write_through: bool,
    /// Page-level cache disable; indirectly determines the memory type used to access the page-directory-pointer table table referenced by this entry (see Section 4.9.2)
    pub page_level_cache_disable: bool,
    /// Accessed; indicates whether this entry has been used for linear-address translation (see Section 4.8)
    pub accessed: bool,
    _ign1: bool,
    /// Must be false
    pub reserved1: bool,
    #[bits(3)]
    _ign2: u8,
    /// For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging
    pub hlat_restart: bool,
    /// Physical address of 4-KByte aligned page-directory-pointer table table referenced by this entry
    #[bits(40)]
    pub page_addr: usize,
    #[bits(11)]
    _ign3: u16,
    /// If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 512 GiB region controlled by this entry; see Section 4.6); otherwise, reserved (must be 0)
    pub disable_execution: bool,
}

impl PML4Entry {
    /// Returns the PDPT referenced by this entry, if present.
    ///
    /// # Errors
    /// This function returns an error if the entry is not present, or is inaccessible, or
    #[allow(clippy::cast_ptr_alignment, reason = "We check alignment manually")]
    pub fn get_pdpt(&self, page_oracle: &impl PageOracle) -> Result<&'static mut PDPT, PageFault> {
        if self.present() {
            let ptr = page_oracle.physical_to_virtual(self.phys_addr())?;
            if ptr.is_aligned_to(align_of::<PDPT>()) {
                Ok(unsafe { ptr.cast::<PDPT>().as_mut() })
            } else {
                Err(PageFault::BrokenPageOracle(
                    self.phys_addr(),
                    ptr.as_ptr() as usize,
                ))
            }
        } else {
            Err(PageFault::NotPresent(self.phys_addr()))
        }
    }
    #[must_use]
    pub const fn phys_addr(self) -> usize {
        self.page_addr() << 12
    }
}

/// A single Page Map Level 5
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(align(4096))]
pub struct PML4([PML4Entry; 512]);

impl PML4 {
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<&PML4Entry> {
        if index < self.0.len() && self.0[index].present() {
            Some(&self.0[index])
        } else {
            None
        }
    }
    pub fn set(&mut self, index: usize, entry: PML4Entry) {
        if index < self.0.len() {
            self.0[index] = entry.with_present(true);
        }
    }
    pub fn delete(&mut self, index: usize) {
        if index < self.0.len() {
            self.0[index].set_present(false);
        }
    }
    /// Attempts to create a mapping for the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if the mapping fails, for example because there is not enough physical memory or because the page oracle fails to provide a valid virtual address.
    pub fn map(
        &mut self,
        virtual_addr: usize,
        physical_addr: usize,
        page_allocator: &mut impl PageAllocator,
        page_oracle: &impl PageOracle,
        write: bool,
        execute: bool,
    ) -> Result<(), PageFault> {
        let index = (virtual_addr >> 39) % 512;
        let pdpt = if let Some(idx) = self.get(index) {
            idx.get_pdpt(page_oracle)?
        } else {
            let page = page_allocator.allocate()?;
            let entry = PML4Entry::new()
                .with_present(true)
                .with_write_enable(true)
                .with_page_addr(page >> 12);
            self.set(index, entry);
            entry.get_pdpt(page_oracle)?
        };
        pdpt.map(
            virtual_addr,
            physical_addr,
            page_allocator,
            page_oracle,
            write,
            execute,
        )?;
        Ok(())
    }
    /// Attempts to resolve the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    pub fn resolve(
        &self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
    ) -> Result<NonNull<u8>, PageFault> {
        let idx = (virtual_addr >> 39) % 512;
        let pdpt = match self.get(idx) {
            Some(idx) => idx.get_pdpt(page_oracle)?,
            None => return Err(PageFault::NotPresent(virtual_addr)),
        };
        pdpt.resolve(virtual_addr, page_oracle)
    }

    /// Maps a recursive page table mapping
    pub fn map_recursive(&mut self, phys_addr: usize) -> usize {
        self.0[510] = PML4Entry::new()
            .with_present(true)
            .with_write_enable(true)
            .with_user_mode_access(false)
            .with_disable_execution(true)
            .with_page_addr(phys_addr >> 12);
        0xffff_ff00_0000_0000
    }
    /// Removes the mapping for the given virtual address, if it exists. It deallocates page table tables as necessary.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    pub fn unmap(
        &mut self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
        page_allocator: &mut impl PageAllocator,
    ) -> Result<bool, PageFault> {
        let idx = (virtual_addr >> 39) % 512;
        let (pdpt, physical) = match self.get(idx) {
            Some(idx) => (idx.get_pdpt(page_oracle)?, idx.phys_addr()),
            None => return Ok(false),
        };
        let empty = pdpt.unmap(virtual_addr, page_oracle, page_allocator)?;
        if empty {
            self.0[idx].set_present(false);
            page_allocator.deallocate(physical);
        }
        for i in 0..512 {
            if self.0[i].present() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A single Page Directory Pointer Table Entry (PDPTE)
#[bitfield(u64)]
#[derive(PartialEq, Eq)]
pub struct PDPTEntry {
    /// Present; must be `true` to reference a page directory
    present: bool,
    /// Read/write; if 0, writes may not be allowed to the 1 GiB region controlled by this entry (see Section 4.6)
    write_enable: bool,
    /// User/supervisor; if 0, user-mode accesses are not allowed to the 1 GiB region controlled by this entry (see Section 4.6)
    user_mode_access: bool,
    /// Page-level write-through; indirectly determines the memory type used to access the page directory referenced by this entry (see Section 4.9.2)
    page_level_write_through: bool,
    /// Page-level cache disable; indirectly determines the memory type used to access the page directory table referenced by this entry (see Section 4.9.2)
    page_level_cache_disable: bool,
    /// Accessed; indicates whether this entry has been used for linear-address translation (see Section 4.8)
    accessed: bool,
    _ign1: bool,
    /// Page size; must be 0 (otherwise, this entry maps a 1-GByte page; see Table 4-16)
    page_size: bool,
    #[bits(3)]
    _ign2: u8,
    /// For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging
    hlat_restart: bool,
    /// Physical address of 4-KByte aligned page-directory-pointer table table referenced by this entry
    #[bits(40)]
    page_addr: usize,
    #[bits(11)]
    _ign3: u16,
    /// If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 1 GiB region controlled by this entry; see Section 4.6); otherwise, reserved (must be 0)
    disable_execution: bool,
}

impl PDPTEntry {
    /// Returns the PD referenced by this entry, if present.
    ///
    /// # Errors
    /// This function returns an error if the entry is not present, or is inaccessible, or
    #[allow(clippy::cast_ptr_alignment, reason = "We check alignment manually")]
    pub fn get_pd(&self, page_oracle: &impl PageOracle) -> Result<&'static mut PD, PageFault> {
        if self.present() {
            let ptr = page_oracle.physical_to_virtual(self.phys_addr())?;
            if ptr.is_aligned_to(align_of::<PD>()) {
                Ok(unsafe { ptr.cast::<PD>().as_mut() })
            } else {
                Err(PageFault::BrokenPageOracle(
                    self.phys_addr(),
                    ptr.as_ptr() as usize,
                ))
            }
        } else {
            Err(PageFault::NotPresent(self.phys_addr()))
        }
    }
    #[must_use]
    pub const fn phys_addr(self) -> usize {
        self.page_addr() << 12
    }
}

/// A single Page Map Level 5
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(align(4096))]
pub struct PDPT([PDPTEntry; 512]);

impl PDPT {
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<&PDPTEntry> {
        if index < self.0.len() && self.0[index].present() {
            Some(&self.0[index])
        } else {
            None
        }
    }
    pub fn set(&mut self, index: usize, entry: PDPTEntry) {
        if index < self.0.len() {
            self.0[index] = entry.with_present(true);
        }
    }
    pub fn delete(&mut self, index: usize) {
        if index < self.0.len() {
            self.0[index].set_present(false);
        }
    }
    /// Attempts to create a mapping for the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if the mapping fails, for example because there is not enough physical memory or because the page oracle fails to provide a valid virtual address.
    fn map(
        &mut self,
        virtual_addr: usize,
        physical_addr: usize,
        page_allocator: &mut impl PageAllocator,
        page_oracle: &impl PageOracle,
        write: bool,
        execute: bool,
    ) -> Result<(), PageFault> {
        let index = (virtual_addr >> 30) % 512;
        let pd = if let Some(idx) = self.get(index) {
            idx.get_pd(page_oracle)?
        } else {
            let page = page_allocator.allocate()?;
            let entry = PDPTEntry::new()
                .with_present(true)
                .with_write_enable(true)
                .with_page_addr(page >> 12);
            self.set(index, entry);
            entry.get_pd(page_oracle)?
        };
        pd.map(
            virtual_addr,
            physical_addr,
            page_allocator,
            page_oracle,
            write,
            execute,
        )?;
        Ok(())
    }
    /// Attempts to resolve the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    pub fn resolve(
        &self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
    ) -> Result<NonNull<u8>, PageFault> {
        let idx = (virtual_addr >> 30) % 512;
        let pd = match self.get(idx) {
            Some(idx) => idx.get_pd(page_oracle)?,
            None => return Err(PageFault::NotPresent(virtual_addr)),
        };
        pd.resolve(virtual_addr, page_oracle)
    }

    /// Removes the mapping for the given virtual address, if it exists. It deallocates page table tables as necessary.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    fn unmap(
        &mut self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
        page_allocator: &mut impl PageAllocator,
    ) -> Result<bool, PageFault> {
        let idx = (virtual_addr >> 30) % 512;
        let (pd, physical) = match self.get(idx) {
            Some(idx) => (idx.get_pd(page_oracle)?, idx.phys_addr()),
            None => return Ok(false),
        };
        let empty = pd.unmap(virtual_addr, page_oracle, page_allocator)?;
        if empty {
            self.0[idx].set_present(false);
            page_allocator.deallocate(physical);
        }
        for i in 0..512 {
            if self.0[i].present() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A single Page Directory Entry (PDE)
#[bitfield(u64)]
#[derive(PartialEq, Eq)]
pub struct PDEntry {
    /// Present; must be `true` to reference a page table
    present: bool,
    /// Read/write; if 0, writes may not be allowed to the 2 MiB region controlled by this entry (see Section 4.6)
    write_enable: bool,
    /// User/supervisor; if 0, user-mode accesses are not allowed to the 2 MiB region controlled by this entry (see Section 4.6)
    user_mode_access: bool,
    /// Page-level write-through; indirectly determines the memory type used to access the page directory referenced by this entry (see Section 4.9.2)
    page_level_write_through: bool,
    /// Page-level cache disable; indirectly determines the memory type used to access the page directory table referenced by this entry (see Section 4.9.2)
    page_level_cache_disable: bool,
    /// Accessed; indicates whether this entry has been used for linear-address translation (see Section 4.8)
    accessed: bool,
    _ign1: bool,
    /// Page size; must be 0 (otherwise, this entry maps a 2 MiB page; see Table 4-16)
    page_size: bool,
    #[bits(3)]
    _ign2: u8,
    /// For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging
    hlat_restart: bool,
    /// Physical address of 4-KByte aligned page table table referenced by this entry
    #[bits(40)]
    page_addr: usize,
    #[bits(11)]
    _ign3: u16,
    /// If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 2 MiB region controlled by this entry; see Section 4.6); otherwise, reserved (must be 0)
    disable_execution: bool,
}

impl PDEntry {
    /// Returns the PT referenced by this entry, if present.
    ///
    /// # Errors
    /// This function returns an error if the entry is not present, or is inaccessible, or
    #[allow(clippy::cast_ptr_alignment, reason = "We check alignment manually")]
    pub fn get_pt(&self, page_oracle: &impl PageOracle) -> Result<&'static mut PT, PageFault> {
        if self.present() {
            let ptr = page_oracle.physical_to_virtual(self.phys_addr())?;
            if ptr.is_aligned_to(align_of::<PT>()) {
                Ok(unsafe { ptr.cast::<PT>().as_mut() })
            } else {
                Err(PageFault::BrokenPageOracle(
                    self.phys_addr(),
                    ptr.as_ptr() as usize,
                ))
            }
        } else {
            Err(PageFault::NotPresent(self.phys_addr()))
        }
    }
    #[must_use]
    pub const fn phys_addr(self) -> usize {
        self.page_addr() << 12
    }
}

/// A single Page Map Level 5
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(align(4096))]
pub struct PD([PDEntry; 512]);

impl PD {
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<&PDEntry> {
        if index < self.0.len() && self.0[index].present() {
            Some(&self.0[index])
        } else {
            None
        }
    }
    pub fn set(&mut self, index: usize, entry: PDEntry) {
        if index < self.0.len() {
            self.0[index] = entry.with_present(true);
        }
    }
    pub fn delete(&mut self, index: usize) {
        if index < self.0.len() {
            self.0[index].set_present(false);
        }
    }
    /// Attempts to create a mapping for the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if the mapping fails, for example because there is not enough physical memory or because the page oracle fails to provide a valid virtual address.
    fn map(
        &mut self,
        virtual_addr: usize,
        physical_addr: usize,
        page_allocator: &mut impl PageAllocator,
        page_oracle: &impl PageOracle,
        write: bool,
        execute: bool,
    ) -> Result<(), PageFault> {
        let index = (virtual_addr >> 21) % 512;
        let pt = if let Some(idx) = self.get(index) {
            idx.get_pt(page_oracle)?
        } else {
            let page = page_allocator.allocate()?;
            let entry = PDEntry::new()
                .with_present(true)
                .with_write_enable(true)
                .with_page_addr(page >> 12);
            self.set(index, entry);
            entry.get_pt(page_oracle)?
        };
        pt.map(virtual_addr, physical_addr, write, execute);
        Ok(())
    }
    /// Attempts to resolve the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    ///
    fn resolve(
        &self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
    ) -> Result<NonNull<u8>, PageFault> {
        let idx = (virtual_addr >> 21) % 512;
        let pt = match self.get(idx) {
            Some(idx) => idx.get_pt(page_oracle)?,
            None => return Err(PageFault::NotPresent(virtual_addr)),
        };
        pt.resolve(virtual_addr, page_oracle)
    }

    /// Removes the mapping for the given virtual address, if it exists. It deallocates page table tables as necessary.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    fn unmap(
        &mut self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
        page_allocator: &mut impl PageAllocator,
    ) -> Result<bool, PageFault> {
        let idx = (virtual_addr >> 21) % 512;
        let (pt, physical) = match self.get(idx) {
            Some(idx) => (idx.get_pt(page_oracle)?, idx.phys_addr()),
            None => return Ok(false),
        };
        let empty = pt.unmap(virtual_addr);
        if empty {
            self.0[idx].set_present(false);
            page_allocator.deallocate(physical);
        }
        for i in 0..512 {
            if self.0[i].present() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// A single Page Table Entry (PTE)
#[bitfield(u64)]
#[derive(PartialEq, Eq)]
pub struct PTEntry {
    /// Present; must be `true` to reference a 4 kiB
    present: bool,
    /// Read/write; if 0, writes may not be allowed to the 4 kiB region controlled by this entry (see Section 4.6)
    write_enable: bool,
    /// User/supervisor; if 0, user-mode accesses are not allowed to the 4 kiB controlled by this entry (see Section 4.6)
    user_mode_access: bool,
    /// Page-level write-through; indirectly determines the memory type used to access the 4 kiB entry referenced by this entry (see Section 4.9.2)
    page_level_write_through: bool,
    /// Page-level cache disable; indirectly determines the memory type used to access the 4 kiB entry referenced by this entry (see Section 4.9.2)
    page_level_cache_disable: bool,
    /// Accessed; indicates whether software has accessed the 4 kiB page referenced by this entry (see Section 4.8)
    accessed: bool,
    /// Dirty; indicates whether software has written to the 4-KByte page referenced by this entry (see Section 4.8)
    dirty: bool,
    /// Indirectly determines the memory type used to access the 4-KByte page referenced by this entry (see Section 4.9.2)
    pat: bool,
    /// Global; if CR4.PGE = 1, determines whether the translation is global (see Section 4.10); ignored otherwise
    global: bool,
    #[bits(2)]
    _ign2: u8,
    /// For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging
    hlat_restart: bool,
    /// Physical address of 4-KByte aligned page table table referenced by this entry
    #[bits(40)]
    page_addr: usize,
    #[bits(7)]
    _ign3: u8,
    /// Protection key; if CR4.PKE = 1 or CR4.PKS = 1, this may control the page’s access rights (see Section 4.6.2); otherwise, it is ignored and not used to control access rights.
    #[bits(4)]
    protection_key: u8,
    /// If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 2 MiB region controlled by this entry; see Section 4.6); otherwise, reserved (must be 0)
    disable_execution: bool,
}

impl PTEntry {
    #[must_use]
    pub const fn phys_addr(self) -> usize {
        self.page_addr() << 12
    }
}

/// A single Page Map Level 5
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(align(4096))]
pub struct PT([PTEntry; 512]);

impl PT {
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<&PTEntry> {
        if index < self.0.len() && self.0[index].present() {
            Some(&self.0[index])
        } else {
            None
        }
    }
    pub fn set(&mut self, index: usize, entry: PTEntry) {
        if index < self.0.len() {
            self.0[index] = entry.with_present(true);
        }
    }
    pub fn delete(&mut self, index: usize) {
        if index < self.0.len() {
            self.0[index].set_present(false);
        }
    }
    /// Attempts to create a mapping for the given virtual address to a physical address.
    pub fn map(&mut self, virtual_addr: usize, physical_addr: usize, write: bool, execute: bool) {
        let index = (virtual_addr >> 12) % 512;
        let entry = PTEntry::new()
            .with_present(true)
            .with_write_enable(write)
            .with_disable_execution(!execute)
            .with_page_addr(physical_addr >> 12);
        self.set(index, entry);
    }
    /// Attempts to resolve the given virtual address to a physical address.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    pub fn resolve(
        &self,
        virtual_addr: usize,
        page_oracle: &impl PageOracle,
    ) -> Result<NonNull<u8>, PageFault> {
        let idx = (virtual_addr >> 12) % 512;
        self.get(idx)
            .map_or(Err(PageFault::NotPresent(virtual_addr)), |pt| {
                page_oracle.physical_to_virtual(pt.phys_addr())
            })
    }

    /// Removes the mapping for the given virtual address, if it exists. It deallocates page table tables as necessary.
    ///
    /// # Errors
    /// This function returns an error if resolving fails
    fn unmap(&mut self, virtual_addr: usize) -> bool {
        let idx = (virtual_addr >> 12) % 512;
        self.0[idx].set_present(false);
        for i in 0..512 {
            if self.0[i].present() {
                return false;
            }
        }
        true
    }
}
