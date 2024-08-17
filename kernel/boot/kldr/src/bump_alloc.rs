//! Bump allocator used for EFI file loading.

use core::{
    alloc::{AllocError, Allocator, Layout},
    cell::Cell,
    ptr::{slice_from_raw_parts_mut, NonNull},
};

use alloc::alloc::alloc_zeroed;
use log::debug;

pub struct BumpAllocator {
    base: *mut u8,
    current: Cell<*mut u8>,
}

impl BumpAllocator {
    /// Creates a new Bump Allocator
    ///
    /// # Panics
    /// Panics if the allocation size is 0.
    #[must_use]
    pub fn new(size: usize) -> Self {
        assert_ne!(size, 0);
        // SAFE: The allocation size is guaranteed to not be 0
        let base = unsafe { alloc_zeroed(Layout::from_size_align(size, 4096).unwrap()) };
        Self {
            base,
            current: Cell::new(base.wrapping_add(size)),
        }
    }
}

unsafe impl Allocator for BumpAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let current = self.current.get();
        let new_ptr = (current as usize - layout.size()) & !(layout.align() - 1);
        debug!("Allocated {:p} to {:p}", new_ptr as *mut u8, current);
        if new_ptr < self.base as usize {
            return Err(AllocError);
        }
        self.current.set(new_ptr as *mut u8);
        assert!(!current.is_null());
        // SAFE: pointer is not null
        Ok(unsafe {
            NonNull::new_unchecked(slice_from_raw_parts_mut(self.current.get(), layout.size()))
        })
    }

    unsafe fn deallocate(&self, _: NonNull<u8>, _: Layout) {}
}
