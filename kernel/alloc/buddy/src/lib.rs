//! Buddy Allocator for physical memory allocation

#![no_std]

use bitvec::{bitvec, vec::BitVec};
use log::debug;

/// A Physical Address.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, PartialOrd, Ord)]
#[repr(transparent)]
#[cfg(target_arch = "x86_64")]
pub struct PAddr(pub u64);

#[cfg(feature = "pagesize_1k")]
const BUDDY_DEPTH: usize = 13;
#[cfg(all(feature = "pagesize_4k", not(feature = "pagesize_1k")))]
const BUDDY_DEPTH: usize = 11;
#[cfg(all(feature = "pagesize_16k", not(feature = "pagesize_4k")))]
const BUDDY_DEPTH: usize = 9;
#[cfg(all(feature = "pagesize_64k", not(feature = "pagesize_16k")))]
const BUDDY_DEPTH: usize = 7;

/// Buddy Allocator structure
#[derive(Debug, Default)]
pub struct BuddyAllocator([BitVec; BUDDY_DEPTH], PAddr);

impl BuddyAllocator {
    /// Creates and initializes a buddy allocator
    ///
    /// `max_addr` is the maximum address to be allocated
    ///
    /// # Panics
    /// This function panics if the maximum address is less than the configured page size
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Magnitude reduced to fit into usize"
    )]
    pub fn new(max_addr: PAddr) -> Self {
        let mut buddies: [BitVec; BUDDY_DEPTH] = Default::default();

        for i in 0..BUDDY_DEPTH {
            if (4 * 1024 * 1024) >> i <= max_addr.0 {
                buddies[i] = bitvec![1; max_addr.0.div_ceil((4 * 1024 * 1024) >> i) as usize];
                return Self(buddies, max_addr);
            }
        }

        panic!("Max address too small for buddy allocator");
    }

    // Checks if the given address is free
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Magnitude reduced to fit into usize"
    )]
    pub fn is_free(&self, address: PAddr) -> bool {
        if address > self.1 {
            return false;
        }
        for i in 0..BUDDY_DEPTH {
            let addr_idx = (address.0 >> (22 - i)) as usize;
            if (addr_idx < self.0[i].len() && self.0[i][addr_idx]) || (addr_idx >= self.0[i].len())
            {
                return true;
            }
        }
        false
    }

    /// Checks if the given address is used
    #[must_use]
    pub fn is_used(&self, address: PAddr) -> bool {
        !self.is_free(address)
    }

    /// Marks page as used
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Magnitude reduced to fit into usize"
    )]
    pub fn mark_used(&mut self, address: PAddr) {
        if address > self.1 {
            return; // Nothing to do
        }
        if self.is_used(address) {
            return; // Page already used, nothing to do
        }
        for i in 0..BUDDY_DEPTH {
            let addr_idx = (address.0 >> (22 - i)) as usize;
            if self.0[i].len() <= addr_idx {
                self.0[i].extend((0..=(addr_idx - self.0[i].len())).map(|_| true));
            }
            self.0[i].set(addr_idx, false);
        }
    }

    /// Mark page range as used
    pub fn mark_range_used(&mut self, start: PAddr, end: PAddr) {
        debug!(
            "Buddy: Marking range as used from 0x{:x} to 0x{:x}",
            start.0, end.0
        );
        for address in (start.0..end.0).step_by(self.page_size()) {
            self.mark_used(PAddr(address));
        }
    }

    /// Marks page as free
    #[allow(
        clippy::cast_possible_truncation,
        reason = "Magnitude reduced to fit into usize"
    )]
    pub fn mark_free(&mut self, address: PAddr) {
        if address > self.1 {
            return; // Nothing to do
        }
        if self.is_free(address) {
            return; // Page already free
        }
        for i in (0..BUDDY_DEPTH).rev() {
            let addr_idx = (address.0 >> (22 - i)) as usize;
            if self.0[i].len() > addr_idx {
                self.0[i].set(addr_idx, true);
            }
            // Shrink the buddy if possible
            if self.0[i].len() == addr_idx + 1 {
                self.0[i].pop();
            }
            // Merge adjacent free pages
            if !(self.0[i].len() > addr_idx ^ 1 && self.0[i][addr_idx ^ 1]) {
                break;
            }
        }
    }

    /// Mark page range as free
    pub fn mark_range_free(&mut self, start: PAddr, end: PAddr) {
        debug!(
            "Buddy: Marking range as free from 0x{:x} to 0x{:x}",
            start.0, end.0
        );
        for address in (start.0..end.0).step_by(self.page_size()) {
            self.mark_free(PAddr(address));
        }
    }

    #[cfg(feature = "pagesize_1k")]
    #[must_use]
    pub const fn page_size(&self) -> usize {
        1024
    }

    #[cfg(all(feature = "pagesize_4k", not(feature = "pagesize_1k")))]
    #[must_use]
    pub const fn page_size(&self) -> usize {
        4096
    }

    #[cfg(all(feature = "pagesize_16k", not(feature = "pagesize_4k")))]
    #[must_use]
    pub const fn page_size(&self) -> usize {
        16384
    }

    #[cfg(all(feature = "pagesize_64k", not(feature = "pagesize_16k")))]
    #[must_use]
    pub const fn page_size(&self) -> usize {
        65536
    }
}
