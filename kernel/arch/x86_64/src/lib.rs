#![feature(allocator_api)]
#![feature(const_refs_to_static)]
#![feature(naked_functions)]
#![feature(pointer_is_aligned_to)]
#![no_std]

use core::arch::asm;

pub mod cpu_info;
#[cfg(feature = "critical-section")]
pub mod critical_section;
pub mod paging;
#[cfg(feature = "runtime")]
pub mod rrt;

#[must_use]
pub fn get_cr4() -> u64 {
    let cr4: u64;
    unsafe {
        asm!("mov {0}, cr4", out(reg) cr4, options(nostack, nomem));
    }
    cr4
}
/// Sets the CR4 register value
///
/// # Safety
/// The caller has to ensure that the CR4 value is valid
pub unsafe fn set_cr4(cr4: u64) {
    asm!("mov cr4, {0}", in(reg) cr4, options(nostack, nomem));
}
