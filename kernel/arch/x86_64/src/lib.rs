#![feature(allocator_api)]
#![feature(asm_const)]
#![feature(const_refs_to_static)]
#![feature(naked_functions)]
#![feature(pointer_is_aligned_to)]
#![no_std]

pub mod cpu_info;
#[cfg(feature = "critical-section")]
pub mod critical_section;
pub mod paging;
#[cfg(feature = "runtime")]
pub mod rrt;
