#![no_std]
#![no_main]
#![feature(allocator_api)]

use core::{arch::asm, fmt::Write};

use buddy::{BuddyAllocator, PAddr};
use embedded_alloc::Heap;
use kernel_arch_x86_64::paging::{
    pml5_support, PageAllocator, PageFault, PageOracle, RecursiveMapPageOracle, PD, PDPT, PML4,
    PML5, PT,
};
use log::debug;
use miniser::Deserialize;
use spin::Mutex;
use startup_info::{ArchivedKernelStartInfo, KernelStartInfo, MemoryType};
use uart_16550::SerialPort;

#[cfg(target_arch = "x86_64")]
mod sys {
    pub use kernel_arch_x86_64::*;
}

#[used]
static START: unsafe extern "C" fn() -> ! = sys::rrt::_start;

static SERIAL: Mutex<SerialPort> = unsafe { Mutex::new(SerialPort::new(0x3F8)) };

#[global_allocator]
static HEAP: Heap = Heap::empty();

struct BuddyPageAlloc(BuddyAllocator);

unsafe impl PageAllocator for BuddyPageAlloc {
    fn allocate(&mut self) -> Result<usize, core::alloc::AllocError> {
        self.0.alloc_page().map(|p| p.0 as usize)
    }

    fn deallocate(&mut self, physical: usize) {
        self.0.mark_free(PAddr(physical as u64));
    }
}

enum PageTable {
    Pml5(&'static mut PML5, BuddyPageAlloc, RecursiveMapPageOracle),
    Pml4(&'static mut PML4, BuddyPageAlloc, RecursiveMapPageOracle),
}

impl PageTable {
    pub fn map(
        &mut self,
        virtual_addr: usize,
        physical_addr: usize,
        write: bool,
        execute: bool,
    ) -> Result<(), PageFault> {
        match self {
            Self::Pml5(pml5, allocator, oracle) => pml5.map(
                virtual_addr,
                physical_addr,
                allocator,
                oracle,
                write,
                execute,
            ),
            Self::Pml4(pml4, allocator, oracle) => pml4.map(
                virtual_addr,
                physical_addr,
                allocator,
                oracle,
                write,
                execute,
            ),
        }
    }
}

fn mark_addresses_used(
    si: &ArchivedKernelStartInfo,
    mut buddy_allocator: BuddyAllocator,
) -> PageTable {
    let cr3: usize;
    unsafe {
        asm!("mov {0}, cr3", out(reg) cr3);
    }
    let pagetable_vaddr = si.pagetable_vaddr;
    buddy_allocator.mark_used(PAddr(cr3 as u64));

    let oracle = RecursiveMapPageOracle::default();
    if pml5_support() {
        let pml5 = unsafe { oracle.resolve_pml5(cr3, pagetable_vaddr).as_mut() };
        for entry in pml5.mapped_phys_pages(&oracle) {
            buddy_allocator.mark_used(PAddr(entry as u64));
        }
        PageTable::Pml5(pml5, BuddyPageAlloc(buddy_allocator), oracle)
    } else {
        let pml4 = unsafe { oracle.resolve_pml4(cr3, pagetable_vaddr).unwrap().as_mut() };
        for entry in pml4.mapped_phys_pages(&oracle) {
            buddy_allocator.mark_used(PAddr(entry as u64));
        }
        PageTable::Pml4(pml4, BuddyPageAlloc(buddy_allocator), oracle)
    }
}

/// # Safety
/// a secret :)
/// # Panics
/// When you violate the secret safety constraints :) maybe
#[no_mangle]
pub unsafe extern "C" fn main(init_buf: *const u8, init_buf_size: usize) -> ! {
    let init_buf = unsafe { core::slice::from_raw_parts(init_buf, init_buf_size) };

    SERIAL.lock().init();

    let mut bufp = init_buf;

    let init_info = KernelStartInfo::deserialize(&mut bufp).unwrap();

    HEAP.init(init_info.cma_vaddr, init_info.cma_size);

    start_kernel(&init_info);
}

fn start_kernel(init_info: &ArchivedKernelStartInfo) -> ! {
    writeln!(SERIAL.lock(), "{init_info:?}").unwrap();
    log::set_logger(&MY_LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
    let max_addr = init_info
        .memory_map
        .map(|v| v.base_addr + v.length)
        .max()
        .unwrap();
    let mut buddy = BuddyAllocator::new(PAddr(max_addr as u64));
    for entry in init_info.memory_map {
        match entry.memory_type {
            MemoryType::Free => {
                // it starts out free
            }
            MemoryType::Reserved => {
                buddy.mark_range_used(
                    PAddr(entry.base_addr as u64),
                    PAddr((entry.base_addr + entry.length) as u64),
                );
            }
            _ => todo!(),
        }
    }
    // Reserve the video buffer if it exists
    if let Some(fb) = init_info.framebuffer {
        let start_addr = fb.buffer_paddr;
        let buffer_size = fb.height as usize * fb.buffer_stride * 4;
        buddy.mark_range_used(
            PAddr(start_addr as u64),
            PAddr(
                ((start_addr + buffer_size).div_ceil(buddy.page_size()) * buddy.page_size()) as u64,
            ),
        );
    }
    let mut page_table = mark_addresses_used(init_info, buddy);
    if let Some(fb) = init_info.framebuffer {
        let start_addr = fb.buffer_paddr;
        let buffer_size = fb.height as usize * fb.buffer_stride * 4;
        for i in (0..buffer_size).step_by(4096) {
            page_table
                .map(start_addr + i, start_addr + i, true, false)
                .unwrap();
        }
        let framebuf =
            unsafe { core::slice::from_raw_parts_mut(start_addr as *mut u32, buffer_size / 4) };
        framebuf.iter_mut().for_each(|v| *v = 0xFFFFFFFF);
    }
    todo!();
}

static MY_LOGGER: MyLogger = MyLogger;

struct MyLogger;

impl log::Log for MyLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        writeln!(SERIAL.lock(), "{record:?}").unwrap();
    }

    fn flush(&self) {}
}

#[cfg(not(feature = "std"))]
#[panic_handler]
pub fn panic(info: &core::panic::PanicInfo) -> ! {
    writeln!(SERIAL.lock(), "{info:?}").unwrap();
    loop {}
}
