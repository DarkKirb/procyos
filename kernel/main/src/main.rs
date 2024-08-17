#![no_std]
#![no_main]

use core::fmt::Write;

use buddy::{BuddyAllocator, PAddr};
use embedded_alloc::Heap;
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

    HEAP.init(init_info.cma_vaddr, 1024 * 1024);

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
