use core::arch::asm;

use raw_cpuid::{CpuId, ExtendedFeatures};

use crate::{get_cr4, set_cr4};

const STACK_SIZE: usize = 16384;

extern "C" {
    fn main(init_buf: *const u8, init_buf_size: usize) -> !;
}

#[repr(C, align(4096))]
struct Stack([u8; STACK_SIZE]);

impl Stack {
    const fn new() -> Self {
        Self([0; STACK_SIZE])
    }
}

static mut STACK: Stack = Stack::new();

#[no_mangle]
#[naked]
#[allow(
    clippy::missing_safety_doc,
    reason = "Implementation detail, highly ABI specific"
)]
pub unsafe extern "C" fn _start() -> ! {
    asm!(
        "mov rsp, [rip + {0}@GOTPCREL]",
        "add rsp, {1}",
        "mov rbp, rsp",
        "jmp {2}",
        sym STACK,
        const STACK_SIZE as u64,
        sym x86_64_init,
        options(noreturn));
}

extern "C" fn x86_64_init(init_buf: *const u8, init_buf_size: usize) -> ! {
    // some hardware initialization before we can get going
    let cpuid = CpuId::new();
    if cpuid
        .get_extended_feature_info()
        .as_ref()
        .is_some_and(ExtendedFeatures::has_umip)
    {
        unsafe {
            set_cr4(get_cr4() | 1 << 11); // Enable UMIP
        }
    }
    if cpuid
        .get_extended_feature_info()
        .as_ref()
        .is_some_and(ExtendedFeatures::has_smep)
    {
        unsafe {
            set_cr4(get_cr4() | 1 << 20); // Enable SMEP
        }
    }
    if cpuid
        .get_extended_feature_info()
        .as_ref()
        .is_some_and(ExtendedFeatures::has_smap)
    {
        unsafe {
            set_cr4(get_cr4() | 1 << 21); // Enable SMAP
        }
    }
    unsafe {
        main(init_buf, init_buf_size);
    }
}
