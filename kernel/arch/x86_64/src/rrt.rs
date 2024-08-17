use core::arch::asm;

const STACK_SIZE: usize = 16384;

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
        "jmp main",
        sym STACK,
        const STACK_SIZE as u64,
        options(noreturn));
}
