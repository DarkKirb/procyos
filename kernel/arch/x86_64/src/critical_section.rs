//! Critical section in kernel code

use core::{
    arch::asm,
    sync::atomic::{AtomicU32, Ordering},
};

static LOCK_OWNER: AtomicU32 = AtomicU32::new(0);

pub struct X86CriticalSection;
unsafe impl critical_section::Impl for X86CriticalSection {
    unsafe fn acquire() -> u8 {
        let core = crate::cpu_info::core_id() + 1;

        if LOCK_OWNER.load(Ordering::Acquire) == core {
            0
        } else {
            loop {
                let interrupt_state: u64;
                unsafe {
                    asm!(
                        "pushf",
                        "pop {0}",
                        "cli",
                        out(reg) interrupt_state
                    );
                }
                let interrupt_state = (interrupt_state & 0x200) != 0;
                if LOCK_OWNER
                    .compare_exchange_weak(0, core, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return if interrupt_state { 2 } else { 1 };
                }
                if interrupt_state {
                    asm!("sti", options(nomem, nostack));
                }
                core::hint::spin_loop();
            }
        }
    }

    unsafe fn release(restore_state: u8) {
        if restore_state == 0 {
            return; // nested critical section, nothing to do
        }
        LOCK_OWNER.store(0, Ordering::Release);
        if restore_state == 2 {
            asm!("sti", options(nomem, nostack));
        }
    }
}

#[expect(clippy::no_mangle_with_rust_abi)]
mod ඞ {
    critical_section::set_impl!(super::X86CriticalSection);
}
