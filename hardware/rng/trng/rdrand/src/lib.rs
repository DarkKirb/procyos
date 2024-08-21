//! Architectural TRNG (True Random Number Generator) for x86 and x86_64 processors
#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#![feature(let_chains)]
#![no_std]

use log::{debug, error};
use rand_core::{CryptoRng, RngCore};
use raw_cpuid::CpuId;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rdrand;

impl Rdrand {
    /// Creates a new rdrand instance
    ///
    /// Returns `None` if rdrand is not supported or is known to be broken.
    pub fn try_new() -> Option<Self> {
        let cpuid = CpuId::new();
        if let Some(fi) = cpuid.get_feature_info()
            && fi.has_rdrand()
        {
            debug!("rdrand is supported");
            if let Some(info) = cpuid.get_vendor_info()
                && info.as_str() == "AuthenticAMD"
                && (fi.family_id() == 0x15 || fi.family_id() == 0x16)
            {
                error!(
                    "rdrand is known to be broken on AMD CPUs with your familiy ID (0x{:x})",
                    fi.family_id()
                );
                return None;
            }
            return Some(Self);
        }
        None
    }

    fn rdrand_raw_32(&self) -> Option<u32> {
        use core::arch::asm;
        let success: u8;
        let rdrand: u32;
        unsafe {
            asm!(
                "rdrand {0:e}",
                "setc {1}",
                out(reg) rdrand,
                out(reg_byte) success,
                options(nostack, nomem)
            );
        }
        if success != 0 {
            Some(rdrand)
        } else {
            None
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn rdrand_raw_64(&self) -> Option<u64> {
        use core::arch::asm;
        let success: u8;
        let rdrand: u64;
        unsafe {
            asm!(
                "rdrand {0}",
                "setc {1}",
                out(reg) rdrand,
                out(reg_byte) success,
                options(nostack, nomem)
            );
        }
        if success != 0 {
            Some(rdrand)
        } else {
            None
        }
    }
}

impl RngCore for Rdrand {
    fn next_u32(&mut self) -> u32 {
        loop {
            if let Some(rand) = self.rdrand_raw_32() {
                return rand;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn next_u64(&mut self) -> u64 {
        loop {
            if let Some(rand) = self.rdrand_raw_64() {
                return rand;
            }
        }
    }

    #[cfg(target_arch = "x86")]
    fn next_u64(&mut self) -> u64 {
        self.next_u32() as u64 | ((self.next_u32() as u64) << 32)
    }

    fn fill_bytes(&mut self, mut dest: &mut [u8]) {
        while !dest.is_empty() {
            let next_chunk = dest.len().min(8);
            let buf = self.next_u64().to_ne_bytes();
            dest[..next_chunk].copy_from_slice(&buf[..next_chunk]);
            dest = &mut dest[next_chunk..];
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rdrand {}
