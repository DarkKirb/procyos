//! Architectural TRNG (True Random Number Generator) for x86 and x86_64 processors
#![cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#![feature(let_chains)]
#![no_std]

use log::debug;
use rand_core::{CryptoRng, RngCore};
use raw_cpuid::CpuId;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Rdseed;

impl Rdseed {
    /// Creates a new rdrand instance
    ///
    /// Returns `None` if rdrand is not supported or is known to be broken.
    pub fn try_new() -> Option<Self> {
        let cpuid = CpuId::new();
        if let Some(efi) = cpuid.get_extended_feature_info()
            && efi.has_rdseed()
        {
            debug!("rdseed is supported");
            return Some(Self);
        }
        None
    }

    fn rdseed_raw_32(&self) -> Option<u32> {
        use core::arch::asm;
        let success: u8;
        let rdseed: u32;
        unsafe {
            asm!(
                "rdseed {0:e}",
                "setc {1}",
                out(reg) rdseed,
                out(reg_byte) success,
                options(nostack, nomem)
            );
        }
        if success != 0 {
            Some(rdseed)
        } else {
            None
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn rdseed_raw_64(&self) -> Option<u64> {
        use core::arch::asm;
        let success: u8;
        let rdseed: u64;
        unsafe {
            asm!(
                "rdseed {0}",
                "setc {1}",
                out(reg) rdseed,
                out(reg_byte) success,
                options(nostack, nomem)
            );
        }
        if success != 0 {
            Some(rdseed)
        } else {
            None
        }
    }
}

impl RngCore for Rdseed {
    fn next_u32(&mut self) -> u32 {
        loop {
            if let Some(seed) = self.rdseed_raw_32() {
                return seed;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn next_u64(&mut self) -> u64 {
        loop {
            if let Some(seed) = self.rdseed_raw_64() {
                return seed;
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

impl CryptoRng for Rdseed {}
