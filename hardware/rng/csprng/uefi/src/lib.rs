//! UEFI CSPRNG
//!
//! It generates a 32 byte seed via the UEFI protocols and then uses a chacha20-based CSPRNG to generate random numbers.
#![no_std]
use core::num::NonZeroU32;

use rand_core::RngCore;
use uefi::{prelude::BootServices, proto::rng::Rng, table::boot::ScopedProtocol};

#[derive(Debug)]
pub struct EfiRng<'a>(ScopedProtocol<'a, Rng>);

impl<'a> EfiRng<'a> {
    /// Creates a new `EfiRng` instance.
    ///
    /// # Errors
    /// This function returns an error if the UEFI RNG is not available.
    pub fn new(boot_services: &'a BootServices) -> uefi::Result<Self> {
        let handle = boot_services.get_handle_for_protocol::<Rng>()?;
        Ok(Self(boot_services.open_protocol_exclusive(handle)?))
    }
}

impl RngCore for EfiRng<'_> {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf).unwrap();
        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf).unwrap();
        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.get_rng(None, dest).map_err(|e| {
            rand_core::Error::from(
                NonZeroU32::new(e.status().0.try_into().unwrap_or(u32::MAX))
                    .expect("Non-zero UEFI error"),
            )
        })
    }
}
