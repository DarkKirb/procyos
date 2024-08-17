//! UEFI-seeded random number generator
//!
//! It generates a 32 byte seed via the UEFI protocols and then uses a chacha20-based CSPRNG to generate random numbers.
#![no_std]
use log::{error, info, warn};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use uefi::{prelude::BootServices, proto::rng::Rng};

fn efi_rng_seed(boot_services: &BootServices) -> uefi::Result<[u8; 32]> {
    info!("Requesting EFI RNG service");
    let handle = boot_services.get_handle_for_protocol::<Rng>()?;
    let mut rng = boot_services.open_protocol_exclusive::<Rng>(handle)?;
    let mut seed = [0u8; 32];
    rng.get_rng(None, &mut seed)?;
    Ok(seed)
}

#[cfg(target_arch = "x86_64")]
fn rdseed_raw() -> Option<u64> {
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

#[cfg(target_arch = "x86_64")]
fn rdseed() -> u64 {
    loop {
        if let Some(seed) = rdseed_raw() {
            return seed;
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn fallback_rng_seed() -> uefi::Result<[u8; 32]> {
    use raw_cpuid::ExtendedFeatures;

    warn!("EFI RNG service not available, falling back to architectural RNG.");
    let cpu_id = raw_cpuid::CpuId::new();

    if cpu_id
        .get_extended_feature_info()
        .as_ref()
        .is_some_and(ExtendedFeatures::has_rdseed)
    {
        info!("Found rdrand");
        // Generate the randomness first
        let rd1 = rdseed();
        let rd2 = rdseed();
        let rd3 = rdseed();
        let rd4 = rdseed();
        // Verify that it actually works.
        // Some implementations have pretty gnarly bugs where they return a fixed pattern in some cases instead of a random number.

        let mut bad_values = 0;
        if rd1 == 0x0000_0000 || rd1 == 0xFFFF_FFFF {
            bad_values += 1;
        }
        if rd1 == rd2 || rd1 == rd3 || rd1 == rd4 {
            bad_values += 1;
        }
        if rd2 == 0x0000_0000 || rd2 == 0xFFFF_FFFF {
            bad_values += 1;
        }
        if rd2 == rd3 || rd2 == rd4 {
            bad_values += 1;
        }
        if rd3 == 0x0000_0000 || rd3 == 0xFFFF_FFFF {
            bad_values += 1;
        }
        if rd3 == rd4 {
            bad_values += 1;
        }
        if rd4 == 0x0000_0000 || rd4 == 0xFFFF_FFFF {
            bad_values += 1;
        }

        if bad_values >= 3 {
            error!("RDSEED returned bad values (badness = {bad_values}): 0x{rd1:016X} 0x{rd2:016X} 0x{rd3:016X} 0x{rd4:016X}");
        } else {
            let mut seed = [0u8; 32];
            seed[0..8].copy_from_slice(&rd1.to_le_bytes());
            seed[8..16].copy_from_slice(&rd2.to_le_bytes());
            seed[16..24].copy_from_slice(&rd3.to_le_bytes());
            seed[24..32].copy_from_slice(&rd4.to_le_bytes());
            return Ok(seed);
        }
    }

    error!("CPU doesn’t support RDSEED or RDRAND.");
    Err(uefi::Status::NOT_FOUND.into())
}

#[cfg(not(target_arch = "x86_64"))]
fn fallback_rng_seed() -> uefi::Result<[u8; 32]> {
    error!("RNG Seed fallback not implemented on this platform!");
    Err(uefi::Status::NOT_FOUND.into())
}

/// Opens the RNG with a fallback to the architectural random number generator.
///
/// # Errors
/// This function returns an error if both the UEFI and the architectural RNGs are not available.
pub fn open_rng(boot_services: &BootServices) -> uefi::Result<ChaCha20Rng> {
    let seed = efi_rng_seed(boot_services).or_else(|_| fallback_rng_seed());
    Ok(ChaCha20Rng::from_seed(seed?))
}
