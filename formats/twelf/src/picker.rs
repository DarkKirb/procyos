//! Picks an executable from a TWELF file

use core::cmp::Ordering;

use crate::deserializer::{Architecture, DeserializationError, TWELFFile, TWELF};

/// Rating on whether the platform can run the given file
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RunLevel {
    /// The platform cannot run the file
    CantRun,
    /// The platform can run the file with software emulation
    SoftwareEmulated,
    /// The platform can run the file with hardware emulation (for example 32 bit backwards compat). The argument is how “optimized” the binary is for the current architecture.
    HardwareEmulated(u32),
    /// The platform can run the file natively. The argument is how “optimized” the binary is for the current architecture.
    ///
    /// A higher value is expected to have higher or the same performance as a lower value.
    Native(u32),
}

impl Ord for RunLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        match (self, other) {
            (Self::HardwareEmulated(a), Self::HardwareEmulated(b))
            | (Self::Native(a), Self::Native(b)) => a.cmp(b),
            (Self::SoftwareEmulated, Self::CantRun)
            | (Self::HardwareEmulated(_), Self::CantRun | Self::SoftwareEmulated)
            | (Self::Native(_), _) => Ordering::Greater,
            (Self::CantRun | Self::SoftwareEmulated, _)
            | (Self::HardwareEmulated(_), Self::Native(_)) => Ordering::Less,
        }
    }
}

impl PartialOrd for RunLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(target_arch = "x86_64")]
fn score(arch: Architecture) -> RunLevel {
    use raw_cpuid::{CpuId, ExtendedFeatures, ExtendedProcessorFeatureIdentifiers, FeatureInfo};

    use crate::deserializer::X64Subarchitecture;

    let cpuid = CpuId::new();
    let feature_info = cpuid.get_feature_info();
    let fi = feature_info.as_ref();
    let extended_processor_and_features_identifiers =
        cpuid.get_extended_processor_and_feature_identifiers();
    let epafi = extended_processor_and_features_identifiers.as_ref();
    let extended_feature_info = cpuid.get_extended_feature_info();
    let efi = extended_feature_info.as_ref();

    log::debug!("fi: {fi:?}, epafi: {epafi:?}, efi: {efi:?}");

    match arch {
        // CMOV, CX8, FPU, FXSR, MMX, OSFXSR, SCE, SSE, SSE2
        Architecture::X64(X64Subarchitecture::V1) => {
            if fi.is_some_and(FeatureInfo::has_cmov)
                && fi.is_some_and(FeatureInfo::has_cmpxchg8b)
                && fi.is_some_and(FeatureInfo::has_fpu)
                && fi.is_some_and(FeatureInfo::has_fxsave_fxstor)
                && fi.is_some_and(FeatureInfo::has_mmx)
                && epafi.is_some_and(ExtendedProcessorFeatureIdentifiers::has_syscall_sysret)
                && fi.is_some_and(FeatureInfo::has_sse)
                && fi.is_some_and(FeatureInfo::has_sse2)
            {
                RunLevel::Native(1)
            } else {
                RunLevel::CantRun
            }
        }
        // CMPXCHG16B, LAHF-SAHF, POPCNT, SSE3, SSE4_1, SSE4_2, SSSE3
        Architecture::X64(X64Subarchitecture::V2) => {
            if fi.is_some_and(FeatureInfo::has_cmpxchg16b)
                && epafi.is_some_and(ExtendedProcessorFeatureIdentifiers::has_lahf_sahf)
                && fi.is_some_and(FeatureInfo::has_popcnt)
                && fi.is_some_and(FeatureInfo::has_sse3)
                && fi.is_some_and(FeatureInfo::has_sse41)
                && fi.is_some_and(FeatureInfo::has_sse42)
                && fi.is_some_and(FeatureInfo::has_ssse3)
            {
                RunLevel::Native(2)
            } else {
                RunLevel::CantRun
            }
        }
        // AVX, AVX2, BMI1, BMI2, F16C, FMA, LZCNT, MOVBE, OSXSAVE
        Architecture::X64(X64Subarchitecture::V3) => {
            if fi.is_some_and(FeatureInfo::has_avx)
                && efi.is_some_and(ExtendedFeatures::has_avx2)
                && efi.is_some_and(ExtendedFeatures::has_bmi1)
                && efi.is_some_and(ExtendedFeatures::has_bmi2)
                && fi.is_some_and(FeatureInfo::has_f16c)
                && fi.is_some_and(FeatureInfo::has_fma)
                && epafi.is_some_and(ExtendedProcessorFeatureIdentifiers::has_lzcnt)
                && fi.is_some_and(FeatureInfo::has_movbe)
                && fi.is_some_and(FeatureInfo::has_oxsave)
            {
                RunLevel::Native(3)
            } else {
                RunLevel::CantRun
            }
        }
        // AVX512F, AVX512BW, AVX512CD, AVX512DQ, AVX512VL
        Architecture::X64(X64Subarchitecture::V4) => {
            if efi.is_some_and(ExtendedFeatures::has_avx512f)
                && efi.is_some_and(ExtendedFeatures::has_avx512bw)
                && efi.is_some_and(ExtendedFeatures::has_avx512cd)
                && efi.is_some_and(ExtendedFeatures::has_avx512dq)
                && efi.is_some_and(ExtendedFeatures::has_avx512vl)
            {
                RunLevel::Native(4)
            } else {
                RunLevel::CantRun
            }
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn score(_arch: Architecture) -> RunLevel {
    RunLevel::CantRun
}

/// Picks the best file from a TWELF file based on the platform's capabilities.
///
/// # Errors
/// this function returns an error if the TWELF file is corrupted or contains invalid data.
pub fn find_best_executable(
    twelf: TWELF<'_>,
) -> Result<Option<TWELFFile<'_>>, DeserializationError> {
    let mut max_score = RunLevel::CantRun;
    let mut best_file = None;
    for index in 0..twelf.num_files() {
        let file = twelf.get_file(index)?;
        let score = score(file.architecture()?);
        if score > max_score {
            max_score = score;
            best_file = Some(file);
        }
    }

    Ok(best_file)
}
