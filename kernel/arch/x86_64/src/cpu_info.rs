//! Various CPU information functions

use raw_cpuid::{CpuId, FeatureInfo};

/// Get the CPU core ID
///
/// # Panics
/// This function panics if it cannot determine the initial local APIC ID of the CPU. This should not happen.
pub fn core_id() -> u32 {
    let cpuid = CpuId::new();
    u32::from(
        cpuid
            .get_feature_info()
            .as_ref()
            .map(FeatureInfo::initial_local_apic_id)
            .unwrap(),
    )
}
