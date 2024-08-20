#![no_main]
#![no_std]
#![feature(allocator_api)]
#![feature(inline_const_pat)]
#![feature(naked_functions)]
#![feature(never_type)]
#![feature(slice_ptr_get)]
#![feature(strict_provenance)]

extern crate alloc;

use log::{error, info};
use spin::Lazy;
use twelf::{
    crypto::{KeyId, PublicVerifyingKey},
    deserializer::TWELF,
    picker::find_best_executable,
};
use uefi::{
    fs::FileSystem,
    prelude::*,
    proto::media::fs::SimpleFileSystem,
    table::boot::{MemoryType, ScopedProtocol},
};

pub mod bump_alloc;
pub mod elf_loader;
pub mod gop_info;

static VERIFYING_KEY: Lazy<PublicVerifyingKey> = Lazy::new(|| {
    PublicVerifyingKey::deserialize(include_bytes!("../../../../.secrets/twelf_public_key"))
        .unwrap()
});

include!(concat!(env!("OUT_DIR"), "/codegen.rs"));

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi::helpers::init(&mut system_table).unwrap();
    let free_system_memory = {
        let memory_map = system_table
            .boot_services()
            .memory_map(MemoryType::LOADER_DATA)
            .unwrap();
        memory_map
            .entries()
            .filter(|entry| entry.ty == MemoryType::CONVENTIONAL)
            .map(|v| v.page_count)
            .sum::<u64>()
            * 4096
    };
    let kernel_data;
    let (best_executable, mut rng) = {
        info!("Hello world!");
        let bs = system_table.boot_services();
        let fs: ScopedProtocol<SimpleFileSystem> =
            bs.get_image_file_system(bs.image_handle()).unwrap();
        let mut fs = FileSystem::new(fs);
        info!("Loading kernel ...");
        kernel_data = fs.read(cstr16!("kernel")).unwrap();
        info!("Verifying kernel ...");
        let kernel = TWELF::new(kernel_data.as_slice(), &KEYRING).unwrap();
        let best_executable = find_best_executable(kernel).unwrap();
        if let Some(executable) = best_executable {
            info!("Found best executable for {:?}", executable.architecture());
        } else {
            error!("Could not find a suitable executable in the kernel. Exiting.");
        }
        let rng = uefi_rand::open_rng(bs).unwrap();
        (best_executable, rng)
    };
    elf_loader::load(
        best_executable.unwrap().read().unwrap(),
        &mut rng,
        system_table,
        free_system_memory as usize,
    )
    .unwrap();
}
