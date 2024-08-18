use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use cargo::{core::Workspace, GlobalContext};
use clap::{Parser, Subcommand};
use eyre::{eyre, Result};
use rand::thread_rng;
use twelf::{
    crypto::PrivateSigningKey,
    serializer::{Architecture, TWELFFile, X64Subarchitecture, TWELF},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates a signing key
    GenerateKeypair {
        /// Default directory for storing secrets. Defaults to .secrets in the current directory.
        #[arg(short, long)]
        secrets_directory: Option<String>,
    },

    /// Performs the build
    Build {
        /// Use release mode for builds.
        #[arg(short, long, default_value = "false")]
        release: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeypair { secrets_directory } => {
            generate_keypair(secrets_directory)?;
        }
        Commands::Build { release } => {
            build(release)?;
        }
    }
    Ok(())
}

fn build(release: bool) -> Result<()> {
    let global_context = GlobalContext::default().map_err(|e| eyre!("Cargo Error {e:?}"))?;
    let workspace = Workspace::new(&project_root().join("Cargo.toml"), &global_context)
        .map_err(|e| eyre!("Cargo Error {e:?}"))?;
    if !fs::exists(".secrets/twelf_private_key")? {
        println!("Generating signing key pair...");
        generate_keypair(Some(".secrets".to_string()))?;
    }

    let private_key = fs::read(".secrets/twelf_private_key")?;
    let private_key = PrivateSigningKey::deserialize(&private_key)?;

    println!("Building Kernel...");

    cargo(
        &[
            "build",
            "--target",
            "./kernel/x86_64-kernel-procyos.json",
            "--package",
            "kernel",
            "-Zbuild-std=core,alloc,compiler_builtins",
        ],
        release,
    )?;

    let release_directory = workspace
        .target_dir()
        .join("x86_64-kernel-procyos")
        .join(if release { "release" } else { "debug" });

    let kernel_path = release_directory.join("kernel");
    let kernel_path_str = format!("{}", kernel_path.display());

    Command::new("strip")
        .arg(&kernel_path_str)
        .arg("--strip-all")
        .arg("-o")
        .arg(format!("{kernel_path_str}.stripped"))
        .status()
        .map_err(|e| eyre!("Error running strip: {}", e))?;

    let kernel = fs::read(format!("{kernel_path_str}.stripped"))?;

    let mut kernel_twelf = TWELF::new(private_key);
    kernel_twelf.add_file(TWELFFile::new(
        &kernel,
        Architecture::X64(X64Subarchitecture::V1),
    ));

    let kernel_twelf = kernel_twelf.serialize()?;
    fs::write(
        release_directory.join("kernel.twelf").as_path_unlocked(),
        kernel_twelf,
    )?;

    println!("Kernel Binary Path: {}", kernel_path.display());

    Ok(())
}

fn cargo(args: &[&str], release: bool) -> Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let mut command = std::process::Command::new(cargo);
    command.current_dir(project_root()).args(args);
    if release {
        command.arg("--release");
    }
    command
        .status()
        .map_err(|e| eyre!("Error running cargo: {}", e))?;

    Ok(())
}

fn project_root() -> PathBuf {
    Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
}

fn generate_keypair(secrets_directory: Option<String>) -> Result<()> {
    let secrets_directory: PathBuf = secrets_directory
        .unwrap_or_else(|| ".secrets".to_string())
        .into();

    let private_key = PrivateSigningKey::generate(&mut thread_rng());

    fs::create_dir_all(&secrets_directory)?;

    fs::write(
        secrets_directory.join("twelf_private_key"),
        private_key.serialize()?,
    )?;

    let public_key = private_key.verifying_key();

    let public_key_file = secrets_directory.join("twelf_public_key");

    fs::write(&public_key_file, public_key.serialize()?)?;
    println!("Key ID: {:?}", public_key.key_id());

    let public_key_id_file = secrets_directory.join("twelf_public_key.id");
    fs::write(&public_key_id_file, public_key.key_id().serialize())?;

    println!(
        "Generated signing key saved to: {}",
        secrets_directory.display()
    );

    Ok(())
}
