// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
use clap::{Parser, Subcommand};
use isohopper_core::{layout, virtualdisk};
use isohopper_media::{ImageEntry, recipes::LinuxRecipe};
use same_file::Handle;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "isohopper",
    version,
    about = "Experimental multiboot toolkit. Pending human testing.",
    after_help = "Physical disk writes are unavailable in this build. Image creation writes only new regular files. EFI image preparation is for firmware testing; it does not establish boot or Secure Boot compatibility."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Discover physical disks read-only; incomplete safety checks remain blocked.
    Devices {
        #[arg(long)]
        json: bool,
    },
    /// Inspect explicitly simulated disks and guard decisions.
    List {
        #[arg(long)]
        demo: bool,
        #[arg(long)]
        json: bool,
    },
    /// Scan a local image library; report untested recipe candidates.
    Scan {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify a signed local artifact manifest against a supplied trust key.
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Preview partition geometry without writing anything.
    Plan {
        #[arg(long)]
        size_mib: u64,
        #[arg(long, default_value_t = 512)]
        sector_size: u64,
        #[arg(long)]
        legacy: bool,
    },
    /// Create or inspect regular-file GPT images and optional EFI test slots.
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Stream SHA-256/512; a checksum is not publisher authentication.
    Verify {
        path: PathBuf,
        #[arg(long, default_value = "sha256")]
        algorithm: String,
        #[arg(long)]
        expected: Option<String>,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Preview an anonymous report locally. Never uploads.
    Report,
    /// Reserved for the validated physical-device writer; currently refused.
    Write {
        #[arg(long)]
        disk: String,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        allow_risky_target: Option<String>,
    },
    /// Reserved for signed boot-slot updates; currently refused.
    Update {
        #[arg(long)]
        disk: String,
    },
}
#[derive(Subcommand)]
enum ImageCommand {
    Create {
        path: PathBuf,
        #[arg(long)]
        size_mib: u64,
        #[arg(long, default_value_t = 512)]
        sector_size: u64,
        #[arg(long)]
        legacy: bool,
        /// Put this x64 EFI application into FAT32 boot slots A and B (64 MiB input limit).
        #[arg(long)]
        efi: Option<PathBuf>,
        /// Read firmware power preferences from YAML/TOML into both EFI test slots.
        #[arg(long, requires = "efi")]
        config: Option<PathBuf>,
    },
    Verify {
        path: PathBuf,
        /// Also verify both FAT32 boot slots against this exact x64 EFI payload.
        #[arg(long)]
        efi: Option<PathBuf>,
    },
}
#[derive(Subcommand)]
enum ManifestCommand {
    Verify {
        path: PathBuf,
        /// Detached signature as exactly 64 raw bytes, not hexadecimal text.
        #[arg(long)]
        signature: PathBuf,
        /// Trusted Ed25519 public key as exactly 64 hexadecimal characters.
        #[arg(long)]
        public_key: String,
    },
}
#[derive(Subcommand)]
enum ConfigCommand {
    Check {
        path: PathBuf,
    },
    Convert {
        path: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        force: bool,
    },
    Defaults,
    Schema,
}
#[derive(Serialize)]
struct ScanImage {
    #[serde(flatten)]
    image: ImageEntry,
    recipe: Option<LinuxRecipe>,
    recipe_error: Option<String>,
}
#[derive(Serialize)]
struct ScanView {
    root: PathBuf,
    images: Vec<ScanImage>,
    warnings: Vec<String>,
}

fn print_json(value: &impl Serialize) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
    );
    Ok(())
}
fn plan(size: u64, sector: u64, legacy: bool) -> Result<layout::Layout, String> {
    layout::plan(
        size.checked_mul(1024 * 1024).ok_or("size overflow")?,
        sector,
        legacy,
    )
    .map_err(|error| error.to_string())
}
fn scan_library(path: &Path, json: bool) -> Result<(), String> {
    let report = isohopper_media::scan(path).map_err(|error| error.to_string())?;
    let images = report
        .images
        .into_iter()
        .map(|image| {
            let candidate = if image.extension == "iso" {
                isohopper_media::recipes::select(&image)
            } else {
                Ok(None)
            };
            let (recipe, recipe_error) = match candidate {
                Ok(recipe) => (recipe, None),
                Err(error) => (None, Some(error.to_string())),
            };
            ScanImage {
                image,
                recipe,
                recipe_error,
            }
        })
        .collect();
    let view = ScanView {
        root: report.root,
        images,
        warnings: report.warnings,
    };
    if json {
        return print_json(&view);
    }
    println!(
        "Library: {} | {} image(s)",
        view.root.display(),
        view.images.len()
    );
    for item in view.images {
        let image = item.image;
        println!(
            "{:?} | {} | {} bytes",
            image.relative_path, image.extension, image.size
        );
        println!(
            "  Inspection: {} | Boot: {}",
            image.inspection_status, image.boot_status
        );
        if let Some(label) = image.iso_volume_label {
            println!("  ISO label: {label:?}");
        }
        if let Some(inspection) = image.boot_inspection {
            let mut platforms = std::collections::BTreeSet::new();
            for catalog in &inspection.catalogs {
                if catalog.complete && catalog.validation_checksum_valid {
                    for entry in &catalog.entries {
                        if entry.bootable {
                            platforms.insert(entry.platform);
                        }
                    }
                }
            }
            println!(
                "  El Torito: {} | {} | not boot-tested",
                if platforms.is_empty() {
                    "no validated boot entries".into()
                } else {
                    platforms.into_iter().collect::<Vec<_>>().join(", ")
                },
                inspection.status,
            );
            if !inspection.udf_identifiers.is_empty() {
                println!(
                    "  UDF: {} (recognition only)",
                    inspection.udf_identifiers.join(", ")
                );
            }
            for issue in inspection.issues {
                println!("  Boot metadata: {issue}");
            }
        }
        if let Some(recipe) = item.recipe {
            println!("  Recipe: {} ({})", recipe.family, recipe.status);
            println!(
                "  Kernel candidates: {}",
                recipe.kernel_candidates.join(", ")
            );
            println!(
                "  Initrd candidates: {}",
                recipe.initrd_candidates.join(", ")
            );
            println!("  Kernel arguments: {}", recipe.kernel_arguments.join(" "));
        } else if let Some(error) = item.recipe_error {
            println!("  Recipe unavailable: {error}");
        } else {
            println!("  Recipe: unknown");
        }
    }
    for warning in view.warnings {
        println!("Warning: {warning}");
    }
    Ok(())
}
fn open_binary(path: &Path) -> Result<File, String> {
    let fail = |error: std::io::Error| format!("{}: {error}", path.display());
    if !fs::symlink_metadata(path)
        .map_err(fail)?
        .file_type()
        .is_file()
    {
        return Err(format!(
            "{}: input must be a regular file, not a symlink or device",
            path.display()
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path).map_err(fail)?;
    let metadata = file.metadata().map_err(fail)?;
    if !metadata.is_file() {
        return Err("opened input is not a regular file".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("input is a reparse point".into());
        }
    }
    Ok(file)
}
fn read_binary(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut file = open_binary(path)?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if before.len() > limit as u64 {
        return Err(format!(
            "{}: input exceeds {limit} byte limit",
            path.display()
        ));
    }
    let identity = Handle::from_file(file.try_clone().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err(format!(
            "{}: input exceeds {limit} byte limit",
            path.display()
        ));
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    let current = Handle::from_file(open_binary(path)?).map_err(|error| error.to_string())?;
    if identity != current
        || before.len() != after.len()
        || bytes.len() as u64 != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("input changed while reading".into());
    }
    Ok(bytes)
}
fn verify_manifest(path: &Path, signature: &Path, public_key: &str) -> Result<(), String> {
    if public_key.len() != 64 || !public_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("public key must contain exactly 64 hexadecimal characters (32 bytes)".into());
    }
    let public_key: [u8; 32] = hex::decode(public_key)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "invalid public key length")?;
    let signature = read_binary(signature, 64)?;
    if signature.len() != 64 {
        return Err("detached signature must contain exactly 64 raw bytes".into());
    }
    let payload = read_binary(path, isohopper_media::manifest::MAX_MANIFEST_BYTES)?;
    let manifest = isohopper_media::manifest::verify(&payload, &signature, &public_key)
        .map_err(|error| error.to_string())?;
    print_json(
        &serde_json::json!({"status":"signature-matches-supplied-key", "artifact_bytes_verified":false, "manifest":manifest}),
    )
}
fn create_image(
    path: &Path,
    size_mib: u64,
    sector_size: u64,
    legacy: bool,
    efi: Option<&Path>,
    config: Option<&Path>,
) -> Result<(), String> {
    let layout = plan(size_mib, sector_size, legacy)?;
    if let Some(efi) = efi {
        let power = if let Some(config) = config {
            let config = isohopper_config::load(config).map_err(|error| error.to_string())?;
            for warning in &config.warnings {
                eprintln!("Warning: {warning}");
            }
            config.launcher.power
        } else {
            isohopper_config::PowerConfig::default()
        };
        let power_mask = u8::from(power.reboot)
            | (u8::from(power.shutdown) << 1)
            | (u8::from(power.firmware_setup) << 2);
        let payload = read_binary(efi, 64 * 1024 * 1024)?;
        virtualdisk::create_bootable_configured(path, &layout, &payload, power_mask)
            .map_err(|error| error.to_string())?;
        print_json(
            &serde_json::json!({"path":path, "efi":efi, "status":"firmware-test-only", "verification":"gpt-and-fat32-payload", "boot_slots":{"A":"fat32","B":"fat32"}, "data_partition":"unformatted", "firmware_boot_tested":false, "secure_boot_verified":false, "power_mask":power_mask, "power":power}),
        )
    } else {
        virtualdisk::create(path, &layout).map_err(|error| error.to_string())?;
        print_json(
            &serde_json::json!({"path":path, "status":"verified-gpt", "formatted":false, "bootable":false}),
        )
    }
}
fn verify_image(path: &Path, efi: Option<&Path>) -> Result<(), String> {
    if let Some(efi) = efi {
        let payload = read_binary(efi, 64 * 1024 * 1024)?;
        virtualdisk::verify_bootable(path, &payload).map_err(|error| error.to_string())?;
        print_json(
            &serde_json::json!({"path":path, "efi":efi, "status":"firmware-test-only", "verification":"gpt-and-fat32-payload", "boot_slots":{"A":"fat32","B":"fat32"}, "data_partition":"not-checked", "firmware_boot_tested":false, "secure_boot_verified":false}),
        )
    } else {
        virtualdisk::verify(path).map_err(|error| error.to_string())?;
        print_json(
            &serde_json::json!({"path":path, "status":"verified-gpt", "filesystem_verification":"not-requested", "firmware_boot_tested":false}),
        )
    }
}
fn run(cli: Cli) -> Result<(), (u8, String)> {
    let result: Result<(), String> = match cli.command {
        Command::Devices { json } => isohopper_inventory::discover().map_err(|error| error.to_string()).and_then(|inventory| {
            if json { print_json(&inventory) } else { print!("{}", isohopper_cli::format_inventory(&inventory)); Ok(()) }
        }),
        Command::List { demo, json } => {
            if !demo { return Err((3, "Use `devices` for read-only physical disk discovery, or `list --demo` for explicitly labelled mock devices. Physical writes remain unavailable.".into())); }
            let views = isohopper_cli::demo_disks();
            if json { print_json(&views) } else {
                for view in views {
                    println!("[MOCK] {} | {} | {} | {} bytes", view.disk.id, view.disk.model, view.verdict.state, view.disk.size_bytes);
                    for reason in view.verdict.hard_blocks.iter().chain(view.verdict.risks.iter()) { println!("  {}", reason.message); }
                    if !view.challenge.is_empty() { println!("  Challenge: {}", view.challenge); }
                }
                Ok(())
            }
        },
        Command::Scan { path, json } => scan_library(&path, json),
        Command::Manifest { command } => match command { ManifestCommand::Verify { path, signature, public_key } => verify_manifest(&path, &signature, &public_key) },
        Command::Plan { size_mib, sector_size, legacy } => plan(size_mib, sector_size, legacy).and_then(|layout| print_json(&layout)),
        Command::Image { command } => match command {
            ImageCommand::Create { path, size_mib, sector_size, legacy, efi, config } => create_image(&path, size_mib, sector_size, legacy, efi.as_deref(), config.as_deref()),
            ImageCommand::Verify { path, efi } => verify_image(&path, efi.as_deref()),
        },
        Command::Verify { path, algorithm, expected } => isohopper_config::verify::file(&path, &algorithm, expected.as_deref()).map_err(|error| error.to_string()).and_then(|value| print_json(&value)),
        Command::Config { command } => match command {
            ConfigCommand::Check { path } => isohopper_config::load(&path).map_err(|error| error.to_string()).and_then(|config| { for warning in &config.warnings { eprintln!("Warning: {warning}"); } print_json(&config) }),
            ConfigCommand::Convert { path, to, force } => isohopper_config::convert(&path, &to, force).map_err(|error| error.to_string()).and_then(|path| print_json(&serde_json::json!({"converted":path, "comments":"retained in backup; normalized output"}))),
            ConfigCommand::Defaults => print_json(&isohopper_config::Config::default()),
            ConfigCommand::Schema => { println!("{}", isohopper_config::schema()); Ok(()) },
        },
        Command::Report => print_json(&serde_json::json!({"application":"IsoHopper", "version":env!("CARGO_PKG_VERSION"), "host_os":std::env::consts::OS, "host_arch":std::env::consts::ARCH, "physical_device_tested":false, "upload":"never automatic", "serials_included":false, "paths_included":false})),
        Command::Write { .. } | Command::Update { .. } => return Err((3, "Refused: physical device writes and boot-slot updates require validated platform adapters and signed boot artifacts. Use `image create` for regular-file testing.".into())),
    };
    result.map_err(|error| (5, error))
}
fn main() {
    if let Err((code, message)) = run(Cli::parse()) {
        eprintln!("{message}");
        std::process::exit(i32::from(code));
    }
}
