// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded YAML/TOML preferences sharing one schema. Accepting a preference
//! does not establish that the corresponding boot capability is implemented.
mod files;
mod parse;
mod regular;
pub mod verify;

pub use files::{convert, load};
pub use parse::parse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf, sync::OnceLock};

pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_DEPTH: usize = 32;
pub const MAX_NODES: usize = 100_000;
pub const MAX_SCALAR_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub boot: BootConfig,
    pub launcher: LauncherConfig,
    pub images: ImagesConfig,
    pub safety: SafetyConfig,
    pub extras: ExtrasConfig,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub overrides: BTreeMap<String, Override>,
    #[serde(skip)]
    pub source: Option<PathBuf>,
    #[serde(skip)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BootConfig {
    pub netboot_xyz: bool,
    pub secure_boot_policy: String,
    pub timeout: u32,
    pub default: String,
}
impl Default for BootConfig {
    fn default() -> Self {
        Self {
            netboot_xyz: true,
            secure_boot_policy: "enforce".into(),
            timeout: 10,
            default: "last".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LauncherConfig {
    pub system_info: bool,
    pub warn_multi_disk: bool,
    pub theme: String,
    pub power: PowerConfig,
}
impl Default for LauncherConfig {
    fn default() -> Self {
        Self {
            system_info: true,
            warn_multi_disk: true,
            theme: "midnight".into(),
            power: PowerConfig::default(),
        }
    }
}

/// Visibility preferences for firmware actions, never host power commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PowerConfig {
    pub reboot: bool,
    pub shutdown: bool,
    pub firmware_setup: bool,
}
impl Default for PowerConfig {
    fn default() -> Self {
        Self {
            reboot: true,
            shutdown: true,
            firmware_setup: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImagesConfig {
    pub verify_hash: bool,
    pub verify_signature: String,
}
impl Default for ImagesConfig {
    fn default() -> Self {
        Self {
            verify_hash: true,
            verify_signature: "prefer".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyConfig {
    pub risky_size_gb: u64,
    pub flag_nvme: bool,
}
impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            risky_size_gb: 256,
            flag_nvme: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExtrasConfig {
    pub memtest86plus: bool,
}
impl Default for ExtrasConfig {
    fn default() -> Self {
        Self {
            memtest86plus: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Override {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub strategy: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub unattend: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub drivers: Vec<String>,
    pub bypass_tpm_check: bool,
}

/// The single schema consumed by parsing, validation and frontend tooling.
pub fn schema() -> &'static str {
    include_str!("../../../schema/isohopper.schema.json")
}

fn validator() -> Result<&'static jsonschema::Validator, ConfigError> {
    static VALIDATOR: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let value: Value = serde_json::from_str(schema()).map_err(|e| e.to_string())?;
            jsonschema::draft202012::options()
                .build(&value)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|error| ConfigError::Invalid(format!("embedded schema: {error}")))
}

pub fn validate(config: &Config) -> Result<(), ConfigError> {
    let value = serde_json::to_value(config).map_err(|e| ConfigError::Invalid(e.to_string()))?;
    validate_value(&value)
}

fn validate_value(value: &Value) -> Result<(), ConfigError> {
    validator()?.validate(value).map_err(|error| {
        ConfigError::Invalid(format!(
            "configuration at {}: {error}",
            error.instance_path()
        ))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Yaml,
    Toml,
}
impl Format {
    fn from_name(name: &str) -> Result<Self, ConfigError> {
        match name.trim_start_matches('.').to_ascii_lowercase().as_str() {
            "yml" | "yaml" => Ok(Self::Yaml),
            "toml" => Ok(Self::Toml),
            _ => Err(ConfigError::Invalid(format!(
                "unsupported configuration format {name:?}; use yml, yaml, or toml"
            ))),
        }
    }
    fn extension(self) -> &'static str {
        match self {
            Self::Yaml => "yml",
            Self::Toml => "toml",
        }
    }
}
