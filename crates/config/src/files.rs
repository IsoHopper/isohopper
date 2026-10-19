// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{Config, ConfigError, Format, MAX_BYTES, parse};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Load an explicit file, or select isohopper.yml/.yaml/.toml in a directory.
pub fn load(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let (source, warnings) = resolve(path.as_ref())?;
    let (data, _) = read_bounded(&source)?;
    let mut config = parse(&data, extension(&source)?)?;
    config.source = Some(source);
    config.warnings = warnings;
    Ok(config)
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(message.into())
}
fn extension(path: &Path) -> Result<&str, ConfigError> {
    path.extension()
        .and_then(|v| v.to_str())
        .ok_or_else(|| invalid("configuration path must have a yml, yaml, or toml extension"))
}
fn present(path: &Path) -> Result<bool, ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn yaml_conflict(path: &Path) -> Result<(), ConfigError> {
    if present(&path.with_extension("yml"))? && present(&path.with_extension("yaml"))? {
        return Err(invalid(
            "both .yml and .yaml files exist; remove one YAML alias",
        ));
    }
    Ok(())
}
fn resolve(path: &Path) -> Result<(PathBuf, Vec<String>), ConfigError> {
    if !fs::metadata(path)?.is_dir() {
        yaml_conflict(path)?;
        return Ok((path.to_owned(), vec![]));
    }
    let base = path.join("isohopper.yml");
    yaml_conflict(&base)?;
    let yml = base.clone();
    let yaml = base.with_extension("yaml");
    let toml = base.with_extension("toml");
    let selected = if present(&yml)? {
        Some(yml)
    } else if present(&yaml)? {
        Some(yaml)
    } else {
        None
    };
    if let Some(selected) = selected {
        let warnings = if present(&toml)? {
            vec![format!(
                "{} takes precedence; ignoring {}",
                selected.display(),
                toml.display()
            )]
        } else {
            vec![]
        };
        return Ok((selected, warnings));
    }
    if present(&toml)? {
        return Ok((toml, vec![]));
    }
    Err(invalid(format!(
        "{}: no isohopper.yml, isohopper.yaml, or isohopper.toml",
        path.display()
    )))
}

fn read_bounded(path: &Path) -> Result<(Vec<u8>, same_file::Handle), ConfigError> {
    let mut file = crate::regular::open(path)?;
    let before = file.metadata()?;
    if before.len() > MAX_BYTES as u64 {
        return Err(invalid(format!(
            "configuration exceeds {MAX_BYTES} byte limit"
        )));
    }
    let identity = crate::regular::identity(&file)?;
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut data)?;
    if data.len() > MAX_BYTES {
        return Err(invalid(format!(
            "configuration exceeds {MAX_BYTES} byte limit"
        )));
    }
    crate::regular::unchanged(path, &file, &before, &identity, data.len() as u64)?;
    Ok((data, identity))
}

/// Convert formats, retain exact original bytes in source.bak, then remove source.
/// Backups are never overwritten. Comments remain in the backup only.
pub fn convert(path: impl AsRef<Path>, to: &str, force: bool) -> Result<PathBuf, ConfigError> {
    let format = Format::from_name(to)?;
    let (source, _) = resolve(path.as_ref())?;
    let original = fs::symlink_metadata(&source)?;
    if !original.is_file() {
        return Err(invalid(
            "conversion source must be a regular file, not a symlink",
        ));
    }
    let from = Format::from_name(extension(&source)?)?;
    if from == format {
        return Err(invalid("configuration is already in the requested format"));
    }
    let (data, opened) = read_bounded(&source)?;
    let config = parse(&data, from.extension())?;
    let destination = source.with_extension(format.extension());
    let mut backup_name = source.as_os_str().to_os_string();
    backup_name.push(".bak");
    let backup = PathBuf::from(backup_name);
    check_destination(&destination, force)?;
    if present(&backup)? {
        return Err(invalid(format!(
            "backup already exists: {}",
            backup.display()
        )));
    }
    if format == Format::Yaml && present(&source.with_extension("yaml"))? {
        return Err(invalid("YAML alias already exists"));
    }
    let encoded = match format {
        Format::Toml => toml::to_string_pretty(&config).map_err(|e| invalid(e.to_string()))?,
        Format::Yaml => {
            let value = serde_json::to_value(&config).map_err(|e| invalid(e.to_string()))?;
            let mut output = String::new();
            emit_yaml(&value, 0, &mut output);
            output
        }
    };
    parse(encoded.as_bytes(), format.extension())?;
    write_output(&backup, &data, false)?;
    // Retain the backup on every later failure so recovery does not depend on cleanup.
    check_destination(&destination, force)?;
    write_output(&destination, encoded.as_bytes(), force)?;
    let (latest, latest_info) = read_bounded(&source)?;
    if latest != data || opened != latest_info {
        return Err(invalid(format!(
            "conversion written to {}, but source changed; source and backup retained",
            destination.display()
        )));
    }
    retire_source(&source, &data, &opened)?;
    Ok(destination)
}

fn retire_source(
    source: &Path,
    data: &[u8],
    identity: &same_file::Handle,
) -> Result<(), ConfigError> {
    let parent = source
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Capture the directory entry atomically before deciding whether to delete
    // it. Keeping this private directory on failure preserves a raced-in file.
    let recovery = tempfile::Builder::new()
        .prefix(".isohopper-retired-")
        .tempdir_in(parent)?
        .keep();
    let retired = recovery.join("source");
    if let Err(error) = fs::rename(source, &retired) {
        let _ = fs::remove_dir(&recovery);
        return Err(error.into());
    }
    let matches = read_bounded(&retired)
        .is_ok_and(|(observed, actual)| observed == data && &actual == identity);
    if !matches {
        return Err(invalid(format!(
            "source changed before removal; converted file and backup retained; unexpected source preserved at {}",
            retired.display()
        )));
    }
    fs::remove_file(&retired)?;
    fs::remove_dir(&recovery)?;
    Ok(())
}

fn check_destination(path: &Path, force: bool) -> Result<(), ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(info) => {
            if !info.is_file() {
                return Err(invalid("destination must be a regular file, not a symlink"));
            }
            if !force {
                return Err(invalid(format!(
                    "destination already exists (use force to replace): {}",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn write_output(path: &Path, data: &[u8], replace: bool) -> Result<(), ConfigError> {
    if !replace {
        // Exclusive creation works on FAT/exFAT, where a no-clobber rename's
        // hard-link fallback is unavailable. Source remains until all writes finish.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        // Retain incomplete output on failure. Unlinking its pathname could
        // delete an unrelated file swapped in after exclusive creation.
        file.write_all(data).and_then(|()| file.sync_all())?;
        return Ok(());
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|e| ConfigError::Io(e.error))?;
    Ok(())
}

// Config contains only JSON-compatible values. Quoted JSON scalars are valid
// YAML 1.2 and avoid implicit type changes in paths and user supplied strings.
fn emit_yaml(value: &Value, indent: usize, output: &mut String) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, value) in map {
                output.push_str(&" ".repeat(indent));
                output.push_str(&Value::String(key.clone()).to_string());
                output.push(':');
                emit_yaml_child(value, indent, output);
            }
        }
        Value::Array(values) if !values.is_empty() => {
            for value in values {
                output.push_str(&" ".repeat(indent));
                output.push('-');
                emit_yaml_child(value, indent, output);
            }
        }
        _ => {
            output.push_str(&" ".repeat(indent));
            output.push_str(&value.to_string());
            output.push('\n');
        }
    }
}
fn emit_yaml_child(value: &Value, indent: usize, output: &mut String) {
    if value.as_object().is_some_and(|v| !v.is_empty())
        || value.as_array().is_some_and(|v| !v.is_empty())
    {
        output.push('\n');
        emit_yaml(value, indent + 2, output);
    } else {
        output.push(' ');
        output.push_str(&value.to_string());
        output.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_replacement_is_preserved_during_conversion_retirement() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("config.yml");
        fs::write(&source, b"original").unwrap();
        let (data, identity) = read_bounded(&source).unwrap();
        fs::rename(&source, directory.path().join("moved-original.yml")).unwrap();
        fs::write(&source, b"replacement data").unwrap();
        assert!(retire_source(&source, &data, &identity).is_err());
        let recovery = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir())
            .expect("replacement retained in recovery directory");
        assert_eq!(
            fs::read(recovery.join("source")).unwrap(),
            b"replacement data"
        );
    }
}
