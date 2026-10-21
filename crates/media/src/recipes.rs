// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{ImageEntry, MediaError, invalid, relative_path};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct LinuxRecipe {
    pub family: String,
    pub kernel_candidates: Vec<String>,
    pub initrd_candidates: Vec<String>,
    pub kernel_arguments: Vec<String>,
    pub status: String,
    pub source: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    family: String,
    filename_prefix: String,
    filename_markers: Vec<String>,
    label_prefixes: Vec<String>,
    kernel_candidates: Vec<String>,
    initrd_candidates: Vec<String>,
    arguments: Vec<String>,
    source: String,
}

/// Return an untested candidate only when both the label and filename match.
/// Paths stay structured data; no shell, GRUB script, or kernel is invoked.
pub fn select(image: &ImageEntry) -> Result<Option<LinuxRecipe>, MediaError> {
    relative_path(&image.relative_path)?;
    if !image
        .relative_path
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._+-".contains(&byte))
    {
        return Err(invalid(
            "recipe paths require ASCII letters, digits, / . _ + or -; rename paths containing whitespace or shell characters before booting",
        ));
    }
    if image.extension != "iso" || image.inspection_status != "iso9660-header" {
        return Ok(None);
    }
    let Some(label) = &image.iso_volume_label else {
        return Ok(None);
    };
    let label = label.to_ascii_lowercase();
    let filename = image
        .relative_path
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    static RULES: OnceLock<Result<Vec<Rule>, String>> = OnceLock::new();
    let rules = RULES
        .get_or_init(|| {
            serde_json::from_str(include_str!("recipes.json")).map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|error| invalid(format!("embedded recipes: {error}")))?;
    for rule in rules {
        if !filename.starts_with(&rule.filename_prefix)
            || !rule
                .label_prefixes
                .iter()
                .any(|prefix| label.starts_with(prefix))
            || (!rule.filename_markers.is_empty()
                && !rule
                    .filename_markers
                    .iter()
                    .any(|marker| filename.contains(marker)))
        {
            continue;
        }
        let absolute = format!("/{}", image.relative_path);
        return Ok(Some(LinuxRecipe {
            family: rule.family.clone(),
            kernel_candidates: rule.kernel_candidates.clone(),
            initrd_candidates: rule.initrd_candidates.clone(),
            kernel_arguments: rule
                .arguments
                .iter()
                .map(|value| value.replace("{image}", &absolute))
                .collect(),
            status: "untested".into(),
            source: rule.source.clone(),
        }));
    }
    Ok(None)
}
