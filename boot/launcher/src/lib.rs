// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
#![no_std]
pub mod power;

/// Evidence must come from a verifier, never an image's own metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    Verified,
    Unsigned,
    Unknown,
    Revoked,
    Tampered,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Enforce,
    Prompt,
    Off,
}
/// Prompt means refuse until a separate, explicit trust operation is completed.
pub fn can_boot(policy: Policy, trust: Trust) -> bool {
    match trust {
        Trust::Verified => true,
        Trust::Unsigned => policy == Policy::Off,
        Trust::Unknown | Trust::Revoked | Trust::Tampered => false,
    }
}
pub fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with('/')
        && !path
            .chars()
            .any(|c| c.is_control() || c == ':' || c == '\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    pub label: &'a str,
    pub path: &'a str,
    pub trust: Trust,
}
pub struct Menu<'a> {
    entries: &'a [Entry<'a>],
    index: usize,
}
impl<'a> Menu<'a> {
    pub const fn new(entries: &'a [Entry<'a>]) -> Self {
        Self { entries, index: 0 }
    }
    pub fn selected(&self) -> Option<&Entry<'a>> {
        self.entries.get(self.index)
    }
    pub fn next(&mut self) {
        if !self.entries.is_empty() {
            self.index = (self.index + 1) % self.entries.len();
        }
    }
    pub fn previous(&mut self) {
        if !self.entries.is_empty() {
            self.index = if self.index == 0 {
                self.entries.len() - 1
            } else {
                self.index - 1
            };
        }
    }
}
