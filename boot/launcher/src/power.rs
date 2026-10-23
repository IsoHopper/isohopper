// SPDX-License-Identifier: GPL-3.0-or-later
//! Boot-environment power preferences. No host OS operations are exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowerConfig {
    pub mask: u8,
}
impl PowerConfig {
    pub const ALL: Self = Self { mask: 7 };
    pub const NONE: Self = Self { mask: 0 };
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 8
            || &bytes[..5] != b"IHPW\x01"
            || bytes[5] & !7 != 0
            || bytes[6..] != [0, 0]
        {
            return None;
        }
        Some(Self { mask: bytes[5] })
    }
    pub fn allows(self, action: Action, firmware_setup_supported: bool) -> bool {
        self.mask & action.bit() != 0
            && (action != Action::FirmwareSetup || firmware_setup_supported)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Reboot,
    Shutdown,
    FirmwareSetup,
}
impl Action {
    pub const fn bit(self) -> u8 {
        match self {
            Self::Reboot => 1,
            Self::Shutdown => 2,
            Self::FirmwareSetup => 4,
        }
    }
}
#[derive(Default)]
pub struct Confirmation {
    pending: Option<Action>,
}
impl Confirmation {
    pub fn select(&mut self, action: Action, config: PowerConfig, supported: bool) -> bool {
        self.pending = config.allows(action, supported).then_some(action);
        self.pending.is_some()
    }
    pub fn answer(&mut self, key: char) -> Option<Action> {
        let action = self.pending.take();
        if key == 'y' || key == 'Y' {
            action
        } else {
            None
        }
    }
}
pub const fn firmware_indications(existing: u64) -> u64 {
    existing | 1
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_valid_config_is_accepted() {
        for mask in 0..=7 {
            assert_eq!(
                PowerConfig::decode(&[b'I', b'H', b'P', b'W', 1, mask, 0, 0]),
                Some(PowerConfig { mask })
            );
        }
        assert!(PowerConfig::decode(b"IHPW\x01\x08\x00\x00").is_none());
        assert!(PowerConfig::decode(b"IHPW\x01\x07\x00\x00x").is_none());
    }
    #[test]
    fn unsupported_and_disabled_actions_are_not_selectable() {
        assert!(!PowerConfig::ALL.allows(Action::FirmwareSetup, false));
        for action in [Action::Reboot, Action::Shutdown, Action::FirmwareSetup] {
            assert!(!PowerConfig::NONE.allows(action, true));
        }
    }
    #[test]
    fn confirmation_is_explicit_and_consumed_once() {
        let mut state = Confirmation::default();
        assert_eq!(state.answer('y'), None);
        assert!(state.select(Action::Shutdown, PowerConfig::ALL, true));
        assert_eq!(state.answer('\n'), None);
        assert_eq!(state.answer('y'), None);
        state.select(Action::Reboot, PowerConfig::ALL, true);
        assert_eq!(state.answer('y'), Some(Action::Reboot));
        assert_eq!(state.answer('y'), None);
    }
    #[test]
    fn firmware_indications_preserve_unrelated_bits() {
        assert_eq!(firmware_indications(0x400), 0x401);
    }
}
