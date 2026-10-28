// SPDX-License-Identifier: GPL-3.0-or-later
//! Interpretation is shared with host tests. The native query is restricted
//! to fixed files in the retained protected installation, never arbitrary paths.

pub(super) fn require_inline(hresult: i32, external: i32) -> Result<(), String> {
    if hresult != 0 {
        return Err(format!(
            "Installed file backing query failed: HRESULT {:#010x}",
            hresult as u32
        ));
    }
    match external {
        0 => Ok(()),
        1 => Err("Externally backed installed files are unsupported".into()),
        _ => Err("Installed file backing query returned an invalid BOOL".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_success_and_false_establish_inline_storage() {
        assert!(require_inline(0, 0).is_ok());
        for result in [1, -1, 0x80070001u32 as i32, 0x80070002u32 as i32] {
            for external in [0, 1, i32::MIN] {
                assert!(require_inline(result, external).is_err());
            }
        }
        for external in [1, 2, -1, i32::MIN] {
            assert!(require_inline(0, external).is_err());
        }
    }
}
