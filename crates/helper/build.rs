// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        // Windows release builds use MSVC. Normal invocation never requests
        // elevation; Studio's explicit runas operation owns that decision.
        println!("cargo:rustc-link-arg-bin=isohopper-helper=/MANIFEST:EMBED,ID=1");
        println!(
            "cargo:rustc-link-arg-bin=isohopper-helper=/MANIFESTUAC:level='asInvoker' uiAccess='false'"
        );
    }
}
