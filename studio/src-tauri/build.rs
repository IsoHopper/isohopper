// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        use sha2::{Digest, Sha256};
        let target = std::env::var("TARGET").expect("missing target triple");
        let path = std::path::PathBuf::from(format!("binaries/isohopper-helper-{target}.exe"));
        println!("cargo:rerun-if-changed={}", path.display());
        let mut file = std::fs::File::open(&path)
            .expect("stage the matching Windows helper before building Studio");
        let mut hash = Sha256::new();
        std::io::copy(&mut file, &mut hash).expect("hash staged Windows helper");
        println!(
            "cargo:rustc-env=ISOHOPPER_HELPER_SHA256={:x}",
            hash.finalize()
        );
    }
    tauri_build::build()
}
