// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::{
    engine::{self, Payloads, Plan},
    virtualdisk,
};
use std::{env, fs, path::PathBuf};

/// The caller must supply decoded boot.img, core.img and ventoy.disk.img from
/// the exact external release. Nothing is downloaded or executed by this test.
/// Optional ISOHOPPER_ENGINE_OUTPUT preserves the new image for firmware tests;
/// an existing output always fails. This test itself does not boot an OS.
#[test]
#[ignore = "requires explicitly supplied pinned decoded engine payloads"]
fn pinned_engine_payload_builds_and_verifies_complete_image() {
    let root = PathBuf::from(
        env::var_os("ISOHOPPER_ENGINE_PAYLOAD_DIR")
            .expect("set ISOHOPPER_ENGINE_PAYLOAD_DIR to decoded external fixture directory"),
    );
    let boot = fs::read(root.join("boot.img")).unwrap();
    let core = fs::read(root.join("core.img")).unwrap();
    let firmware = fs::read(root.join("ventoy.disk.img")).unwrap();
    let payloads = Payloads::verify(&boot, &core, &firmware).unwrap();
    for index in 0..3 {
        let mut altered = [&boot, &core, &firmware][index].clone();
        let last = altered.len() - 1;
        altered[last] ^= 1;
        let sources = match index {
            0 => (&altered, &core, &firmware),
            1 => (&boot, &altered, &firmware),
            _ => (&boot, &core, &altered),
        };
        assert!(Payloads::verify(sources.0, sources.1, sources.2).is_err());
    }
    let temp = tempfile::tempdir().unwrap();
    let path = env::var_os("ISOHOPPER_ENGINE_OUTPUT")
        .map_or_else(|| temp.path().join("engine.img"), PathBuf::from);
    let plan = Plan::new(2 << 30, 512).unwrap();
    let image = engine::create(&path, &plan, &payloads).unwrap();
    engine::verify(&path, &image).unwrap();
    assert!(virtualdisk::verify(&path).is_err());
    assert_eq!(fs::metadata(path).unwrap().len(), 2 << 30);
    println!(
        "engine={} GPT512 metadata+payload readback=verified data=unformatted boot=not-tested",
        engine::VERSION
    );
}
