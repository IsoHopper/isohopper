use super::*;
use crate::imports::source_catalog::PreparedSource;
use std::fs;

fn source(catalogue: &Mutex<SourceCatalog>, root: &Path, relative: &str) -> ImportedImage {
    let file = isohopper_media::open_image(root, relative).unwrap();
    catalogue
        .lock()
        .unwrap()
        .insert_batch(vec![PreparedSource::new(file, relative).unwrap()])
        .unwrap()
        .remove(0)
}
fn image_path(root: &Path, relative: &str) -> ImagePath {
    ImagePath {
        root: root.to_path_buf(),
        relative_path: relative.into(),
    }
}

#[test]
fn restart_restores_nested_images_with_fresh_ids_from_exact_saved_bytes() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    fs::create_dir(library.path().join("Linux")).unwrap();
    fs::write(library.path().join("Linux/boot.iso"), b"abc").unwrap();
    let old_catalogue = Mutex::new(SourceCatalog::default());
    let original = source(&old_catalogue, library.path(), "Linux/boot.iso");
    let mut first = Session::load(data.path().to_path_buf()).unwrap();
    first
        .remember(
            &[image_path(library.path(), "Linux/boot.iso")],
            std::slice::from_ref(&original),
        )
        .unwrap();
    let saved = fs::read_to_string(data.path().join(STATE_FILE)).unwrap();
    assert!(!saved.contains(&original.source_id));
    assert!(!saved.contains("source_id"));
    drop(first);
    drop(old_catalogue);
    let mut second = Session::load(data.path().to_path_buf()).unwrap();
    let fresh_catalogue = Mutex::new(SourceCatalog::default());
    let restored = second
        .restore_into(&fresh_catalogue, |_| panic!("no saved archive"))
        .unwrap();
    assert_eq!(restored.images.len(), 1);
    assert!(restored.warnings.is_empty());
    assert_ne!(restored.images[0].source_id, original.source_id);
    assert_eq!(restored.images[0].relative_path, "Linux/boot.iso");
    assert_eq!(
        restored.images[0].verification.digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(
        !serde_json::to_string(&restored)
            .unwrap()
            .contains(&library.path().display().to_string())
    );
}

#[test]
fn missing_or_changed_images_are_warnings_never_newly_trusted_sources() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    let catalogue = Mutex::new(SourceCatalog::default());
    let mut first = Session::load(data.path().to_path_buf()).unwrap();
    for relative in ["changed.iso", "missing.iso", "good.iso"] {
        fs::write(library.path().join(relative), b"abc").unwrap();
        first
            .remember(
                &[image_path(library.path(), relative)],
                &[source(&catalogue, library.path(), relative)],
            )
            .unwrap();
    }
    drop(catalogue);
    drop(first);
    fs::write(library.path().join("changed.iso"), b"xyz").unwrap();
    fs::remove_file(library.path().join("missing.iso")).unwrap();
    let mut second = Session::load(data.path().to_path_buf()).unwrap();
    let restored_catalogue = Mutex::new(SourceCatalog::default());
    let report = second
        .restore_into(&restored_catalogue, |_| Ok(()))
        .unwrap();
    assert_eq!(report.images.len(), 1);
    assert_eq!(report.images[0].relative_path, "good.iso");
    assert_eq!(report.warnings.len(), 2);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("changed.iso"))
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("missing.iso"))
    );
    assert_eq!(restored_catalogue.lock().unwrap().list_sources().len(), 1);
}

#[test]
fn explicit_removal_is_persisted_but_plain_catalogue_release_keeps_selection() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    let catalogue = Mutex::new(SourceCatalog::default());
    let mut saved = Session::load(data.path().to_path_buf()).unwrap();
    for relative in ["removed.iso", "released.iso"] {
        fs::write(library.path().join(relative), b"abc").unwrap();
        let image = source(&catalogue, library.path(), relative);
        saved
            .remember(
                &[image_path(library.path(), relative)],
                std::slice::from_ref(&image),
            )
            .unwrap();
        if relative == "removed.iso" {
            saved
                .forget(std::slice::from_ref(&image.source_id))
                .unwrap();
        }
        catalogue
            .lock()
            .unwrap()
            .release_sources(&[image.source_id])
            .unwrap();
    }
    let mut restarted = Session::load(data.path().to_path_buf()).unwrap();
    let report = restarted
        .restore_into(&Mutex::new(SourceCatalog::default()), |_| Ok(()))
        .unwrap();
    assert_eq!(report.images.len(), 1);
    assert_eq!(report.images[0].relative_path, "released.iso");
}

#[test]
fn invalid_and_oversized_saved_state_fail_without_opening_sources() {
    let data = tempfile::tempdir().unwrap();
    fs::write(
        data.path().join(STATE_FILE),
        vec![b' '; MAX_STATE_BYTES as usize + 1],
    )
    .unwrap();
    assert!(Session::load(data.path().to_path_buf()).is_err());
    fs::write(
        data.path().join(STATE_FILE),
        br#"{"version":99,"images":[],"archive":null}"#,
    )
    .unwrap();
    assert!(Session::load(data.path().to_path_buf()).is_err());
    fs::write(data.path().join(STATE_FILE), br#"{"version":1,"images":[{"root":"/tmp","relative_path":"../escape.iso","bytes":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}],"archive":null}"#).unwrap();
    assert!(Session::load(data.path().to_path_buf()).is_err());
}

#[test]
fn archive_path_and_pin_survive_restart_and_failed_restore_is_visible() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    let archive = library.path().join("engine.tar.gz");
    fs::write(&archive, b"fixture").unwrap();
    let mut first = Session::load(data.path().to_path_buf()).unwrap();
    first.remember_archive(&archive).unwrap();
    let mut second = Session::load(data.path().to_path_buf()).unwrap();
    let mut restored = false;
    let report = second
        .restore_into(&Mutex::new(SourceCatalog::default()), |path| {
            assert_eq!(path, fs::canonicalize(&archive).unwrap());
            restored = true;
            Err("archive failed verification".into())
        })
        .unwrap();
    assert!(restored);
    assert_eq!(report.warnings.len(), 1);
    assert!(report.warnings[0].contains("engine archive"));
}

#[cfg(unix)]
#[test]
fn state_and_source_symlinks_are_never_followed() {
    use std::os::unix::fs::symlink;
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    fs::write(library.path().join("real.iso"), b"abc").unwrap();
    let catalogue = Mutex::new(SourceCatalog::default());
    let image = source(&catalogue, library.path(), "real.iso");
    let mut saved = Session::load(data.path().to_path_buf()).unwrap();
    saved
        .remember(&[image_path(library.path(), "real.iso")], &[image])
        .unwrap();
    fs::rename(
        library.path().join("real.iso"),
        library.path().join("moved.iso"),
    )
    .unwrap();
    symlink(
        library.path().join("moved.iso"),
        library.path().join("real.iso"),
    )
    .unwrap();
    let mut restarted = Session::load(data.path().to_path_buf()).unwrap();
    let report = restarted
        .restore_into(&Mutex::new(SourceCatalog::default()), |_| Ok(()))
        .unwrap();
    assert!(report.images.is_empty());
    assert_eq!(report.warnings.len(), 1);
    let untouched = library.path().join("untouched.json");
    fs::write(&untouched, b"leave this file alone").unwrap();
    fs::remove_file(data.path().join(STATE_FILE)).unwrap();
    symlink(&untouched, data.path().join(STATE_FILE)).unwrap();
    assert!(Session::load(data.path().to_path_buf()).is_err());
    assert!(
        saved
            .remember_archive(&library.path().join("moved.iso"))
            .is_err()
    );
    assert_eq!(fs::read(untouched).unwrap(), b"leave this file alone");
}

#[test]
fn renderer_reload_keeps_current_ids_without_reopening_saved_paths() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    let image = library.path().join("boot.iso");
    fs::write(&image, b"abc").unwrap();
    let original = Mutex::new(SourceCatalog::default());
    let mut saved = Session::load(data.path().to_path_buf()).unwrap();
    saved
        .remember(
            &[image_path(library.path(), "boot.iso")],
            &[source(&original, library.path(), "boot.iso")],
        )
        .unwrap();
    let current = Mutex::new(SourceCatalog::default());
    let state = Mutex::new(None);
    let first = initialize_into(&state, &current, data.path().to_path_buf(), |_| Ok(())).unwrap();
    fs::rename(image, library.path().join("renamed.iso")).unwrap();
    let second = initialize_into(&state, &current, data.path().to_path_buf(), |_| {
        panic!("archive reopened on renderer reload")
    })
    .unwrap();
    assert_eq!(first.images.len(), 1);
    assert_eq!(second.images.len(), 1);
    assert_eq!(first.images[0].source_id, second.images[0].source_id);
    assert!(second.warnings.is_empty());
}

#[test]
fn releasing_duplicate_import_keeps_the_original_saved_selection() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    fs::write(library.path().join("boot.iso"), b"abc").unwrap();
    let catalogue = Mutex::new(SourceCatalog::default());
    let mut saved = Session::load(data.path().to_path_buf()).unwrap();
    let first = source(&catalogue, library.path(), "boot.iso");
    let duplicate = source(&catalogue, library.path(), "boot.iso");
    for image in [&first, &duplicate] {
        saved
            .remember(
                &[image_path(library.path(), "boot.iso")],
                std::slice::from_ref(image),
            )
            .unwrap();
    }
    saved
        .forget(std::slice::from_ref(&duplicate.source_id))
        .unwrap();
    let mut restarted = Session::load(data.path().to_path_buf()).unwrap();
    let report = restarted
        .restore_into(&Mutex::new(SourceCatalog::default()), |_| Ok(()))
        .unwrap();
    assert_eq!(report.images.len(), 1);
    saved
        .forget(std::slice::from_ref(&first.source_id))
        .unwrap();
    assert!(
        Session::load(data.path().to_path_buf())
            .unwrap()
            .saved
            .images
            .is_empty()
    );
}

#[test]
fn sealing_then_reimporting_and_removing_does_not_keep_stale_aliases() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    fs::write(library.path().join("boot.iso"), b"abc").unwrap();
    let catalogue = Mutex::new(SourceCatalog::default());
    let mut saved = Session::load(data.path().to_path_buf()).unwrap();
    let original = source(&catalogue, library.path(), "boot.iso");
    saved
        .remember(
            &[image_path(library.path(), "boot.iso")],
            std::slice::from_ref(&original),
        )
        .unwrap();
    saved.release_handles(std::slice::from_ref(&original.source_id));
    catalogue
        .lock()
        .unwrap()
        .release_sources(&[original.source_id])
        .unwrap();
    assert_eq!(
        Session::load(data.path().to_path_buf())
            .unwrap()
            .saved
            .images
            .len(),
        1
    );
    let again = source(&catalogue, library.path(), "boot.iso");
    saved
        .remember(
            &[image_path(library.path(), "boot.iso")],
            std::slice::from_ref(&again),
        )
        .unwrap();
    saved.forget(&[again.source_id]).unwrap();
    assert!(
        Session::load(data.path().to_path_buf())
            .unwrap()
            .saved
            .images
            .is_empty()
    );
}

#[test]
fn unavailable_saved_images_are_pruned_so_a_full_old_library_cannot_block_imports() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    let mut initial = Session::load(data.path().to_path_buf()).unwrap();
    let mut saved = Saved::default();
    for index in 0..MAX_SOURCES {
        saved.images.push(SavedImage {
            root: library.path().to_path_buf(),
            relative_path: format!("missing-{index}.iso"),
            bytes: 3,
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        });
    }
    initial.save(saved).unwrap();
    let mut restarted = Session::load(data.path().to_path_buf()).unwrap();
    let catalogue = Mutex::new(SourceCatalog::default());
    let report = restarted.restore_into(&catalogue, |_| Ok(())).unwrap();
    assert_eq!(report.warnings.len(), MAX_SOURCES);
    fs::write(library.path().join("new.iso"), b"abc").unwrap();
    restarted
        .remember(
            &[image_path(library.path(), "new.iso")],
            &[source(&catalogue, library.path(), "new.iso")],
        )
        .unwrap();
    assert_eq!(
        Session::load(data.path().to_path_buf())
            .unwrap()
            .saved
            .images
            .len(),
        1
    );
}

#[test]
fn failed_pruning_keeps_saved_records_and_rolls_back_restored_handles() {
    let data = tempfile::tempdir().unwrap();
    let library = tempfile::tempdir().unwrap();
    fs::write(library.path().join("good.iso"), b"abc").unwrap();
    let catalogue = Mutex::new(SourceCatalog::default());
    let mut initial = Session::load(data.path().to_path_buf()).unwrap();
    let good = source(&catalogue, library.path(), "good.iso");
    initial
        .remember(&[image_path(library.path(), "good.iso")], &[good])
        .unwrap();
    let mut next = initial.saved.clone();
    let mut missing = next.images[0].clone();
    missing.relative_path = "missing.iso".into();
    next.images.push(missing);
    initial.save(next).unwrap();
    let mut restarted = Session::load(data.path().to_path_buf()).unwrap();
    let original_json = fs::read(data.path().join(STATE_FILE)).unwrap();
    fs::rename(
        data.path().join(STATE_FILE),
        data.path().join("before.json"),
    )
    .unwrap();
    fs::create_dir(data.path().join(STATE_FILE)).unwrap();
    let restored = Mutex::new(SourceCatalog::default());
    assert!(restarted.restore_into(&restored, |_| Ok(())).is_err());
    assert!(restored.lock().unwrap().list_sources().is_empty());
    assert_eq!(restarted.saved.images.len(), 2);
    assert_eq!(
        fs::read(data.path().join("before.json")).unwrap(),
        original_json
    );
}
