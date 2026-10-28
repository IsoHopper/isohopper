// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    // Windows bounds its command line, and we additionally cap argument count
    // before collecting. Non-Unicode or extra arguments cannot select a mode.
    let args: Result<Vec<_>, _> = std::env::args_os()
        .skip(1)
        .take(8)
        .map(|arg| arg.into_string())
        .collect();
    let Ok(args) = args else {
        std::process::exit(3);
    };
    if args == ["--version"] {
        println!("isohopper-helper {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.first().is_some_and(|arg| arg == "--prepare-broker-v1") {
        let args = match isohopper_helper::prepare_protocol::PrepareArgs::parse(&args) {
            Ok(args) => args,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(3);
            }
        };
        #[cfg(windows)]
        match isohopper_helper::windows_prepare::serve(args) {
            Ok(()) => return,
            Err(error) => {
                eprintln!("Preparation helper failed: {error}");
                std::process::exit(3);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = args;
            eprintln!("Elevated preparation helper is Windows-only");
            std::process::exit(3);
        }
    }
    if args.first().is_some_and(|arg| arg == "--probe-broker-v1") {
        let args = match isohopper_helper::broker_probe::ProbeArgs::parse(&args) {
            Ok(args) => args,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(3);
            }
        };
        #[cfg(windows)]
        match isohopper_helper::windows_probe::serve(args) {
            Ok(()) => return,
            Err(error) => {
                eprintln!("Read-only helper probe failed: {error}");
                std::process::exit(3);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = args;
            eprintln!("Read-only elevated helper probe is Windows-only");
            std::process::exit(3);
        }
    }
    eprintln!(
        "Use installed IsoHopper Studio for Windows preparation. This helper does not accept direct device paths or standalone write commands."
    );
    std::process::exit(3);
}
