// SPDX-License-Identifier: GPL-3.0-or-later
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("isohopper-helper {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    eprintln!(
        "Physical-device access is unavailable: platform peer authentication and exclusive device locking require validation. Use isohopper image create for regular-file testing."
    );
    std::process::exit(3);
}
