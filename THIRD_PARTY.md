# Third-party components

IsoHopper's original code is GPL-3.0-or-later. Dependencies and imported boot components retain their own licenses.

## External boot engine

The experimental image builder accepts the **Ventoy 1.1.18 Linux archive** from the [official release](https://github.com/ventoy/Ventoy/releases/tag/v1.1.18). Its SHA-256 is:

```text
d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54
```

No Ventoy binary payloads are committed here or bundled in IsoHopper packages. Studio can download the pinned archive on request, or the user can supply an offline copy. Download verifies the exact size and SHA-256 before selection. Import validates its hash, fixed member paths, decoded sizes and payload hashes before building an image; it does not run the upstream installer.

Ventoy and its dependencies have separate component licenses. Consult the [matching source and license directory](https://github.com/ventoy/Ventoy/tree/6116894ab8abdf3ef8d43411a6732d34ee19214e/License) and [upstream build instructions](https://github.com/ventoy/Ventoy/blob/6116894ab8abdf3ef8d43411a6732d34ee19214e/DOC/BuildVentoyFromSource.txt). IsoHopper does not relicense those components or imply upstream endorsement.

## Application dependencies

Exact Rust and JavaScript dependency versions are recorded in the Cargo and npm lockfiles. Archive decoding uses flate2 (MIT/Apache-2.0), tar (MIT/Apache-2.0) and lzma-rust2 (Apache-2.0).
