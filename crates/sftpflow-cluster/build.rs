// ============================================================
// build.rs - protobuf code generation for sftpflow-cluster
// ============================================================
//
// Generates Rust types + tonic service stubs from
// src/proto/cluster.proto. Uses `protoc-bin-vendored` so that
// contributors do not need a system `protoc` install — keeping
// the build experience uniform across Linux / macOS / Windows.

use std::path::Path;

fn main() {
    let proto = Path::new("src/proto/cluster.proto");

    // Re-run if the proto file or its directory changes.
    println!("cargo:rerun-if-changed=src/proto/cluster.proto");
    println!("cargo:rerun-if-changed=src/proto");

    if !proto.exists() {
        // Defensive: skip codegen if someone deletes the proto
        // mid-development. The crate's lib.rs `tonic::include_proto!`
        // call would then fail with a clearer error pointing at the
        // missing file rather than a vague codegen panic.
        return;
    }

    // ---- Vendored protoc ----
    // protoc-bin-vendored ships per-target prebuilt protoc binaries.
    // Setting PROTOC redirects prost-build (called by tonic-build)
    // away from system PATH lookup.
    let protoc = protoc_bin_vendored::protoc_bin_path()
        .expect("protoc-bin-vendored: no prebuilt protoc for this target");

    // SAFETY: build scripts run single-threaded before any other
    // code in the crate executes, so mutating the process env here
    // cannot race with another thread reading it. The 2024 edition
    // marks std::env::set_var unsafe because of multi-threaded
    // misuse risk; that risk does not apply in build.rs.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["src/proto/cluster.proto"], &["src/proto"])
        .expect("failed to compile cluster.proto");
}
