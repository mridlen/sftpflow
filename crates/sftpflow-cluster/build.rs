// ============================================================
// build.rs - protobuf code generation for sftpflow-cluster
// ============================================================
//
// Generates Rust types + tonic service stubs from
// src/proto/cluster.proto. The proto file is added in the next
// M12 task; this build script is guarded so the crate builds
// cleanly even before the proto file exists.

use std::path::Path;

fn main() {
    // ---- Proto file (added in next M12 task) ----
    let proto = Path::new("src/proto/cluster.proto");

    if !proto.exists() {
        // No proto file yet — skip codegen. Re-run if the file
        // appears later.
        println!("cargo:rerun-if-changed=src/proto/cluster.proto");
        return;
    }

    println!("cargo:rerun-if-changed=src/proto/cluster.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["src/proto/cluster.proto"], &["src/proto"])
        .expect("failed to compile cluster.proto");
}
