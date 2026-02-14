// Build script for Nexus SFU
//
// Compiles both Cap'n Proto and Protocol Buffer schemas at build time.
// Cap'n Proto schemas are used for real-time signaling (WebSocket/QUIC).
// Protocol Buffer schemas are used for gRPC API and metrics export.

use std::io::Result;

fn main() -> Result<()> {
    // Compile Cap'n Proto schemas
    // These are used for real-time signaling messages
    compile_capnp_schemas();

    // Compile Protocol Buffer schemas
    // These are used for gRPC API and metrics
    compile_protobuf_schemas()?;

    // Check for io_uring feature on Linux (Requirement 26.6)
    check_io_uring_feature();

    Ok(())
}

/// Emit a compile-time warning when io_uring feature is not enabled on Linux.
///
/// This helps ensure production Linux builds use the high-performance io_uring
/// receive path instead of falling back to recvmmsg.
///
/// # Requirements
/// - Requirement 26.6: Emit compile-time warning when io_uring not enabled on Linux
fn check_io_uring_feature() {
    // Only check on Linux
    #[cfg(target_os = "linux")]
    {
        // Check if io_uring feature is enabled
        #[cfg(not(feature = "io_uring"))]
        {
            println!(
                "cargo:warning=io_uring feature is not enabled on Linux. \
                 For optimal receive performance, enable the 'io_uring' feature. \
                 Without io_uring, the transport will fall back to recvmmsg."
            );
        }
    }
}

/// Compile Cap'n Proto schemas for signaling and metrics streaming
fn compile_capnp_schemas() {
    capnpc::CompilerCommand::new()
        .src_prefix("proto")
        .file("proto/signaling.capnp")
        .file("proto/metrics.capnp")
        .run()
        .expect("Cap'n Proto schema compilation failed");
}

/// Compile Protocol Buffer schemas for gRPC API
fn compile_protobuf_schemas() -> Result<()> {
    // Configure prost-build
    let mut config = prost_build::Config::new();

    // Add derive macros for generated types
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");

    // Generate code for api.proto and metrics.proto
    config.compile_protos(
        &["proto/api.proto", "proto/metrics.proto"],
        &["proto/"],
    )?;

    // Tell Cargo to rerun if proto files change
    println!("cargo:rerun-if-changed=proto/api.proto");
    println!("cargo:rerun-if-changed=proto/metrics.proto");

    Ok(())
}
