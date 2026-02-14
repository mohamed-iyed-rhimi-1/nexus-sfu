// Compile Cap'n Proto schemas at build time
fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("proto")
        .file("proto/signaling.capnp")
        .file("proto/metrics.capnp")
        .import_path("proto")
        .default_parent_module(vec!["protocol".into(), "capnp_codec".into()])
        .run()
        .expect("Cap'n Proto schema compilation failed");
}
