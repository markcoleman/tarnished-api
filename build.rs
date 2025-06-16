use vergen::EmitBuilder;

fn main() {
    // Generate build-time metadata
    EmitBuilder::builder()
        .build_timestamp()
        .git_sha(false) // Short SHA
        .emit()
        .expect("Unable to generate vergen instructions");
}
