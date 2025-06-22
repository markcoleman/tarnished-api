use vergen::EmitBuilder;
use std::process::Command;

fn main() {
    // Check if we're in a git repository
    let is_git_available = Command::new("git")
        .args(&["rev-parse", "--git-dir"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    // Generate build-time metadata based on git availability
    let result = if is_git_available {
        // We have git, include git metadata
        EmitBuilder::builder()
            .build_timestamp()
            .git_sha(false) // Short SHA
            .emit()
    } else {
        // No git, build without git metadata
        EmitBuilder::builder()
            .build_timestamp()
            .emit()
    };

    result.expect("Unable to generate build metadata");
}
