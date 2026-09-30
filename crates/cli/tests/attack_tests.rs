//! Attack tests for the `txwatch` CLI binary verifying resilient error handling
//! against malicious inputs, unreadable paths, and abnormal CLI parameters.

use std::{env, process::Command};

fn txwatch_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_txwatch"))
}

#[test]
fn test_attack_nonexistent_or_device_config_fails_gracefully() {
    let output = txwatch_bin()
        .args([
            "--config",
            "/nonexistent/path/to/attack_config.toml",
            "validate",
        ])
        .output()
        .expect("failed to execute txwatch");

    assert!(
        !output.status.success(),
        "CLI must fail on nonexistent config file"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The CLI now reports a missing config by name and points at the ways to
    // supply one, which is friendlier than a bare "No such file".
    assert!(
        stderr.contains("not found") || stderr.contains("No such file"),
        "Expected error message on unreadable file, got: {}",
        stderr
    );
}

#[test]
fn test_attack_directory_as_config_fails_gracefully() {
    let dir = env::temp_dir();
    let output = txwatch_bin()
        .args(["--config", dir.to_str().unwrap(), "validate"])
        .output()
        .expect("failed to execute txwatch");

    assert!(
        !output.status.success(),
        "CLI must reject directory provided as config file"
    );
}
