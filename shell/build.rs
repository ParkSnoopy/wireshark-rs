//! Builds the Leptos UI with trunk into `$OUT_DIR/dist`. main.rs embeds the result.

use std::env;
use std::path::PathBuf;
use std::process::Command;

/// Variables cargo sets for build scripts. They describe the host build, not the wasm build.
const BUILD_SCRIPT_VARS: [&str; 11] = [
    "TARGET",
    "HOST",
    "PROFILE",
    "OPT_LEVEL",
    "DEBUG",
    "NUM_JOBS",
    "OUT_DIR",
    "RUSTC",
    "RUSTDOC",
    "RUSTC_LINKER",
    "RUSTC_WORKSPACE_WRAPPER",
];

fn main() {
    let ui = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo")).join("../ui");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("set by cargo"));
    for path in ["src", "index.html", "Cargo.toml", "Trunk.toml"] {
        println!("cargo::rerun-if-changed={}", ui.join(path).display());
    }
    println!("cargo::rerun-if-changed=../Cargo.lock");

    let mut trunk = Command::new("trunk");
    for (key, _) in env::vars_os() {
        let key = key.to_string_lossy();
        let cargo_var = key.starts_with("CARGO_") && key != "CARGO_HOME";
        if cargo_var || key.starts_with("__CARGO") || BUILD_SCRIPT_VARS.contains(&&*key) {
            trunk.env_remove(&*key);
        }
    }
    trunk
        .current_dir(&ui)
        .arg("build")
        .arg("--dist")
        .arg(out.join("dist"))
        // Own target dir: the outer cargo holds the lock on the main one, so sharing it deadlocks.
        .env("CARGO_TARGET_DIR", out.join("target"));
    if env::var("PROFILE").as_deref() == Ok("release") {
        trunk.arg("--release");
    }

    let output = trunk.output().unwrap_or_else(|e| {
        panic!("cannot run trunk (install it with `cargo install trunk`): {e}")
    });
    if !output.status.success() {
        panic!(
            "trunk build failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
