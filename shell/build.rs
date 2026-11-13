//! Builds the Leptos UI with trunk into `$OUT_DIR/dist` and writes
//! `$OUT_DIR/assets.rs`, the list of built files that main.rs embeds.

use std::env;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
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
    let inputs = [
        "src",
        "index.html",
        "style.css",
        "app.js",
        "fonts",
        "Cargo.toml",
        "Trunk.toml",
    ];
    for path in inputs {
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

    let dist = out.join("dist");
    let mut files = Vec::new();
    collect(&dist, &mut files);
    files.sort();
    let mut code = String::from("&[\n");
    for file in &files {
        let url = format!(
            "/{}",
            file.strip_prefix(&dist).expect("under dist").display()
        );
        // Debug formatting of a str is a valid Rust string literal.
        writeln!(
            code,
            "    ({url:?}, include_bytes!({:?})),",
            file.display().to_string()
        )
        .expect("write to String");
    }
    code.push(']');
    fs::write(out.join("assets.rs"), code).expect("write assets.rs");
}

/// Lists files under `dir`, skipping trunk's dot files (`.stage`, `.trunk-lock`).
fn collect(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read dist dir") {
        let path = entry.expect("read dist entry").path();
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            collect(&path, files);
        } else {
            files.push(path);
        }
    }
}
