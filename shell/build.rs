//! Builds the Leptos UI with trunk into `$OUT_DIR/dist` and writes
//! `$OUT_DIR/assets.rs`, the list of built files that main.rs embeds.

use std::env;
use std::fmt;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

/// Why the build failed. Its `Debug` output is the plain message, because
/// cargo shows the `Debug` form of an error that `main` returns.
struct BuildError(String);

impl fmt::Debug for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Wraps an error with what was being done when it happened.
fn context<E: fmt::Display>(what: &str) -> impl FnOnce(E) -> BuildError {
    move |e| BuildError(format!("{what}: {e}"))
}

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

fn main() -> Result<(), BuildError> {
    let var = |name: &str| {
        env::var_os(name)
            .map(PathBuf::from)
            .ok_or_else(|| BuildError(format!("cargo did not set {name}")))
    };
    let ui = var("CARGO_MANIFEST_DIR")?.join("../ui");
    let out = var("OUT_DIR")?;
    let inputs = [
        "src",
        "index.html",
        "style.css",
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

    let output = trunk.output().map_err(context(
        "cannot run trunk (install it with `cargo install trunk`)",
    ))?;
    if !output.status.success() {
        return Err(BuildError(format!(
            "trunk build failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let dist = out.join("dist");
    let mut files = Vec::new();
    collect(&dist, &mut files)?;
    files.sort();
    let mut code = String::from("&[\n");
    for file in &files {
        let url = file
            .strip_prefix(&dist)
            .map_err(context("file outside dist"))?;
        // Debug formatting of a str is a valid Rust string literal.
        let line = format!(
            "    ({:?}, include_bytes!({:?})),\n",
            format!("/{}", url.display()),
            file.display().to_string()
        );
        code.push_str(&line);
    }
    code.push(']');
    fs::write(out.join("assets.rs"), code).map_err(context("cannot write assets.rs"))
}

/// Lists files under `dir`, skipping trunk's dot files (`.stage`, `.trunk-lock`).
fn collect(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), BuildError> {
    for entry in fs::read_dir(dir).map_err(context("cannot read the dist dir"))? {
        let path = entry.map_err(context("cannot read the dist dir"))?.path();
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            collect(&path, files)?;
        } else {
            files.push(path);
        }
    }
    Ok(())
}
