//! Compile fixtures using a Cargo-reported artifact, never a directory heuristic.
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub struct FixtureCompiler {
    rustc: OsString,
    anyhow: PathBuf,
}

impl FixtureCompiler {
    pub fn build(directory: &Path) -> Self {
        Self::build_with_rustc(directory, selected_rustc(std::env::var_os("RUSTC")))
    }

    pub fn build_with_rustc(directory: &Path, rustc: OsString) -> Self {
        let target = directory.join("dependency-target");
        let output = Command::new(env!("CARGO"))
            .args([
                "build",
                "--offline",
                "--locked",
                "-p",
                "anyhow",
                "--message-format=json",
            ])
            .arg("--manifest-path")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .arg("--target")
            .arg(env!("WHATSPEC_FIXTURE_TARGET"))
            .env("RUSTC", &rustc)
            .output()
            .expect("run Cargo for fixture dependency");
        assert!(
            output.status.success(),
            "fixture dependency build failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut artifacts = Vec::new();
        for line in output
            .stdout
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
        {
            let message: serde_json::Value =
                serde_json::from_slice(line).expect("Cargo JSON message");
            if message["reason"] == "compiler-artifact" && message["target"]["name"] == "anyhow" {
                for file in message["filenames"].as_array().expect("artifact filenames") {
                    let path = PathBuf::from(file.as_str().expect("artifact path"));
                    if path.extension().is_some_and(|ext| ext == "rlib") {
                        artifacts.push(path);
                    }
                }
            }
        }
        assert_eq!(
            artifacts.len(),
            1,
            "expected exactly one Cargo-reported anyhow rlib: {artifacts:?}"
        );
        let anyhow = artifacts
            .pop()
            .unwrap()
            .canonicalize()
            .expect("reported rlib exists");
        assert!(
            anyhow.starts_with(target.canonicalize().unwrap()),
            "artifact must belong to the isolated build"
        );
        // Preserve the binding beside generated.rs for diagnosing a failed fixture.
        fs::write(directory.join("dependency-artifact.json"), &output.stdout).unwrap();
        Self { rustc, anyhow }
    }

    pub fn command(&self, directory: &Path, test: bool) -> Command {
        let mut command = Command::new(&self.rustc);
        command
            .arg("--edition=2024")
            .arg("--target")
            .arg(env!("WHATSPEC_FIXTURE_TARGET"))
            .arg(directory.join("main.rs"))
            .arg("--extern")
            .arg(format!("anyhow={}", self.anyhow.display()))
            .arg("-L")
            .arg(format!(
                "dependency={}",
                self.anyhow.parent().unwrap().display()
            ))
            .arg("-o")
            .arg(directory.join("run"));
        if test {
            command.arg("--test");
        }
        command
    }
}

pub fn selected_rustc(override_path: Option<OsString>) -> OsString {
    override_path.unwrap_or_else(|| env!("WHATSPEC_FIXTURE_RUSTC").into())
}
