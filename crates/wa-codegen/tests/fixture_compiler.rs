//! Dependency selection regressions independent of the IQ emitter.
mod support;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn directory(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "whatspec-fixture-compiler-{label}-{}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("new regression directory");
    root
}

fn run_fixture(compiler: &support::FixtureCompiler, root: &Path) {
    let compiled = compiler.command(root, false).output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(Command::new(root.join("run")).status().unwrap().success());
}

#[test]
fn cargo_artifact_binding_ignores_invalid_and_other_build_rlibs() {
    let root = directory("artifacts");
    let deps = root
        .join("dependency-target")
        .join(env!("WHATSPEC_FIXTURE_TARGET"))
        .join("debug/deps");
    fs::create_dir_all(&deps).unwrap();
    let stale = deps.join("libanyhow-other-build.rlib");
    let invalid = deps.join("libanyhow-invalid.rlib");
    fs::write(root.join("stale.rs"), "pub fn stale_artifact_marker() {}\n").unwrap();
    let rustc = support::selected_rustc(std::env::var_os("RUSTC"));
    let compiled = Command::new(&rustc)
        .args([
            "--crate-name",
            "anyhow",
            "--crate-type",
            "rlib",
            "--target",
            env!("WHATSPEC_FIXTURE_TARGET"),
        ])
        .arg(root.join("stale.rs"))
        .arg("-o")
        .arg(&stale)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    fs::write(&invalid, b"not Rust metadata").unwrap();
    fs::write(
        root.join("main.rs"),
        "fn main() -> anyhow::Result<()> { Ok(()) }\n",
    )
    .unwrap();
    // Negative controls establish that these files cannot satisfy this fixture.
    for wrong in [&stale, &invalid] {
        let rejected = Command::new(&rustc)
            .args([
                "--edition=2024",
                "--target",
                env!("WHATSPEC_FIXTURE_TARGET"),
            ])
            .arg(root.join("main.rs"))
            .arg("--extern")
            .arg(format!("anyhow={}", wrong.display()))
            .arg("-o")
            .arg(root.join("wrong-run"))
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "wrong artifact unexpectedly compiled: {}",
            wrong.display()
        );
    }
    let compiler = support::FixtureCompiler::build(&root);
    let command = compiler.command(&root, false);
    let selected = command
        .get_args()
        .find(|arg| arg.to_string_lossy().starts_with("anyhow="))
        .unwrap();
    assert_ne!(selected, format!("anyhow={}", stale.display()).as_str());
    assert_ne!(selected, format!("anyhow={}", invalid.display()).as_str());
    run_fixture(&compiler, &root);
    // Both contaminated candidates still exist: success did not depend on cleaning
    // the directory. Also exercise Cargo's fresh-artifact report on the second build.
    assert!(stale.exists() && invalid.exists());
    run_fixture(&support::FixtureCompiler::build(&root), &root);
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn rustc_override_compiles_both_dependency_and_fixture() {
    use std::os::unix::fs::PermissionsExt;
    let root = directory("override");
    let rustc = support::selected_rustc(std::env::var_os("RUSTC"));
    let wrapper = root.join("rustc-wrapper");
    let log = root.join("rustc.log");
    let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
    fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\nexec {} \"$@\"\n",
            quote(log.to_str().unwrap()),
            quote(rustc.to_str().unwrap())
        ),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        root.join("main.rs"),
        "fn main() -> anyhow::Result<()> { Ok(()) }\n",
    )
    .unwrap();
    let selected = support::selected_rustc(Some(wrapper.clone().into_os_string()));
    assert_eq!(selected, wrapper.as_os_str());
    let compiler = support::FixtureCompiler::build_with_rustc(&root, selected);
    run_fixture(&compiler, &root);
    let calls = fs::read_to_string(log).unwrap();
    assert!(
        calls
            .lines()
            .any(|line| line.contains("--crate-name anyhow")),
        "{calls}"
    );
    assert!(
        calls.lines().any(|line| line.contains("main.rs")),
        "{calls}"
    );
    fs::remove_dir_all(root).unwrap();
}
