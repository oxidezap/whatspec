//! Independent cases read from verified Web module bodies, executed against
//! freshly emitted Rust. Requires the explicit #51 + #53 composition.
use std::{fs, process::Command};

fn qualify(label: &str, input: &str) {
    let mut ir: wa_ir::IqIr = serde_json::from_str(input).unwrap();
    ir.stanzas.retain(|op| {
        matches!(
            op.module_name.as_str(),
            "WASmaxOutGroupsSetSubjectRequest" | "WASmaxOutGroupsAcceptGroupAddRequest"
        )
    });
    assert_eq!(ir.stanzas.len(), 2);
    let dir = std::env::temp_dir().join(format!(
        "whatspec-independent-iq-{label}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let output = wa_codegen::generate_iq(&ir);
    assert_eq!(output, wa_codegen::generate_iq(&ir));
    fs::write(dir.join("generated.rs"), output).unwrap();
    // Reuse only the reference-emitter adapter, imports and tree constructors.
    // None of the other workstream's assertions or expectations are executed.
    let adapter = include_str!("fixtures/iq_runtime.rs")
        .split_once("\nfn main() {")
        .expect("explicit adapter/main boundary from #53")
        .0;
    fs::write(
        dir.join("main.rs"),
        format!(
            "{adapter}\n{}",
            include_str!("fixtures/independent_iq_cases.rs")
        ),
    )
    .unwrap();
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let anyhow = fs::read_dir(&deps)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("libanyhow-")
                && p.extension().is_some_and(|e| e == "rlib")
        })
        .unwrap();
    let compile = Command::new("rustc")
        .arg("--edition=2024")
        .arg("--test")
        .arg(dir.join("main.rs"))
        .arg("--extern")
        .arg(format!("anyhow={}", anyhow.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("-o")
        .arg(dir.join("run"))
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(dir.join("run")).output().unwrap();
    assert!(
        run.status.success(),
        "runtime cases failed; generated source retained at {}:\n{}\n{}",
        dir.display(),
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn current_snapshot_generated_code() {
    qualify(
        "current",
        include_str!("../../../tests/conformance/compiled/inputs/2.3000.1047483476.json"),
    );
}
#[test]
fn previous_snapshot_generated_code() {
    qualify(
        "previous",
        include_str!("../../../tests/conformance/compiled/inputs/2.3000.1045368834.json"),
    );
}
