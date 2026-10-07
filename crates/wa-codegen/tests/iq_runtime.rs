//! Compile and execute the emitted pilot parsers against a small in-memory node
//! adapter. This checks generated Rust, not a binary codec or external client API.
use std::{fs, process::Command};

#[test]
fn generated_pilot_requests_and_responses_execute() {
    let mut ir: wa_ir::IqIr =
        serde_json::from_str(include_str!("../../../generated/iq/index.json")).unwrap();
    ir.stanzas.retain(|op| {
        matches!(
            op.module_name.as_str(),
            "WASmaxOutGroupsSetSubjectRequest" | "WASmaxOutGroupsAcceptGroupAddRequest"
        )
    });
    assert_eq!(ir.stanzas.len(), 2);
    let dir = std::env::temp_dir().join(format!("whatspec-iq-runtime-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("generated.rs"), wa_codegen::generate_iq(&ir)).unwrap();
    fs::write(dir.join("main.rs"), include_str!("fixtures/iq_runtime.rs")).unwrap();
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
                && p.extension().is_some_and(|ext| ext == "rlib")
        })
        .expect("anyhow dev dependency rlib");
    let compile = Command::new("rustc")
        .arg("--edition=2024")
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
        "generated pilot compilation failed:\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(dir.join("run")).output().unwrap();
    assert!(
        run.status.success(),
        "generated pilot execution failed:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    fs::remove_dir_all(dir).unwrap();
}
