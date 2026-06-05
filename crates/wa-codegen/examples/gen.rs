//! Scan a bundle for IQ stanzas and generate Rust `IqSpec` modules.
//! Run: cargo run -p wa-codegen --example gen -- <bundle.js> <outdir>
//!      cargo run -p wa-codegen --example gen -- <bundle.js> --ir   (dump IqIr JSON)

fn main() -> anyhow::Result<()> {
    let bundle = std::env::args()
        .nth(1)
        .expect("usage: gen <bundle.js> <outdir|--ir>");
    let target = std::env::args()
        .nth(2)
        .expect("usage: gen <bundle.js> <outdir|--ir>");
    let source = std::fs::read_to_string(&bundle)?;

    let scan = wa_scan::scan_iq_stanzas(&source);
    let ir = wa_ir::IqIr {
        wa_version: "0.0.0".to_string(),
        stanzas: scan.stanzas,
        unparseable: scan.unparseable,
    };

    if target == "--ir" {
        println!("{}", serde_json::to_string(&ir)?);
        return Ok(());
    }

    std::fs::create_dir_all(&target)?;
    let modules = wa_codegen::generate_rust_modules(&ir);
    for m in &modules {
        std::fs::write(format!("{target}/{}", m.filename), &m.code)?;
    }
    eprintln!("wrote {} modules to {target}", modules.len());
    Ok(())
}
