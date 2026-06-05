//! Extract __d() modules from a real bundle file and sanity-check offsets.
//! Run: cargo run -p wa-transform --example extract -- <bundle.js>

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: extract <bundle.js>");
    let code = std::fs::read_to_string(&path)?;
    let mods = wa_transform::extract_module_definitions(&code);

    println!("file: {path}");
    println!("bytes: {}", code.len());
    println!("modules: {}", mods.len());

    let mut offset_ok = 0usize;
    for m in &mods {
        let call = &code[m.start..m.end];
        let factory = &code[m.factory_start..m.factory_end];
        if call.starts_with("__d(") && (factory.starts_with("function") || factory.starts_with('('))
        {
            offset_ok += 1;
        }
    }
    println!("offset-valid modules: {offset_ok}/{}", mods.len());

    println!("\nfirst 8 modules:");
    for m in mods.iter().take(8) {
        println!("  {} (deps: {})", m.name, m.deps.len());
    }
    Ok(())
}
