//! Inspect the extracted wasm surface over a local bundle set (dev tool).
//! Run: cargo run --release -p wa-wasm --example probe -- <bundles_dir>

fn main() -> anyhow::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".wa-cache/bundles".to_string());
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    let mut source = String::new();
    for p in &paths {
        source.push_str(&String::from_utf8_lossy(&std::fs::read(p)?));
        source.push_str("\n;\n");
    }
    eprintln!("loaded {} files, {} bytes", paths.len(), source.len());

    let t = std::time::Instant::now();
    let ir = wa_wasm::extract_wasm(&source, "probe");
    eprintln!("extracted in {:?}", t.elapsed());

    println!("binaries: {}", ir.binaries.len());
    for b in &ir.binaries {
        println!("  {:34} <- {}", b.name, b.modules.join(", "));
    }
    println!("resources (bx handles): {}", ir.resources.len());
    for r in &ir.resources {
        println!(
            "  {:>6}  hint=[{}]  {}",
            r.bx_id,
            r.wasm_hint.join(","),
            r.consumers.join(", ")
        );
    }
    let hinted = ir
        .resources
        .iter()
        .filter(|r| !r.wasm_hint.is_empty())
        .count();
    println!("hinted: {hinted} / {}", ir.resources.len());
    Ok(())
}
