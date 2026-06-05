//! Scan a real bundle file for IQ stanzas.
//! Run: cargo run -p wa-scan --example scan -- <bundle.js> [--list]

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .expect("usage: scan <bundle.js> [--list]");
    let list = std::env::args().any(|a| a == "--list");
    let code = std::fs::read_to_string(&path)?;

    let res = wa_scan::scan_iq_stanzas(&code);
    println!("file: {path}");
    println!("stanzas: {}", res.stanzas.len());

    let with_children = res
        .stanzas
        .iter()
        .filter(|s| !s.request.children.is_empty())
        .count();
    let with_fields = res
        .stanzas
        .iter()
        .filter(|s| !s.response.fields.is_empty())
        .count();
    println!("  with request children: {with_children}");
    println!("  with response fields:  {with_fields}");

    if list {
        for s in &res.stanzas {
            println!(
                "  [{}:{:?}] {} ({} children, {} resp fields, parser={})",
                s.namespace,
                s.iq_type,
                s.module_name,
                s.request.children.len(),
                s.response.fields.len(),
                s.parser_name,
            );
        }
    }
    Ok(())
}
