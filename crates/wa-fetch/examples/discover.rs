//! Fetcher spike: hit web.whatsapp.com browserless with ureq and report what we
//! can discover. Measures whether plain ureq is enough or if anti-bot escalation
//! is needed.
//!
//! Run: cargo run -p wa-fetch --example discover

fn main() -> anyhow::Result<()> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| wa_fetch::WA_WEB_URL.to_string());

    eprintln!("GET {url}");
    let d = wa_fetch::discover_bundle_urls(&url)?;

    println!("status:      {}", d.status);
    println!("html bytes:  {}", d.html_bytes);
    println!("wa version:  {:?}", d.wa_version);
    println!("client rev:  {:?}", d.client_revision);
    println!("js bundles:  {}", d.js.len());
    println!("wasm refs:   {}", d.wasm.len());
    println!(
        "by source:   script_tag={} rsrc_map={} scheduled_js={} wasm_ref={}",
        d.by_source.script_tag,
        d.by_source.rsrc_map,
        d.by_source.scheduled_js,
        d.by_source.wasm_ref
    );

    if let Ok(out) = std::env::var("WA_URLS_OUT") {
        std::fs::write(&out, d.js.join("\n"))?;
        eprintln!("wrote {} js urls to {out}", d.js.len());
    }

    println!("\nfirst 15 js:");
    for u in d.js.iter().take(15) {
        println!("  {u}");
    }
    if !d.wasm.is_empty() {
        println!("\nwasm:");
        for u in &d.wasm {
            println!("  {u}");
        }
    }
    Ok(())
}
