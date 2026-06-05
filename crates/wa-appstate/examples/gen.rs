//! Extract AppState schemas from bundle file(s) (concatenated) and print JSON.
//! Run: cargo run -p wa-appstate --example gen -- <version> <bundle.js>...

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let version = args.next().expect("usage: gen <version> <bundle.js>...");
    let mut source = String::new();
    for path in args {
        source.push_str(&std::fs::read_to_string(&path)?);
        source.push_str("\n;\n");
    }
    let ir = wa_appstate::extract_appstate(&source, &version);
    println!("{}", serde_json::to_string_pretty(&ir)?);
    Ok(())
}
