//! Generate WAProto.proto from one or more bundle files (concatenated).
//! Run: cargo run -p wa-proto --example gen -- <ver> <bundle.js>...

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let version = args.next().expect("usage: gen <version> <bundle.js>...");
    let mut source = String::new();
    for path in args {
        source.push_str(&std::fs::read_to_string(&path)?);
        source.push('\n');
    }
    let file = wa_proto::extract_proto(&source, &version);
    print!("{}", wa_proto::stringify(&file));
    Ok(())
}
