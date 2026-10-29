//! Fail-closed lowering from one locked bundle containing the validation module.
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let version = args.next().expect("gen_validation <version> <bundle>");
    let mut source = std::fs::read_to_string(args.next().expect("bundle"))?;
    if args.next().as_deref() == Some("--batch") {
        if let Some(dependency) = args.next() {
            source.push_str("\n;");
            source.push_str(&std::fs::read_to_string(dependency)?);
        }
        let ir = wa_appstate::validation_batch::extract(&source, &version)
            .map_err(anyhow::Error::msg)?;
        println!("{}", serde_json::to_string_pretty(&ir)?);
        return Ok(());
    }
    let ir = wa_appstate::validation::extract(&source, &version).map_err(anyhow::Error::msg)?;
    println!("{}", serde_json::to_string_pretty(&ir)?);
    Ok(())
}
