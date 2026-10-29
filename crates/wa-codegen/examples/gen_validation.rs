fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let input = std::fs::read_to_string(args.next().expect("input.json output.rs value.rs"))?;
    let ir = serde_json::from_str(&input)?;
    std::fs::write(
        args.next().expect("output.rs"),
        wa_codegen::generate_appstate_validation(&ir).map_err(anyhow::Error::msg)?,
    )?;
    std::fs::write(
        args.next().expect("value.rs"),
        wa_codegen::APPSTATE_VALIDATION_VALUE,
    )?;
    if let Some(batch) = args.next() {
        let ir = serde_json::from_str(&std::fs::read_to_string(batch)?)?;
        std::fs::write(
            args.next().expect("batch output"),
            wa_codegen::generate_appstate_batch_validation(&ir).map_err(anyhow::Error::msg)?,
        )?;
    }
    Ok(())
}
