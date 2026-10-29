//! Report emission gaps, or emit a selected fail-closed IQ catalog.
//! iq_contracts index.json [Module ...]
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let input = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: iq_contracts index.json [Module ...]"))?;
    let mut ir: wa_ir::IqIr = serde_json::from_str(&std::fs::read_to_string(input)?)?;
    let modules: Vec<_> = args.collect();
    if modules.is_empty() {
        for diagnostic in wa_codegen::diagnose_iq_generation(&ir) {
            println!(
                "{}\t{}",
                diagnostic.module,
                if diagnostic.reasons.is_empty() {
                    "emittable, not independently qualified".into()
                } else {
                    diagnostic.reasons.join("; ")
                }
            );
        }
    } else {
        for module in &modules {
            anyhow::ensure!(
                ir.stanzas
                    .iter()
                    .filter(|s| &s.module_name == module)
                    .count()
                    == 1,
                "expected exactly one {module}"
            );
        }
        ir.stanzas.retain(|s| modules.contains(&s.module_name));
        match wa_codegen::generate_iq_checked(&ir) {
            Ok(code) => print!("{code}"),
            Err(diagnostics) => anyhow::bail!("IQ contracts cannot be emitted: {diagnostics:#?}"),
        }
    }
    Ok(())
}
