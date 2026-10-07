//! Static module spans for reviewed conformance captures; never executes JS.
//! Usage: module_spans BUNDLE MODULE [MODULE ...]
use anyhow::{Context, Result};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .context("usage: module_spans BUNDLE MODULE ...")?;
    let names: Vec<_> = args.collect();
    anyhow::ensure!(!names.is_empty(), "at least one module is required");
    let source = std::fs::read_to_string(path)?;
    for module in wa_transform::extract_module_definitions(&source) {
        if names.contains(&module.name) {
            println!("{}\t{}\t{}", module.name, module.start, module.end);
        }
    }
    Ok(())
}
