//! Static module spans for reviewed conformance captures; never executes JS.
//! Usage: module_spans BUNDLE MODULE [MODULE ...]
//! Use `-` for BUNDLE to parse verified bytes supplied on stdin.
use anyhow::{Context, Result};
use std::io::Read;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .context("usage: module_spans BUNDLE MODULE ...")?;
    let names: Vec<_> = args.collect();
    anyhow::ensure!(!names.is_empty(), "at least one module is required");
    let source = if path == "-" {
        let mut source = String::new();
        std::io::stdin().read_to_string(&mut source)?;
        source
    } else {
        std::fs::read_to_string(path)?
    };
    for module in wa_transform::extract_module_definitions(&source) {
        if names.contains(&module.name) {
            println!("{}\t{}\t{}", module.name, module.start, module.end);
        }
    }
    Ok(())
}
