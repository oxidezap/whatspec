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
    for module in capture_modules(&source)? {
        if names.contains(&module.name) {
            println!("{}\t{}\t{}", module.name, module.start, module.end);
        }
    }
    Ok(())
}

fn capture_modules(source: &str) -> Result<Vec<wa_transform::ModuleDefinition>> {
    // Validate the complete file before emitting any span. The checked API also
    // visits nested definitions; retain production boundaries for this capture.
    wa_transform::extract_module_definitions_checked(source)
        .map_err(|errors| anyhow::anyhow!("bundle parse failed: {}", errors.join("; ")))?;
    Ok(wa_transform::extract_module_definitions(source))
}

#[cfg(test)]
mod tests {
    use super::capture_modules;

    #[test]
    fn malformed_file_cannot_qualify_complete_requested_modules() {
        let valid = r#"__d("Wanted",[],function(){});"#;
        for source in [
            format!("{valid} function broken("),
            format!("function broken( {valid}"),
            format!(r#"{valid} let = ; __d("Later",[],function(){{}});"#),
        ] {
            assert!(
                capture_modules(&source).is_err(),
                "accepted recovery: {source}"
            );
        }
    }

    #[test]
    fn valid_capture_preserves_production_module_boundaries() {
        let source = r#"__d('Outer',[],function(){__d('Inner',[],function(){});}); __d('Later',[],function(){});"#;
        let captured = capture_modules(source).unwrap();
        assert_eq!(captured, wa_transform::extract_module_definitions(source));
        assert_eq!(
            captured.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["Outer", "Later"]
        );
        assert_eq!(
            wa_transform::extract_module_definitions_checked(source)
                .unwrap()
                .len(),
            3
        );
    }
}
