//! Emit the isolated unlink projection without regenerating unrelated domains.
use std::{collections::HashMap, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut slices = HashMap::new();
    for path in std::env::args().skip(1).map(PathBuf::from) {
        let source = std::fs::read_to_string(path)?;
        for module in wa_transform::extract_module_definitions(&source) {
            let text = source[module.start..module.end].to_string();
            if let Some(previous) = slices.insert(module.name.clone(), text.clone()) {
                assert_eq!(previous, text, "conflicting module {}", module.name);
            }
        }
    }
    let borrowed = slices
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let contract = wa_notif::group_normalization::extract_unlink(&borrowed)?;
    println!("{}", serde_json::to_string_pretty(&contract)?);
    Ok(())
}
