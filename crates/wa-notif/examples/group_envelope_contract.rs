//! Extract the ordered envelope program without executing client JavaScript.
use std::{collections::HashMap, path::PathBuf};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut slices = HashMap::new();
    for path in std::env::args().skip(1).map(PathBuf::from) {
        let source = std::fs::read_to_string(path)?;
        for module in wa_transform::extract_module_definitions(&source) {
            let text = source[module.start..module.end].to_string();
            if let Some(previous) = slices.insert(module.name.clone(), text.clone())
                && previous != text
            {
                return Err(format!("conflicting module {}", module.name).into());
            }
        }
    }
    let borrowed = slices
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    println!(
        "{}",
        serde_json::to_string_pretty(&wa_notif::group_envelope::extract_group_envelope(
            &borrowed
        )?)?
    );
    Ok(())
}
