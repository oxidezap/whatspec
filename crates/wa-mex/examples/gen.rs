//! Extract Mex persisted operations from one or more bundle files (concatenated).
//! Run: cargo run -p wa-mex --example gen -- <version> <bundle.js>... [--json]

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let version = args
        .next()
        .expect("usage: gen <version> <bundle.js>... [--json]");
    let mut source = String::new();
    let mut json = false;
    for a in args {
        if a == "--json" {
            json = true;
            continue;
        }
        source.push_str(&std::fs::read_to_string(&a)?);
        source.push('\n');
    }
    let ir = wa_mex::extract_mex(&source, &version);

    if json {
        println!("{}", serde_json::to_string_pretty(&ir)?);
        return Ok(());
    }

    let queries = ir
        .operations
        .values()
        .filter(|o| matches!(o.operation_kind, wa_ir::MexOperationKind::Query))
        .count();
    let mutations = ir.operations.len() - queries;
    eprintln!(
        "operations: {} ({} queries, {} mutations)",
        ir.operations.len(),
        queries,
        mutations
    );
    for (name, op) in &ir.operations {
        println!(
            "{name}\t{:?}\t{}\t[{}]",
            op.operation_kind,
            op.doc_id,
            op.variables.join(",")
        );
    }
    Ok(())
}
