//! Admission diagnostics for consumers that require both halves of an IQ.
use wa_ir::{IqIr, IqStanzaDef, IqTarget, WapChildNode};

/// An emission limitation, not a claim about server behavior or proof that an
/// admitted contract was compared against independently executed Web code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IqGenerationDiagnostic {
    pub module: String,
    pub reasons: Vec<String>,
}

fn request_gaps(nodes: &[WapChildNode], reasons: &mut Vec<String>) {
    for node in nodes {
        if node.tag.is_empty() {
            reasons.push("request.tag_missing".into());
        }
        if node.is_combinator_fed() && node.arg_path.as_ref().is_none_or(Vec::is_empty) {
            reasons.push(format!("request.{}.argument_missing", node.tag));
        }
        if node.repeats && (node.repeat_min.is_none() || node.repeat_max.is_none()) {
            reasons.push(format!("request.{}.repeat_bounds_missing", node.tag));
        }
        for attr in &node.attrs {
            if attr.value.is_some()
                && !matches!(
                    attr.kind,
                    wa_ir::WapAttrKind::Const | wa_ir::WapAttrKind::GeneratedId
                )
            {
                reasons.push(format!(
                    "request.{}.{}.fixed_value_validation_unemitted",
                    node.tag, attr.name
                ));
            }
            if attr.reads_argument() && attr.arg_path.as_ref().is_none_or(Vec::is_empty) {
                reasons.push(format!(
                    "request.{}.{}.argument_missing",
                    node.tag, attr.name
                ));
            }
        }
        if node
            .content
            .as_ref()
            .is_some_and(|c| c.reads_argument() && c.arg_path.as_ref().is_none_or(Vec::is_empty))
        {
            reasons.push(format!("request.{}.content_argument_missing", node.tag));
        }
        // The legacy emitter models repeated payloads as an owned Node and does
        // not enforce list bounds. Keep them out of checked generation until
        // there is a fallible builder API capable of enforcing the contract.
        if node.repeats {
            reasons.push(format!("request.{}.repeat_validation_unemitted", node.tag));
        }
        if !node.variant_groups.is_empty() {
            reasons.push(format!(
                "request.{}.disjunction_validation_unqualified",
                node.tag
            ));
        }
        request_gaps(&node.children, reasons);
    }
}

/// Diagnose each catalog entry without treating 142 recovered stanzas as 142
/// complete contracts. Consumers can select a bounded set before checking it.
pub fn diagnose_iq_generation(ir: &IqIr) -> Vec<IqGenerationDiagnostic> {
    ir.stanzas.iter().map(diagnose).collect()
}

fn diagnose(op: &IqStanzaDef) -> IqGenerationDiagnostic {
    let mut reasons = Vec::new();
    if op.response.variants.is_empty() {
        reasons.push("response.rpc_outcomes_missing".into());
    }
    if op.namespace != op.request.namespace
        || op.iq_type != op.request.iq_type
        || op.target != op.request.target
    {
        reasons.push("request.envelope_disagreement".into());
    }
    if matches!(op.target, IqTarget::Unknown | IqTarget::Unset) {
        reasons.push("request.target_unresolved".into());
    }
    if op.target == IqTarget::GroupJid
        && op
            .request
            .target_arg_path
            .as_ref()
            .is_none_or(Vec::is_empty)
    {
        reasons.push("request.target_argument_missing".into());
    }
    request_gaps(&op.request.children, &mut reasons);
    let (_, response) = crate::spec::generate_spec_diagnosed(op, "CHECK_NAMESPACE", "CheckSpec");
    if let Some(reason) = response {
        reasons.push(reason);
    }
    IqGenerationDiagnostic {
        module: op.module_name.clone(),
        reasons,
    }
}

/// Fail closed instead of emitting builders that silently omit unresolved
/// inputs or parsers that always return a generation error.
pub fn generate_iq_checked(ir: &IqIr) -> Result<String, Vec<IqGenerationDiagnostic>> {
    let diagnostics: Vec<_> = diagnose_iq_generation(ir)
        .into_iter()
        .filter(|d| !d.reasons.is_empty())
        .collect();
    if diagnostics.is_empty() {
        Ok(crate::generate_iq(ir))
    } else {
        Err(diagnostics)
    }
}
