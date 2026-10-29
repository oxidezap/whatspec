//! Whole-module qualification for the batch algorithms. A bounded recognizer,
//! deliberately stricter than the general protobuf expression compiler.
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use std::collections::{HashMap, HashSet};

use super::validation::Lower;
use sha2::{Digest, Sha256};
use wa_ir::{AppstateBatchValidationIr, BatchValidationRecipe, ValidationFunction};
use wa_oxc::parse_cjs;
pub const MODULE: &str = "WAWebSyncdValidateMutations";
const REFERENCE: &str = include_str!("fixtures/validate_mutations.js");

pub fn extract(source: &str, version: &str) -> Result<AppstateBatchValidationIr, String> {
    let modules =
        wa_transform::extract_module_definitions_checked(source).map_err(|e| e.join(";"))?;
    let modules: Vec<_> = modules.iter().filter(|m| m.name == MODULE).collect();
    let first = modules.first().ok_or("missing batch validation module")?;
    let text = &source[first.start..first.end];
    if modules.iter().any(|m| &source[m.start..m.end] != text) {
        return Err("conflicting batch validator definitions".into());
    }
    if canonical(text)? != canonical(REFERENCE)? {
        return Err("unqualified batch algorithm drift; review complete control flow before updating the recognizer".into());
    }
    let allocator = Allocator::default();
    let parsed = parse_cjs(&allocator, text);
    let mut finder = TypeSet {
        function: None,
        requires: super::validation::require_bindings(&parsed.program),
    };
    finder.visit_program(&parsed.program);
    let function = finder.function.ok_or("missing typed SET boundary")?;
    let (set_operation, remove_operation, operation_enum_sha256) = operation_enum(source)?;
    Ok(AppstateBatchValidationIr {
        format_version: 1,
        wa_version: version.into(),
        module_sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
        recipe: BatchValidationRecipe::SeparateSetRemoveV1,
        set_operation,
        remove_operation,
        operation_enum_sha256,
        type_set: function,
    })
}
struct TypeSet {
    function: Option<ValidationFunction>,
    requires: HashSet<String>,
}
impl<'a> Visit<'a> for TypeSet {
    fn visit_function(&mut self, function: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        // Export resolution is covered by complete alpha-equivalent qualification;
        // locate the one function whose body lowers through SyncActionDataSpec.
        if function.params.items.len() == 2
            && let Ok(body) = Lower::function(function, self.requires.clone())
            && matches!(body.as_slice(),[wa_ir::ValidationStatement::Return{value:wa_ir::ValidationExpression::Map{body,..}}] if matches!(body.first(),Some(wa_ir::ValidationStatement::Bind{value:wa_ir::ValidationExpression::Transform{transform:wa_ir::ValidationTransform::DecodeSyncActionData,..},..})))
        {
            self.function = Some(ValidationFunction {
                module: MODULE.into(),
                start_byte: function.span.start as usize,
                end_byte: function.span.end as usize,
                parameters: 2,
                body,
            });
            return;
        }
        walk::walk_function(self, function, flags);
    }
}
#[derive(Default)]
struct Identifiers {
    bindings: HashSet<String>,
    uses: Vec<(usize, usize, String)>,
}
impl<'a> Visit<'a> for Identifiers {
    fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'a>) {
        self.bindings.insert(id.name.to_string());
        self.uses.push((
            id.span.start as usize,
            id.span.end as usize,
            id.name.to_string(),
        ));
    }
    fn visit_identifier_reference(&mut self, id: &IdentifierReference<'a>) {
        self.uses.push((
            id.span.start as usize,
            id.span.end as usize,
            id.name.to_string(),
        ));
    }
}
fn canonical(source: &str) -> Result<String, String> {
    let allocator = Allocator::default();
    let parsed = parse_cjs(&allocator, source);
    if !parsed.errors.is_empty() || parsed.panicked {
        return Err("batch parser recovery is forbidden".into());
    }
    let mut ids = Identifiers::default();
    ids.visit_program(&parsed.program);
    ids.uses.sort();
    let mut names = HashMap::new();
    let mut cursor = 0;
    let mut rewritten = String::new();
    for (start, end, name) in ids.uses {
        if !ids.bindings.contains(&name) {
            continue;
        }
        rewritten.push_str(&source[cursor..start]);
        let count = names.len();
        let normalized = names.entry(name).or_insert_with(|| format!("local{count}"));
        rewritten.push_str(normalized);
        cursor = end;
    }
    rewritten.push_str(&source[cursor..]);
    // Strip only inter-token whitespace. Strings retain their exact bytes.
    let mut out = String::new();
    let mut quoted = None;
    let mut escaped = false;
    for ch in rewritten.chars() {
        if let Some(q) = quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quoted = None;
            }
        } else if ch == '\'' || ch == '"' {
            quoted = Some(ch);
            out.push(ch);
        } else if ch.is_whitespace() {
            if out
                .chars()
                .last()
                .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '$')
            {
                out.push(' ');
            }
        } else {
            if out.ends_with(' ') && !(ch.is_alphanumeric() || ch == '_' || ch == '$') {
                out.pop();
            }
            out.push(ch);
        }
    }
    // ASI and token joining can change semantics without changing a whitespace-
    // stripped token stream. Preserve AST expression/statement shapes as well.
    #[derive(Default)]
    struct Shape(String);
    impl<'a> Visit<'a> for Shape {
        fn visit_statement(&mut self, s: &Statement<'a>) {
            self.0.push_str(&format!("{:?}", std::mem::discriminant(s)));
            walk::walk_statement(self, s);
        }
        fn visit_expression(&mut self, e: &Expression<'a>) {
            self.0.push_str(&format!("{:?}", std::mem::discriminant(e)));
            walk::walk_expression(self, e);
        }
        fn visit_update_expression(&mut self, u: &UpdateExpression<'a>) {
            self.0.push_str(if u.prefix { "prefix" } else { "postfix" });
            walk::walk_update_expression(self, u);
        }
    }
    let mut shape = Shape::default();
    shape.visit_program(&parsed.program);
    out.push_str(&shape.0);
    Ok(out)
}

fn operation_enum(source: &str) -> Result<(i32, i32, String), String> {
    let definitions =
        wa_transform::extract_module_definitions_checked(source).map_err(|e| e.join(";"))?;
    let defs: Vec<_> = definitions
        .iter()
        .filter(|d| d.name == "WAWebProtobufsServerSync.pb")
        .collect();
    let first = defs.first().ok_or("missing SyncdOperation enum module")?;
    let text = &source[first.start..first.end];
    if defs.iter().any(|d| &source[d.start..d.end] != text) {
        return Err("conflicting operation enums".into());
    }
    let allocator = Allocator::default();
    let parsed = parse_cjs(&allocator, text);
    #[derive(Default)]
    struct Enums {
        locals: HashMap<String, (i32, i32)>,
        export: Option<String>,
    }
    impl<'a> Visit<'a> for Enums {
        fn visit_variable_declarator(&mut self, d: &VariableDeclarator<'a>) {
            if let BindingPattern::BindingIdentifier(id) = &d.id
                && let Some(Expression::CallExpression(call)) = &d.init
                && let Expression::CallExpression(require) = &call.callee
                && wa_oxc::first_string_arg(require) == Some("$InternalEnum")
                && call.arguments.len() == 1
                && let Some(Expression::ObjectExpression(object)) =
                    call.arguments[0].as_expression()
            {
                let mut fields = HashMap::new();
                for property in &object.properties {
                    if let ObjectPropertyKind::ObjectProperty(property) = property
                        && let Some(key) = property.key.static_name()
                        && let Some(value) = wa_oxc::as_int(&property.value)
                        && let Ok(value) = i32::try_from(value)
                    {
                        fields.insert(key.to_string(), value);
                    }
                }
                if fields.len() == 2
                    && let (Some(set), Some(remove)) = (fields.get("SET"), fields.get("REMOVE"))
                {
                    self.locals.insert(id.name.to_string(), (*set, *remove));
                }
            }
            walk::walk_variable_declarator(self, d);
        }
        fn visit_assignment_expression(&mut self, a: &AssignmentExpression<'a>) {
            if let AssignmentTarget::StaticMemberExpression(member) = &a.left
                && member.property.name == "SyncdMutation$SyncdOperation"
                && let Expression::Identifier(id) = &a.right
            {
                self.export = Some(id.name.to_string());
            }
            walk::walk_assignment_expression(self, a);
        }
    }
    let mut finder = Enums::default();
    finder.visit_program(&parsed.program);
    let (set, remove) = finder
        .export
        .and_then(|name| finder.locals.get(&name).copied())
        .ok_or("unqualified SyncdOperation enum")?;
    if set == remove {
        return Err("SET and REMOVE collide".into());
    }
    Ok((
        set,
        remove,
        format!("{:x}", Sha256::digest(text.as_bytes())),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualify_and_reject_drift() {
        let source = format!("{REFERENCE};{}", include_str!("fixtures/server_sync.pb.js"));
        let original = extract(&source, "test").unwrap();
        assert_eq!(
            original.type_set.body,
            extract(&source.replace(';', ";\n"), "test")
                .unwrap()
                .type_set
                .body
        );
        assert!(extract(&source.replace("r.has(i.index)", "a.has(i.index)"), "test").is_err());
        assert!(extract(&source.replace("isFatal:!1", "isFatal:!0"), "test").is_err());
        assert!(extract(&source.replace("===", "!=="), "test").is_err());
        assert!(extract(&source.replace("return e==null", "return\ne==null"), "test").is_err());
        let renamed = source
            .replace(
                "function(t,n,r,o,a,i,l)",
                "function(t,n,r,requireAlias,a,i,l)",
            )
            .replace("o(\"", "requireAlias(\"");
        assert!(extract(&renamed, "test").is_ok());
    }
}
