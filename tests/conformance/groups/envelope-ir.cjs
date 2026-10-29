// Test-only interpreter for the emitted envelope program. ParsableWapNode and
// context facts are the same qualified external adapters used by the source
// harness. Child payload parsing remains an explicit independent boundary.
function evaluateEnvelope(contract, node, facts) {
  const locals = Array(contract.locals);
  function expr(e) {
    switch (e.expr) {
      case 'node': return node;
      case 'local': return locals[e.local];
      case 'string': case 'integer': case 'bool': return e.value;
      case 'null': return null;
      case 'undefined': return undefined;
      case 'context':
        switch (e.fact) {
          case 'meDeviceLid': return facts.WAWebUserPrefsMeUser.getMeDeviceLidOrThrow();
          case 'maybeMeDevicePn': return facts.WAWebUserPrefsMeUser.getMaybeMeDevicePn();
          case 'usernameDisplayed': return facts.WAWebUsernameGatingUtils.usernameDisplayedEnabled();
          default: throw Error('unsupported context '+e.fact);
        }
      case 'read': return node[e.method](e.name);
      case 'convert': {
        const value = expr(e.value);
        switch (e.conversion) {
          case 'toJid': return value.toJid();
          case 'groupJidToWid': return facts.WAWebJidToWid.groupJidToWid(value);
          case 'userJidToWid': return facts.WAWebJidToWid.userJidToUserWid(value);
          case 'asIsoCountryCode': return facts.WAWebAsISOCountryCode.asISOCountryCode(value);
          default: throw Error('unsupported conversion '+e.conversion);
        }
      }
      case 'isEmpty': return facts.isStringNullOrEmpty(expr(e.value));
      case 'not': return !expr(e.value);
      case 'binary': {
        const left = expr(e.left), right = expr(e.right);
        switch (e.operator) {
          case 'strictEqual': return left === right;
          case 'strictNotEqual': return left !== right;
          case 'nullishEqual': return left == right;
          case 'nullishNotEqual': return left != right;
          case 'add': return left + right;
          default: throw Error('unsupported binary '+e.operator);
        }
      }
      case 'logical':
        if(e.operator === 'and') return expr(e.left) && expr(e.right);
        if(e.operator === 'or') return expr(e.left) || expr(e.right);
        throw Error('unsupported logical '+e.operator);
      case 'conditional': return expr(e.condition) ? expr(e.thenValue) : expr(e.elseValue);
      case 'assign': return locals[e.local] = expr(e.value);
      case 'sequence': { let value; for(const item of e.values) value = expr(item); return value; }
      case 'reject': throw node.createParseError(expr(e.message));
      case 'object': return Object.fromEntries(e.fields.map(field => [field.name, expr(field.value)]));
      default: throw Error('unsupported expression '+e.expr);
    }
  }
  function ops(program) {
    for(const op of program) {
      switch(op.op) {
        case 'bind': if(op.value != null) locals[op.local] = expr(op.value); break;
        case 'evaluate': expr(op.value); break;
        case 'if': ops(expr(op.condition) ? op.thenOps : op.elseOps); break;
        case 'tryDiagnostic':
          try { ops(op.body); } catch(error) { facts.WALogger.ERROR(op.messageParts, facts.getErrorSafe(error).toString()); }
          break;
        default: throw Error('unsupported op '+op.op);
      }
    }
  }
  ops(contract.prefix);
  const action = contract.actions;
  locals[action.resultLocal] = node.mapChildren(child => {
    const tag = child.tag();
    if(tag === action.missingIdentificationTag) {
      locals[action.missingIdentificationLocal] = true;
      return undefined;
    }
    // These 29 inputs exercise only this unit adapter, markers and unknowns.
    // Complex action payloads are qualified by their separate differential suite.
    if(tag === 'suspended') return {actionType: 'suspend', value: true};
    throw node.createParseError(action.unknownActionErrorPrefix + tag);
  }).filter(Boolean);
  return expr(contract.projection);
}
module.exports = {evaluateEnvelope};
