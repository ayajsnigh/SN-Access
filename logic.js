// Pure ACL evaluation logic. No DOM, no network.
(function (root) {
  // Names to look for, most specific first.
  function buildLevels(chain, field) {
    var record = chain.concat(['*']);
    var fld = [];
    if (field) {
      chain.forEach(function (t) { fld.push(t + '.' + field); });
      fld.push('*.' + field);
      chain.forEach(function (t) { fld.push(t + '.*'); });
      fld.push('*.*');
    }
    return { record: record, field: fld };
  }

  // acl: {id,name,condition,hasScript,adminOv,need:[roles],condOk:true|false|null,condNote}
  // userRoles: [role names]
  function evalAcl(acl, userRoles) {
    var need = acl.need || [];
    var isAdmin = userRoles.indexOf('admin') > -1;
    var roleOk = need.length === 0 || need.indexOf('public') > -1 ||
      need.some(function (r) { return userRoles.indexOf(r) > -1; });
    var bypass = !!(acl.adminOv && isAdmin);
    var status;
    if (bypass) status = 'pass';
    else if (!roleOk || acl.condOk === false) status = 'fail';
    else if (acl.condOk === null || acl.hasScript) status = 'maybe';
    else status = 'pass';
    return Object.assign({}, acl, {
      roleOk: roleOk,
      bypass: bypass,
      missingRoles: roleOk ? [] : need.filter(function (r) { return userRoles.indexOf(r) === -1; }),
      status: status
    });
  }

  // Access is granted if any ACL at a level passes.
  function levelStatus(list) {
    if (list.some(function (e) { return e.status === 'pass'; })) return 'pass';
    if (list.some(function (e) { return e.status === 'maybe'; })) return 'maybe';
    return 'fail';
  }

  // Evaluation stops at the first (most specific) level that has any matching ACL.
  function scopeResult(names, evaluated) {
    var levels = names.map(function (n) {
      var list = evaluated.filter(function (e) { return e.name === n; });
      return { name: n, acls: list, status: list.length ? levelStatus(list) : 'none' };
    });
    var idx = -1;
    for (var i = 0; i < levels.length; i++) {
      if (levels[i].acls.length) { idx = i; break; }
    }
    return { levels: levels, decidedIdx: idx, status: idx < 0 ? 'none' : levels[idx].status };
  }

  // Table access and field access must both pass.
  function decide(plan, evaluated) {
    var rec = scopeResult(plan.record, evaluated);
    var fld = plan.field.length ? scopeResult(plan.field, evaluated) : null;
    var verdict;
    if (rec.status === 'fail' || (fld && fld.status === 'fail')) verdict = 'denied';
    else if (rec.status === 'none') verdict = 'unknown';
    else if (rec.status === 'maybe' || (fld && fld.status === 'maybe')) verdict = 'depends';
    else verdict = 'allowed';
    return { verdict: verdict, record: rec, field: fld };
  }

  var api = { buildLevels: buildLevels, evalAcl: evalAcl, levelStatus: levelStatus, scopeResult: scopeResult, decide: decide };
  root.__aclLogic = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
