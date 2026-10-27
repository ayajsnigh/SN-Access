(function () {
  'use strict';
  var ID = 'acl-troubleshooter-host';
  var prev = document.getElementById(ID);
  if (prev) { prev.remove(); return; }
  var L = window.__aclLogic;

  /* ---------- ServiceNow API ---------- */
  function token() { try { return window.g_ck || window.top.g_ck || ''; } catch (e) { return ''; } }

  async function api(path) {
    var res = await fetch(path, {
      headers: { Accept: 'application/json', 'X-UserToken': token() },
      credentials: 'same-origin'
    });
    if (!res.ok) {
      var hint = (res.status === 401 || res.status === 403) ? '. This session needs read access to the table (admin or security_admin).' : '';
      throw new Error('HTTP ' + res.status + ' from ' + path.split('?')[0] + hint);
    }
    return (await res.json()).result;
  }

  function rows(table, query, fields, limit) {
    var p = new URLSearchParams({ sysparm_query: query, sysparm_fields: fields, sysparm_limit: String(limit || 1000) });
    return api('/api/now/table/' + table + '?' + p.toString());
  }

  async function tableChain(t) {
    var chain = [], n = t, guard = 0;
    while (n && guard++ < 15) {
      var r = await rows('sys_db_object', 'name=' + n, 'name,super_class.name', 1);
      if (!r.length) break;
      chain.push(n);
      n = r[0]['super_class.name'];
    }
    return chain;
  }

  async function userRoles(id) {
    var r = await rows('sys_user_has_role', 'user=' + id + '^state=active', 'role.name', 2000);
    return r.map(function (x) { return x['role.name']; });
  }

  async function aclRoles(id) {
    var r = await rows('sys_security_acl_role', 'sys_security_acl=' + id, 'sys_user_role.name', 200);
    return r.map(function (x) { return x['sys_user_role.name']; });
  }

  async function currentUser() {
    try {
      if (window.g_user && g_user.userID) {
        return { id: g_user.userID, name: g_user.getFullName ? g_user.getFullName() : g_user.userName };
      }
    } catch (e) {}
    // "Me" dynamic filter
    var r = await rows('sys_user', 'sys_idDYNAMIC90d1921e5f510100a9ad2572f2b477fe', 'sys_id,name', 1);
    return r[0] ? { id: r[0].sys_id, name: r[0].name } : null;
  }

  // Runs the ACL condition as an encoded query against the record.
  async function evalCond(table, sysId, cond, isSelf) {
    if (!cond) return { ok: true };
    if (!sysId) return { ok: null, note: 'needs a record sys_id to test' };
    if (/javascript:|DYNAMIC/.test(cond) && !isSelf) return { ok: null, note: 'dynamic condition would run as you, not the target user' };
    var parts = cond.split('^NQ');
    for (var i = 0; i < parts.length; i++) {
      var r = await rows(table, 'sys_id=' + sysId + '^' + parts[i], 'sys_id', 1);
      if (r.length) return { ok: true };
    }
    return { ok: false };
  }

  var FIELD_RE = /^([a-z0-9_.]+?)(NOT IN|NOT LIKE|NOT ?IN|IN|LIKE|STARTSWITH|ENDSWITH|ISEMPTY|ISNOTEMPTY|SAMEAS|NSAMEAS|BETWEEN|VALCHANGES|CHANGESFROM|CHANGESTO|DYNAMIC|!=|>=|<=|=|>|<)/;

  async function recordValues(table, sysId, names) {
    var p = new URLSearchParams({ sysparm_fields: names.join(','), sysparm_display_value: 'all' });
    var res = await api('/api/now/table/' + table + '/' + sysId + '?' + p.toString());
    var o = {};
    names.forEach(function (n) {
      var v = res[n];
      if (v && typeof v === 'object') {
        o[n] = v.display_value && v.display_value !== v.value ? v.display_value + ' (' + v.value + ')' : v.value;
      }
    });
    return o;
  }

  // For a failed condition: which clauses fail, and what the record holds for them.
  async function diagnose(table, sysId, e) {
    if (e.condOk !== false || !e.condition) return;
    var simple = !/\^(OR|NQ)/.test(e.condition);
    if (!simple) { e.failing = [e.condition]; return; }
    var parts = e.condition.split('^').filter(Boolean), bad = [];
    for (var i = 0; i < parts.length; i++) {
      var r = await rows(table, 'sys_id=' + sysId + '^' + parts[i], 'sys_id', 1);
      if (!r.length) bad.push(parts[i]);
    }
    e.failing = bad.length ? bad : [e.condition];
    var names = [];
    e.failing.forEach(function (c) {
      var m = c.match(FIELD_RE);
      if (m && names.indexOf(m[1]) < 0) names.push(m[1]);
    });
    if (names.length) { try { e.values = await recordValues(table, sysId, names); } catch (x) {} }
  }

  /* ---------- page context ---------- */
  function fromUrl() {
    var href = decodeURIComponent(location.href), table = '', sysId = '', m;
    if ((m = href.match(/\/([a-z0-9_]+)_list\.do/i))) table = m[1];
    else if ((m = href.match(/\/([a-z0-9_]+)\.do/i))) table = m[1];
    if ((m = href.match(/\/record\/([a-z0-9_]+)\/([0-9a-f]{32})/i))) { table = m[1]; sysId = m[2]; }
    if (!sysId && (m = href.match(/sys_id=([0-9a-f]{32})/i))) sysId = m[1];
    return { table: table, sysId: sysId };
  }

  function pageContext() {
    var u = fromUrl();
    try {
      if (window.g_form && g_form.getTableName) {
        var id = g_form.getUniqueValue();
        return { table: g_form.getTableName(), sysId: id && id !== '-1' ? id : u.sysId };
      }
    } catch (e) {}
    return u;
  }

  /* ---------- DOM helpers ---------- */
  function h(tag, props, kids) {
    var el = document.createElement(tag);
    Object.keys(props || {}).forEach(function (k) {
      if (k === 'class') el.className = props[k];
      else if (k === 'text') el.textContent = props[k];
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), props[k]);
      else el.setAttribute(k, props[k]);
    });
    (kids || []).forEach(function (c) {
      if (c != null) el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return el;
  }

  var CSS = [
    ':host{all:initial}',
    '*{box-sizing:border-box}',
    '.p{position:fixed;top:12px;right:12px;width:460px;max-width:calc(100vw - 24px);max-height:calc(100vh - 24px);overflow:auto;background:#f6f7f9;color:#18202b;font:13px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;border:1px solid #c5ccd6;border-radius:8px;box-shadow:0 12px 32px rgba(20,30,50,.24);z-index:2147483647}',
    'header{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#1f4e5f;color:#fff;border-radius:7px 7px 0 0}',
    'header b{font-size:14px;font-weight:600}',
    'header button{all:unset;cursor:pointer;padding:2px 8px;font-size:18px;line-height:1;border-radius:4px}',
    'header button:hover,header button:focus-visible{background:rgba(255,255,255,.2)}',
    '.form{padding:12px 14px;display:grid;gap:8px;border-bottom:1px solid #d5dae1}',
    '.two{display:grid;grid-template-columns:1fr 130px;gap:8px}',
    'label{display:grid;gap:3px;font-weight:600;font-size:12px}',
    'label small{font-weight:400;color:#5b6675}',
    'input,select{font:inherit;padding:6px 8px;border:1px solid #b9c1cc;border-radius:5px;background:#fff;color:#18202b;min-width:0}',
    'input:focus-visible,select:focus-visible,.go:focus-visible,a:focus-visible,.copy:focus-visible{outline:2px solid #1f4e5f;outline-offset:1px}',
    '.go{font:inherit;font-weight:600;padding:8px 10px;border:0;border-radius:5px;background:#1f4e5f;color:#fff;cursor:pointer}',
    '.go:hover{background:#17404f}',
    '.out{padding:12px 14px;display:grid;gap:12px}',
    '.muted{color:#5b6675;margin:0}',
    '.err{color:#b42318;margin:0}',
    '.verdict{padding:10px 12px;border-radius:6px;border-left:5px solid}',
    '.verdict b{display:block;font-size:15px}',
    '.v-allowed{background:#e6f4ec;border-color:#1b7a46}',
    '.v-denied{background:#fbe9e7;border-color:#b42318}',
    '.v-depends{background:#fdf1d9;border-color:#94600a}',
    '.v-unknown{background:#e8ecf1;border-color:#5b6675}',
    'h3{margin:0 0 4px;font-size:13px}',
    '.lv{border:1px solid #d5dae1;border-radius:6px;background:#fff;overflow:auto}',
    '.lv.skip{opacity:.55}',
    '.lvh{display:flex;justify-content:space-between;padding:5px 8px;background:#eef1f5;font-size:12px}',
    'table{border-collapse:collapse;width:100%;font-size:12px}',
    'td,th{padding:4px 8px;text-align:left;border-top:1px solid #e3e7ec;vertical-align:top}',
    'th{font-weight:600;color:#5b6675;border-top:0}',
    'a{color:#1f4e5f}',
    '.m{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}',
    '.pass{color:#1b7a46;font-weight:600}.fail{color:#b42318;font-weight:600}.maybe{color:#94600a;font-weight:600}',
    '.fix{background:#fff;border:1px solid #d5dae1;border-radius:6px;padding:8px 10px}',
    '.fix p{margin:0 0 4px}',
    '.fix ul{margin:0;padding-left:18px}',
    '.copy{font:inherit;padding:5px 10px;border:1px solid #b9c1cc;border-radius:5px;background:#fff;cursor:pointer;justify-self:start}',
    '@media (prefers-reduced-motion:no-preference){.go,.copy{transition:background .12s}}'
  ].join('');

  /* ---------- build panel ---------- */
  var host = h('div', { id: ID });
  var root = host.attachShadow({ mode: 'open' });
  root.appendChild(h('style', { text: CSS }));

  var ctx = pageContext();
  var users = {};
  var uIn = h('input', { id: 'u', list: 'ul', autocomplete: 'off', placeholder: 'Type a name to search' });
  var tIn = h('input', { id: 't', value: ctx.table, autocomplete: 'off', placeholder: 'e.g. incident' });
  var oSel = h('select', { id: 'o' }, ['read', 'write', 'create', 'delete'].map(function (v) { return h('option', { value: v, text: v }); }));
  var fIn = h('input', { id: 'f', list: 'fl', autocomplete: 'off', placeholder: 'Leave empty for table access only' });
  var rIn = h('input', { id: 'r', value: ctx.sysId, autocomplete: 'off', placeholder: '32-character sys_id' });
  var uList = h('datalist', { id: 'ul' });
  var fList = h('datalist', { id: 'fl' });
  var out = h('div', { class: 'out' }, [h('p', { class: 'muted', text: 'Choose a user, table and operation, then check access.' })]);
  var lastSummary = '';

  var panel = h('div', { class: 'p', role: 'dialog', 'aria-label': 'ServiceNow access troubleshooter' }, [
    h('header', {}, [
      h('b', { text: 'Access troubleshooter' }),
      h('button', { 'aria-label': 'Close', text: '\u00d7', onclick: function () { host.remove(); } })
    ]),
    h('div', { class: 'form' }, [
      h('label', {}, ['User', uIn]), uList,
      h('div', { class: 'two' }, [h('label', {}, ['Table', tIn]), h('label', {}, ['Operation', oSel])]),
      h('label', {}, [h('span', {}, ['Field ', h('small', { text: '(optional)' })]), fIn]), fList,
      h('label', {}, [h('span', {}, ['Record sys_id ', h('small', { text: '(needed to test conditions)' })]), rIn]),
      h('button', { class: 'go', text: 'Check access', onclick: run })
    ]),
    out
  ]);
  root.appendChild(panel);
  document.documentElement.appendChild(host);

  /* ---------- helpers for the form ---------- */
  var searchTimer;
  uIn.addEventListener('input', function () {
    clearTimeout(searchTimer);
    var t = uIn.value.trim();
    if (t.length < 2 || users[uIn.value]) return;
    searchTimer = setTimeout(async function () {
      try {
        var r = await rows('sys_user', 'active=true^nameLIKE' + t + '^ORuser_nameLIKE' + t, 'sys_id,name,user_name', 8);
        uList.replaceChildren();
        r.forEach(function (x) {
          var label = x.name + ' (' + x.user_name + ')';
          users[label] = x.sys_id;
          uList.appendChild(h('option', { value: label }));
        });
      } catch (e) {}
    }, 250);
  });

  async function loadFields() {
    var t = tIn.value.trim();
    if (!t) return;
    try {
      var chain = await tableChain(t);
      if (!chain.length) return;
      var r = await rows('sys_dictionary', 'nameIN' + chain.join(',') + '^elementISNOTEMPTY', 'element', 2000);
      var seen = {};
      fList.replaceChildren();
      r.map(function (x) { return x.element; }).sort().forEach(function (n) {
        if (!seen[n]) { seen[n] = 1; fList.appendChild(h('option', { value: n })); }
      });
    } catch (e) {}
  }
  tIn.addEventListener('change', loadFields);

  var self = null;
  (async function init() {
    try {
      self = await currentUser();
      if (self) {
        var label = self.name + ' (you)';
        users[label] = self.id;
        uIn.value = label;
      }
    } catch (e) {}
    loadFields();
  })();

  /* ---------- rendering ---------- */
  function mark(s) { return s === 'pass' ? '\u2713' : s === 'fail' ? '\u2717' : '?'; }

  function aclRow(e) {
    var roleCell = e.bypass ? 'admin override' : (e.need.length ? e.need.join(', ') : 'none required');
    var roleSt = e.bypass || e.roleOk ? 'pass' : 'fail';
    var condSt = !e.condition ? null : (e.condOk === true ? 'pass' : e.condOk === false ? 'fail' : 'maybe');
    return h('tr', {}, [
      h('td', {}, [h('a', { class: 'm', href: '/sys_security_acl.do?sys_id=' + e.id, target: '_blank', rel: 'noopener', text: e.name })]),
      h('td', {}, [h('span', { class: roleSt, text: mark(roleSt) + ' ' }), roleCell]),
      h('td', {}, [condSt ? h('span', { class: condSt, title: e.condNote || e.condition, text: mark(condSt) }) : '\u2013']),
      h('td', {}, [e.hasScript ? h('span', { class: 'maybe', title: 'Script is not evaluated for the target user', text: '?' }) : '\u2013'])
    ]);
  }

  function levelBlock(lv, state) {
    var label = state === 'decides' ? 'decides access' : 'not reached';
    return h('div', { class: 'lv' + (state === 'skip' ? ' skip' : '') }, [
      h('div', { class: 'lvh' }, [h('span', { class: 'm', text: lv.name }), h('span', { class: lv.status, text: label })]),
      h('table', {}, [
        h('tr', {}, [h('th', { text: 'ACL' }), h('th', { text: 'Roles' }), h('th', { text: 'Condition' }), h('th', { text: 'Script' })]),
        h('tbody', {}, lv.acls.map(aclRow))
      ])
    ]);
  }

  function scopeBlock(title, scope, emptyText) {
    var kids = [h('h3', { text: title })];
    if (scope.decidedIdx < 0) { kids.push(h('p', { class: 'muted', text: emptyText })); return h('div', {}, kids); }
    scope.levels.forEach(function (lv, i) {
      if (!lv.acls.length) return;
      kids.push(levelBlock(lv, i === scope.decidedIdx ? 'decides' : 'skip'));
    });
    return h('div', {}, kids);
  }

  function fixesFor(result) {
    var items = [];
    [result.record, result.field].forEach(function (scope) {
      if (!scope || scope.status !== 'fail') return;
      scope.levels[scope.decidedIdx].acls.forEach(function (e) {
        if (e.status !== 'fail') return;
        var steps = [];
        if (!e.roleOk) steps.push('Grant any one of these roles: ' + e.need.join(', '));
        if (e.condOk === false) {
          (e.failing || [e.condition]).forEach(function (c) {
            var m = c.match(FIELD_RE), cur = m && e.values && e.values[m[1]];
            steps.push('Make this condition true: ' + c + (cur ? '  (record has ' + m[1] + ' = ' + cur + ')' : ''));
          });
        }
        items.push({ acl: e, steps: steps });
      });
    });
    return items;
  }

  var VERDICT = {
    allowed: ['Allowed', 'At least one ACL at each deciding level passes.'],
    denied: ['Denied', 'Every ACL at a deciding level fails.'],
    depends: ['Depends on a script or record', 'Roles pass, but a script ACL or a condition without a record decides. Add a record sys_id, or test with impersonation.'],
    unknown: ['No matching table ACL', 'The instance default deny setting decides.']
  };

  function render(result, meta, fixes) {
    var v = VERDICT[result.verdict];
    var kids = [
      h('div', { class: 'verdict v-' + result.verdict }, [
        h('b', { text: v[0] }),
        h('span', { text: meta.userLabel + ' \u00b7 ' + meta.op + ' on ' + meta.table + (meta.field ? '.' + meta.field : '') }),
        h('div', { text: v[1] })
      ]),
      scopeBlock('Table access', result.record, 'No ACL matches this table, so default deny applies.')
    ];
    if (result.field) kids.push(scopeBlock('Field access (' + meta.field + ')', result.field, 'No field ACL matches. Table access alone applies.'));

    var lines = [v[0] + ': ' + meta.userLabel + ', ' + meta.op + ' on ' + meta.table + (meta.field ? '.' + meta.field : '')];
    if (fixes.length) {
      var box = h('div', { class: 'fix' }, [h('h3', { text: 'How to get access (any one route is enough)' })]);
      fixes.forEach(function (f) {
        lines.push('Route via ACL ' + f.acl.name + ' (' + f.acl.id + '):');
        box.appendChild(h('p', {}, ['Via ', h('span', { class: 'm', text: f.acl.name }), ':']));
        box.appendChild(h('ul', {}, f.steps.map(function (s) { lines.push('  - ' + s); return h('li', { text: s }); })));
      });
      kids.push(box);
    }
    lastSummary = lines.join('\n');
    kids.push(h('button', {
      class: 'copy', text: 'Copy summary',
      onclick: function (ev) {
        var b = ev.target;
        navigator.clipboard.writeText(lastSummary).then(function () { b.textContent = 'Copied'; setTimeout(function () { b.textContent = 'Copy summary'; }, 1500); });
      }
    }));
    out.replaceChildren.apply(out, kids);
  }

  /* ---------- run ---------- */
  async function run() {
    out.replaceChildren(h('p', { class: 'muted', text: 'Checking\u2026' }));
    try {
      var table = tIn.value.trim(), field = fIn.value.trim(), op = oSel.value, sysId = rIn.value.trim();
      var userId = users[uIn.value];
      if (!userId) throw new Error('Pick a user from the list.');
      if (!table) throw new Error('Enter a table name.');
      var chain = await tableChain(table);
      if (!chain.length) throw new Error('Table "' + table + '" was not found.');

      var plan = L.buildLevels(chain, field);
      var names = plan.record.concat(plan.field);
      var acls = await rows('sys_security_acl',
        'nameIN' + names.join(',') + '^operation.name=' + op + '^active=true^type.name=record',
        'sys_id,name,condition,advanced,admin_overrides', 1000);
      var roles = await userRoles(userId);
      var isSelf = !!self && userId === self.id;

      var evaluated = await Promise.all(acls.map(async function (a) {
        var need = await aclRoles(a.sys_id);
        var c = await evalCond(table, sysId, a.condition, isSelf);
        return L.evalAcl({
          id: a.sys_id, name: a.name, condition: a.condition,
          hasScript: a.advanced === 'true', adminOv: a.admin_overrides === 'true',
          need: need, condOk: c.ok, condNote: c.note
        }, roles);
      }));

      var result = L.decide(plan, evaluated);
      for (var s of [result.record, result.field]) {
        if (!s || s.decidedIdx < 0) continue;
        for (var e of s.levels[s.decidedIdx].acls) { if (sysId) await diagnose(table, sysId, e); }
      }
      render(result, { userLabel: uIn.value.replace(/ \(you\)$/, ''), table: table, field: field, op: op }, fixesFor(result));
      if (!acls.length) out.appendChild(h('p', { class: 'muted', text: 'No ACL rows were returned. If you expected some, this session may lack read access to sys_security_acl.' }));
    } catch (e) {
      out.replaceChildren(h('p', { class: 'err', text: e.message }));
    }
  }
})();
