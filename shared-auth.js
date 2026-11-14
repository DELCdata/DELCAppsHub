// DELC Apps Hub — shared auth helpers
// Loaded by the hub, the Admin Portal, and all four apps so a single login on
// one page is recognized by the others (they all share the delcdata.github.io
// origin, so localStorage here is visible to all of them).
//
// Security note: like the rest of these apps, this checks credentials
// entirely in the browser against a Supabase table reachable with a public
// key. That's fine for a small trusted group but is not the same as a real
// authentication backend — treat it as convenience, not a security boundary.
(function (global) {
  var SESSION_KEY = 'delc_hub_session';
  var SUPABASE_URL = 'https://ksdxhqyusaylfpyeecbv.supabase.co';
  var SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtzZHhocXl1c2F5bGZweWVlY2J2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg1NTE1NDgsImV4cCI6MjEwNDEyNzU0OH0.6HI0XWmlIfzyVy0iRH2GkAVNqYIZQwMeNhr4drTOUNo';

  // Built-in fallback list, used only if the hub_apps table can't be reached.
  // The real list of apps is managed in the Admin Portal ("Apps" section)
  // and stored in the hub_apps table.
  var DEFAULT_APPS = [
    { key: 'fb', name: 'delcEVENTS', icon: '🍽️', sort_order: 10, active: true,
      url: 'https://delcdata.github.io/FBEventPotal/',
      description: 'Plan and track food & beverage events, purchases, offerings, and volunteers.' },
    { key: 'mug', name: 'Motivational Mug POS', icon: '☕', sort_order: 20, active: true,
      url: 'https://delcdata.github.io/motivational-mug/',
      description: 'Point-of-sale for the Motivational Mug coffee shop — menu, orders, and closeouts.' },
    { key: 'pantry', name: 'delcPANTRY', icon: '🥫', sort_order: 30, active: true,
      url: 'https://delcdata.github.io/HSPMugPantry/',
      description: 'Manage food pantry inventory, receiving, dispensing, and stock counts.' },
    { key: 'pet', name: 'delcPETPANTRY', icon: '🐾', sort_order: 40, active: true,
      url: 'https://delcdata.github.io/DELCPETPANTRY/',
      description: 'Manage pet food & supply inventory, donations, and client distributions.' }
  ];

  var APP_LABELS = {};
  DEFAULT_APPS.forEach(function (a) { APP_LABELS[a.key] = a.name; });

  function restHeaders() {
    return {
      'apikey': SUPABASE_KEY,
      'Authorization': 'Bearer ' + SUPABASE_KEY,
      'Content-Type': 'application/json'
    };
  }

  async function sha256Hex(text) {
    var enc = new TextEncoder().encode(text);
    var buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  function genSalt() {
    var arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return Array.prototype.map.call(arr, function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  function hashPassword(password, salt) {
    return sha256Hex(salt + ':' + password);
  }

  function getSession() {
    try {
      var raw = localStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      var s = JSON.parse(raw);
      if (!s || !s.username) return null;
      return s;
    } catch (e) {
      return null;
    }
  }

  function setSession(session) {
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  }

  function clearSession() {
    localStorage.removeItem(SESSION_KEY);
  }

  function hasAppAccess(session, appKey) {
    if (!session) return false;
    if (session.isAdmin) return true;
    return Array.isArray(session.allowedApps) && session.allowedApps.indexOf(appKey) !== -1;
  }

  // Fetch a user row by username (lowercase). Returns null if not found.
  async function fetchUserByUsername(username) {
    var url = SUPABASE_URL + '/rest/v1/hub_users?username=eq.' +
      encodeURIComponent(username.toLowerCase()) + '&select=*';
    var res = await fetch(url, { headers: restHeaders() });
    if (!res.ok) throw new Error('Lookup failed (' + res.status + ')');
    var rows = await res.json();
    return rows && rows.length ? rows[0] : null;
  }

  // Fetch a user row by email (case-insensitive). Returns null if not found.
  async function fetchUserByEmail(email) {
    var url = SUPABASE_URL + '/rest/v1/hub_users?email=ilike.' +
      encodeURIComponent(String(email || '').trim().replace(/[%_*]/g, '')) + '&select=*';
    var res = await fetch(url, { headers: restHeaders() });
    if (!res.ok) throw new Error('Lookup failed (' + res.status + ')');
    var rows = await res.json();
    return rows && rows.length ? rows[0] : null;
  }

  // Attempt a login against hub_users. Returns {ok:true, session} or {ok:false, error}.
  // The first box accepts either the username (ddetrich) or the email (ddetrich@mydelc.org).
  async function login(username, password) {
    username = (username || '').trim().toLowerCase();
    if (!username) return { ok: false, error: 'Please enter your username or email.' };
    var user;
    try {
      user = username.indexOf('@') !== -1 ? await fetchUserByEmail(username) : await fetchUserByUsername(username);
    } catch (e) {
      return { ok: false, error: 'Could not reach the login service. Try again.' };
    }
    if (!user) return { ok: false, error: 'Incorrect username or password.' };
    var hash = await hashPassword(password, user.salt);
    if (hash !== user.password_hash) {
      return { ok: false, error: 'Incorrect username or password.' };
    }
    var session = {
      username: user.username,
      displayName: user.display_name || user.username,
      email: user.email,
      isAdmin: !!user.is_admin,
      allowedApps: Array.isArray(user.allowed_apps) ? user.allowed_apps : [],
      loggedInAt: new Date().toISOString()
    };
    setSession(session);
    return { ok: true, session: session };
  }

  // Load the list of hub apps from the hub_apps table (sorted).
  // includeInactive=true is used by the Admin Portal; the hub shows active only.
  // Falls back to DEFAULT_APPS if the table can't be reached.
  async function fetchApps(includeInactive) {
    try {
      var url = SUPABASE_URL + '/rest/v1/hub_apps?select=*&order=sort_order.asc,name.asc' +
        (includeInactive ? '' : '&active=eq.true');
      var res = await fetch(url, { headers: restHeaders() });
      if (!res.ok) throw new Error('Apps lookup failed (' + res.status + ')');
      var rows = await res.json();
      rows.forEach(function (a) { APP_LABELS[a.key] = a.name; });
      return { ok: true, apps: rows };
    } catch (e) {
      return { ok: false, apps: DEFAULT_APPS.slice(), error: e.message };
    }
  }

  // Re-read the signed-in user's row so newly granted apps (or a removed
  // account) take effect without logging out and back in.
  async function refreshSession() {
    var s = getSession();
    if (!s) return null;
    try {
      var user = await fetchUserByUsername(s.username);
      if (!user) { clearSession(); return null; }
      s.displayName = user.display_name || user.username;
      s.email = user.email;
      s.isAdmin = !!user.is_admin;
      s.allowedApps = Array.isArray(user.allowed_apps) ? user.allowed_apps : [];
      setSession(s);
    } catch (e) { /* offline: keep the cached session */ }
    return s;
  }

  // "Who changed it" (2026-11-14): every write to the database from any delcAPP carries the signed-in
  // hub username inside the x-client-info header (already allowed by the database's CORS rules).
  // A database trigger copies it into the row's updated_by column. Reads are untouched.
  (function stampWrites() {
    if (global.__delcStamp || typeof global.fetch !== 'function') return;
    global.__delcStamp = true;
    var orig = global.fetch; global.__delcOrigFetch = orig;
    global.fetch = function (input, init) {
      try {
        var url = typeof input === 'string' ? input : (input && input.url) || '';
        var method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD' && url.indexOf(SUPABASE_URL + '/rest/v1/') === 0) {
          var s = getSession(), u = s && String(s.username || '').replace(/[^A-Za-z0-9._-]/g, '');
          if (u) {
            init = Object.assign({}, init || {});
            var h = new Headers(init.headers || (input && input.headers) || {});
            var ci = h.get('x-client-info') || 'delc-apps';
            if (ci.indexOf('delc-user=') < 0) h.set('x-client-info', ci + ' delc-user=' + u);
            init.headers = h;
          }
        }
      } catch (e) { /* never block a save over this */ }
      return orig.call(this, input, init);
    };
  })();

  // "Last changed by …" (2026-11-14): an app puts <span class="delc-changed" data-t="<table>" data-id="<row id>"></span>
  // where it wants the line; this fills it from the row's updated_by / updated_at (recorded by the database on every save).
  (function lastChanged() {
    if (global.__delcChanged || typeof document === 'undefined' || typeof MutationObserver === 'undefined') return;
    global.__delcChanged = true;
    var names = null, namesAt = 0, cache = {};
    function hdr() { return {apikey: SUPABASE_KEY, Authorization: 'Bearer ' + SUPABASE_KEY}; }
    function loadNames() {
      if (names && Date.now() - namesAt < 600000) return Promise.resolve(names);
      if (loadNames.p) return loadNames.p;
      return loadNames.p = orig(SUPABASE_URL + '/rest/v1/hub_users?select=username,display_name', {headers: hdr()}).then(function (r) { return r.ok ? r.json() : []; })
        .then(function (L) { names = {}; (L || []).forEach(function (u) { names[String(u.username).toLowerCase()] = u.display_name || u.username; }); namesAt = Date.now(); return names; })
        .catch(function () { names = names || {}; return names; }).then(function (N) { loadNames.p = null; return N; });
    }
    var orig = function (u, o) { return (global.__delcOrigFetch || global.fetch)(u, o); };
    function when(ts) { var d = new Date(ts); if (isNaN(d)) return ''; var now = new Date(), same = d.toDateString() === now.toDateString();
      var t = d.toLocaleTimeString('en-US', {hour: 'numeric', minute: '2-digit'});
      return same ? 'today at ' + t : d.toLocaleDateString('en-US', {month: 'short', day: 'numeric', year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric'}) + ' at ' + t; }
    function who(by, N) { if (!by) return ''; var k = String(by).toLowerCase(); if (N[k]) return N[k];
      if (/^delc|apps admin|public form|daily/i.test(by)) return 'through ' + by;   // sync between apps, the admin page, public forms
      return by; }
    function fill(el) {
      var t = el.getAttribute('data-t'), id = el.getAttribute('data-id'); if (!t || !id || !/^[a-z_]+$/.test(t)) return;
      el.setAttribute('data-done', '1');
      var key = t + '|' + id, c;
      // data-also="table:column" also looks at related rows (e.g. a meeting's agenda items) and shows the newest change
      var also = (el.getAttribute('data-also') || '').split(',').map(function (x) { return x.trim().split(':'); }).filter(function (a) { return a.length === 2 && /^[a-z_]+$/.test(a[0]) && /^[a-z_]+$/.test(a[1]); });
      key += '|' + (el.getAttribute('data-also') || ''); c = cache[key];
      var get = function (url) { return orig(url, {headers: hdr()}).then(function (r) { return r.ok ? r.json() : []; }).catch(function () { return []; }); };
      var p = c && Date.now() - c.at < 5000 ? Promise.resolve(c.row) : Promise.all([get(SUPABASE_URL + '/rest/v1/' + t + '?select=updated_by,updated_at&id=eq.' + encodeURIComponent(id))].concat(also.map(function (a) {
          return get(SUPABASE_URL + '/rest/v1/' + a[0] + '?select=updated_by,updated_at&' + a[1] + '=eq.' + encodeURIComponent(id) + '&order=updated_at.desc.nullslast&limit=1'); })))
        .then(function (R) { var row = null; R.forEach(function (L) { var x = L && L[0]; if (x && x.updated_at && (!row || new Date(x.updated_at) > new Date(row.updated_at))) row = x; }); cache[key] = {at: Date.now(), row: row}; return row; });
      Promise.all([p, loadNames()]).then(function (a) {
        var row = a[0], N = a[1]; if (!row || !row.updated_at) { el.textContent = ''; return; }
        var w = who(row.updated_by, N);
        el.textContent = 'Last changed ' + (w ? (/^through /.test(w) ? w + ' ' : 'by ' + w + ' ') : '') + when(row.updated_at);
        el.title = row.updated_by ? 'Saved by ' + row.updated_by : '';
      }).catch(function () {});
    }
    function scan(root) { var L = (root || document).querySelectorAll ? (root || document).querySelectorAll('.delc-changed[data-t][data-id]:not([data-done])') : []; for (var i = 0; i < L.length; i++) fill(L[i]); }
    function start() {
      var st = document.createElement('style'); st.textContent = '.delc-changed{display:block;font-size:12px;color:#5d6a82;margin-top:4px}.delc-changed:empty{display:none}@media print{.delc-changed{display:none}}'; document.head.appendChild(st);
      scan(document); new MutationObserver(function () { scan(document); }).observe(document.body, {childList: true, subtree: true});
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  })();

  global.DelcAuth = {
    SESSION_KEY: SESSION_KEY,
    SUPABASE_URL: SUPABASE_URL,
    SUPABASE_KEY: SUPABASE_KEY,
    APP_LABELS: APP_LABELS,
    DEFAULT_APPS: DEFAULT_APPS,
    fetchApps: fetchApps,
    refreshSession: refreshSession,
    restHeaders: restHeaders,
    sha256Hex: sha256Hex,
    genSalt: genSalt,
    hashPassword: hashPassword,
    getSession: getSession,
    setSession: setSession,
    clearSession: clearSession,
    hasAppAccess: hasAppAccess,
    fetchUserByUsername: fetchUserByUsername,
    fetchUserByEmail: fetchUserByEmail,
    login: login
  };
})(window);
