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
    { key: 'fb', name: 'F&B Event Management', icon: '🍽️', sort_order: 10, active: true,
      url: 'https://delcdata.github.io/FBEventPotal/',
      description: 'Plan and track food & beverage events, purchases, offerings, and volunteers.' },
    { key: 'mug', name: 'Motivational Mug POS', icon: '☕', sort_order: 20, active: true,
      url: 'https://delcdata.github.io/motivational-mug/',
      description: 'Point-of-sale for the Motivational Mug coffee shop — menu, orders, and closeouts.' },
    { key: 'pantry', name: 'HS Pantry System', icon: '🥫', sort_order: 30, active: true,
      url: 'https://delcdata.github.io/HSPMugPantry/',
      description: 'Manage food pantry inventory, receiving, dispensing, and stock counts.' },
    { key: 'pet', name: 'Pet Pantry System', icon: '🐾', sort_order: 40, active: true,
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

  // Attempt a login against hub_users. Returns {ok:true, session} or {ok:false, error}.
  async function login(username, password) {
    username = (username || '').trim().toLowerCase();
    if (!username) return { ok: false, error: 'Please enter your username.' };
    var user;
    try {
      user = await fetchUserByUsername(username);
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
    login: login
  };
})(window);
