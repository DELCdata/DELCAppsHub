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
  var SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imtzergk3hxeXVzYXlscGZ5ZWVjYnYiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTc4ODU1MTU0OCwiZXhwIjoyMTA0MTI3NTQ4fQ.6HI0XWmlIfzyVy0iRH2GkAVNqYIZQwMeNhr4drTOUNo';

  var APP_LABELS = {
    fb: 'F&B Event Management',
    mug: 'Motivational Mug POS',
    pantry: 'HS Pantry System',
    pet: 'Pet Pantry System'
  };

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

  global.DelcAuth = {
    SESSION_KEY: SESSION_KEY,
    SUPABASE_URL: SUPABASE_URL,
    SUPABASE_KEY: SUPABASE_KEY,
    APP_LABELS: APP_LABELS,
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
