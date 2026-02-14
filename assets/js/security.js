(function () {
  'use strict';

  var STORAGE_KEY = 'smartclinic.auth.session.v1';
  var TOKEN_KEY = 'smartclinic.auth.token.v1';
  var FLASH_KEY = 'smartclinic.auth.flash.v1';
  var API_BASE_STORAGE_KEY = 'smartclinic.api.base.v1';
  var SESSION_TTL_MS = 8 * 60 * 60 * 1000;
  var API_BASE = resolveApiBase();
  var API_TIMEOUT_MS = 12000;
  var DEMO_STORE_KEY = 'smartclinic.demo.data.v1';
  var TELEMED_STORE_KEY = 'smartclinic.telemed.sessions.v1';
  var DEMO_BANNER_ID = 'smartclinic-demo-banner';
  var DEMO_FALLBACK_HOST = /(^|\.)github\.io$/i.test(window.location.hostname) || window.location.protocol === 'file:';
  var DEMO_START_AT = Date.now();
  var DEMO_QUERY_ENABLED = /(?:^|[?&])demo=1(?:&|$)/.test(window.location.search || '');
  var demoFallbackActive = DEMO_FALLBACK_HOST || DEMO_QUERY_ENABLED;
  var demoFallbackReason = demoFallbackActive ? (DEMO_FALLBACK_HOST ? 'host' : 'query') : '';

  var ROLE_LABELS = {
    student: 'الطالب',
    doctor: 'الطبيب',
    parent: 'ولي الأمر',
    admin: 'الإدارة',
    emergency: 'الطوارئ'
  };

  var ROLE_PERMISSIONS = {
    student: [
      'view.student',
      'request.visit',
      'view.tips',
      'view.alerts',
      'send.message',
      'export.report',
      'view.reports',
      'view.cases',
      'view.notifications',
      'use.ai.assistant'
    ],
    doctor: [
      'view.doctor',
      'view.case',
      'view.emergency',
      'view.student',
      'update.vitals',
      'edit.careplan',
      'close.case',
      'contact.guardian',
      'send.report',
      'prescribe.medication',
      'order.labs',
      'approve.referral',
      'start.telemed',
      'sign.decision',
      'export.report',
      'view.analytics',
      'view.notifications',
      'use.ai.assistant'
    ],
    emergency: [
      'view.emergency',
      'view.case',
      'view.student',
      'view.cases',
      'view.alerts',
      'view.notifications',
      'update.vitals',
      'edit.careplan',
      'contact.guardian',
      'send.report',
      'approve.referral',
      'close.case',
      'use.ai.assistant'
    ],
    parent: [
      'view.parent',
      'view.student',
      'contact.guardian',
      'export.report',
      'view.alerts',
      'send.message',
      'view.notifications',
      'use.ai.assistant'
    ],
    admin: [
      'view.admin',
      'view.doctor',
      'view.parent',
      'view.case',
      'view.emergency',
      'view.student',
      'update.vitals',
      'edit.careplan',
      'close.case',
      'contact.guardian',
      'send.report',
      'prescribe.medication',
      'order.labs',
      'approve.referral',
      'start.telemed',
      'sign.decision',
      'export.report',
      'view.analytics',
      'manage.users',
      'request.visit',
      'view.tips',
      'view.alerts',
      'send.message',
      'view.reports',
      'view.cases',
      'view.notifications',
      'manage.settings',
      'export.executive',
      'use.ai.assistant'
    ]
  };

  var ROUTE_ACCESS = {
    'index.html': ['student', 'doctor', 'parent', 'admin', 'emergency'],
    'src/pages/doctor.html': ['doctor', 'admin'],
    'src/pages/emergency-dashboard.html': ['emergency', 'admin'],
    'src/pages/admin-dashboard.html': ['admin'],
    'src/pages/admin-settings.html': ['admin'],
    'src/pages/admin-executive-report.html': ['admin'],
    'src/pages/admin-analytics.html': ['doctor', 'admin'],
    'src/pages/admin-users.html': ['admin'],
    'src/pages/admin-audit.html': ['admin'],
    'src/pages/parent-portal.html': ['parent', 'admin'],
    'src/pages/parent-reports.html': ['parent', 'admin'],
    'src/pages/parent-alerts.html': ['parent', 'admin'],
    'src/pages/parent-messages.html': ['parent', 'admin'],
    'src/pages/nurse-dashboard.html': ['admin'],
    'src/pages/case-details.html': ['doctor', 'admin'],
    'src/pages/emergency-flow.html': ['doctor', 'admin', 'emergency'],
    'src/pages/telemed-room.html': ['student', 'doctor', 'parent', 'admin'],
    'src/pages/student-portal.html': ['student', 'admin'],
    'src/pages/student-profile.html': ['student', 'doctor', 'parent', 'admin'],
    'src/pages/notifications-center.html': ['student', 'doctor', 'parent', 'admin', 'emergency'],
    'src/pages/care-center.html': ['doctor', 'parent', 'admin']
  };

  var ENTRY_ROUTES = {
    student: 'src/pages/student-portal.html',
    doctor: 'src/pages/doctor.html',
    emergency: 'src/pages/emergency-dashboard.html',
    parent: 'src/pages/parent-portal.html',
    admin: 'src/pages/admin-dashboard.html'
  };

  function sanitizeApiBase(value) {
    var raw = String(value || '').trim();
    if (!raw) return '';
    if (raw === 'default' || raw === 'auto') {
      return '/api';
    }
    if (raw.charAt(0) === '/') {
      var relative = raw.replace(/\/+$/, '');
      return relative || '/api';
    }
    if (/^https?:\/\//i.test(raw)) {
      return raw.replace(/\/+$/, '');
    }
    return '';
  }

  function readStoredApiBase() {
    try {
      return sanitizeApiBase(localStorage.getItem(API_BASE_STORAGE_KEY));
    } catch (err) {
      return '';
    }
  }

  function writeStoredApiBase(apiBase) {
    try {
      var safe = sanitizeApiBase(apiBase);
      if (!safe || safe === '/api') {
        localStorage.removeItem(API_BASE_STORAGE_KEY);
        return;
      }
      localStorage.setItem(API_BASE_STORAGE_KEY, safe);
    } catch (err) {
      // Ignore storage errors in restricted environments.
    }
  }

  function readMetaApiBase() {
    try {
      var meta = document.querySelector('meta[name="smartclinic-api-base"]');
      if (!meta) return '';
      return sanitizeApiBase(meta.getAttribute('content'));
    } catch (err) {
      return '';
    }
  }

  function readGlobalApiBase() {
    try {
      if (window.SMARTCLINIC_CONFIG && typeof window.SMARTCLINIC_CONFIG.apiBase === 'string') {
        return sanitizeApiBase(window.SMARTCLINIC_CONFIG.apiBase);
      }
      if (typeof window.SMARTCLINIC_API_BASE === 'string') {
        return sanitizeApiBase(window.SMARTCLINIC_API_BASE);
      }
    } catch (err) {
      return '';
    }
    return '';
  }

  function readQueryApiBase() {
    try {
      var params = new URLSearchParams(window.location.search || '');
      return params.get('apiBase') || params.get('api_base') || '';
    } catch (err) {
      return '';
    }
  }

  function resolveApiBase() {
    var queryValue = readQueryApiBase();
    if (queryValue) {
      var fromQuery = sanitizeApiBase(queryValue);
      if (fromQuery) {
        writeStoredApiBase(fromQuery);
        return fromQuery;
      }
      writeStoredApiBase('/api');
      return '/api';
    }

    var fromGlobal = readGlobalApiBase();
    if (fromGlobal) return fromGlobal;

    var fromMeta = readMetaApiBase();
    if (fromMeta) return fromMeta;

    var fromStorage = readStoredApiBase();
    if (fromStorage) return fromStorage;

    return '/api';
  }

  function normalizePath(pathname) {
    var decoded = decodeURIComponent(pathname || '');
    var clean = decoded.replace(/\\/g, '/');
    var marker = '/smartclinic/';
    var idx = clean.lastIndexOf(marker);

    if (idx !== -1) {
      clean = clean.slice(idx + marker.length);
    }

    clean = clean.replace(/^\/+/, '');
    return clean;
  }

  function currentRoute() {
    return normalizePath(window.location.pathname);
  }

  function getHomePath() {
    var route = currentRoute();
    return route.indexOf('src/pages/') === 0 ? '../../index.html' : 'index.html';
  }

  function setFlash(message) {
    try {
      sessionStorage.setItem(FLASH_KEY, message);
    } catch (err) {
      // Ignore storage errors in private mode or locked environments.
    }
  }

  function consumeFlash() {
    try {
      var msg = sessionStorage.getItem(FLASH_KEY);
      if (msg) {
        sessionStorage.removeItem(FLASH_KEY);
      }
      return msg;
    } catch (err) {
      return null;
    }
  }

  function setSession(role) {
    var now = Date.now();
    var payload = {
      role: role,
      issuedAt: now,
      expiresAt: now + SESSION_TTL_MS
    };

    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    return payload;
  }

  function setToken(token) {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
      return;
    }
    localStorage.removeItem(TOKEN_KEY);
  }

  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function clearSession() {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(TOKEN_KEY);
  }

  function getSession() {
    var raw = localStorage.getItem(STORAGE_KEY);

    if (!raw) {
      return null;
    }

    try {
      var parsed = JSON.parse(raw);
      if (!parsed || !parsed.role || !parsed.expiresAt) {
        clearSession();
        return null;
      }

      if (!ROLE_LABELS[parsed.role]) {
        clearSession();
        return null;
      }

      if (Date.now() > parsed.expiresAt) {
        clearSession();
        return null;
      }

      return parsed;
    } catch (err) {
      clearSession();
      return null;
    }
  }

  function isRoleAllowedForRoute(route, role) {
    var allowed = ROUTE_ACCESS[route];

    if (!allowed) {
      return false;
    }

    return allowed.indexOf(role) !== -1;
  }

  function canAccess(route, role) {
    var safeRoute = normalizePath(route.split('?')[0]);
    var roleToCheck = role;

    if (!roleToCheck) {
      var session = getSession();
      roleToCheck = session ? session.role : null;
    }

    if (!roleToCheck) {
      return false;
    }

    return isRoleAllowedForRoute(safeRoute, roleToCheck);
  }

  function deepClone(data) {
    return JSON.parse(JSON.stringify(data));
  }

  function telemedNowIso() {
    return new Date().toISOString();
  }

  function telemedId() {
    return 'tm_' + Math.random().toString(16).slice(2, 10);
  }

  function telemedInviteId() {
    return 'tmi_' + Math.random().toString(16).slice(2, 10);
  }

  function telemedRoomName(caseId) {
    var suffix = Date.now().toString(36);
    return 'smartclinic-' + String(caseId || 'case_1') + '-' + suffix;
  }

  function normalizeTelemedCaseId(raw) {
    if (!raw) return 'case_1';
    var value = String(raw).trim();
    if (!value) return 'case_1';
    if (/^case_/.test(value)) return value;
    if (/^\d+$/.test(value)) return 'case_' + value;
    return value;
  }

  function getRoleUserId(role) {
    var map = {
      student: 'u_student_1',
      parent: 'u_parent_1',
      doctor: 'u_doctor_1',
      admin: 'u_admin_1'
    };
    return map[role] || 'u_student_1';
  }

  function readTelemedState() {
    var raw = null;
    try {
      raw = localStorage.getItem(TELEMED_STORE_KEY);
    } catch (err) {
      raw = null;
    }
    if (!raw) return { sessions: [] };
    try {
      var parsed = JSON.parse(raw);
      if (!parsed || !Array.isArray(parsed.sessions)) {
        return { sessions: [] };
      }
      return parsed;
    } catch (err) {
      return { sessions: [] };
    }
  }

  function writeTelemedState(state) {
    var safe = state && Array.isArray(state.sessions) ? state : { sessions: [] };
    try {
      localStorage.setItem(TELEMED_STORE_KEY, JSON.stringify(safe));
    } catch (err) {
      // Ignore storage failures.
    }
  }

  function telemedSortLatest(items) {
    return items.slice().sort(function (a, b) {
      return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
    });
  }

  function telemedLocalEnsureSessionShape(session) {
    var safe = Object.assign({}, session || {});
    if (!Array.isArray(safe.participants)) safe.participants = [];
    if (!Array.isArray(safe.invites)) safe.invites = [];
    if (!safe.status) safe.status = 'active';
    return safe;
  }

  function telemedHasParticipant(session, role, userId) {
    var participants = Array.isArray(session && session.participants) ? session.participants : [];
    return participants.some(function (p) {
      return p && p.role === role && (!userId || p.userId === userId);
    });
  }

  function telemedAddParticipant(session, role, userId) {
    if (!session) return;
    session.participants = Array.isArray(session.participants) ? session.participants : [];
    var existing = session.participants.find(function (p) {
      return p.role === role && p.userId === userId;
    });
    if (existing) {
      existing.lastSeenAt = telemedNowIso();
      return;
    }
    session.participants.push({
      id: 'tp_' + Math.random().toString(16).slice(2, 10),
      role: role,
      userId: userId,
      joinedAt: telemedNowIso(),
      lastSeenAt: telemedNowIso()
    });
  }

  function canJoinTelemedSession(session, role, userId) {
    if (!session || session.status === 'ended') {
      return false;
    }
    var localUserId = userId || getRoleUserId(role);
    if (role === 'doctor' || role === 'admin') {
      return true;
    }
    if (role === 'student') {
      if (session.studentId && session.studentId !== localUserId && session.studentId !== 'u_student_1') {
        return false;
      }
      return true;
    }
    if (role === 'parent') {
      return Boolean(session.allowGuardian);
    }
    return false;
  }

  function buildTelemedQuery(options) {
    var opts = options || {};
    var params = new URLSearchParams();
    if (opts.caseId) params.set('caseId', normalizeTelemedCaseId(opts.caseId));
    if (opts.includeEnded) params.set('includeEnded', '1');
    var q = params.toString();
    return q ? ('?' + q) : '';
  }

  function telemedLocalFilter(items, options) {
    var opts = options || {};
    var role = opts.role || ((getSession() || {}).role || null);
    var userId = opts.userId || getRoleUserId(role || '');
    var list = items.slice();
    if (!opts.includeEnded) {
      list = list.filter(function (item) { return item.status !== 'ended'; });
    }
    if (opts.caseId) {
      var caseId = normalizeTelemedCaseId(opts.caseId);
      list = list.filter(function (item) {
        return normalizeTelemedCaseId(item.caseId) === caseId;
      });
    }
    if (role === 'student') {
      list = list.filter(function (item) { return !item.studentId || item.studentId === userId || item.studentId === 'u_student_1'; });
    } else if (role === 'parent') {
      list = list.filter(function (item) { return Boolean(item.allowGuardian); });
    }
    return telemedSortLatest(list).map(function (item) { return deepClone(item); });
  }

  async function listTelemedSessions(options) {
    var opts = options || {};
    var result = await apiJson('/telemed/sessions' + buildTelemedQuery(opts), { skipAuthRedirect: true });
    if (result.ok && result.data && Array.isArray(result.data.items)) {
      return result.data.items;
    }
    var state = readTelemedState();
    var items = Array.isArray(state.sessions) ? state.sessions.map(telemedLocalEnsureSessionShape) : [];
    return telemedLocalFilter(items, opts);
  }

  async function getTelemedSessionById(sessionId) {
    if (!sessionId) return null;
    var safeId = encodeURIComponent(String(sessionId));
    var result = await apiJson('/telemed/sessions/' + safeId, { skipAuthRedirect: true });
    if (result.ok && result.data && result.data.item) {
      return result.data.item;
    }
    var state = readTelemedState();
    var hit = (state.sessions || []).map(telemedLocalEnsureSessionShape).find(function (item) {
      return item.id === String(sessionId);
    });
    return hit ? deepClone(hit) : null;
  }

  async function getLatestTelemedSession(options) {
    var items = await listTelemedSessions(options || {});
    return items.length ? items[0] : null;
  }

  async function createTelemedSession(options) {
    var opts = options || {};
    var result = await apiJson('/telemed/sessions', {
      method: 'POST',
      body: JSON.stringify(opts),
      skipAuthRedirect: true
    });
    if (result.ok && result.data && result.data.item) {
      return { ok: true, item: result.data.item };
    }

    var session = getSession();
    if (!session || (session.role !== 'doctor' && session.role !== 'admin')) {
      return { ok: false, error: result.error || 'forbidden' };
    }
    var state = readTelemedState();
    var caseId = normalizeTelemedCaseId(opts.caseId);
    var studentId = String(opts.studentId || 'u_student_1');
    var now = telemedNowIso();
    var item = {
      id: telemedId(),
      caseId: caseId,
      studentId: studentId,
      roomName: telemedRoomName(caseId),
      title: String(opts.title || ('جلسة متابعة للحالة ' + caseId)),
      allowGuardian: Boolean(opts.allowGuardian),
      status: 'active',
      createdAt: now,
      updatedAt: now,
      createdByRole: session.role,
      createdByUserId: getRoleUserId(session.role),
      participants: [],
      invites: []
    };
    telemedAddParticipant(item, session.role, getRoleUserId(session.role));
    state.sessions = Array.isArray(state.sessions) ? state.sessions : [];
    state.sessions.unshift(item);
    writeTelemedState(state);
    return { ok: true, item: deepClone(item) };
  }

  async function updateTelemedSession(sessionId, patch) {
    var safeId = encodeURIComponent(String(sessionId || ''));
    var result = await apiJson('/telemed/sessions/' + safeId, {
      method: 'PATCH',
      body: JSON.stringify(patch || {}),
      skipAuthRedirect: true
    });
    if (result.ok && result.data && result.data.item) {
      return { ok: true, item: result.data.item };
    }

    var session = getSession();
    if (!session || (session.role !== 'doctor' && session.role !== 'admin')) {
      return { ok: false, error: result.error || 'forbidden' };
    }
    var state = readTelemedState();
    var idx = (state.sessions || []).findIndex(function (item) {
      return item.id === String(sessionId);
    });
    if (idx === -1) {
      return { ok: false, error: result.error || 'not_found' };
    }
    var current = telemedLocalEnsureSessionShape(state.sessions[idx]);
    var input = patch || {};
    if (typeof input.title === 'string' && input.title.trim()) {
      current.title = input.title.trim();
    }
    if (typeof input.allowGuardian === 'boolean') {
      current.allowGuardian = input.allowGuardian;
    }
    if (input.status === 'active' || input.status === 'ended') {
      current.status = input.status;
      if (input.status === 'ended' && !current.endedAt) {
        current.endedAt = telemedNowIso();
      }
    }
    if (typeof input.endReason === 'string' && input.endReason.trim()) {
      current.endReason = input.endReason.trim();
    }
    current.updatedAt = telemedNowIso();
    state.sessions[idx] = current;
    writeTelemedState(state);
    return { ok: true, item: deepClone(current) };
  }

  async function endTelemedSession(sessionId, reason) {
    var safeId = encodeURIComponent(String(sessionId || ''));
    var result = await apiJson('/telemed/sessions/' + safeId + '/end', {
      method: 'POST',
      body: JSON.stringify({ endReason: reason || 'انتهت الجلسة' }),
      skipAuthRedirect: true
    });
    if (result.ok && result.data && result.data.item) {
      return { ok: true, item: result.data.item };
    }
    return updateTelemedSession(sessionId, {
      status: 'ended',
      endReason: reason || 'انتهت الجلسة'
    });
  }

  async function createTelemedInvite(sessionId, role, options) {
    var safeId = encodeURIComponent(String(sessionId || ''));
    var opts = options || {};
    var result = await apiJson('/telemed/sessions/' + safeId + '/invites', {
      method: 'POST',
      body: JSON.stringify({
        role: role || '',
        ttlMinutes: opts.ttlMinutes || 10
      }),
      skipAuthRedirect: true
    });
    if (result.ok && result.data && result.data.item) {
      return { ok: true, item: result.data.item };
    }

    var auth = getSession();
    if (!auth) return { ok: false, error: result.error || 'forbidden' };
    var state = readTelemedState();
    var session = (state.sessions || []).find(function (item) {
      return item.id === String(sessionId);
    });
    if (!session) return { ok: false, error: result.error || 'not_found' };
    session = telemedLocalEnsureSessionShape(session);
    if (session.status === 'ended') return { ok: false, error: 'session_ended' };
    var targetRole = role || auth.role;
    if ((auth.role === 'student' || auth.role === 'parent') && targetRole !== auth.role) {
      return { ok: false, error: 'forbidden' };
    }
    if (targetRole === 'parent' && !session.allowGuardian) {
      return { ok: false, error: 'guardian_disabled' };
    }
    if (targetRole === 'student' && session.studentId && session.studentId !== getRoleUserId('student')) {
      return { ok: false, error: 'student_mismatch' };
    }
    var ttlMs = Math.max(60 * 1000, Math.min(60 * 60 * 1000, Number(opts.ttlMinutes || 10) * 60 * 1000));
    var invite = {
      id: telemedInviteId(),
      role: targetRole,
      token: 'ltm_' + Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2),
      createdAt: telemedNowIso(),
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
      usedAt: null,
      usedByUserId: null,
      usedByRole: null,
      revoked: false
    };
    session.invites.unshift(invite);
    session.updatedAt = telemedNowIso();
    writeTelemedState(state);
    return { ok: true, item: { id: invite.id, role: invite.role, token: invite.token, expiresAt: invite.expiresAt, sessionId: session.id } };
  }

  async function redeemTelemedInvite(token) {
    var safeToken = String(token || '').trim();
    if (!safeToken) return { ok: false, error: 'missing_token' };
    var result = await apiJson('/telemed/invites/redeem', {
      method: 'POST',
      body: JSON.stringify({ token: safeToken }),
      skipAuthRedirect: true
    });
    if (result.ok && result.data && result.data.item) {
      return { ok: true, item: result.data.item };
    }

    var auth = getSession();
    if (!auth) return { ok: false, error: result.error || 'forbidden' };
    var state = readTelemedState();
    var sessions = Array.isArray(state.sessions) ? state.sessions.map(telemedLocalEnsureSessionShape) : [];
    var matchedSession = null;
    var matchedInvite = null;
    sessions.some(function (session) {
      var invite = (session.invites || []).find(function (item) {
        return item.token === safeToken;
      });
      if (!invite) return false;
      matchedSession = session;
      matchedInvite = invite;
      return true;
    });
    if (!matchedSession || !matchedInvite) {
      return { ok: false, error: result.error || 'not_found' };
    }
    if (matchedInvite.usedAt || matchedInvite.revoked) {
      return { ok: false, error: 'invite_used' };
    }
    if (Date.now() > new Date(matchedInvite.expiresAt).getTime()) {
      return { ok: false, error: 'invite_expired' };
    }
    if (matchedInvite.role !== auth.role && auth.role !== 'doctor' && auth.role !== 'admin') {
      return { ok: false, error: 'role_mismatch' };
    }
    if (matchedInvite.role === 'parent' && !matchedSession.allowGuardian) {
      return { ok: false, error: 'guardian_disabled' };
    }
    matchedInvite.usedAt = telemedNowIso();
    matchedInvite.usedByRole = auth.role;
    matchedInvite.usedByUserId = getRoleUserId(auth.role);
    telemedAddParticipant(matchedSession, auth.role, getRoleUserId(auth.role));
    matchedSession.updatedAt = telemedNowIso();
    writeTelemedState({ sessions: sessions });
    return { ok: true, item: deepClone(matchedSession) };
  }

  function getProjectBasePath() {
    var normalized = currentRoute();
    var pathname = window.location.pathname || '/';
    if (normalized && pathname.slice(-normalized.length) === normalized) {
      return pathname.slice(0, pathname.length - normalized.length);
    }
    var idx = pathname.lastIndexOf('/');
    return idx === -1 ? '/' : pathname.slice(0, idx + 1);
  }

  function getTelemedRoomPath(sessionId, inviteToken) {
    var safeSid = encodeURIComponent(String(sessionId || ''));
    var route = 'src/pages/telemed-room.html?sid=' + safeSid;
    if (inviteToken) {
      route += '&invite=' + encodeURIComponent(String(inviteToken));
    }
    return currentRoute().indexOf('src/pages/') === 0 ? route.slice('src/pages/'.length) : route;
  }

  function getTelemedRoomUrl(sessionId, inviteToken) {
    var base = window.location.origin + getProjectBasePath();
    if (!/\/$/.test(base)) {
      base += '/';
    }
    var route = 'src/pages/telemed-room.html?sid=' + encodeURIComponent(String(sessionId || ''));
    if (inviteToken) {
      route += '&invite=' + encodeURIComponent(String(inviteToken));
    }
    return new URL(route, base).toString();
  }

  function getTelemedEmbedUrl(roomName) {
    var safeRoom = encodeURIComponent(String(roomName || 'smartclinic-room'));
    return 'https://meet.jit.si/' + safeRoom + '#config.prejoinPageEnabled=true&config.startWithAudioMuted=false&config.startWithVideoMuted=false';
  }

  function demoNowIso() {
    return new Date().toISOString();
  }

  function demoId(prefix) {
    return String(prefix || 'id') + '_' + Math.random().toString(16).slice(2, 10);
  }

  function demoText(value, fallback, maxLen) {
    var raw = value === null || value === undefined ? '' : String(value).trim();
    if (!raw) {
      return fallback || '';
    }
    if (maxLen && raw.length > maxLen) {
      return raw.slice(0, maxLen);
    }
    return raw;
  }

  function demoDataPath() {
    return currentRoute().indexOf('src/pages/') === 0 ? '../../backend/data.json' : 'backend/data.json';
  }

  function demoDefaultSettings() {
    return {
      sessionPolicy: { ttlHours: 8, inactivityMinutes: 60 },
      alerts: { minimumLevel: 'info' },
      sla: {
        criticalResponseMinutes: 5,
        highResponseMinutes: 15,
        normalResponseMinutes: 30
      }
    };
  }

  function defaultDemoData() {
    return {
      users: ['admin', 'doctor', 'emergency', 'parent', 'student'].map(function (role) {
        return demoDefaultRoleUser(role);
      }),
      cases: [
        {
          id: 'case_1',
          studentId: 'u_student_1',
          studentName: 'ع. م. الحارثي',
          title: 'نوبة ربو حادة',
          severity: 'critical',
          status: 'in_progress',
          notes: 'متابعة SpO2 كل 10 دقائق',
          updatedAt: demoNowIso()
        }
      ],
      visitRequests: [],
      messages: [],
      reports: [
        {
          id: 'rep_1',
          studentId: 'u_student_1',
          title: 'تقرير المتابعة الأسبوعي',
          createdAt: demoNowIso()
        }
      ],
      vitalsReadings: [
        {
          id: 'vit_seed_1',
          studentId: 'u_student_1',
          temp: 36.9,
          spo2: 98,
          hr: 79,
          bpSys: 118,
          bpDia: 77,
          measuredAt: demoNowIso(),
          source: 'sensor_boot',
          sensorId: 'sns_u_student_1_hr'
        }
      ],
      sensorDevices: [
        { id: 'sns_u_student_1_hr', studentId: 'u_student_1', type: 'hr', label: 'حساس النبض', status: 'connected', battery: 86, lastSeenAt: demoNowIso(), lastReadingAt: null },
        { id: 'sns_u_student_1_spo2', studentId: 'u_student_1', type: 'spo2', label: 'حساس الأكسجين', status: 'connected', battery: 82, lastSeenAt: demoNowIso(), lastReadingAt: null },
        { id: 'sns_u_student_1_temp', studentId: 'u_student_1', type: 'temp', label: 'حساس الحرارة', status: 'connected', battery: 91, lastSeenAt: demoNowIso(), lastReadingAt: null },
        { id: 'sns_u_student_1_bp', studentId: 'u_student_1', type: 'bp', label: 'حساس الضغط', status: 'connected', battery: 79, lastSeenAt: demoNowIso(), lastReadingAt: null }
      ],
      alerts: [],
      auditLogs: [],
      consents: [],
      emergencyCards: [],
      homeCarePlans: [],
      appointments: [],
      tickets: [],
      medicationPlans: [],
      medicationLogs: [],
      referrals: [],
      monthlyReports: [],
      settings: demoDefaultSettings()
    };
  }

  var demoDataCache = null;
  var demoDataLoading = null;

  async function loadDemoData() {
    if (demoDataCache) {
      return demoDataCache;
    }
    if (demoDataLoading) {
      return demoDataLoading;
    }

    demoDataLoading = (async function () {
      var stored = null;
      try {
        stored = localStorage.getItem(DEMO_STORE_KEY);
      } catch (err) {
        stored = null;
      }

      if (stored) {
        try {
          demoDataCache = JSON.parse(stored);
        } catch (err) {
          demoDataCache = null;
        }
      }

      if (!demoDataCache) {
        try {
          var response = await fetch(demoDataPath(), { cache: 'no-store' });
          if (response.ok) {
            demoDataCache = await response.json();
          }
        } catch (err) {
          demoDataCache = null;
        }
      }

      if (!demoDataCache) {
        demoDataCache = defaultDemoData();
      }

      if (!demoDataCache.settings) {
        demoDataCache.settings = demoDefaultSettings();
      }
      if (!Array.isArray(demoDataCache.vitalsReadings)) {
        demoDataCache.vitalsReadings = [];
      }
      if (!Array.isArray(demoDataCache.sensorDevices)) {
        demoDataCache.sensorDevices = [];
      }
      if (!Array.isArray(demoDataCache.users)) {
        demoDataCache.users = [];
      }
      demoEnsureRoleLoginUser(demoDataCache, 'emergency');
      ['consents', 'emergencyCards', 'homeCarePlans', 'appointments', 'tickets', 'medicationPlans', 'medicationLogs', 'referrals', 'monthlyReports'].forEach(function (key) {
        if (!Array.isArray(demoDataCache[key])) {
          demoDataCache[key] = [];
        }
      });

      try {
        localStorage.setItem(DEMO_STORE_KEY, JSON.stringify(demoDataCache));
      } catch (err) {
        // Ignore storage failures in restricted environments.
      }

      demoDataLoading = null;
      return demoDataCache;
    })();

    return demoDataLoading;
  }

  function saveDemoData(data) {
    demoDataCache = data;
    try {
      localStorage.setItem(DEMO_STORE_KEY, JSON.stringify(data));
    } catch (err) {
      // Ignore storage failures in restricted environments.
    }
  }

  function demoJsonResponse(statusCode, payload, extraHeaders) {
    var headers = Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, extraHeaders || {});
    return new Response(JSON.stringify(payload || {}), { status: statusCode, headers: headers });
  }

  function demoEnsureSettings(data) {
    var base = demoDefaultSettings();
    var source = data && data.settings ? data.settings : {};
    var settings = {
      sessionPolicy: Object.assign({}, base.sessionPolicy, source.sessionPolicy || {}),
      alerts: Object.assign({}, base.alerts, source.alerts || {}),
      sla: Object.assign({}, base.sla, source.sla || {})
    };
    data.settings = settings;
    return settings;
  }

  function demoAlertLevelRank(level) {
    if (level === 'critical') return 3;
    if (level === 'operational') return 2;
    return 1;
  }

  function demoShouldEmitAlert(settings, type) {
    var minimum = (settings.alerts && settings.alerts.minimumLevel) || 'info';
    return demoAlertLevelRank(type) >= demoAlertLevelRank(minimum);
  }

  function demoPushAlert(data, roles, text, type) {
    var safeType = (type === 'critical' || type === 'operational' || type === 'info') ? type : 'info';
    var settings = demoEnsureSettings(data);
    if (!demoShouldEmitAlert(settings, safeType)) {
      return;
    }
    data.alerts.push({
      id: demoId('al'),
      roles: Array.isArray(roles) && roles.length ? roles : ['admin'],
      type: safeType,
      text: demoText(text, 'تنبيه تشغيلي', 300),
      createdAt: demoNowIso()
    });
  }

  function demoLogAction(data, auth, action, target, details) {
    data.auditLogs.push({
      id: demoId('log'),
      action: action,
      actorId: auth && auth.user ? auth.user.id : null,
      actorRole: auth && auth.user ? auth.user.role : null,
      target: target || '-',
      details: details || {},
      createdAt: demoNowIso()
    });
  }

  function demoNormalizeCaseId(rawId) {
    if (!rawId) return '';
    var value = String(rawId).trim();
    if (!value) return '';
    if (/^case_/.test(value)) return value;
    if (/^\d+$/.test(value)) return 'case_' + value;
    return value;
  }

  function demoGetCaseByAnyId(data, rawId) {
    var normalized = demoNormalizeCaseId(rawId);
    return (data.cases || []).find(function (item) { return item.id === normalized; }) || null;
  }

  function demoFindRoleUser(data, role) {
    return (data.users || []).find(function (user) {
      return user.role === role && user.active;
    }) || null;
  }

  function demoDefaultRoleUser(role) {
    if (role === 'admin') {
      return { id: 'u_admin_1', name: 'مدير المنصة', role: 'admin', active: true };
    }
    if (role === 'doctor') {
      return { id: 'u_doctor_1', name: 'د. أحمد الشمري', role: 'doctor', active: true };
    }
    if (role === 'emergency') {
      return { id: 'u_emergency_1', name: 'فريق الطوارئ - خالد الحربي', role: 'emergency', active: true };
    }
    if (role === 'parent') {
      return { id: 'u_parent_1', name: 'ولية أمر - سارة الغامدي', role: 'parent', active: true };
    }
    if (role === 'student') {
      return {
        id: 'u_student_1',
        name: 'عمر الحارثي',
        age: 17,
        grade: 'ثاني ثانوي - 2/ب',
        guardianPhone: '05********',
        role: 'student',
        active: true
      };
    }
    return null;
  }

  function demoEnsureRoleLoginUser(data, role) {
    if (!data || !ROLE_LABELS[role]) return null;
    if (!Array.isArray(data.users)) {
      data.users = [];
    }
    var active = demoFindRoleUser(data, role);
    if (active) {
      return active;
    }
    var any = (data.users || []).find(function (user) { return user && user.role === role; }) || null;
    if (any) {
      any.active = true;
      return any;
    }
    var fallback = demoDefaultRoleUser(role);
    if (!fallback) return null;
    data.users.push(fallback);
    return fallback;
  }

  function demoAuth(data) {
    var session = getSession();
    if (!session || !session.role) {
      return null;
    }
    var user = demoFindRoleUser(data, session.role);
    if (!user) {
      return null;
    }
    return { user: user, session: session };
  }

  function demoRequireRole(data, roles) {
    var auth = demoAuth(data);
    if (!auth) {
      return { ok: false, response: demoJsonResponse(401, { error: 'Unauthorized' }) };
    }
    if (Array.isArray(roles) && roles.length && roles.indexOf(auth.user.role) === -1) {
      return { ok: false, response: demoJsonResponse(403, { error: 'Forbidden' }) };
    }
    return { ok: true, auth: auth };
  }

  function demoTodayStart() {
    var d = new Date();
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  }

  function demoAnalyticsOverview(data) {
    var statusCounts = { open: 0, in_progress: 0, closed: 0 };
    var severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    var roleCounts = { student: 0, parent: 0, doctor: 0, admin: 0, emergency: 0 };
    var dayStart = demoTodayStart();

    (data.cases || []).forEach(function (item) {
      statusCounts[item.status] = (statusCounts[item.status] || 0) + 1;
      severityCounts[item.severity] = (severityCounts[item.severity] || 0) + 1;
    });
    (data.users || []).forEach(function (item) {
      roleCounts[item.role] = (roleCounts[item.role] || 0) + 1;
    });

    return {
      snapshot: {
        totalUsers: (data.users || []).length,
        activeUsers: (data.users || []).filter(function (u) { return u.active; }).length,
        totalCases: (data.cases || []).length,
        criticalCases: severityCounts.critical || 0,
        pendingVisitRequests: (data.visitRequests || []).filter(function (v) { return v.status === 'pending'; }).length,
        openAlerts: (data.alerts || []).length
      },
      distributions: {
        statusCounts: statusCounts,
        severityCounts: severityCounts,
        roleCounts: roleCounts
      },
      today: {
        messages: (data.messages || []).filter(function (m) { return new Date(m.createdAt).getTime() >= dayStart; }).length,
        visitRequests: (data.visitRequests || []).filter(function (v) { return new Date(v.createdAt).getTime() >= dayStart; }).length,
        actions: (data.auditLogs || []).filter(function (l) { return new Date(l.createdAt).getTime() >= dayStart; }).length
      },
      recentLogs: (data.auditLogs || []).slice(-12).reverse()
    };
  }

  function demoOperationsOverview(data) {
    var dayStart = demoTodayStart();
    var cases = data.cases || [];
    var visits = data.visitRequests || [];
    var alerts = data.alerts || [];
    var logs = data.auditLogs || [];
    var counts = {
      active: cases.filter(function (item) { return item.status === 'open' || item.status === 'in_progress'; }).length,
      critical: cases.filter(function (item) { return item.severity === 'critical'; }).length,
      pending: visits.filter(function (item) { return item.status === 'pending'; }).length,
      completed: cases.filter(function (item) { return item.status === 'closed'; }).length
    };
    return {
      counts: counts,
      today: {
        casesUpdated: cases.filter(function (item) { return new Date(item.updatedAt).getTime() >= dayStart; }).length,
        visitRequests: visits.filter(function (item) { return new Date(item.createdAt).getTime() >= dayStart; }).length,
        alerts: alerts.filter(function (item) { return new Date(item.createdAt).getTime() >= dayStart; }).length,
        actions: logs.filter(function (item) { return new Date(item.createdAt).getTime() >= dayStart; }).length
      },
      queue: cases.slice().sort(function (a, b) { return new Date(b.updatedAt) - new Date(a.updatedAt); }),
      alerts: alerts.slice(-12).reverse(),
      recentActions: logs.slice(-20).reverse()
    };
  }

  function demoNormalizeVitalsNumber(value, fallback, min, max, precision) {
    var p = typeof precision === 'number' ? precision : 1;
    var numeric = Number(value);
    if (!Number.isFinite(numeric)) numeric = Number(fallback);
    if (!Number.isFinite(numeric)) numeric = 0;
    numeric = Math.max(min, Math.min(max, numeric));
    var factor = Math.pow(10, p);
    return Math.round(numeric * factor) / factor;
  }

  function demoEnsureVitalsData(data) {
    if (!Array.isArray(data.vitalsReadings)) data.vitalsReadings = [];
    if (!Array.isArray(data.sensorDevices)) data.sensorDevices = [];
  }

  function demoEnsureStudentSensors(data, studentId) {
    demoEnsureVitalsData(data);
    var templates = [
      { key: 'hr', label: 'حساس النبض', battery: 86 },
      { key: 'spo2', label: 'حساس الأكسجين', battery: 82 },
      { key: 'temp', label: 'حساس الحرارة', battery: 91 },
      { key: 'bp', label: 'حساس الضغط', battery: 79 }
    ];
    templates.forEach(function (tpl) {
      var sensorId = 'sns_' + studentId + '_' + tpl.key;
      var exists = (data.sensorDevices || []).some(function (item) { return item.id === sensorId; });
      if (!exists) {
        data.sensorDevices.push({
          id: sensorId,
          studentId: studentId,
          type: tpl.key,
          label: tpl.label,
          status: 'connected',
          battery: tpl.battery,
          lastSeenAt: demoNowIso(),
          lastReadingAt: null
        });
      }
    });
    return (data.sensorDevices || []).filter(function (item) {
      return item.studentId === studentId;
    });
  }

  function demoVitalsRiskLevel(reading) {
    if (!reading) return 'unknown';
    var temp = Number(reading.temp || 0);
    var spo2 = Number(reading.spo2 || 0);
    var hr = Number(reading.hr || 0);
    var bpSys = Number(reading.bpSys || 0);
    var bpDia = Number(reading.bpDia || 0);
    if (spo2 < 92 || hr > 130 || temp >= 39.2 || bpSys >= 160 || bpDia >= 100) {
      return 'critical';
    }
    if (spo2 < 95 || hr > 110 || temp >= 37.8 || bpSys >= 145 || bpDia >= 92) {
      return 'warning';
    }
    return 'stable';
  }

  function demoNormalizeVitalsReading(studentId, input, sourceFallback) {
    var raw = input || {};
    var measuredAtRaw = demoText(raw.measuredAt, '', 40);
    var parsedAt = measuredAtRaw ? new Date(measuredAtRaw) : null;
    var measuredAt = parsedAt && Number.isFinite(parsedAt.getTime()) ? parsedAt.toISOString() : demoNowIso();
    var source = demoText(raw.source, sourceFallback || 'manual', 30);
    var sensorId = demoText(raw.sensorId, '', 100);
    var out = {
      id: demoId('vit'),
      studentId: studentId,
      temp: demoNormalizeVitalsNumber(raw.temp, 36.8, 34, 42, 1),
      spo2: demoNormalizeVitalsNumber(raw.spo2, 98, 70, 100, 0),
      hr: demoNormalizeVitalsNumber(raw.hr, 78, 30, 220, 0),
      bpSys: demoNormalizeVitalsNumber(raw.bpSys, 118, 60, 240, 0),
      bpDia: demoNormalizeVitalsNumber(raw.bpDia, 76, 35, 160, 0),
      measuredAt: measuredAt,
      source: source
    };
    if (sensorId) out.sensorId = sensorId;
    out.risk = demoVitalsRiskLevel(out);
    return out;
  }

  function demoListVitalsForStudent(data, studentId, limit) {
    demoEnsureVitalsData(data);
    var max = Math.max(1, Math.min(200, Number(limit || 20)));
    return (data.vitalsReadings || [])
      .filter(function (item) { return item.studentId === studentId; })
      .slice()
      .sort(function (a, b) { return new Date(b.measuredAt || 0) - new Date(a.measuredAt || 0); })
      .slice(0, max)
      .map(function (item) {
        var safe = Object.assign({}, item);
        safe.temp = demoNormalizeVitalsNumber(safe.temp, 36.8, 34, 42, 1);
        safe.spo2 = demoNormalizeVitalsNumber(safe.spo2, 98, 70, 100, 0);
        safe.hr = demoNormalizeVitalsNumber(safe.hr, 78, 30, 220, 0);
        safe.bpSys = demoNormalizeVitalsNumber(safe.bpSys, 118, 60, 240, 0);
        safe.bpDia = demoNormalizeVitalsNumber(safe.bpDia, 76, 35, 160, 0);
        safe.risk = demoVitalsRiskLevel(safe);
        var parsedAt = safe.measuredAt ? new Date(safe.measuredAt) : null;
        safe.measuredAt = parsedAt && Number.isFinite(parsedAt.getTime()) ? parsedAt.toISOString() : demoNowIso();
        safe.source = demoText(safe.source, 'manual', 30);
        return safe;
      });
  }

  function demoPersistVitalsReading(data, reading) {
    demoEnsureVitalsData(data);
    data.vitalsReadings.push(reading);
    if (data.vitalsReadings.length > 800) {
      data.vitalsReadings = data.vitalsReadings.slice(data.vitalsReadings.length - 800);
    }
  }

  function demoUpdateSensorAfterReading(data, studentId, reading) {
    var sensors = demoEnsureStudentSensors(data, studentId);
    var chosen = null;
    if (reading.sensorId) {
      chosen = sensors.find(function (item) { return item.id === reading.sensorId; }) || null;
    }
    if (!chosen) {
      chosen = sensors.find(function (item) { return item.type === 'hr'; }) || sensors[0] || null;
    }
    if (!chosen) return;
    chosen.status = 'connected';
    chosen.lastSeenAt = demoNowIso();
    chosen.lastReadingAt = reading.measuredAt;
    chosen.battery = demoNormalizeVitalsNumber((chosen.battery || 80) - (Math.random() * 0.7), chosen.battery || 80, 25, 100, 0);
    if (!reading.sensorId) {
      reading.sensorId = chosen.id;
    }
  }

  function demoGenerateVitalsReading(data, studentId, options) {
    var opts = options || {};
    var profile = demoText(opts.profile, 'normal', 20).toLowerCase();
    var sensors = demoEnsureStudentSensors(data, studentId);
    var latest = demoListVitalsForStudent(data, studentId, 1)[0] || null;
    var base = latest || { temp: 36.8, spo2: 98, hr: 78, bpSys: 118, bpDia: 76 };
    var rand = function (range) { return (Math.random() * 2 - 1) * range; };
    var temp = Number(base.temp) + rand(0.35);
    var spo2 = Number(base.spo2) + rand(1.4);
    var hr = Number(base.hr) + rand(7);
    var bpSys = Number(base.bpSys) + rand(7);
    var bpDia = Number(base.bpDia) + rand(6);

    if (profile === 'watch') {
      temp += 0.4;
      spo2 -= 1.8;
      hr += 10;
      bpSys += 8;
      bpDia += 6;
    } else if (profile === 'critical') {
      temp += 1.2;
      spo2 -= 5.5;
      hr += 22;
      bpSys += 18;
      bpDia += 12;
    }

    var fallbackSensor = sensors.find(function (item) { return item.type === 'hr'; }) || sensors[0] || null;
    var reading = demoNormalizeVitalsReading(studentId, {
      temp: temp,
      spo2: spo2,
      hr: hr,
      bpSys: bpSys,
      bpDia: bpDia,
      source: demoText(opts.source, 'sensor_simulator', 30),
      sensorId: demoText(opts.sensorId, fallbackSensor ? fallbackSensor.id : '', 100),
      measuredAt: demoNowIso()
    }, 'sensor_simulator');
    demoPersistVitalsReading(data, reading);
    demoUpdateSensorAfterReading(data, studentId, reading);
    return reading;
  }

  function demoVitalsPayloadForStudent(data, studentId, limit) {
    var sensors = demoEnsureStudentSensors(data, studentId).map(function (sensor) {
      return {
        id: sensor.id,
        studentId: sensor.studentId,
        type: sensor.type,
        label: sensor.label,
        status: sensor.status || 'connected',
        battery: demoNormalizeVitalsNumber(sensor.battery, 80, 0, 100, 0),
        lastSeenAt: sensor.lastSeenAt || null,
        lastReadingAt: sensor.lastReadingAt || null
      };
    });
    var items = demoListVitalsForStudent(data, studentId, limit || 20);
    return {
      latest: items[0] || null,
      items: items,
      sensors: sensors
    };
  }

  function demoParentRiskScore(value) {
    var level = demoText(value, '', 20).toLowerCase();
    if (level === 'critical') return 96;
    if (level === 'high') return 84;
    if (level === 'warning' || level === 'medium') return 64;
    if (level === 'stable' || level === 'low') return 28;
    return 44;
  }

  function demoParentRiskLabel(score) {
    var safeScore = Number(score || 0);
    if (safeScore >= 80) return 'critical';
    if (safeScore >= 55) return 'warning';
    return 'stable';
  }

  function demoParentRiskLabelAr(level) {
    if (level === 'critical') return 'مرتفع';
    if (level === 'warning') return 'متوسط';
    if (level === 'stable') return 'منخفض';
    return 'غير متوفر';
  }

  function demoCaseSeverityToRisk(caseItem) {
    return demoParentRiskScore(caseItem && caseItem.severity ? caseItem.severity : 'warning');
  }

  function demoIsoDayKey(value) {
    var date = new Date(value || 0);
    if (!Number.isFinite(date.getTime())) return '';
    return date.toISOString().slice(0, 10);
  }

  function demoBuildParentRiskTimeline(cases, vitalsHistory, alerts) {
    var days = [];
    for (var idx = 6; idx >= 0; idx -= 1) {
      var date = new Date();
      date.setUTCHours(0, 0, 0, 0);
      date.setUTCDate(date.getUTCDate() - idx);
      days.push(date.toISOString().slice(0, 10));
    }
    var buckets = {};
    days.forEach(function (day) { buckets[day] = []; });

    (vitalsHistory || []).forEach(function (reading) {
      var day = demoIsoDayKey(reading && reading.measuredAt);
      if (!day || !buckets[day]) return;
      buckets[day].push(demoParentRiskScore(reading.risk || 'stable'));
    });
    (cases || []).forEach(function (item) {
      var day = demoIsoDayKey(item && item.updatedAt);
      if (!day || !buckets[day]) return;
      buckets[day].push(demoCaseSeverityToRisk(item));
    });
    (alerts || []).forEach(function (item) {
      var day = demoIsoDayKey(item && item.createdAt);
      if (!day || !buckets[day]) return;
      var type = demoText(item.type, 'info', 30);
      var score = type === 'critical' ? 90 : (type === 'operational' ? 62 : 36);
      buckets[day].push(score);
    });

    var latestSignals = [];
    (vitalsHistory || []).slice(0, 2).forEach(function (reading) {
      latestSignals.push(demoParentRiskScore(reading.risk || 'stable'));
    });
    (cases || []).slice(0, 1).forEach(function (item) {
      latestSignals.push(demoCaseSeverityToRisk(item));
    });
    var baselineScore = latestSignals.length
      ? Math.round(latestSignals.reduce(function (sum, value) { return sum + value; }, 0) / latestSignals.length)
      : 42;

    var previous = baselineScore;
    return days.map(function (day) {
      var values = buckets[day] || [];
      var score;
      if (values.length) {
        score = Math.round(values.reduce(function (sum, value) { return sum + value; }, 0) / values.length);
        previous = score;
      } else {
        score = Math.round(Math.max(24, Math.min(98, previous * 0.94)));
        previous = score;
      }
      var risk = demoParentRiskLabel(score);
      return {
        date: day,
        score: score,
        risk: risk,
        label: demoParentRiskLabelAr(risk)
      };
    });
  }

  function demoBuildParentConditionSummary(cases, vitalsHistory, riskTimeline) {
    var currentCaseScore = cases.length ? demoCaseSeverityToRisk(cases[0]) : null;
    var previousCaseScore = cases.length > 1 ? demoCaseSeverityToRisk(cases[1]) : null;
    var currentVitalsScore = vitalsHistory.length ? demoParentRiskScore(vitalsHistory[0].risk || 'stable') : null;
    var previousVitalsScore = vitalsHistory.length > 1 ? demoParentRiskScore(vitalsHistory[1].risk || 'stable') : null;
    var timelineCurrent = riskTimeline.length ? riskTimeline[riskTimeline.length - 1].score : null;
    var timelinePrevious = riskTimeline.length > 1 ? riskTimeline[riskTimeline.length - 2].score : null;

    var currentCandidates = [currentCaseScore, currentVitalsScore, timelineCurrent].filter(function (value) { return Number.isFinite(value); });
    var previousCandidates = [previousCaseScore, previousVitalsScore, timelinePrevious].filter(function (value) { return Number.isFinite(value); });
    var currentScore = currentCandidates.length
      ? Math.round(currentCandidates.reduce(function (sum, value) { return sum + value; }, 0) / currentCandidates.length)
      : 42;
    var previousScore = previousCandidates.length
      ? Math.round(previousCandidates.reduce(function (sum, value) { return sum + value; }, 0) / previousCandidates.length)
      : currentScore;
    var delta = currentScore - previousScore;

    var direction = 'stable';
    var label = 'استقرار نسبي';
    var summary = 'الحالة مستقرة نسبيًا مع الحاجة للاستمرار على خطة المتابعة.';
    if (delta <= -8) {
      direction = 'improving';
      label = 'تحسن';
      summary = 'مؤشرات الطالب تميل للتحسن مقارنة بآخر قراءة.';
    } else if (delta >= 8) {
      direction = 'deteriorating';
      label = 'تراجع';
      summary = 'يوجد ارتفاع في مؤشرات الخطر ويحتاج متابعة أسرع.';
    }

    return {
      direction: direction,
      label: label,
      deltaScore: delta,
      currentRisk: demoParentRiskLabel(currentScore),
      previousRisk: demoParentRiskLabel(previousScore),
      currentScore: currentScore,
      previousScore: previousScore,
      summary: summary
    };
  }

  function demoBuildParentGuidance(latestCase, latestVitals, adherence, riskTimeline) {
    var tips = [];
    if (latestVitals && Number(latestVitals.spo2 || 0) < 95) {
      tips.push('راقب مستوى الأكسجين كل 2-3 ساعات وتواصل مع العيادة إذا انخفض عن 94%.');
    }
    if (latestVitals && Number(latestVitals.temp || 0) >= 38) {
      tips.push('قدّم سوائل بشكل منتظم ودوّن درجة الحرارة قبل المدرسة وبعدها.');
    }
    if (adherence && adherence.status === 'warning') {
      tips.push('الالتزام الدوائي منخفض هذا الأسبوع، يفضل تثبيت منبه للأدوية صباحًا ومساءً.');
    }
    if (Array.isArray(riskTimeline) && riskTimeline.some(function (point) { return point.risk === 'critical'; })) {
      tips.push('تم تسجيل يوم عالي الخطورة خلال الأسبوع، يفضل تقليل الجهد الرياضي مؤقتًا.');
    }
    if (!tips.length) {
      tips.push('استمر على نفس الخطة العلاجية مع مراجعة يومية سريعة للأعراض.');
      tips.push('شارك ملاحظات الحالة مع المرشد الصحي في المدرسة عند أي تغيّر غير معتاد.');
    }

    var protocols = [
      {
        id: 'school-contact',
        title: 'بروتوكول التواصل المدرسي',
        summary: 'تسلسل التواصل الرسمي عند ظهور أعراض متوسطة أو عالية.',
        steps: [
          'إبلاغ الممرضة المدرسية بالأعراض المسجلة في نفس اليوم.',
          'تأكيد قرار العودة للفصل أو البقاء بالملاحظة الصحية.',
          'تحديث ولي الأمر برسالة موحدة تتضمن الإجراء الطبي.'
        ]
      },
      {
        id: 'medication-safety',
        title: 'بروتوكول الالتزام العلاجي',
        summary: 'ضبط الجرعات اليومية وربطها بروتين المنزل والمدرسة.',
        steps: [
          'توثيق وقت الجرعة في نفس لحظة الإعطاء.',
          'عند نسيان الجرعة يتم إشعار العيادة عبر التذاكر فورًا.',
          'مراجعة أسبوعية لنسبة الالتزام وتحديث الخطة إذا هبطت عن 80%.'
        ]
      }
    ];

    var caseText = ((latestCase && latestCase.title) || '') + ' ' + ((latestCase && latestCase.notes) || '');
    caseText = caseText.toLowerCase();
    if (caseText.indexOf('ربو') !== -1 || caseText.indexOf('تنفس') !== -1 || Number((latestVitals || {}).spo2 || 98) < 95) {
      protocols.unshift({
        id: 'asthma-response',
        title: 'بروتوكول نوبات التنفس في المدرسة',
        summary: 'إجراءات سريعة للتعامل مع أي ضيق تنفس داخل المدرسة.',
        steps: [
          'إيقاف النشاط البدني فورًا وإبقاء الطالب بوضعية جلوس مريحة.',
          'متابعة SpO2 والنبض كل 10 دقائق حتى الاستقرار.',
          'تصعيد فوري للطوارئ إذا استمر انخفاض الأكسجين أو ساءت الأعراض.'
        ]
      });
    } else {
      protocols.unshift({
        id: 'general-symptoms',
        title: 'بروتوكول الأعراض العامة',
        summary: 'التعامل مع الصداع والحمى والأعراض اليومية المتكررة.',
        steps: [
          'راحة 20 دقيقة مع قياس أولي للعلامات الحيوية.',
          'إعادة القياس بعد الراحة وتحديد الحاجة للمراجعة الطبية.',
          'إشعار ولي الأمر عند تكرار الأعراض لنفس اليوم الدراسي.'
        ]
      });
    }

    return {
      lastUpdatedAt: demoNowIso(),
      tips: tips.slice(0, 6),
      protocols: protocols.slice(0, 4)
    };
  }

  function demoStudentOverview(data, studentId) {
    var user = (data.users || []).find(function (u) { return u.id === studentId; }) || null;
    var cases = (data.cases || []).filter(function (c) { return c.studentId === studentId; }).slice().sort(function (a, b) {
      return new Date(b.updatedAt) - new Date(a.updatedAt);
    });
    var reports = (data.reports || []).filter(function (r) { return r.studentId === studentId; }).slice().sort(function (a, b) {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
    var visits = (data.visitRequests || []).filter(function (v) { return v.studentId === studentId; }).slice().sort(function (a, b) {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
    var alerts = (data.alerts || []).filter(function (a) {
      return Array.isArray(a.roles) && (a.roles.indexOf('student') !== -1 || a.roles.indexOf('parent') !== -1);
    }).slice().sort(function (a, b) {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
    var appointments = (data.appointments || []).filter(function (item) { return item.studentId === studentId; }).slice().sort(function (a, b) {
      return new Date(b.slotAt || b.createdAt || 0) - new Date(a.slotAt || a.createdAt || 0);
    });
    var latestCase = cases[0] || null;
    var vitals = demoVitalsPayloadForStudent(data, studentId, 8);
    var adherence = demoMedicationAdherenceSummary(data, studentId);
    var riskTimeline = demoBuildParentRiskTimeline(cases, vitals.items || [], alerts);
    var condition = demoBuildParentConditionSummary(cases, vitals.items || [], riskTimeline);

    var hasAdherenceSignal = Number(adherence.expectedDoses || 0) > 0 || Number(adherence.takenDoses || 0) > 0 || Number(adherence.skippedDoses || 0) > 0;
    var adherencePercent = hasAdherenceSignal ? Number(adherence.adherencePercent || 0) : null;
    var adherenceStatus = 'inactive';
    var adherenceLabel = 'غير مفعل';
    if (Number.isFinite(adherencePercent)) {
      if (adherencePercent >= 90) {
        adherenceStatus = 'excellent';
        adherenceLabel = 'ممتاز';
      } else if (adherencePercent >= 80) {
        adherenceStatus = 'good';
        adherenceLabel = 'مقبول';
      } else {
        adherenceStatus = 'warning';
        adherenceLabel = 'منخفض';
      }
    }

    var riskScores = riskTimeline.map(function (point) { return Number(point.score || 0); });
    var riskAverage = riskScores.length
      ? Math.round(riskScores.reduce(function (sum, value) { return sum + value; }, 0) / riskScores.length)
      : 0;
    var appointmentsByStatus = {
      pending: appointments.filter(function (item) { return item.status === 'pending'; }).length,
      confirmed: appointments.filter(function (item) { return item.status === 'confirmed'; }).length,
      completed: appointments.filter(function (item) { return item.status === 'completed'; }).length,
      cancelled: appointments.filter(function (item) { return item.status === 'cancelled'; }).length
    };
    var latestCompleted = appointments.find(function (item) { return item.status === 'completed'; }) || null;
    var nextAppointment = appointments.filter(function (item) {
      return item.status === 'pending' || item.status === 'confirmed';
    }).slice().sort(function (a, b) {
      return new Date(a.slotAt || a.createdAt || 0) - new Date(b.slotAt || b.createdAt || 0);
    })[0] || null;

    var parentAnalytics = {
      generatedAt: demoNowIso(),
      visits: {
        total: visits.length + appointments.length,
        visitRequests: visits.length,
        appointmentsTotal: appointments.length,
        pending: Number((visits.filter(function (item) { return item.status === 'pending'; }).length || 0) + appointmentsByStatus.pending),
        confirmed: appointmentsByStatus.confirmed,
        completed: appointmentsByStatus.completed,
        cancelled: appointmentsByStatus.cancelled,
        lastVisitAt: latestCompleted ? (latestCompleted.completedAt || latestCompleted.updatedAt || latestCompleted.slotAt || null) : null,
        nextVisitAt: nextAppointment ? (nextAppointment.slotAt || nextAppointment.createdAt || null) : null
      },
      condition: condition,
      adherence: {
        status: adherenceStatus,
        statusLabel: adherenceLabel,
        percent: Number.isFinite(adherencePercent) ? adherencePercent : null,
        expectedDoses: Number(adherence.expectedDoses || 0),
        takenDoses: Number(adherence.takenDoses || 0),
        skippedDoses: Number(adherence.skippedDoses || 0),
        alert: adherence.alert || null
      },
      riskIndicators: {
        averageScore: riskAverage,
        peakScore: riskScores.length ? Math.max.apply(Math, riskScores) : 0,
        highDays: riskTimeline.filter(function (point) { return point.risk === 'critical'; }).length,
        warningDays: riskTimeline.filter(function (point) { return point.risk === 'warning'; }).length,
        stableDays: riskTimeline.filter(function (point) { return point.risk === 'stable'; }).length,
        currentRisk: riskTimeline.length ? riskTimeline[riskTimeline.length - 1].risk : 'unknown'
      },
      riskTimeline: riskTimeline
    };
    var parentGuidance = demoBuildParentGuidance(latestCase, vitals.latest || null, parentAnalytics.adherence, riskTimeline);

    return {
      student: user,
      snapshot: {
        totalCases: cases.length,
        openCases: cases.filter(function (c) { return c.status !== 'closed'; }).length,
        criticalCases: cases.filter(function (c) { return c.severity === 'critical'; }).length,
        reports: reports.length,
        pendingVisits: visits.filter(function (v) { return v.status === 'pending'; }).length,
        alerts: alerts.length,
        latestVitalsRisk: vitals.latest ? vitals.latest.risk : 'unknown'
      },
      latestCase: latestCase,
      latestVitals: vitals.latest,
      vitalsHistory: vitals.items,
      sensors: vitals.sensors,
      cases: cases,
      reports: reports,
      visitRequests: visits,
      appointments: appointments,
      alerts: alerts.slice(0, 20),
      parentAnalytics: parentAnalytics,
      parentGuidance: parentGuidance
    };
  }

  function demoSystemOverview(data) {
    var analytics = demoAnalyticsOverview(data);
    var operations = demoOperationsOverview(data);
    return {
      health: {
        api: 'demo',
        uptimeSec: Math.floor((Date.now() - DEMO_START_AT) / 1000),
        serverTime: demoNowIso()
      },
      snapshot: analytics.snapshot,
      operations: operations.counts,
      today: Object.assign({}, analytics.today, operations.today),
      topAlerts: (data.alerts || []).slice(-5).reverse(),
      lastAuditEvents: (data.auditLogs || []).slice(-8).reverse()
    };
  }

  function demoNotificationsForRole(data, role) {
    var alerts = (data.alerts || []).filter(function (item) {
      return Array.isArray(item.roles) && item.roles.indexOf(role) !== -1;
    }).map(function (item) {
      return {
        id: item.id || demoId('ntf'),
        source: 'alert',
        type: item.type || 'info',
        text: item.text,
        createdAt: item.createdAt
      };
    });
    var derived = [];
    if (role === 'admin' || role === 'doctor' || role === 'emergency') {
      (data.visitRequests || []).filter(function (v) {
        return v.status === 'pending';
      }).slice(-10).forEach(function (v) {
        derived.push({
          id: 'vr_' + v.id,
          source: 'visit_request',
          type: String(v.reason || '').toLowerCase().indexOf('urgent') !== -1 ? 'critical' : 'operational',
          text: 'طلب زيارة قيد الانتظار: ' + v.reason,
          createdAt: v.createdAt
        });
      });
    }
    return alerts.concat(derived).sort(function (a, b) {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });
  }

  function demoSlaMonitor(data) {
    var settings = demoEnsureSettings(data);
    var now = Date.now();
    var thresholds = {
      critical: Number(settings.sla.criticalResponseMinutes || 5),
      high: Number(settings.sla.highResponseMinutes || 15),
      medium: Number(settings.sla.normalResponseMinutes || 30),
      low: Number(settings.sla.normalResponseMinutes || 30)
    };
    var items = (data.cases || []).map(function (item) {
      var elapsedMin = Math.max(0, Math.round((now - new Date(item.updatedAt || demoNowIso()).getTime()) / 60000));
      var allowedMin = thresholds[item.severity] || thresholds.low;
      var breached = item.status !== 'closed' ? elapsedMin > allowedMin : false;
      return {
        id: item.id,
        studentName: item.studentName,
        severity: item.severity,
        status: item.status,
        elapsedMin: elapsedMin,
        allowedMin: allowedMin,
        breached: breached
      };
    });
    return {
      summary: {
        totalOpen: items.filter(function (i) { return i.status !== 'closed'; }).length,
        breached: items.filter(function (i) { return i.breached; }).length
      },
      items: items.sort(function (a, b) { return Number(b.breached) - Number(a.breached); })
    };
  }

  function demoEmergencyClinicalSnapshot(data, target, logs) {
    var vitals = demoVitalsPayloadForStudent(data, target.studentId, 6);
    var latest = vitals.latest || null;
    var previous = vitals.items && vitals.items.length > 1 ? vitals.items[1] : null;
    if (!latest) {
      return {
        latestVitals: null,
        oxygenLevel: null,
        oxygenStatus: 'غير متوفر',
        measuredAt: null,
        trend: { spo2Delta: null, hrDelta: null, tempDelta: null },
        treatmentResponse: { score: 0, status: 'unknown', label: 'لا توجد بيانات كافية' },
        summary: 'لا توجد قراءات حيوية حديثة للحكم على الاستجابة.',
        observations: ['يتطلب المسار قياسًا حيويًا مباشرًا للحالة.']
      };
    }

    var trend = {
      spo2Delta: previous ? Number((latest.spo2 - previous.spo2).toFixed(1)) : null,
      hrDelta: previous ? Number((latest.hr - previous.hr).toFixed(1)) : null,
      tempDelta: previous ? Number((latest.temp - previous.temp).toFixed(1)) : null
    };
    var observations = [];
    var score = 50;

    if (latest.spo2 >= 95) {
      score += 18;
    } else if (latest.spo2 >= 92) {
      score += 8;
      observations.push('الأكسجين على الحد الأدنى (' + latest.spo2 + '%).');
    } else {
      score -= 22;
      observations.push('انخفاض تشبع الأكسجين (' + latest.spo2 + '%) يتطلب تدخلًا فوريًا.');
    }

    if (latest.hr >= 60 && latest.hr <= 110) {
      score += 10;
    } else if (latest.hr > 130 || latest.hr < 50) {
      score -= 14;
      observations.push('نبض غير مستقر (' + latest.hr + ' نبضة/دقيقة).');
    } else {
      score -= 4;
    }

    if (latest.temp <= 37.8) {
      score += 8;
    } else if (latest.temp >= 39) {
      score -= 10;
      observations.push('حرارة مرتفعة (' + latest.temp + '°C).');
    } else {
      score -= 4;
    }

    if (latest.risk === 'critical') {
      score -= 18;
      observations.push('تصنيف الخطر الحيوي الحالي = critical.');
    } else if (latest.risk === 'warning') {
      score -= 8;
    } else if (latest.risk === 'stable') {
      score += 8;
    }

    if (Number.isFinite(trend.spo2Delta)) {
      if (trend.spo2Delta >= 2) {
        score += 10;
        observations.push('تحسن ملحوظ في SpO2 (+' + trend.spo2Delta + ').');
      } else if (trend.spo2Delta <= -2) {
        score -= 10;
        observations.push('تراجع في SpO2 (' + trend.spo2Delta + ').');
      }
    }
    if (Number.isFinite(trend.hrDelta)) {
      if (trend.hrDelta <= -10) score += 6;
      if (trend.hrDelta >= 12) {
        score -= 8;
        observations.push('ارتفاع النبض مقارنة بآخر قراءة (+' + trend.hrDelta + ').');
      }
    }
    if (Number.isFinite(trend.tempDelta)) {
      if (trend.tempDelta <= -0.4) score += 4;
      if (trend.tempDelta >= 0.4) score -= 5;
    }

    var stabilized = logs.some(function (item) {
      return item.action === 'case.action.stabilized_case' || item.action === 'case.action.handover_complete';
    });
    var escalated = logs.some(function (item) {
      return item.action === 'case.action.external_referral' || item.action === 'case.action.ambulance_dispatch';
    });
    if (stabilized) score += 10;
    if (escalated && target.status !== 'closed') score -= 6;

    score = Math.round(Math.max(0, Math.min(100, score)));
    var response = { status: 'poor', label: 'استجابة ضعيفة' };
    if (score >= 70) {
      response = { status: 'improving', label: 'استجابة إيجابية' };
    } else if (score >= 45) {
      response = { status: 'fluctuating', label: 'استجابة متذبذبة' };
    }

    var oxygenStatus = 'مستقر';
    if (latest.spo2 < 92) oxygenStatus = 'حرج';
    else if (latest.spo2 < 95) oxygenStatus = 'قابل للتدهور';

    return {
      latestVitals: {
        temp: latest.temp,
        spo2: latest.spo2,
        hr: latest.hr,
        bpSys: latest.bpSys,
        bpDia: latest.bpDia,
        risk: latest.risk || 'unknown'
      },
      oxygenLevel: latest.spo2,
      oxygenStatus: oxygenStatus,
      measuredAt: latest.measuredAt || null,
      trend: trend,
      treatmentResponse: {
        score: score,
        status: response.status,
        label: response.label
      },
      summary: response.label + ' - مستوى الأكسجين الحالي ' + latest.spo2 + '% (' + oxygenStatus + ').',
      observations: observations.slice(0, 5)
    };
  }

  function demoEmergencyAiInsights(target, urgency, steps, recommendation) {
    var missingSteps = (steps || []).filter(function (step) { return step.status !== 'done'; }).map(function (step) { return step.label; });
    var referralDone = (steps || []).some(function (step) { return step.id === 'referral_decision' && step.status === 'done'; });
    var priority = urgency && urgency.breached ? 'immediate' : (target.severity === 'critical' ? 'immediate' : (target.severity === 'high' ? 'urgent' : 'standard'));
    var confidence = priority === 'immediate' ? 0.93 : (priority === 'urgent' ? 0.84 : 0.76);

    var actions = [];
    if (priority === 'immediate') {
      actions.push('تفعيل مسار RED وتثبيت ABC دون تأخير.');
    }
    actions.push('مراقبة SpO2 والنبض والضغط كل 10 دقائق.');
    actions.push('تحديث ولي الأمر بالحالة والإجراءات المنفذة.');
    if (urgency && urgency.breached && !referralDone) {
      actions.push('تجاوز SLA: يوصى بطلب إسعاف/تحويل خارجي فوري.');
    }
    missingSteps.slice(0, 2).forEach(function (item) {
      actions.push('إغلاق فجوة المسار: ' + item);
    });

    var rationale = [];
    rationale.push('تصنيف الفرز الحالي: ' + (urgency && urgency.triage ? urgency.triage : 'YELLOW'));
    if (urgency && urgency.breached) rationale.push('تم رصد تجاوز SLA للحالة الحالية.');
    if (target.severity === 'critical') rationale.push('الحالة موسومة كحرجة (critical).');

    return {
      generatedAt: demoNowIso(),
      priority: priority,
      confidence: confidence,
      triageCode: urgency && urgency.triage ? urgency.triage : 'YELLOW',
      protocol: {
        id: priority === 'immediate' ? 'SC-TRIAGE-01' : 'SC-TRIAGE-02',
        title: priority === 'immediate' ? 'بروتوكول الاستجابة الفورية' : 'بروتوكول المتابعة العاجلة',
        version: '2026.02'
      },
      recommendation: recommendation || 'استمر في بروتوكول الطوارئ.',
      actions: Array.from(new Set(actions)).slice(0, 6),
      rationale: rationale
    };
  }

  function demoEmergencyFlowForCase(data, caseId) {
    var target = demoGetCaseByAnyId(data, caseId);
    if (!target) {
      return null;
    }
    var settings = demoEnsureSettings(data);
    var logs = (data.auditLogs || []).filter(function (item) { return item.target === target.id; });
    var hasAction = function (name) {
      return logs.some(function (item) { return item.action === name; });
    };
    var hasOneOf = function (names) {
      return names.some(function (name) { return hasAction(name); });
    };
    var slaMap = {
      critical: Number(settings.sla.criticalResponseMinutes || 5),
      high: Number(settings.sla.highResponseMinutes || 15),
      medium: Number(settings.sla.normalResponseMinutes || 30),
      low: Number(settings.sla.normalResponseMinutes || 30)
    };
    var allowedMin = slaMap[target.severity] || slaMap.low;
    var elapsedMin = Math.max(0, Math.round((Date.now() - new Date(target.updatedAt).getTime()) / 60000));
    var breached = target.status !== 'closed' ? elapsedMin > allowedMin : false;
    var steps = [
      { id: 'rapid_assessment', label: 'تقييم سريع للوعي والتنفس', status: 'done' },
      { id: 'vitals_monitoring', label: 'قياس العلامات الحيوية الأساسية', status: hasAction('case.action.vitals_update') ? 'done' : 'in_progress' },
      { id: 'initial_protocol', label: 'تطبيق البروتوكول العلاجي الأولي', status: hasOneOf(['case.action.emergency_protocol', 'case.action.bronchodilator', 'case.action.oxygen_support']) ? 'done' : 'todo' },
      { id: 'guardian_contact', label: 'إبلاغ ولي الأمر', status: hasAction('case.action.contact_guardian') ? 'done' : 'todo' },
      { id: 'referral_decision', label: 'قرار التحويل الخارجي', status: hasOneOf(['case.action.external_referral', 'case.action.ambulance_dispatch']) ? 'done' : 'todo' },
      { id: 'handover', label: 'تسليم الحالة وتوثيق محضر الطوارئ', status: hasOneOf(['case.action.handover_complete', 'case.action.close_case']) ? 'done' : 'todo' }
    ];
    var doneCount = steps.filter(function (step) { return step.status === 'done'; }).length;
    var recommendation = 'استمر في المتابعة وفق البروتوكول الحالي.';
    if (breached && !hasOneOf(['case.action.external_referral', 'case.action.ambulance_dispatch'])) {
      recommendation = 'تجاوز SLA للطوارئ: يوصى بتفعيل التحويل الخارجي أو طلب إسعاف فورًا.';
    } else if (!hasAction('case.action.emergency_protocol')) {
      recommendation = 'يوصى ببدء بروتوكول الطوارئ وتثبيت العلامات الحيوية فورًا.';
    }
    return {
      case: {
        id: target.id,
        studentId: target.studentId,
        studentName: target.studentName,
        title: target.title,
        severity: target.severity,
        status: target.status,
        updatedAt: target.updatedAt
      },
      urgency: {
        triage: target.severity === 'critical' ? 'RED' : (target.severity === 'high' ? 'ORANGE' : 'YELLOW'),
        elapsedMin: elapsedMin,
        allowedMin: allowedMin,
        breached: breached
      },
      recommendation: recommendation,
      progress: Math.round((doneCount / steps.length) * 100),
      startedAt: logs.length ? logs[0].createdAt : target.updatedAt,
      steps: steps,
      timeline: logs.slice(-12).reverse(),
      clinical: demoEmergencyClinicalSnapshot(data, target, logs),
      aiInsights: demoEmergencyAiInsights(target, {
        triage: target.severity === 'critical' ? 'RED' : (target.severity === 'high' ? 'ORANGE' : 'YELLOW'),
        elapsedMin: elapsedMin,
        allowedMin: allowedMin,
        breached: breached
      }, steps, recommendation)
    };
  }

  function demoResolveStudentId(auth, urlObj) {
    if (!auth || !auth.user) return null;
    if (auth.user.role === 'student') return auth.user.id;
    if (auth.user.role === 'parent') return 'u_student_1';
    if (auth.user.role === 'doctor' || auth.user.role === 'admin' || auth.user.role === 'emergency') {
      return urlObj.searchParams.get('studentId') || 'u_student_1';
    }
    return null;
  }

  function demoEnsureAdvancedStores(data) {
    [
      'consents',
      'emergencyCards',
      'homeCarePlans',
      'appointments',
      'tickets',
      'medicationPlans',
      'medicationLogs',
      'referrals',
      'monthlyReports'
    ].forEach(function (key) {
      if (!Array.isArray(data[key])) {
        data[key] = [];
      }
    });
  }

  function demoRoleLabel(role) {
    return ROLE_LABELS[role] || role;
  }

  function demoCanAccessStudentScope(auth, studentId) {
    if (!auth || !auth.user) return false;
    if (auth.user.role === 'admin' || auth.user.role === 'doctor') return true;
    if (auth.user.role === 'student') return auth.user.id === studentId;
    if (auth.user.role === 'parent') return studentId === 'u_student_1';
    return false;
  }

  function demoCanAccessTicket(auth, ticket) {
    if (!auth || !auth.user || !ticket) return false;
    if (auth.user.role === 'admin' || auth.user.role === 'doctor') return true;
    if (auth.user.role === 'student') {
      return ticket.studentId === auth.user.id || ticket.createdByUserId === auth.user.id;
    }
    if (auth.user.role === 'parent') {
      return ticket.studentId === 'u_student_1' || ticket.createdByUserId === auth.user.id;
    }
    return false;
  }

  function demoFindStudent(data, studentId) {
    return (data.users || []).find(function (user) {
      return user.id === studentId && user.role === 'student';
    }) || null;
  }

  function demoEmergencyCardPayload(data, studentId) {
    demoEnsureAdvancedStores(data);
    var student = demoFindStudent(data, studentId);
    if (!student) return null;
    var card = (data.emergencyCards || []).find(function (item) { return item.studentId === studentId; }) || null;
    if (!card) {
      card = {
        id: demoId('emg'),
        studentId: studentId,
        token: demoId('token') + Date.now().toString(36),
        createdAt: demoNowIso(),
        updatedAt: demoNowIso()
      };
      data.emergencyCards.push(card);
    }
    var publicPath = '/api/emergency/public/' + card.token;
    var publicUrl = 'https://jkg9rmd8td-blip.github.io/smartclinic/?emergency=' + encodeURIComponent(card.token);
    return {
      card: {
        id: card.id,
        token: card.token,
        studentId: student.id,
        studentName: student.name || student.id,
        grade: student.grade || '-',
        allergies: demoText(student.allergies, 'لا توجد حساسية مسجلة', 280),
        chronicCondition: demoText(student.chronicCondition, 'لا توجد حالة مزمنة مسجلة', 280),
        emergencyContact: demoText(student.guardianPhone, 'غير متوفر', 60),
        updatedAt: card.updatedAt || card.createdAt
      },
      publicPath: publicPath,
      publicUrl: publicUrl,
      qrImageUrl: 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' + encodeURIComponent(publicUrl)
    };
  }

  function demoMedicationAdherenceSummary(data, studentId) {
    demoEnsureAdvancedStores(data);
    var now = Date.now();
    var from = now - (7 * 24 * 60 * 60 * 1000);
    var plans = (data.medicationPlans || []).filter(function (item) {
      return item.studentId === studentId && item.active !== false;
    });
    var logs = (data.medicationLogs || []).filter(function (item) {
      return item.studentId === studentId && new Date(item.takenAt || item.createdAt || 0).getTime() >= from;
    }).sort(function (a, b) {
      return new Date(b.takenAt || b.createdAt || 0) - new Date(a.takenAt || a.createdAt || 0);
    });

    var expected = plans.reduce(function (sum, plan) {
      var dosesPerDay = Math.max(1, Math.min(8, Number(plan.dosesPerDay || 1)));
      var createdAt = new Date(plan.createdAt || demoNowIso()).getTime();
      var activeFrom = Math.max(createdAt, from);
      var days = Math.max(1, Math.ceil((now - activeFrom) / (24 * 60 * 60 * 1000)));
      return sum + (dosesPerDay * Math.min(7, days));
    }, 0);
    var taken = logs.filter(function (item) { return item.status === 'taken'; }).length;
    var skipped = logs.filter(function (item) { return item.status === 'skipped'; }).length;
    var adherence = expected > 0 ? Math.max(0, Math.min(100, Math.round((taken / expected) * 100))) : 100;

    return {
      studentId: studentId,
      weekStart: new Date(from).toISOString(),
      weekEnd: new Date(now).toISOString(),
      expectedDoses: expected,
      takenDoses: taken,
      skippedDoses: skipped,
      adherencePercent: adherence,
      plans: plans.slice().sort(function (a, b) { return new Date(b.createdAt || 0) - new Date(a.createdAt || 0); }),
      recentLogs: logs.slice(0, 20),
      alert: adherence < 80 ? 'انخفاض الالتزام الدوائي عن الحد الآمن (80%)' : null
    };
  }

  function demoNormalizeMonthKey(raw) {
    var value = demoText(raw, '', 20);
    if (/^\d{4}-\d{2}$/.test(value)) {
      var y = Number(value.slice(0, 4));
      var m = Number(value.slice(5, 7));
      if (y >= 2000 && y <= 2100 && m >= 1 && m <= 12) {
        return value;
      }
    }
    var now = new Date();
    return now.getUTCFullYear() + '-' + String(now.getUTCMonth() + 1).padStart(2, '0');
  }

  function demoMonthRange(monthKey) {
    var normalized = demoNormalizeMonthKey(monthKey);
    var y = Number(normalized.slice(0, 4));
    var m = Number(normalized.slice(5, 7));
    var start = new Date(Date.UTC(y, m - 1, 1, 0, 0, 0));
    var end = new Date(Date.UTC(y, m, 1, 0, 0, 0));
    return { month: normalized, start: start, end: end };
  }

  function demoInRange(iso, start, end) {
    var t = new Date(iso || 0).getTime();
    if (!Number.isFinite(t)) return false;
    return t >= start.getTime() && t < end.getTime();
  }

  function demoMonthlyExecutiveSummary(data, monthKey) {
    demoEnsureAdvancedStores(data);
    var range = demoMonthRange(monthKey);
    var start = range.start;
    var end = range.end;
    var visits = (data.visitRequests || []).filter(function (item) { return demoInRange(item.createdAt, start, end); });
    var appointments = (data.appointments || []).filter(function (item) { return demoInRange(item.createdAt, start, end); });
    var tickets = (data.tickets || []).filter(function (item) { return demoInRange(item.createdAt, start, end); });
    var closedTickets = (data.tickets || []).filter(function (item) { return item.closedAt && demoInRange(item.closedAt, start, end); });
    var criticalCases = (data.cases || []).filter(function (item) { return item.severity === 'critical' && demoInRange(item.updatedAt, start, end); });
    var referrals = (data.referrals || []).filter(function (item) { return demoInRange(item.createdAt, start, end); });
    var consents = (data.consents || []).filter(function (item) { return demoInRange(item.createdAt, start, end); });
    var approvedConsents = consents.filter(function (item) { return item.status === 'approved'; });
    var avgResolutionHours = 0;
    if (closedTickets.length) {
      var sum = closedTickets.reduce(function (acc, item) {
        var opened = new Date(item.createdAt || 0).getTime();
        var closed = new Date(item.closedAt || 0).getTime();
        if (!Number.isFinite(opened) || !Number.isFinite(closed) || closed <= opened) {
          return acc;
        }
        return acc + ((closed - opened) / (60 * 60 * 1000));
      }, 0);
      avgResolutionHours = Math.round((sum / closedTickets.length) * 10) / 10;
    }
    return {
      month: range.month,
      generatedAt: demoNowIso(),
      metrics: {
        criticalCases: criticalCases.length,
        visitRequests: visits.length,
        appointmentsTotal: appointments.length,
        appointmentsCompleted: appointments.filter(function (item) { return item.status === 'completed'; }).length,
        ticketsOpened: tickets.length,
        ticketsClosed: closedTickets.length,
        ticketClosureRate: tickets.length ? Math.round((closedTickets.length / tickets.length) * 100) : 0,
        avgTicketResolutionHours: avgResolutionHours,
        referrals: referrals.length,
        consentsRequested: consents.length,
        consentsApproved: approvedConsents.length
      }
    };
  }

  function demoAiStudentSupport(data, studentId, input) {
    var text = demoText(input && input.text, '', 600).toLowerCase();
    var overview = demoStudentOverview(data, studentId);
    var latest = overview.latestCase || null;
    var pendingVisits = Number((overview.snapshot && overview.snapshot.pendingVisits) || 0);
    var criticalCases = Number((overview.snapshot && overview.snapshot.criticalCases) || 0);
    var risk = 'low';
    var triggers = [];

    if (criticalCases > 0 || (latest && latest.severity === 'critical')) {
      risk = 'critical';
      triggers.push('يوجد سجل حالة حرجة نشطة');
    }
    if (text.indexOf('ضيق') !== -1 || text.indexOf('تنفس') !== -1 || text.indexOf('صدر') !== -1 || text.indexOf('إغماء') !== -1) {
      risk = 'critical';
      triggers.push('تم رصد كلمات خطورة تنفس/وعي');
    }
    if (risk !== 'critical' && (text.indexOf('حمى') !== -1 || text.indexOf('دوخة') !== -1 || text.indexOf('ألم') !== -1)) {
      risk = 'medium';
      triggers.push('أعراض تتطلب تقييمًا طبيًا قريبًا');
    }
    if (risk === 'low' && pendingVisits > 0) {
      risk = 'medium';
      triggers.push('يوجد طلب زيارة قيد الانتظار');
    }
    if (!triggers.length) {
      triggers.push('لا توجد مؤشرات خطورة مباشرة من البيانات الحالية');
    }

    var actions = [];
    if (risk === 'critical') {
      actions.push('التوجه فورًا لمسار الطوارئ داخل العيادة');
      actions.push('إرسال طلب زيارة مستعجل مع وصف الأعراض الحالية');
      actions.push('إبلاغ ولي الأمر بشكل فوري');
    } else if (risk === 'medium') {
      actions.push('حجز زيارة خلال نفس اليوم');
      actions.push('رفع مستوى المتابعة في بوابة الطالب');
      actions.push('إرسال رسالة للطبيب مع تفاصيل الأعراض');
    } else {
      actions.push('الاستمرار في متابعة المؤشرات اليومية');
      actions.push('تطبيق إرشادات الوقاية والنوم والترطيب');
    }

    return {
      role: 'student',
      generatedAt: demoNowIso(),
      risk: risk,
      confidence: risk === 'critical' ? 0.93 : (risk === 'medium' ? 0.84 : 0.75),
      triggers: triggers,
      actions: actions,
      summary: {
        latestCaseSeverity: latest ? latest.severity : 'none',
        pendingVisits: pendingVisits,
        alerts: Number((overview.snapshot && overview.snapshot.alerts) || 0)
      }
    };
  }

  function demoAiDoctorSupport(data, caseId, input) {
    var target = demoGetCaseByAnyId(data, caseId);
    if (!target) {
      return null;
    }
    var flow = demoEmergencyFlowForCase(data, target.id);
    var note = demoText(input && input.note, '', 800).toLowerCase();
    var urgent = ['هبوط', 'فشل', 'نزيف', 'اختناق', 'severe', 'critical'].some(function (word) {
      return note.indexOf(word) !== -1;
    });
    var priority = target.severity === 'critical' ? 'immediate' : (target.severity === 'high' ? 'urgent' : 'standard');
    if (flow && flow.urgency && flow.urgency.breached) {
      priority = 'immediate';
    }
    if (urgent) {
      priority = 'immediate';
    }

    var checklist = [
      'تحديث العلامات الحيوية مع توثيق واضح',
      'إشعار ولي الأمر بحالة الطالب'
    ];
    if (priority === 'immediate') {
      checklist.unshift('تفعيل بروتوكول الطوارئ للحالة');
    }

    return {
      role: 'doctor',
      generatedAt: demoNowIso(),
      caseId: target.id,
      triage: flow && flow.urgency ? flow.urgency.triage : 'YELLOW',
      priority: priority,
      confidence: priority === 'immediate' ? 0.95 : (priority === 'urgent' ? 0.88 : 0.8),
      sla: flow && flow.urgency ? flow.urgency : { allowedMin: 30, elapsedMin: 0, breached: false },
      checklist: checklist,
      carePlan: [
        'استقرار أولي: تأمين مجرى التنفس وتقييم ABC',
        'مراقبة مستمرة: قياس SpO2 والنبض والضغط كل 10 دقائق',
        'تواصل: تحديث الحالة للطبيب المناوب وولي الأمر',
        'قرار التحويل الخارجي حسب الاستجابة خلال نافذة SLA'
      ],
      recommendation: flow && flow.recommendation ? flow.recommendation : 'متابعة الحالة حسب البروتوكول القياسي.'
    };
  }

  async function parseRequestBody(body) {
    if (!body) {
      return {};
    }
    if (typeof body === 'string') {
      try {
        return JSON.parse(body);
      } catch (err) {
        return {};
      }
    }
    if (body instanceof FormData) {
      var out = {};
      body.forEach(function (value, key) {
        out[key] = value;
      });
      return out;
    }
    return {};
  }

  async function demoApiRequest(path, fetchOpts) {
    var method = String((fetchOpts && fetchOpts.method) || 'GET').toUpperCase();
    var urlObj = new URL(path, 'https://smartclinic.local');
    var pathname = urlObj.pathname;
    var parts = [];
    var data = await loadDemoData();
    demoEnsureAdvancedStores(data);
    var parsedBody = null;

    if (pathname.indexOf('/api/') === 0) {
      pathname = pathname.slice('/api'.length);
    } else if (pathname === '/api') {
      pathname = '/';
    }
    parts = pathname.split('/').filter(Boolean);

    async function body() {
      if (parsedBody !== null) {
        return parsedBody;
      }
      parsedBody = await parseRequestBody(fetchOpts && fetchOpts.body);
      return parsedBody;
    }

    if (pathname === '/health' && method === 'GET') {
      return demoJsonResponse(200, { ok: true, time: demoNowIso(), mode: 'demo' });
    }

    if (parts[0] === 'emergency' && parts[1] === 'public' && parts[2] && method === 'GET') {
      var token = demoText(parts[2], '', 160);
      var cardPublic = (data.emergencyCards || []).find(function (item) { return item.token === token; }) || null;
      if (!cardPublic) {
        return demoJsonResponse(404, { error: 'Emergency card not found' });
      }
      var studentPublic = demoFindStudent(data, cardPublic.studentId);
      if (!studentPublic) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      return demoJsonResponse(200, {
        studentName: studentPublic.name || studentPublic.id,
        grade: studentPublic.grade || '-',
        allergies: demoText(studentPublic.allergies, 'لا توجد حساسية مسجلة', 280),
        chronicCondition: demoText(studentPublic.chronicCondition, 'لا توجد حالة مزمنة مسجلة', 280),
        emergencyContact: demoText(studentPublic.guardianPhone, 'غير متوفر', 60),
        cardUpdatedAt: cardPublic.updatedAt || cardPublic.createdAt || null
      });
    }

    if (pathname === '/auth/login' && method === 'POST') {
      var loginBody = await body();
      var role = demoText(loginBody.role, '', 20);
      if (!ROLE_LABELS[role]) {
        return demoJsonResponse(400, { error: 'Invalid role' });
      }
      var loginUser = demoEnsureRoleLoginUser(data, role);
      if (!loginUser) {
        return demoJsonResponse(404, { error: 'No active user for this role' });
      }
      var session = setSession(role);
      var token = 'demo_' + demoId('tk');
      setToken(token);
      demoLogAction(data, { user: loginUser }, 'auth.login', 'session', { role: role });
      saveDemoData(data);
      return demoJsonResponse(200, {
        token: token,
        session: session,
        user: loginUser,
        permissions: ROLE_PERMISSIONS[role] || []
      });
    }

    if (pathname === '/auth/logout' && method === 'POST') {
      return demoJsonResponse(200, { ok: true });
    }

    if (pathname === '/auth/me' && method === 'GET') {
      var meGate = demoRequireRole(data);
      if (!meGate.ok) return meGate.response;
      return demoJsonResponse(200, {
        user: meGate.auth.user,
        session: meGate.auth.session,
        permissions: ROLE_PERMISSIONS[meGate.auth.user.role] || []
      });
    }

    if (pathname === '/cases' && method === 'GET') {
      var casesGate = demoRequireRole(data, ['doctor', 'admin', 'emergency', 'student', 'parent']);
      if (!casesGate.ok) return casesGate.response;
      var list = deepClone(data.cases || []);
      if (casesGate.auth.user.role === 'student') {
        list = list.filter(function (item) { return item.studentId === casesGate.auth.user.id; });
      }
      if (casesGate.auth.user.role === 'parent') {
        list = list.filter(function (item) { return item.studentId === 'u_student_1'; });
      }
      return demoJsonResponse(200, { items: list });
    }

    if (parts[0] === 'cases' && parts.length === 3 && parts[2] === 'actions' && method === 'POST') {
      var actionGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!actionGate.ok) return actionGate.response;
      var targetCaseForAction = demoGetCaseByAnyId(data, parts[1]);
      if (!targetCaseForAction) {
        return demoJsonResponse(404, { error: 'Case not found' });
      }
      var actionBody = await body();
      var actionType = demoText(actionBody.type, 'note', 40);
      var actionNote = demoText(actionBody.note, 'تم تنفيذ إجراء على الحالة', 320);
      targetCaseForAction.updatedAt = demoNowIso();
      if (actionType === 'close_case' || actionType === 'handover_complete') targetCaseForAction.status = 'closed';
      if (actionType === 'external_referral' || actionType === 'emergency_protocol' || actionType === 'ambulance_dispatch') {
        targetCaseForAction.status = 'in_progress';
        targetCaseForAction.severity = 'critical';
      }
      if (actionType === 'stabilized_case') targetCaseForAction.severity = 'medium';
      if (actionType === 'careplan_save' && actionBody.plan) targetCaseForAction.notes = String(actionBody.plan);
      if (actionType === 'vitals_update') {
        var actionVitals = actionBody && typeof actionBody.vitals === 'object' ? actionBody.vitals : actionBody;
        var actionReading = demoNormalizeVitalsReading(targetCaseForAction.studentId, {
          temp: actionVitals.temp,
          spo2: actionVitals.spo2,
          hr: actionVitals.hr,
          bpSys: actionVitals.bpSys,
          bpDia: actionVitals.bpDia,
          sensorId: demoText(actionVitals.sensorId, '', 100),
          source: demoText(actionVitals.source, 'case_action', 30),
          measuredAt: demoNowIso()
        }, 'case_action');
        demoPersistVitalsReading(data, actionReading);
        demoUpdateSensorAfterReading(data, targetCaseForAction.studentId, actionReading);
      }
      demoLogAction(data, actionGate.auth, 'case.action.' + actionType, targetCaseForAction.id, { note: actionNote });
      demoPushAlert(
        data,
        ['admin', 'doctor', 'emergency', 'parent', 'student'],
        'تحديث حالة ' + targetCaseForAction.studentName + ': ' + actionNote,
        (actionType === 'emergency_protocol' || actionType === 'external_referral' || actionType === 'ambulance_dispatch') ? 'critical' : 'operational'
      );
      saveDemoData(data);
      return demoJsonResponse(201, { ok: true });
    }

    if (parts[0] === 'cases' && parts.length === 2 && method === 'GET') {
      var caseGate = demoRequireRole(data, ['doctor', 'admin', 'emergency', 'student', 'parent']);
      if (!caseGate.ok) return caseGate.response;
      var targetCase = demoGetCaseByAnyId(data, parts[1]);
      if (!targetCase) {
        return demoJsonResponse(404, { error: 'Case not found' });
      }
      if (caseGate.auth.user.role === 'student' && targetCase.studentId !== caseGate.auth.user.id) {
        return demoJsonResponse(403, { error: 'Forbidden' });
      }
      if (caseGate.auth.user.role === 'parent' && targetCase.studentId !== 'u_student_1') {
        return demoJsonResponse(403, { error: 'Forbidden' });
      }
      var timeline = (data.auditLogs || []).filter(function (item) {
        return item.target === targetCase.id;
      }).slice(-20).reverse();
      return demoJsonResponse(200, { item: targetCase, timeline: timeline });
    }

    if (parts[0] === 'cases' && parts.length === 2 && method === 'PATCH') {
      var patchGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!patchGate.ok) return patchGate.response;
      var targetCaseForPatch = demoGetCaseByAnyId(data, parts[1]);
      if (!targetCaseForPatch) {
        return demoJsonResponse(404, { error: 'Case not found' });
      }
      var patchBody = await body();
      if (typeof patchBody.status === 'string') targetCaseForPatch.status = patchBody.status;
      if (typeof patchBody.notes === 'string') targetCaseForPatch.notes = patchBody.notes;
      if (typeof patchBody.severity === 'string') targetCaseForPatch.severity = patchBody.severity;
      targetCaseForPatch.updatedAt = demoNowIso();
      demoLogAction(data, patchGate.auth, 'case.update', targetCaseForPatch.id, patchBody || {});
      saveDemoData(data);
      return demoJsonResponse(200, { item: targetCaseForPatch });
    }

    if (pathname === '/visit-requests' && method === 'GET') {
      var visitListGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!visitListGate.ok) return visitListGate.response;
      return demoJsonResponse(200, { items: (data.visitRequests || []).slice().reverse() });
    }

    if (pathname === '/visit-requests' && method === 'POST') {
      var visitCreateGate = demoRequireRole(data, ['student', 'admin']);
      if (!visitCreateGate.ok) return visitCreateGate.response;
      var visitBody = await body();
      var visit = {
        id: demoId('vr'),
        studentId: visitCreateGate.auth.user.role === 'student' ? visitCreateGate.auth.user.id : demoText(visitBody.studentId, 'u_student_1', 40),
        reason: demoText(visitBody.reason, 'طلب فحص عام', 220),
        status: 'pending',
        createdAt: demoNowIso()
      };
      data.visitRequests.push(visit);
      demoPushAlert(
        data,
        ['doctor', 'admin', 'emergency', 'parent', 'student'],
        'طلب زيارة جديد: ' + visit.reason,
        String(visit.reason || '').toLowerCase().indexOf('urgent') !== -1 ? 'critical' : 'operational'
      );
      demoLogAction(data, visitCreateGate.auth, 'visit.request.create', visit.id, visit);
      saveDemoData(data);
      return demoJsonResponse(201, { item: visit });
    }

    if (pathname === '/emergency-card' && method === 'GET') {
      var emergencyCardGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!emergencyCardGate.ok) return emergencyCardGate.response;
      var emergencyStudentId = demoResolveStudentId(emergencyCardGate.auth, urlObj);
      if (!demoCanAccessStudentScope(emergencyCardGate.auth, emergencyStudentId)) {
        return demoJsonResponse(403, { error: 'Forbidden student scope' });
      }
      var emergencyPayload = demoEmergencyCardPayload(data, emergencyStudentId);
      if (!emergencyPayload) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      demoLogAction(data, emergencyCardGate.auth, 'student.emergency.card.view', emergencyStudentId, { studentId: emergencyStudentId });
      saveDemoData(data);
      return demoJsonResponse(200, emergencyPayload);
    }

    if (pathname === '/consents' && method === 'GET') {
      var consentsGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!consentsGate.ok) return consentsGate.response;
      var consentItems = (data.consents || []).slice();
      if (consentsGate.auth.user.role === 'student') {
        consentItems = consentItems.filter(function (item) { return item.studentId === consentsGate.auth.user.id; });
      } else if (consentsGate.auth.user.role === 'parent') {
        consentItems = consentItems.filter(function (item) { return item.studentId === 'u_student_1'; });
      } else {
        var consentStudentFilter = demoText(urlObj.searchParams.get('studentId'), '', 80);
        if (consentStudentFilter) {
          consentItems = consentItems.filter(function (item) { return item.studentId === consentStudentFilter; });
        }
      }
      var consentStatusFilter = demoText(urlObj.searchParams.get('status'), '', 20);
      if (consentStatusFilter) {
        consentItems = consentItems.filter(function (item) { return item.status === consentStatusFilter; });
      }
      consentItems = consentItems.sort(function (a, b) { return new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0); });
      return demoJsonResponse(200, { items: consentItems });
    }

    if (pathname === '/consents' && method === 'POST') {
      var consentCreateGate = demoRequireRole(data, ['doctor', 'admin']);
      if (!consentCreateGate.ok) return consentCreateGate.response;
      var consentBody = await body();
      var consentStudent = demoText(consentBody.studentId, '', 80) || demoResolveStudentId(consentCreateGate.auth, urlObj);
      var consentStudentUser = demoFindStudent(data, consentStudent);
      if (!consentStudentUser) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      var consentType = demoText(consentBody.type, 'medication', 30);
      if (['medication', 'referral', 'telemed'].indexOf(consentType) === -1) {
        return demoJsonResponse(400, { error: 'Invalid consent type' });
      }
      var consent = {
        id: demoId('cons'),
        studentId: consentStudent,
        studentName: consentStudentUser.name || consentStudentUser.id,
        type: consentType,
        title: demoText(consentBody.title, 'طلب موافقة ' + consentType, 220),
        details: demoText(consentBody.details, 'يرجى مراجعة الطلب واتخاذ القرار المناسب.', 900),
        status: 'pending',
        relatedEntityId: demoText(consentBody.relatedEntityId, '', 80) || null,
        createdAt: demoNowIso(),
        updatedAt: demoNowIso(),
        createdByUserId: consentCreateGate.auth.user.id,
        createdByRole: consentCreateGate.auth.user.role,
        decisionNote: null,
        decidedAt: null,
        decidedByUserId: null,
        decidedByRole: null,
        digitalSignature: null,
        legalLog: [
          {
            id: demoId('legal'),
            event: 'consent_requested',
            at: demoNowIso(),
            actorUserId: consentCreateGate.auth.user.id,
            actorRole: consentCreateGate.auth.user.role,
            note: 'تم إنشاء طلب الموافقة.'
          }
        ]
      };
      data.consents.unshift(consent);
      demoPushAlert(data, ['parent', 'admin', 'doctor'], 'طلب موافقة جديد (' + consentType + ') للطالب ' + consent.studentName, consentType === 'referral' ? 'critical' : 'operational');
      demoLogAction(data, consentCreateGate.auth, 'consent.request.create', consent.id, {
        studentId: consentStudent,
        type: consentType,
        status: consent.status
      });
      saveDemoData(data);
      return demoJsonResponse(201, { item: consent });
    }

    if (parts[0] === 'consents' && parts[2] === 'decision' && method === 'POST') {
      var consentDecisionGate = demoRequireRole(data, ['parent', 'admin']);
      if (!consentDecisionGate.ok) return consentDecisionGate.response;
      var consentId = demoText(parts[1], '', 80);
      var consentItem = (data.consents || []).find(function (item) { return item.id === consentId; }) || null;
      if (!consentItem) {
        return demoJsonResponse(404, { error: 'Consent not found' });
      }
      if (consentDecisionGate.auth.user.role === 'parent' && consentItem.studentId !== 'u_student_1') {
        return demoJsonResponse(403, { error: 'Forbidden' });
      }
      if (consentItem.status !== 'pending') {
        return demoJsonResponse(409, { error: 'Consent already decided' });
      }
      var consentDecisionBody = await body();
      var consentDecision = demoText(consentDecisionBody.decision, '', 20).toLowerCase();
      if (consentDecision !== 'approve' && consentDecision !== 'reject') {
        return demoJsonResponse(400, { error: 'Invalid decision' });
      }
      consentItem.status = consentDecision === 'approve' ? 'approved' : 'rejected';
      consentItem.decidedAt = demoNowIso();
      consentItem.updatedAt = demoNowIso();
      consentItem.decidedByUserId = consentDecisionGate.auth.user.id;
      consentItem.decidedByRole = consentDecisionGate.auth.user.role;
      consentItem.decisionNote = demoText(consentDecisionBody.note, '', 500);
      consentItem.digitalSignature = demoText(consentDecisionBody.signature, consentDecisionGate.auth.user.id + ':' + Date.now(), 120);
      consentItem.legalLog = Array.isArray(consentItem.legalLog) ? consentItem.legalLog : [];
      consentItem.legalLog.push({
        id: demoId('legal'),
        event: 'consent_decision',
        at: consentItem.decidedAt,
        actorUserId: consentDecisionGate.auth.user.id,
        actorRole: consentDecisionGate.auth.user.role,
        decision: consentItem.status,
        signature: consentItem.digitalSignature,
        note: consentItem.decisionNote || null
      });
      demoPushAlert(data, ['doctor', 'admin', 'parent'], 'تم ' + (consentItem.status === 'approved' ? 'اعتماد' : 'رفض') + ' موافقة ' + consentItem.type + ' للطالب ' + consentItem.studentName, consentItem.status === 'approved' ? 'operational' : 'info');
      demoLogAction(data, consentDecisionGate.auth, 'consent.request.decide', consentItem.id, {
        decision: consentItem.status,
        signature: consentItem.digitalSignature
      });
      saveDemoData(data);
      return demoJsonResponse(200, { item: consentItem });
    }

    if (pathname === '/home-care/plans' && method === 'GET') {
      var homeCareGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!homeCareGate.ok) return homeCareGate.response;
      var homeCareStudentId = demoResolveStudentId(homeCareGate.auth, urlObj);
      if (!demoCanAccessStudentScope(homeCareGate.auth, homeCareStudentId)) {
        return demoJsonResponse(403, { error: 'Forbidden student scope' });
      }
      var homeStatusFilter = demoText(urlObj.searchParams.get('status'), '', 30);
      var homeItems = (data.homeCarePlans || []).filter(function (item) { return item.studentId === homeCareStudentId; });
      if (homeStatusFilter) {
        homeItems = homeItems.filter(function (item) { return item.status === homeStatusFilter; });
      }
      homeItems = homeItems.sort(function (a, b) { return new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0); });
      return demoJsonResponse(200, { items: homeItems });
    }

    if (pathname === '/home-care/plans' && method === 'POST') {
      var homeCreateGate = demoRequireRole(data, ['doctor', 'admin']);
      if (!homeCreateGate.ok) return homeCreateGate.response;
      var homeCreateBody = await body();
      var homeStudent = demoText(homeCreateBody.studentId, '', 80) || demoResolveStudentId(homeCreateGate.auth, urlObj);
      var homeStudentUser = demoFindStudent(data, homeStudent);
      if (!homeStudentUser) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      var sourceItems = [];
      if (Array.isArray(homeCreateBody.items)) {
        sourceItems = homeCreateBody.items;
      } else if (typeof homeCreateBody.itemsText === 'string') {
        sourceItems = homeCreateBody.itemsText.split('\n');
      }
      var checklist = sourceItems.map(function (entry) {
        return demoText(entry, '', 160);
      }).filter(function (entry) {
        return Boolean(entry);
      }).slice(0, 12).map(function (label) {
        return {
          id: demoId('chk'),
          label: label,
          done: false,
          reminderTime: demoText(homeCreateBody.reminderTime, '19:00', 20),
          lastDoneAt: null
        };
      });
      if (!checklist.length) {
        checklist = [
          { id: demoId('chk'), label: 'تأكيد تناول الدواء بالجرعة المحددة', done: false, reminderTime: '19:00', lastDoneAt: null },
          { id: demoId('chk'), label: 'متابعة السوائل والراحة', done: false, reminderTime: '20:00', lastDoneAt: null },
          { id: demoId('chk'), label: 'تسجيل أي أعراض جديدة', done: false, reminderTime: '21:00', lastDoneAt: null }
        ];
      }
      var plan = {
        id: demoId('hcp'),
        studentId: homeStudent,
        studentName: homeStudentUser.name || homeStudentUser.id,
        title: demoText(homeCreateBody.title, 'خطة متابعة منزلية', 220),
        notes: demoText(homeCreateBody.notes, '', 500),
        status: 'active',
        createdAt: demoNowIso(),
        updatedAt: demoNowIso(),
        createdByUserId: homeCreateGate.auth.user.id,
        createdByRole: homeCreateGate.auth.user.role,
        checklist: checklist,
        logs: []
      };
      data.homeCarePlans.unshift(plan);
      demoPushAlert(data, ['parent', 'student', 'doctor', 'admin'], 'تم إنشاء خطة متابعة منزلية للطالب ' + plan.studentName, 'operational');
      demoLogAction(data, homeCreateGate.auth, 'homecare.plan.create', plan.id, { studentId: homeStudent, items: checklist.length });
      saveDemoData(data);
      return demoJsonResponse(201, { item: plan });
    }

    if (parts[0] === 'home-care' && parts[1] === 'plans' && parts[3] === 'check' && method === 'POST') {
      var homeCheckGate = demoRequireRole(data, ['student', 'parent', 'admin']);
      if (!homeCheckGate.ok) return homeCheckGate.response;
      var planId = demoText(parts[2], '', 80);
      var planItem = (data.homeCarePlans || []).find(function (item) { return item.id === planId; }) || null;
      if (!planItem) {
        return demoJsonResponse(404, { error: 'Plan not found' });
      }
      if (!demoCanAccessStudentScope(homeCheckGate.auth, planItem.studentId)) {
        return demoJsonResponse(403, { error: 'Forbidden' });
      }
      var homeCheckBody = await body();
      var itemId = demoText(homeCheckBody.itemId, '', 80);
      var idx = Number(homeCheckBody.index);
      var task = null;
      if (itemId) {
        task = (planItem.checklist || []).find(function (entry) { return entry.id === itemId; }) || null;
      } else if (Number.isInteger(idx) && idx >= 0 && idx < (planItem.checklist || []).length) {
        task = planItem.checklist[idx];
      }
      if (!task) {
        return demoJsonResponse(404, { error: 'Checklist item not found' });
      }
      var done = typeof homeCheckBody.done === 'boolean' ? homeCheckBody.done : !task.done;
      task.done = done;
      task.lastDoneAt = done ? demoNowIso() : null;
      task.lastNote = demoText(homeCheckBody.note, '', 200);
      planItem.updatedAt = demoNowIso();
      planItem.logs = Array.isArray(planItem.logs) ? planItem.logs : [];
      planItem.logs.unshift({
        id: demoId('hcl'),
        itemId: task.id,
        itemLabel: task.label,
        done: done,
        note: task.lastNote || null,
        actorUserId: homeCheckGate.auth.user.id,
        actorRole: homeCheckGate.auth.user.role,
        at: demoNowIso()
      });
      if ((planItem.checklist || []).every(function (entry) { return Boolean(entry.done); })) {
        planItem.status = 'completed';
      } else if (planItem.status === 'completed') {
        planItem.status = 'active';
      }
      demoLogAction(data, homeCheckGate.auth, 'homecare.check.update', planItem.id, { itemId: task.id, done: done });
      saveDemoData(data);
      return demoJsonResponse(200, { item: planItem, task: task });
    }

    if (pathname === '/appointments' && method === 'GET') {
      var appointmentsGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!appointmentsGate.ok) return appointmentsGate.response;
      var appointmentItems = (data.appointments || []).slice();
      if (appointmentsGate.auth.user.role === 'doctor' || appointmentsGate.auth.user.role === 'admin') {
        var allAppointments = String(urlObj.searchParams.get('all') || '') === '1';
        if (!allAppointments) {
          var doctorStudent = demoResolveStudentId(appointmentsGate.auth, urlObj);
          appointmentItems = appointmentItems.filter(function (item) { return item.studentId === doctorStudent; });
        }
      } else if (appointmentsGate.auth.user.role === 'student') {
        appointmentItems = appointmentItems.filter(function (item) { return item.studentId === appointmentsGate.auth.user.id; });
      } else {
        appointmentItems = appointmentItems.filter(function (item) { return item.studentId === 'u_student_1'; });
      }
      var appointmentStatus = demoText(urlObj.searchParams.get('status'), '', 20);
      if (appointmentStatus) {
        appointmentItems = appointmentItems.filter(function (item) { return item.status === appointmentStatus; });
      }
      appointmentItems = appointmentItems.sort(function (a, b) { return new Date(a.slotAt || a.createdAt || 0) - new Date(b.slotAt || b.createdAt || 0); });
      return demoJsonResponse(200, { items: appointmentItems });
    }

    if (pathname === '/appointments' && method === 'POST') {
      var appointmentCreateGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!appointmentCreateGate.ok) return appointmentCreateGate.response;
      var appointmentBody = await body();
      var appointmentStudent = demoText(appointmentBody.studentId, '', 80) || demoResolveStudentId(appointmentCreateGate.auth, urlObj);
      if (!demoCanAccessStudentScope(appointmentCreateGate.auth, appointmentStudent) && (appointmentCreateGate.auth.user.role !== 'doctor' && appointmentCreateGate.auth.user.role !== 'admin')) {
        return demoJsonResponse(403, { error: 'Forbidden student scope' });
      }
      var appointmentStudentUser = demoFindStudent(data, appointmentStudent);
      if (!appointmentStudentUser) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      var slot = demoText(appointmentBody.slotAt, '', 40);
      var slotDate = slot ? new Date(slot) : new Date(Date.now() + (24 * 60 * 60 * 1000));
      var slotAt = Number.isFinite(slotDate.getTime()) ? slotDate.toISOString() : new Date(Date.now() + (24 * 60 * 60 * 1000)).toISOString();
      var appointment = {
        id: demoId('apt'),
        studentId: appointmentStudent,
        studentName: appointmentStudentUser.name || appointmentStudentUser.id,
        reason: demoText(appointmentBody.reason, 'حجز موعد زيارة للعيادة', 260),
        slotAt: slotAt,
        status: 'pending',
        requestedByUserId: appointmentCreateGate.auth.user.id,
        requestedByRole: appointmentCreateGate.auth.user.role,
        createdAt: demoNowIso(),
        updatedAt: demoNowIso(),
        notes: demoText(appointmentBody.notes, '', 280)
      };
      data.appointments.unshift(appointment);
      demoPushAlert(data, ['doctor', 'admin', 'parent', 'student'], 'تم إنشاء موعد جديد بتاريخ ' + new Date(slotAt).toLocaleString('ar-SA'), 'operational');
      demoLogAction(data, appointmentCreateGate.auth, 'appointment.create', appointment.id, { studentId: appointmentStudent, slotAt: slotAt });
      saveDemoData(data);
      return demoJsonResponse(201, { item: appointment });
    }

    if (parts[0] === 'appointments' && parts[2] === 'status' && method === 'POST') {
      var appointmentStatusGate = demoRequireRole(data, ['doctor', 'admin']);
      if (!appointmentStatusGate.ok) return appointmentStatusGate.response;
      var appointmentId = demoText(parts[1], '', 80);
      var appointmentTarget = (data.appointments || []).find(function (item) { return item.id === appointmentId; }) || null;
      if (!appointmentTarget) {
        return demoJsonResponse(404, { error: 'Appointment not found' });
      }
      var appointmentStatusBody = await body();
      var nextStatus = demoText(appointmentStatusBody.status, '', 20).toLowerCase();
      if (['pending', 'confirmed', 'completed', 'cancelled'].indexOf(nextStatus) === -1) {
        return demoJsonResponse(400, { error: 'Invalid status' });
      }
      appointmentTarget.status = nextStatus;
      appointmentTarget.updatedAt = demoNowIso();
      if (nextStatus === 'confirmed') appointmentTarget.confirmedAt = demoNowIso();
      if (nextStatus === 'completed') appointmentTarget.completedAt = demoNowIso();
      if (nextStatus === 'cancelled') appointmentTarget.cancelledAt = demoNowIso();
      appointmentTarget.statusNote = demoText(appointmentStatusBody.note, appointmentTarget.statusNote || '', 300);
      demoPushAlert(data, ['student', 'parent', 'doctor', 'admin'], 'تحديث الموعد: ' + nextStatus + ' (' + appointmentTarget.reason + ')', nextStatus === 'cancelled' ? 'info' : 'operational');
      demoLogAction(data, appointmentStatusGate.auth, 'appointment.status.update', appointmentTarget.id, { status: nextStatus });
      saveDemoData(data);
      return demoJsonResponse(200, { item: appointmentTarget });
    }

    if (pathname === '/tickets' && method === 'GET') {
      var ticketsGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!ticketsGate.ok) return ticketsGate.response;
      var ticketStatusFilter = demoText(urlObj.searchParams.get('status'), '', 20);
      var tickets = (data.tickets || []).filter(function (item) { return demoCanAccessTicket(ticketsGate.auth, item); });
      if (ticketStatusFilter) {
        tickets = tickets.filter(function (item) { return item.status === ticketStatusFilter; });
      }
      tickets = tickets.slice().sort(function (a, b) {
        return new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0);
      }).map(function (item) {
        return {
          id: item.id,
          number: item.number,
          studentId: item.studentId,
          studentName: item.studentName,
          subject: item.subject,
          priority: item.priority,
          status: item.status,
          assignedToUserId: item.assignedToUserId || null,
          createdAt: item.createdAt,
          updatedAt: item.updatedAt,
          closedAt: item.closedAt || null,
          messagesCount: Array.isArray(item.messages) ? item.messages.length : 0,
          lastMessage: Array.isArray(item.messages) && item.messages.length ? item.messages[item.messages.length - 1].text : null
        };
      });
      return demoJsonResponse(200, { items: tickets });
    }

    if (pathname === '/tickets' && method === 'POST') {
      var ticketCreateGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!ticketCreateGate.ok) return ticketCreateGate.response;
      var ticketBody = await body();
      var ticketStudent = demoText(ticketBody.studentId, '', 80) || demoResolveStudentId(ticketCreateGate.auth, urlObj);
      if (!demoCanAccessStudentScope(ticketCreateGate.auth, ticketStudent) && (ticketCreateGate.auth.user.role !== 'doctor' && ticketCreateGate.auth.user.role !== 'admin')) {
        return demoJsonResponse(403, { error: 'Forbidden student scope' });
      }
      var ticketStudentUser = demoFindStudent(data, ticketStudent);
      if (!ticketStudentUser) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      var ticketText = demoText(ticketBody.text, '', 1000);
      if (!ticketText) {
        return demoJsonResponse(400, { error: 'Ticket text is required' });
      }
      var ticket = {
        id: demoId('tkt'),
        number: 'TKT-' + Date.now().toString().slice(-6),
        studentId: ticketStudent,
        studentName: ticketStudentUser.name || ticketStudentUser.id,
        subject: demoText(ticketBody.subject, 'استفسار صحي', 220),
        priority: ['low', 'normal', 'high', 'critical'].indexOf(ticketBody.priority) !== -1 ? ticketBody.priority : 'normal',
        status: 'open',
        createdByUserId: ticketCreateGate.auth.user.id,
        createdByRole: ticketCreateGate.auth.user.role,
        assignedToUserId: demoText(ticketBody.assignedToUserId, 'u_doctor_1', 80),
        createdAt: demoNowIso(),
        updatedAt: demoNowIso(),
        closedAt: null,
        messages: [
          {
            id: demoId('tmsg'),
            fromUserId: ticketCreateGate.auth.user.id,
            fromRole: ticketCreateGate.auth.user.role,
            text: ticketText,
            createdAt: demoNowIso()
          }
        ]
      };
      data.tickets.unshift(ticket);
      demoPushAlert(data, ['doctor', 'admin'], 'تذكرة جديدة ' + ticket.number + ': ' + ticket.subject, ticket.priority === 'critical' ? 'critical' : 'operational');
      demoLogAction(data, ticketCreateGate.auth, 'ticket.create', ticket.id, { number: ticket.number, priority: ticket.priority });
      saveDemoData(data);
      return demoJsonResponse(201, { item: ticket });
    }

    if (parts[0] === 'tickets' && parts.length === 3 && parts[2] === 'messages' && method === 'GET') {
      var ticketMessagesGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!ticketMessagesGate.ok) return ticketMessagesGate.response;
      var ticketIdView = demoText(parts[1], '', 80);
      var ticketView = (data.tickets || []).find(function (item) { return item.id === ticketIdView; }) || null;
      if (!ticketView) {
        return demoJsonResponse(404, { error: 'Ticket not found' });
      }
      if (!demoCanAccessTicket(ticketMessagesGate.auth, ticketView)) {
        return demoJsonResponse(403, { error: 'Forbidden' });
      }
      return demoJsonResponse(200, { item: ticketView, messages: ticketView.messages || [] });
    }

    if (parts[0] === 'tickets' && parts.length === 3 && parts[2] === 'messages' && method === 'POST') {
      var ticketReplyGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!ticketReplyGate.ok) return ticketReplyGate.response;
      var ticketReplyId = demoText(parts[1], '', 80);
      var ticketReply = (data.tickets || []).find(function (item) { return item.id === ticketReplyId; }) || null;
      if (!ticketReply) {
        return demoJsonResponse(404, { error: 'Ticket not found' });
      }
      if (!demoCanAccessTicket(ticketReplyGate.auth, ticketReply)) {
        return demoJsonResponse(403, { error: 'Forbidden' });
      }
      var ticketReplyBody = await body();
      var ticketReplyText = demoText(ticketReplyBody.text, '', 1000);
      if (!ticketReplyText) {
        return demoJsonResponse(400, { error: 'Message text is required' });
      }
      var ticketMessage = {
        id: demoId('tmsg'),
        fromUserId: ticketReplyGate.auth.user.id,
        fromRole: ticketReplyGate.auth.user.role,
        text: ticketReplyText,
        createdAt: demoNowIso()
      };
      if (!Array.isArray(ticketReply.messages)) ticketReply.messages = [];
      ticketReply.messages.push(ticketMessage);
      ticketReply.updatedAt = demoNowIso();
      if (ticketReply.status === 'closed' && (ticketReplyGate.auth.user.role === 'student' || ticketReplyGate.auth.user.role === 'parent')) {
        ticketReply.status = 'open';
        ticketReply.closedAt = null;
      } else if (ticketReply.status === 'open' && (ticketReplyGate.auth.user.role === 'doctor' || ticketReplyGate.auth.user.role === 'admin')) {
        ticketReply.status = 'in_progress';
      }
      if ((ticketReply.status === 'closed' || ticketReply.status === 'resolved') && !ticketReply.closedAt) {
        ticketReply.closedAt = demoNowIso();
      }
      demoLogAction(data, ticketReplyGate.auth, 'ticket.message.send', ticketReply.id, { messageId: ticketMessage.id });
      saveDemoData(data);
      return demoJsonResponse(201, { item: ticketReply, message: ticketMessage });
    }

    if (parts[0] === 'tickets' && parts.length === 2 && method === 'PATCH') {
      var ticketPatchGate = demoRequireRole(data, ['doctor', 'admin']);
      if (!ticketPatchGate.ok) return ticketPatchGate.response;
      var ticketPatchId = demoText(parts[1], '', 80);
      var ticketPatch = (data.tickets || []).find(function (item) { return item.id === ticketPatchId; }) || null;
      if (!ticketPatch) {
        return demoJsonResponse(404, { error: 'Ticket not found' });
      }
      var ticketPatchBody = await body();
      if (typeof ticketPatchBody.assignedToUserId === 'string' && ticketPatchBody.assignedToUserId.trim()) {
        ticketPatch.assignedToUserId = demoText(ticketPatchBody.assignedToUserId, ticketPatch.assignedToUserId || '', 80);
      }
      if (typeof ticketPatchBody.status === 'string') {
        var patchStatus = demoText(ticketPatchBody.status, '', 20).toLowerCase();
        if (patchStatus === 'open' || patchStatus === 'in_progress' || patchStatus === 'closed') {
          ticketPatch.status = patchStatus;
          if (patchStatus === 'closed') {
            ticketPatch.closedAt = demoNowIso();
          } else {
            ticketPatch.closedAt = null;
          }
        }
      }
      ticketPatch.updatedAt = demoNowIso();
      demoLogAction(data, ticketPatchGate.auth, 'ticket.update', ticketPatch.id, {
        status: ticketPatch.status,
        assignedToUserId: ticketPatch.assignedToUserId
      });
      saveDemoData(data);
      return demoJsonResponse(200, { item: ticketPatch });
    }

    if (pathname === '/medications/plans' && method === 'POST') {
      var medicationPlanGate = demoRequireRole(data, ['doctor', 'admin']);
      if (!medicationPlanGate.ok) return medicationPlanGate.response;
      var medicationPlanBody = await body();
      var medicationStudent = demoText(medicationPlanBody.studentId, '', 80) || demoResolveStudentId(medicationPlanGate.auth, urlObj);
      var medicationStudentUser = demoFindStudent(data, medicationStudent);
      if (!medicationStudentUser) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      var medicationName = demoText(medicationPlanBody.name, '', 140);
      if (!medicationName) {
        return demoJsonResponse(400, { error: 'Medication name is required' });
      }
      var medicationPlan = {
        id: demoId('medp'),
        studentId: medicationStudent,
        studentName: medicationStudentUser.name || medicationStudentUser.id,
        name: medicationName,
        dosesPerDay: Math.max(1, Math.min(8, Number(medicationPlanBody.dosesPerDay || 1))),
        instructions: demoText(medicationPlanBody.instructions, '', 400),
        startDate: demoText(medicationPlanBody.startDate, new Date().toISOString().slice(0, 10), 40),
        endDate: demoText(medicationPlanBody.endDate, '', 40),
        active: true,
        createdAt: demoNowIso(),
        createdByUserId: medicationPlanGate.auth.user.id,
        createdByRole: medicationPlanGate.auth.user.role
      };
      data.medicationPlans.unshift(medicationPlan);
      demoPushAlert(data, ['parent', 'student', 'doctor', 'admin'], 'تمت إضافة خطة دوائية: ' + medicationPlan.name, 'operational');
      demoLogAction(data, medicationPlanGate.auth, 'medication.plan.create', medicationPlan.id, { studentId: medicationStudent, dosesPerDay: medicationPlan.dosesPerDay });
      saveDemoData(data);
      return demoJsonResponse(201, { item: medicationPlan });
    }

    if (pathname === '/medications/logs' && method === 'POST') {
      var medicationLogGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!medicationLogGate.ok) return medicationLogGate.response;
      var medicationLogBody = await body();
      var planId = demoText(medicationLogBody.planId, '', 80);
      var planTarget = planId ? (data.medicationPlans || []).find(function (item) { return item.id === planId; }) : null;
      var logStudent = planTarget ? planTarget.studentId : demoText(medicationLogBody.studentId, '', 80);
      if (!logStudent) {
        logStudent = demoResolveStudentId(medicationLogGate.auth, urlObj);
      }
      if (!demoCanAccessStudentScope(medicationLogGate.auth, logStudent) && (medicationLogGate.auth.user.role !== 'doctor' && medicationLogGate.auth.user.role !== 'admin')) {
        return demoJsonResponse(403, { error: 'Forbidden student scope' });
      }
      var logStatus = demoText(medicationLogBody.status, 'taken', 20).toLowerCase();
      if (logStatus !== 'taken' && logStatus !== 'skipped') {
        return demoJsonResponse(400, { error: 'Invalid medication log status' });
      }
      var logEntry = {
        id: demoId('medl'),
        studentId: logStudent,
        planId: planTarget ? planTarget.id : null,
        planName: planTarget ? planTarget.name : demoText(medicationLogBody.planName, '', 140),
        status: logStatus,
        note: demoText(medicationLogBody.note, '', 220),
        takenAt: demoNowIso(),
        createdAt: demoNowIso(),
        loggedByUserId: medicationLogGate.auth.user.id,
        loggedByRole: medicationLogGate.auth.user.role
      };
      data.medicationLogs.unshift(logEntry);
      var medSummary = demoMedicationAdherenceSummary(data, logStudent);
      if (medSummary.alert) {
        demoPushAlert(data, ['doctor', 'admin', 'parent', 'student'], medSummary.alert, 'critical');
      }
      demoLogAction(data, medicationLogGate.auth, 'medication.log.create', logEntry.id, {
        studentId: logStudent,
        planId: logEntry.planId,
        status: logStatus
      });
      saveDemoData(data);
      return demoJsonResponse(201, { item: logEntry, summary: medSummary });
    }

    if (pathname === '/medications/adherence' && method === 'GET') {
      var adherenceGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!adherenceGate.ok) return adherenceGate.response;
      var adherenceStudent = demoResolveStudentId(adherenceGate.auth, urlObj);
      if (!demoCanAccessStudentScope(adherenceGate.auth, adherenceStudent)) {
        return demoJsonResponse(403, { error: 'Forbidden student scope' });
      }
      return demoJsonResponse(200, demoMedicationAdherenceSummary(data, adherenceStudent));
    }

    if (pathname === '/referrals' && method === 'GET') {
      var referralsGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!referralsGate.ok) return referralsGate.response;
      var referralItems = (data.referrals || []).slice();
      if (referralsGate.auth.user.role === 'student') {
        referralItems = referralItems.filter(function (item) { return item.studentId === referralsGate.auth.user.id; });
      } else if (referralsGate.auth.user.role === 'parent') {
        referralItems = referralItems.filter(function (item) { return item.studentId === 'u_student_1'; });
      } else {
        var referralFilter = demoText(urlObj.searchParams.get('studentId'), '', 80);
        if (referralFilter) {
          referralItems = referralItems.filter(function (item) { return item.studentId === referralFilter; });
        }
      }
      referralItems = referralItems.sort(function (a, b) { return new Date(b.createdAt || 0) - new Date(a.createdAt || 0); });
      return demoJsonResponse(200, { items: referralItems });
    }

    if (pathname === '/referrals' && method === 'POST') {
      var referralCreateGate = demoRequireRole(data, ['doctor', 'admin']);
      if (!referralCreateGate.ok) return referralCreateGate.response;
      var referralBody = await body();
      var referralStudent = demoText(referralBody.studentId, '', 80) || demoResolveStudentId(referralCreateGate.auth, urlObj);
      var referralStudentUser = demoFindStudent(data, referralStudent);
      if (!referralStudentUser) {
        return demoJsonResponse(404, { error: 'Student not found' });
      }
      var referralReason = demoText(referralBody.reason, '', 280);
      if (!referralReason) {
        return demoJsonResponse(400, { error: 'Referral reason is required' });
      }
      var referral = {
        id: demoId('ref'),
        studentId: referralStudent,
        studentName: referralStudentUser.name || referralStudentUser.id,
        destination: demoText(referralBody.destination, 'مستشفى الطوارئ', 180),
        reason: referralReason,
        diagnosis: demoText(referralBody.diagnosis, '', 240),
        clinicalSummary: demoText(referralBody.clinicalSummary, '', 1000),
        status: 'issued',
        createdAt: demoNowIso(),
        createdByUserId: referralCreateGate.auth.user.id,
        createdByRole: referralCreateGate.auth.user.role
      };
      data.referrals.unshift(referral);
      demoPushAlert(data, ['parent', 'student', 'doctor', 'admin'], 'تم إنشاء إحالة خارجية للطالب ' + referral.studentName, 'critical');
      demoLogAction(data, referralCreateGate.auth, 'referral.create', referral.id, { studentId: referralStudent, destination: referral.destination });
      saveDemoData(data);
      return demoJsonResponse(201, { item: referral });
    }

    if (parts[0] === 'referrals' && parts[2] === 'pdf' && method === 'GET') {
      var referralPdfGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!referralPdfGate.ok) return referralPdfGate.response;
      var referralId = demoText(parts[1], '', 80);
      var referralTarget = (data.referrals || []).find(function (item) { return item.id === referralId; }) || null;
      if (!referralTarget) {
        return demoJsonResponse(404, { error: 'Referral not found' });
      }
      if (!demoCanAccessStudentScope(referralPdfGate.auth, referralTarget.studentId)) {
        return demoJsonResponse(403, { error: 'Forbidden' });
      }
      demoLogAction(data, referralPdfGate.auth, 'referral.pdf.export', referralTarget.id, {});
      saveDemoData(data);
      var referralPdfBody = [
        'Smart Clinic External Referral',
        'Referral ID: ' + referralTarget.id,
        'Generated At: ' + demoNowIso(),
        '---',
        'Student: ' + (referralTarget.studentName || referralTarget.studentId),
        'Student ID: ' + referralTarget.studentId,
        'Destination: ' + (referralTarget.destination || '-'),
        'Reason: ' + (referralTarget.reason || '-'),
        'Diagnosis: ' + (referralTarget.diagnosis || '-'),
        'Clinical Summary: ' + (referralTarget.clinicalSummary || '-'),
        'Issued By: ' + demoRoleLabel(referralTarget.createdByRole) + ' (' + (referralTarget.createdByUserId || '-') + ')'
      ].join('\n');
      return new Response(referralPdfBody, {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename="referral-' + referralTarget.id + '.pdf"'
        }
      });
    }

    if (pathname === '/reports/monthly' && method === 'GET') {
      var monthlyGate = demoRequireRole(data, ['admin']);
      if (!monthlyGate.ok) return monthlyGate.response;
      var monthlySummary = demoMonthlyExecutiveSummary(data, demoNormalizeMonthKey(urlObj.searchParams.get('month')));
      var monthlyIdx = (data.monthlyReports || []).findIndex(function (item) { return item.month === monthlySummary.month; });
      if (monthlyIdx >= 0) {
        data.monthlyReports[monthlyIdx] = monthlySummary;
      } else {
        data.monthlyReports.unshift(monthlySummary);
      }
      demoLogAction(data, monthlyGate.auth, 'report.monthly.view', monthlySummary.month, monthlySummary.metrics);
      saveDemoData(data);
      return demoJsonResponse(200, { item: monthlySummary });
    }

    if (pathname === '/reports/monthly/pdf' && method === 'GET') {
      var monthlyPdfGate = demoRequireRole(data, ['admin']);
      if (!monthlyPdfGate.ok) return monthlyPdfGate.response;
      var monthlyPdfSummary = demoMonthlyExecutiveSummary(data, demoNormalizeMonthKey(urlObj.searchParams.get('month')));
      demoLogAction(data, monthlyPdfGate.auth, 'report.monthly.pdf', monthlyPdfSummary.month, monthlyPdfSummary.metrics);
      saveDemoData(data);
      var monthlyPdfBody = [
        'Smart Clinic Monthly Executive Report',
        'Month: ' + monthlyPdfSummary.month,
        'Generated At: ' + demoNowIso(),
        '---',
        'Critical Cases: ' + monthlyPdfSummary.metrics.criticalCases,
        'Visit Requests: ' + monthlyPdfSummary.metrics.visitRequests,
        'Appointments Total: ' + monthlyPdfSummary.metrics.appointmentsTotal,
        'Appointments Completed: ' + monthlyPdfSummary.metrics.appointmentsCompleted,
        'Tickets Opened: ' + monthlyPdfSummary.metrics.ticketsOpened,
        'Tickets Closed: ' + monthlyPdfSummary.metrics.ticketsClosed,
        'Ticket Closure Rate: ' + monthlyPdfSummary.metrics.ticketClosureRate + '%',
        'Avg Ticket Resolution Hours: ' + monthlyPdfSummary.metrics.avgTicketResolutionHours,
        'Referrals: ' + monthlyPdfSummary.metrics.referrals,
        'Consents Requested: ' + monthlyPdfSummary.metrics.consentsRequested,
        'Consents Approved: ' + monthlyPdfSummary.metrics.consentsApproved
      ].join('\n');
      return new Response(monthlyPdfBody, {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename="monthly-executive-' + monthlyPdfSummary.month + '.pdf"'
        }
      });
    }

    if (pathname === '/messages' && method === 'POST') {
      var msgCreateGate = demoRequireRole(data, ['parent', 'student', 'admin']);
      if (!msgCreateGate.ok) return msgCreateGate.response;
      var msgBody = await body();
      var msgText = demoText(msgBody.text, '', 1000);
      if (!msgText) {
        return demoJsonResponse(400, { error: 'Message text is required' });
      }
      var message = {
        id: demoId('msg'),
        fromUserId: msgCreateGate.auth.user.id,
        fromRole: msgCreateGate.auth.user.role,
        text: msgText,
        createdAt: demoNowIso()
      };
      data.messages.push(message);
      demoPushAlert(data, ['doctor', 'admin'], 'رسالة جديدة من ' + msgCreateGate.auth.user.role, 'info');
      demoLogAction(data, msgCreateGate.auth, 'message.send', message.id, {});
      saveDemoData(data);
      return demoJsonResponse(201, { item: message });
    }

    if (pathname === '/messages' && method === 'GET') {
      var msgListGate = demoRequireRole(data, ['parent', 'student', 'doctor', 'admin']);
      if (!msgListGate.ok) return msgListGate.response;
      var msgItems = deepClone(data.messages || []);
      if (msgListGate.auth.user.role !== 'doctor' && msgListGate.auth.user.role !== 'admin') {
        msgItems = msgItems.filter(function (m) { return m.fromUserId === msgListGate.auth.user.id; });
      }
      return demoJsonResponse(200, { items: msgItems });
    }

    if (pathname === '/reports' && method === 'GET') {
      var reportGate = demoRequireRole(data, ['parent', 'doctor', 'admin', 'student']);
      if (!reportGate.ok) return reportGate.response;
      var reportItems = deepClone(data.reports || []);
      if (reportGate.auth.user.role === 'student') {
        reportItems = reportItems.filter(function (r) { return r.studentId === reportGate.auth.user.id; });
      }
      if (reportGate.auth.user.role === 'parent') {
        reportItems = reportItems.filter(function (r) { return r.studentId === 'u_student_1'; });
      }
      return demoJsonResponse(200, { items: reportItems });
    }

    if (pathname === '/reports/export' && method === 'POST') {
      var exportGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin']);
      if (!exportGate.ok) return exportGate.response;
      var exportBody = await body();
      var reportId = exportBody.reportId ? String(exportBody.reportId) : '';
      var report = reportId ? (data.reports || []).find(function (r) { return r.id === reportId; }) : null;
      if (reportId && !report) {
        return demoJsonResponse(404, { error: 'Report not found' });
      }
      demoLogAction(data, exportGate.auth, 'report.export', reportId || 'bulk', { reportId: reportId || null });
      saveDemoData(data);
      return demoJsonResponse(200, {
        ok: true,
        exportId: demoId('exp'),
        message: 'تم تجهيز ملف التقرير للتنزيل.',
        filename: report ? (report.title + '.pdf') : 'student-report.pdf'
      });
    }

    if (pathname === '/reports/executive' && method === 'GET') {
      var execGate = demoRequireRole(data, ['admin']);
      if (!execGate.ok) return execGate.response;
      return demoJsonResponse(200, {
        generatedAt: demoNowIso(),
        system: demoSystemOverview(data),
        analytics: demoAnalyticsOverview(data)
      });
    }

    if (pathname === '/reports/executive/pdf' && method === 'GET') {
      var pdfGate = demoRequireRole(data, ['admin']);
      if (!pdfGate.ok) return pdfGate.response;
      demoLogAction(data, pdfGate.auth, 'report.executive.pdf', 'executive_report', {});
      saveDemoData(data);
      var pdfBody = 'Smart Clinic Executive Report\nGenerated At: ' + demoNowIso() + '\nMode: demo';
      return new Response(pdfBody, {
        status: 200,
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename="executive-report.pdf"'
        }
      });
    }

    if (pathname === '/sla/monitor' && method === 'GET') {
      var slaGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!slaGate.ok) return slaGate.response;
      return demoJsonResponse(200, demoSlaMonitor(data));
    }

    if (pathname === '/vitals' && method === 'GET') {
      var vitalsGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin', 'emergency']);
      if (!vitalsGate.ok) return vitalsGate.response;
      var vitalsStudentId = demoResolveStudentId(vitalsGate.auth, urlObj);
      if (!vitalsStudentId) {
        return demoJsonResponse(400, { error: 'Student scope is invalid' });
      }
      var vitalsLimit = Math.max(1, Math.min(200, Number(urlObj.searchParams.get('limit') || 30)));
      return demoJsonResponse(200, demoVitalsPayloadForStudent(data, vitalsStudentId, vitalsLimit));
    }

    if (pathname === '/vitals/generate' && method === 'POST') {
      var vitalsGenerateGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!vitalsGenerateGate.ok) return vitalsGenerateGate.response;
      if ((ROLE_PERMISSIONS[vitalsGenerateGate.auth.user.role] || []).indexOf('update.vitals') === -1) {
        return demoJsonResponse(403, { error: 'Permission denied for vitals generation' });
      }
      var vitalsGenerateBody = await body();
      var vitalsGenerateStudent = demoText(vitalsGenerateBody.studentId, '', 60) || demoResolveStudentId(vitalsGenerateGate.auth, urlObj);
      if (!vitalsGenerateStudent) {
        return demoJsonResponse(400, { error: 'Student scope is invalid' });
      }
      var generated = demoGenerateVitalsReading(data, vitalsGenerateStudent, vitalsGenerateBody || {});
      if (generated.risk === 'critical') {
        demoPushAlert(
          data,
          ['doctor', 'admin', 'parent', 'student'],
          'قراءة حساسات حرجة للطالب ' + vitalsGenerateStudent + ' (SpO2 ' + generated.spo2 + '% / HR ' + generated.hr + ')',
          'critical'
        );
      }
      demoLogAction(data, vitalsGenerateGate.auth, 'vitals.generate', vitalsGenerateStudent, {
        studentId: vitalsGenerateStudent,
        readingId: generated.id,
        risk: generated.risk
      });
      saveDemoData(data);
      return demoJsonResponse(201, {
        item: generated,
        latest: generated,
        sensors: demoVitalsPayloadForStudent(data, vitalsGenerateStudent, 1).sensors
      });
    }

    if (pathname === '/vitals/ingest' && method === 'POST') {
      var vitalsIngestGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!vitalsIngestGate.ok) return vitalsIngestGate.response;
      if ((ROLE_PERMISSIONS[vitalsIngestGate.auth.user.role] || []).indexOf('update.vitals') === -1) {
        return demoJsonResponse(403, { error: 'Permission denied for vitals ingest' });
      }
      var vitalsIngestBody = await body();
      var vitalsIngestStudent = demoText(vitalsIngestBody.studentId, '', 60) || demoResolveStudentId(vitalsIngestGate.auth, urlObj);
      if (!vitalsIngestStudent) {
        return demoJsonResponse(400, { error: 'Student scope is invalid' });
      }
      var ingested = demoNormalizeVitalsReading(vitalsIngestStudent, {
        temp: vitalsIngestBody.temp,
        spo2: vitalsIngestBody.spo2,
        hr: vitalsIngestBody.hr,
        bpSys: vitalsIngestBody.bpSys,
        bpDia: vitalsIngestBody.bpDia,
        sensorId: demoText(vitalsIngestBody.sensorId, '', 100),
        source: demoText(vitalsIngestBody.source, 'sensor_bridge', 30),
        measuredAt: demoText(vitalsIngestBody.measuredAt, demoNowIso(), 40)
      }, 'sensor_bridge');
      demoPersistVitalsReading(data, ingested);
      demoUpdateSensorAfterReading(data, vitalsIngestStudent, ingested);
      if (ingested.risk === 'critical') {
        demoPushAlert(data, ['doctor', 'admin', 'parent', 'student'], 'إنذار حيوي: قراءة حرجة للطالب ' + vitalsIngestStudent, 'critical');
      }
      demoLogAction(data, vitalsIngestGate.auth, 'vitals.ingest', vitalsIngestStudent, {
        studentId: vitalsIngestStudent,
        readingId: ingested.id,
        sensorId: ingested.sensorId || null,
        risk: ingested.risk
      });
      saveDemoData(data);
      return demoJsonResponse(201, {
        item: ingested,
        latest: ingested,
        sensors: demoVitalsPayloadForStudent(data, vitalsIngestStudent, 1).sensors
      });
    }

    if (pathname === '/student/overview' && method === 'GET') {
      var overviewGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin', 'emergency']);
      if (!overviewGate.ok) return overviewGate.response;
      var studentId = demoResolveStudentId(overviewGate.auth, urlObj);
      if (!studentId) {
        return demoJsonResponse(400, { error: 'Student scope is invalid' });
      }
      return demoJsonResponse(200, demoStudentOverview(data, studentId));
    }

    if (pathname === '/ai/student-support' && method === 'POST') {
      var aiStudentGate = demoRequireRole(data, ['student', 'admin']);
      if (!aiStudentGate.ok) return aiStudentGate.response;
      var studentScope = demoResolveStudentId(aiStudentGate.auth, urlObj);
      var aiStudentBody = await body();
      var aiStudentResult = demoAiStudentSupport(data, studentScope, aiStudentBody || {});
      demoLogAction(data, aiStudentGate.auth, 'ai.student.support', studentScope, { risk: aiStudentResult.risk });
      saveDemoData(data);
      return demoJsonResponse(200, { item: aiStudentResult });
    }

    if (pathname === '/ai/doctor-support' && method === 'POST') {
      var aiDoctorGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!aiDoctorGate.ok) return aiDoctorGate.response;
      var aiDoctorBody = await body();
      var doctorCaseId = demoText(aiDoctorBody.caseId, '', 60);
      if (!doctorCaseId) {
        return demoJsonResponse(400, { error: 'caseId is required' });
      }
      var aiDoctorResult = demoAiDoctorSupport(data, doctorCaseId, aiDoctorBody || {});
      if (!aiDoctorResult) {
        return demoJsonResponse(404, { error: 'Case not found' });
      }
      demoLogAction(data, aiDoctorGate.auth, 'ai.doctor.support', aiDoctorResult.caseId, { priority: aiDoctorResult.priority });
      saveDemoData(data);
      return demoJsonResponse(200, { item: aiDoctorResult });
    }

    if (pathname === '/notifications' && method === 'GET') {
      var ntfGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin', 'emergency']);
      if (!ntfGate.ok) return ntfGate.response;
      var typeFilter = String(urlObj.searchParams.get('type') || 'all');
      var limit = Math.max(1, Math.min(200, Number(urlObj.searchParams.get('limit') || 100)));
      var ntfItems = demoNotificationsForRole(data, ntfGate.auth.user.role);
      if (typeFilter === 'critical' || typeFilter === 'operational' || typeFilter === 'info') {
        ntfItems = ntfItems.filter(function (item) { return item.type === typeFilter; });
      }
      return demoJsonResponse(200, { items: ntfItems.slice(0, limit) });
    }

    if (pathname === '/system/overview' && method === 'GET') {
      var sysGate = demoRequireRole(data, ['admin']);
      if (!sysGate.ok) return sysGate.response;
      return demoJsonResponse(200, demoSystemOverview(data));
    }

    if (pathname === '/settings' && method === 'GET') {
      var settingsGate = demoRequireRole(data, ['admin']);
      if (!settingsGate.ok) return settingsGate.response;
      return demoJsonResponse(200, { settings: demoEnsureSettings(data) });
    }

    if (pathname === '/settings' && method === 'PATCH') {
      var settingsPatchGate = demoRequireRole(data, ['admin']);
      if (!settingsPatchGate.ok) return settingsPatchGate.response;
      var currentSettings = demoEnsureSettings(data);
      var incomingBody = await body();
      var incoming = incomingBody && incomingBody.settings ? incomingBody.settings : {};
      var next = {
        sessionPolicy: Object.assign({}, currentSettings.sessionPolicy, incoming.sessionPolicy || {}),
        alerts: Object.assign({}, currentSettings.alerts, incoming.alerts || {}),
        sla: Object.assign({}, currentSettings.sla, incoming.sla || {})
      };
      if (['info', 'operational', 'critical'].indexOf(next.alerts.minimumLevel) === -1) {
        return demoJsonResponse(400, { error: 'Invalid alerts.minimumLevel' });
      }
      next.sessionPolicy.ttlHours = Math.max(1, Math.min(24, Number(next.sessionPolicy.ttlHours || 8)));
      next.sessionPolicy.inactivityMinutes = Math.max(5, Math.min(480, Number(next.sessionPolicy.inactivityMinutes || 60)));
      next.sla.criticalResponseMinutes = Math.max(1, Number(next.sla.criticalResponseMinutes || 5));
      next.sla.highResponseMinutes = Math.max(1, Number(next.sla.highResponseMinutes || 15));
      next.sla.normalResponseMinutes = Math.max(1, Number(next.sla.normalResponseMinutes || 30));
      data.settings = next;
      demoLogAction(data, settingsPatchGate.auth, 'settings.update', 'platform_settings', next);
      saveDemoData(data);
      return demoJsonResponse(200, { settings: next });
    }

    if (pathname === '/alerts' && method === 'GET') {
      var alertsGate = demoRequireRole(data, ['student', 'parent', 'doctor', 'admin', 'emergency']);
      if (!alertsGate.ok) return alertsGate.response;
      var alertsItems = (data.alerts || []).filter(function (item) {
        return Array.isArray(item.roles) && item.roles.indexOf(alertsGate.auth.user.role) !== -1;
      });
      return demoJsonResponse(200, { items: alertsItems });
    }

    if (pathname === '/analytics/overview' && method === 'GET') {
      var analyticsGate = demoRequireRole(data, ['doctor', 'admin']);
      if (!analyticsGate.ok) return analyticsGate.response;
      return demoJsonResponse(200, demoAnalyticsOverview(data));
    }

    if (pathname === '/operations/overview' && method === 'GET') {
      var operationsGate = demoRequireRole(data, ['admin', 'doctor']);
      if (!operationsGate.ok) return operationsGate.response;
      return demoJsonResponse(200, demoOperationsOverview(data));
    }

    if (parts[0] === 'emergency' && parts.length === 2 && method === 'GET') {
      var emergencyGate = demoRequireRole(data, ['doctor', 'admin', 'emergency']);
      if (!emergencyGate.ok) return emergencyGate.response;
      var emergencyPayload = demoEmergencyFlowForCase(data, parts[1]);
      if (!emergencyPayload) {
        return demoJsonResponse(404, { error: 'Case not found' });
      }
      return demoJsonResponse(200, emergencyPayload);
    }

    if (pathname === '/users' && method === 'GET') {
      var usersGate = demoRequireRole(data, ['admin']);
      if (!usersGate.ok) return usersGate.response;
      return demoJsonResponse(200, { items: data.users || [] });
    }

    if (parts[0] === 'users' && parts.length === 2 && method === 'PATCH') {
      var usersPatchGate = demoRequireRole(data, ['admin']);
      if (!usersPatchGate.ok) return usersPatchGate.response;
      var userToUpdate = (data.users || []).find(function (item) { return item.id === parts[1]; });
      if (!userToUpdate) {
        return demoJsonResponse(404, { error: 'User not found' });
      }
      var userBody = await body();
      if (typeof userBody.active === 'boolean') userToUpdate.active = userBody.active;
      if (typeof userBody.role === 'string' && ROLE_PERMISSIONS[userBody.role]) userToUpdate.role = userBody.role;
      demoLogAction(data, usersPatchGate.auth, 'user.update', userToUpdate.id, userBody || {});
      saveDemoData(data);
      return demoJsonResponse(200, { item: userToUpdate });
    }

    if (pathname === '/audit-logs' && method === 'GET') {
      var auditGate = demoRequireRole(data, ['admin']);
      if (!auditGate.ok) return auditGate.response;
      return demoJsonResponse(200, { items: (data.auditLogs || []).slice(-200).reverse() });
    }

    return demoJsonResponse(404, { error: 'API route not found' });
  }

  function demoBannerMessage() {
    var reasonText = 'تعذر الوصول إلى خدمة API.';
    if (demoFallbackReason === 'host') {
      reasonText = 'البيئة الحالية ثابتة (GitHub Pages / ملف محلي).';
    } else if (demoFallbackReason === 'query') {
      reasonText = 'تم تفعيل وضع العرض من رابط الصفحة.';
    } else if (demoFallbackReason === 'api_404') {
      reasonText = 'الخدمة الخلفية غير متاحة على المسار الحالي.';
    } else if (demoFallbackReason === 'network') {
      reasonText = 'فشل الاتصال بالخدمة الخلفية.';
    }
    return 'وضع العرض التجريبي مفعل. ' + reasonText + ' API Base: ' + API_BASE;
  }

  function renderDemoBanner() {
    var body = document.body;
    if (!body) return;
    var banner = document.getElementById(DEMO_BANNER_ID);
    if (!banner) {
      banner = document.createElement('div');
      banner.id = DEMO_BANNER_ID;
      banner.style.position = 'fixed';
      banner.style.left = '12px';
      banner.style.right = '12px';
      banner.style.bottom = '12px';
      banner.style.padding = '10px 12px';
      banner.style.background = 'rgba(15, 23, 42, 0.94)';
      banner.style.border = '1px solid rgba(251, 191, 36, 0.7)';
      banner.style.borderRadius = '10px';
      banner.style.color = '#f8fafc';
      banner.style.fontFamily = '"Tajawal", system-ui, sans-serif';
      banner.style.fontSize = '13px';
      banner.style.lineHeight = '1.5';
      banner.style.zIndex = '9999';
      banner.style.boxShadow = '0 12px 28px rgba(2, 6, 23, 0.45)';
      body.appendChild(banner);
    }
    banner.textContent = demoBannerMessage();
  }

  function showDemoBanner() {
    if (typeof document === 'undefined') return;
    if (document.body) {
      renderDemoBanner();
      return;
    }
    document.addEventListener('DOMContentLoaded', renderDemoBanner, { once: true });
  }

  function activateDemoFallback(reason) {
    demoFallbackActive = true;
    if (reason) {
      demoFallbackReason = reason;
    }
    showDemoBanner();
  }

  function shouldActivateDemoFallback(response) {
    if (!response || response.status !== 404) {
      return false;
    }
    var type = '';
    try {
      type = String(response.headers.get('content-type') || '').toLowerCase();
    } catch (err) {
      type = '';
    }
    return type.indexOf('application/json') === -1;
  }

  async function apiRequest(path, options) {
    var opts = options || {};
    var headers = Object.assign({}, opts.headers || {});
    if (!(opts.body instanceof FormData) && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }
    var token = getToken();
    if (token) {
      headers.Authorization = 'Bearer ' + token;
    }

    var fetchOpts = Object.assign({}, opts, { headers: headers });
    var timeoutMs = Number(opts.timeoutMs || API_TIMEOUT_MS);
    delete fetchOpts.timeoutMs;

    if (demoFallbackActive) {
      showDemoBanner();
      return demoApiRequest(path, fetchOpts);
    }

    if (typeof AbortController !== 'undefined') {
      var controller = new AbortController();
      var signal = fetchOpts.signal;
      fetchOpts.signal = controller.signal;
      if (signal) {
        signal.addEventListener('abort', function () {
          controller.abort();
        }, { once: true });
      }
      var timer = window.setTimeout(function () {
        controller.abort();
      }, timeoutMs);

      try {
        var timedResponse = await fetch(API_BASE + path, fetchOpts);
        if (shouldActivateDemoFallback(timedResponse)) {
          activateDemoFallback('api_404');
          return demoApiRequest(path, fetchOpts);
        }
        return timedResponse;
      } catch (err) {
        if (err && err.name === 'AbortError') {
          throw err;
        }
        activateDemoFallback('network');
        return demoApiRequest(path, fetchOpts);
      } finally {
        window.clearTimeout(timer);
      }
    }

    try {
      var response = await fetch(API_BASE + path, fetchOpts);
      if (shouldActivateDemoFallback(response)) {
        activateDemoFallback('api_404');
        return demoApiRequest(path, fetchOpts);
      }
      return response;
    } catch (err) {
      activateDemoFallback('network');
      return demoApiRequest(path, fetchOpts);
    }
  }

  async function apiJson(path, options) {
    var opts = options || {};
    try {
      var response = await apiRequest(path, opts);
      var payload = {};
      try {
        payload = await response.json();
      } catch (err) {
        payload = {};
      }

      if (response.status === 401 && !opts.skipAuthRedirect) {
        clearSession();
        redirectHome('انتهت الجلسة. سجل الدخول مرة أخرى.');
      }

      return {
        ok: response.ok,
        status: response.status,
        data: payload,
        error: payload && payload.error ? payload.error : (response.ok ? null : 'request_failed')
      };
    } catch (err) {
      var message = err && err.name === 'AbortError' ? 'request_timeout' : 'network_error';
      return { ok: false, status: 0, data: null, error: message };
    }
  }

  async function login(role) {
    if (!ROLE_LABELS[role]) {
      return { ok: false, message: 'الدور غير صالح.' };
    }

    try {
      var response = await apiRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ role: role })
      });
      var payload = await response.json();
      if (!response.ok) {
        return { ok: false, message: payload.error || 'فشل تسجيل الدخول.' };
      }

      var session = payload.session || setSession(role);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
      setToken(payload.token || null);
      return { ok: true, session: session, user: payload.user };
    } catch (err) {
      return { ok: false, message: 'تعذر الاتصال بالخادم.' };
    }
  }

  async function logout() {
    try {
      await apiRequest('/auth/logout', { method: 'POST' });
    } catch (err) {
      // Ignore network errors and continue local logout.
    }
    clearSession();
  }

  function redirectHome(message) {
    if (message) {
      setFlash(message);
    }

    window.location.href = getHomePath();
  }

  function applyRoleDecorators(role) {
    var roleLabel = ROLE_LABELS[role] || role;
    var tags = document.querySelectorAll('[data-session-role]');

    tags.forEach(function (el) {
      el.textContent = roleLabel;
    });

    document.body.setAttribute('data-current-role', role);

    var permissions = ROLE_PERMISSIONS[role] || [];
    var gated = document.querySelectorAll('[data-permission]');

    gated.forEach(function (el) {
      var required = el.getAttribute('data-permission');
      if (permissions.indexOf(required) === -1) {
        el.setAttribute('hidden', 'hidden');
      }
    });
  }

  function bindLogoutButtons() {
    var buttons = document.querySelectorAll('[data-action="logout"]');

    buttons.forEach(function (btn) {
      btn.addEventListener('click', async function () {
        await logout();
        redirectHome('تم تسجيل الخروج بنجاح.');
      });
    });
  }

  function requireAccess(allowedRoles, pageName) {
    var route = currentRoute();
    var session = getSession();

    if (!session) {
      redirectHome('يجب تسجيل الدخول أولًا للوصول إلى ' + (pageName || 'هذه الصفحة') + '.');
      return null;
    }

    if (allowedRoles && allowedRoles.indexOf(session.role) === -1) {
      redirectHome('صلاحياتك الحالية لا تسمح بفتح ' + (pageName || 'هذه الصفحة') + '.');
      return null;
    }

    if (!canAccess(route, session.role)) {
      redirectHome('تم منع الوصول غير المصرح لهذه الصفحة.');
      return null;
    }

    applyRoleDecorators(session.role);
    bindLogoutButtons();
    return session;
  }

  function getRoleHomePath(role) {
    var targetRole = role;
    if (!targetRole) {
      var session = getSession();
      targetRole = session ? session.role : null;
    }
    var route = ENTRY_ROUTES[targetRole] || getHomePath();
    var current = currentRoute();
    if (typeof route === 'string' && route.indexOf('src/pages/') === 0 && current.indexOf('src/pages/') === 0) {
      return route.slice('src/pages/'.length);
    }
    return route;
  }

  function goToRoleHome(role) {
    window.location.href = getRoleHomePath(role);
  }

  function createAutoRefresh(task, intervalMs, options) {
    var opts = options || {};
    var every = Math.max(3000, Number(intervalMs || 15000));
    var timer = null;
    var running = false;

    async function tick() {
      if (running) return;
      running = true;
      try {
        await task();
      } finally {
        running = false;
      }
    }

    function startTimer() {
      if (timer) return;
      timer = window.setInterval(function () {
        if (!document.hidden) {
          tick();
        }
      }, every);
    }

    function stopTimer() {
      if (timer) {
        window.clearInterval(timer);
        timer = null;
      }
    }

    function onVisibilityChange() {
      if (!document.hidden && opts.reloadOnFocus !== false) {
        tick();
      }
    }

    if (opts.immediate !== false) {
      tick();
    }
    startTimer();
    document.addEventListener('visibilitychange', onVisibilityChange);

    return function stop() {
      stopTimer();
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }

  function initFlashNotice() {
    var message = consumeFlash();
    if (!message) {
      return;
    }

    window.setTimeout(function () {
      window.alert(message);
    }, 50);
  }

  if (demoFallbackActive) {
    activateDemoFallback(demoFallbackReason);
  }

  window.SmartClinicSecurity = {
    roles: ROLE_LABELS,
    entryRoutes: ENTRY_ROUTES,
    apiBase: API_BASE,
    getApiBase: function () { return API_BASE; },
    apiRequest: apiRequest,
    apiJson: apiJson,
    login: login,
    logout: logout,
    getSession: getSession,
    getToken: getToken,
    canAccess: canAccess,
    listTelemedSessions: listTelemedSessions,
    getTelemedSessionById: getTelemedSessionById,
    getLatestTelemedSession: getLatestTelemedSession,
    createTelemedSession: createTelemedSession,
    updateTelemedSession: updateTelemedSession,
    endTelemedSession: endTelemedSession,
    createTelemedInvite: createTelemedInvite,
    redeemTelemedInvite: redeemTelemedInvite,
    canJoinTelemedSession: canJoinTelemedSession,
    getTelemedRoomPath: getTelemedRoomPath,
    getTelemedRoomUrl: getTelemedRoomUrl,
    getTelemedEmbedUrl: getTelemedEmbedUrl,
    isDemoMode: function () { return demoFallbackActive; },
    requireAccess: requireAccess,
    getHomePath: getHomePath,
    getRoleHomePath: getRoleHomePath,
    goToRoleHome: goToRoleHome,
    createAutoRefresh: createAutoRefresh,
    initFlashNotice: initFlashNotice
  };
})();
