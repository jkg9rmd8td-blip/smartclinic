(function () {
  'use strict';

  var STORAGE_KEY = 'smartclinic.auth.session.v1';
  var TOKEN_KEY = 'smartclinic.auth.token.v1';
  var FLASH_KEY = 'smartclinic.auth.flash.v1';
  var SESSION_TTL_MS = 8 * 60 * 60 * 1000;
  var API_BASE = '/api';
  var API_TIMEOUT_MS = 12000;

  var ROLE_LABELS = {
    student: 'الطالب',
    doctor: 'الطبيب',
    parent: 'ولي الأمر',
    admin: 'الإدارة'
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
    '  index.html': ['student', 'doctor', 'parent', 'admin'],
    'index.html': ['student', 'doctor', 'parent', 'admin'],
    'src/pages/doctor.html': ['doctor', 'admin'],
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
    'src/pages/emergency-flow.html': ['doctor', 'admin'],
    'src/pages/student-portal.html': ['student', 'admin'],
    'src/pages/student-profile.html': ['student', 'doctor', 'parent', 'admin'],
    'src/pages/notifications-center.html': ['student', 'doctor', 'parent', 'admin']
  };

  var ENTRY_ROUTES = {
    student: 'src/pages/student-portal.html',
    doctor: 'src/pages/doctor.html',
    parent: 'src/pages/parent-portal.html',
    admin: 'src/pages/admin-dashboard.html'
  };

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
    return route.indexOf('src/pages/') === 0 ? '../../  index.html' : '  index.html';
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

  function apiRequest(path, options) {
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
      return fetch(API_BASE + path, fetchOpts).finally(function () {
        window.clearTimeout(timer);
      });
    }

    return fetch(API_BASE + path, fetchOpts);
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

      if ((response.status === 401 || response.status === 403) && !opts.skipAuthRedirect) {
        clearSession();
        redirectHome('انتهت الجلسة أو لا توجد صلاحية للوصول.');
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

  window.SmartClinicSecurity = {
    roles: ROLE_LABELS,
    entryRoutes: ENTRY_ROUTES,
    apiBase: API_BASE,
    apiRequest: apiRequest,
    apiJson: apiJson,
    login: login,
    logout: logout,
    getSession: getSession,
    getToken: getToken,
    canAccess: canAccess,
    requireAccess: requireAccess,
    getHomePath: getHomePath,
    getRoleHomePath: getRoleHomePath,
    goToRoleHome: goToRoleHome,
    createAutoRefresh: createAutoRefresh,
    initFlashNotice: initFlashNotice
  };
})();
