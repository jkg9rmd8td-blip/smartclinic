(function () {
  'use strict';

  var STYLE_ID = 'smartclinic-ui-shell-style-v1';
  var NAV_ID = 'smartclinic-quick-nav';

  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = [
      '.scq-nav{margin:10px 0 14px;padding:10px;border:1px solid rgba(148,163,184,.34);border-radius:14px;background:rgba(15,23,42,.28);backdrop-filter:blur(6px)}',
      '.scq-head{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}',
      '.scq-title{font-size:14px;font-weight:700;color:#dbeafe}',
      '.scq-meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center}',
      '.scq-chip{border:1px solid rgba(148,163,184,.34);border-radius:999px;padding:4px 9px;font-size:11px;color:#cbd5e1;background:rgba(255,255,255,.03)}',
      '.scq-chip strong{color:#f8fafc}',
      '.scq-links{display:flex;gap:6px;flex-wrap:wrap}',
      '.scq-link{border:1px solid rgba(125,211,252,.32);border-radius:999px;padding:6px 10px;font-size:12px;color:#e2e8f0;background:rgba(255,255,255,.02);text-decoration:none;transition:.2s ease}',
      '.scq-link:hover{background:rgba(125,211,252,.12);transform:translateY(-1px)}',
      '.scq-link.active{background:#38bdf8;color:#082f49;border-color:#38bdf8;font-weight:700}',
      '.scq-refresh{border:1px solid rgba(148,163,184,.34);background:transparent;color:#f1f5f9;border-radius:999px;padding:5px 10px;font:inherit;font-size:11px;cursor:pointer}',
      '@media (max-width:680px){.scq-nav{margin-top:8px}}'
    ].join('');
    document.head.appendChild(style);
  }

  function normalizePath(pathname) {
    var decoded = decodeURIComponent(pathname || '');
    var clean = decoded.replace(/\\/g, '/');
    var marker = '/smartclinic/';
    var idx = clean.lastIndexOf(marker);
    if (idx !== -1) clean = clean.slice(idx + marker.length);
    return clean.replace(/^\/+/, '');
  }

  function currentRoute() {
    return normalizePath(window.location.pathname);
  }

  function pageNameFromRoute(route) {
    if (!route) return '';
    var parts = String(route).split('/');
    return parts[parts.length - 1] || route;
  }

  function isSameRoute(route) {
    var current = pageNameFromRoute(currentRoute());
    var target = pageNameFromRoute(String(route || '').split('?')[0]);
    return current === target;
  }

  function roleLabel(role) {
    if (!window.SmartClinicSecurity || !SmartClinicSecurity.roles) return role || '-';
    return SmartClinicSecurity.roles[role] || role || '-';
  }

  function defaultLinks(role) {
    var links = [];
    links.push({ label: 'بوابة الدور', href: window.SmartClinicSecurity ? SmartClinicSecurity.getRoleHomePath(role) : '#' });
    links.push({ label: 'مركز التنسيق', href: 'care-center.html' });
    links.push({ label: 'الإشعارات', href: 'notifications-center.html' });

    if (role === 'student') {
      links.push({ label: 'الملف الصحي', href: 'student-profile.html' });
    } else if (role === 'doctor') {
      links.push({ label: 'الحالات', href: 'case-details.html?id=case_1' });
      links.push({ label: 'الطوارئ', href: 'emergency-flow.html?id=case_1' });
    } else if (role === 'parent') {
      links.push({ label: 'التقارير', href: 'parent-reports.html' });
      links.push({ label: 'الرسائل', href: 'parent-messages.html' });
    } else if (role === 'admin') {
      links.push({ label: 'المستخدمون', href: 'admin-users.html' });
      links.push({ label: 'الإعدادات', href: 'admin-settings.html' });
      links.push({ label: 'التحليلات', href: 'admin-analytics.html' });
    }
    return links;
  }

  function sanitizeLinks(links, role) {
    return (links || [])
      .filter(function (item) {
        if (!item || !item.href || !item.label) return false;
        if (!item.roles || !item.roles.length) return true;
        return item.roles.indexOf(role) !== -1;
      })
      .slice(0, 10);
  }

  function mountQuickNav(options) {
    if (!window.SmartClinicSecurity || !SmartClinicSecurity.getSession) return;
    injectStyles();

    var existing = document.getElementById(NAV_ID);
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }

    var session = SmartClinicSecurity.getSession();
    var role = session ? session.role : '';
    var route = currentRoute();
    var links = sanitizeLinks((options && options.links) || defaultLinks(role), role);
    var mode = SmartClinicSecurity.isDemoMode && SmartClinicSecurity.isDemoMode() ? 'Demo' : 'Live';

    var nav = document.createElement('section');
    nav.id = NAV_ID;
    nav.className = 'scq-nav';

    var head = document.createElement('div');
    head.className = 'scq-head';
    head.innerHTML =
      '<div class="scq-title">تنقل سريع منظم</div>' +
      '<div class="scq-meta">' +
        '<span class="scq-chip">الدور: <strong>' + roleLabel(role) + '</strong></span>' +
        '<span class="scq-chip">الوضع: <strong id="scq-mode">' + mode + '</strong></span>' +
        '<span class="scq-chip">آخر مزامنة: <strong id="scq-sync">-</strong></span>' +
        '<button class="scq-refresh" type="button" id="scq-refresh-btn">تحديث الآن</button>' +
      '</div>';
    nav.appendChild(head);

    var linkWrap = document.createElement('div');
    linkWrap.className = 'scq-links';
    linkWrap.innerHTML = links.map(function (item) {
      var active = isSameRoute(item.href) ? ' active' : '';
      return '<a class="scq-link' + active + '" href="' + item.href + '">' + item.label + '</a>';
    }).join('');
    nav.appendChild(linkWrap);

    var anchor = null;
    if (options && options.afterSelector) {
      anchor = document.querySelector(options.afterSelector);
    }
    if (anchor && anchor.parentNode) {
      anchor.insertAdjacentElement('afterend', nav);
    } else {
      var shell = document.querySelector('.shell') || document.body;
      shell.insertAdjacentElement('afterbegin', nav);
    }

    function setSyncNow() {
      var sync = document.getElementById('scq-sync');
      if (sync) {
        sync.textContent = new Date().toLocaleTimeString('ar-SA');
      }
    }
    setSyncNow();

    var refreshBtn = document.getElementById('scq-refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', function () {
        setSyncNow();
        if (options && typeof options.onRefresh === 'function') {
          options.onRefresh();
          return;
        }
        window.location.reload();
      });
    }

    return nav;
  }

  window.SmartClinicUI = {
    mountQuickNav: mountQuickNav
  };
})();
