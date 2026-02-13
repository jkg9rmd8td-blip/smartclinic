(function () {
  'use strict';

  var STYLE_ID = 'smartclinic-ui-shell-style-v1';
  var NAV_ID = 'smartclinic-quick-nav';

  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = [
      '.sc-apple .card,.sc-apple .mini,.sc-apple .service-card,.sc-apple .panel,.sc-apple .hero,.sc-apple .stat,.sc-apple .item,.sc-apple .role-card,.sc-apple .header{',
      '  border-radius:20px !important;border:1px solid rgba(148,163,184,.26) !important;',
      '  background:linear-gradient(160deg, rgba(255,255,255,.1), rgba(255,255,255,.02)) !important;',
      '  box-shadow:0 14px 30px rgba(15,23,42,.22) !important;backdrop-filter:blur(16px)}',
      '.sc-apple .grid,.sc-apple .services-grid,.sc-apple .roles,.sc-apple .stats{gap:12px !important;align-items:stretch !important}',
      '.sc-apple .btn,.sc-apple .cta,.sc-apple .ghost-btn,.sc-apple .muted-btn,.sc-apple .act,.sc-apple .tab,.sc-apple .resume-btn{',
      '  border-radius:14px !important;transition:transform .2s ease,filter .2s ease,box-shadow .2s ease}',
      '.sc-apple .btn:hover,.sc-apple .cta:hover,.sc-apple .ghost-btn:hover,.sc-apple .muted-btn:hover,.sc-apple .act:hover,.sc-apple .tab:hover{',
      '  transform:translateY(-1px);filter:brightness(1.06)}',
      '.sc-apple .top,.sc-apple .topbar{margin-bottom:6px !important}',
      '.scq-nav{margin:10px 0 14px;padding:12px;border:1px solid rgba(148,163,184,.34);border-radius:16px;background:rgba(15,23,42,.32);backdrop-filter:blur(10px)}',
      '.scq-head{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}',
      '.scq-title{font-size:14px;font-weight:700;color:#dbeafe}',
      '.scq-meta{display:flex;gap:6px;flex-wrap:wrap;align-items:center}',
      '.scq-chip{border:1px solid rgba(148,163,184,.34);border-radius:999px;padding:4px 9px;font-size:11px;color:#cbd5e1;background:rgba(255,255,255,.03)}',
      '.scq-chip strong{color:#f8fafc}',
      '.scq-actions{display:flex;gap:6px;flex-wrap:wrap}',
      '.scq-action{border:1px solid rgba(148,163,184,.34);background:rgba(255,255,255,.03);color:#e2e8f0;border-radius:999px;padding:5px 10px;font:inherit;font-size:11px;cursor:pointer}',
      '.scq-action.logout{border-color:rgba(248,113,113,.4);color:#fecaca}',
      '.scq-links{display:flex;gap:6px;flex-wrap:wrap}',
      '.scq-link{border:1px solid rgba(125,211,252,.32);border-radius:999px;padding:6px 10px;font-size:12px;color:#e2e8f0;background:rgba(255,255,255,.02);text-decoration:none;transition:.2s ease}',
      '.scq-link:hover{background:rgba(125,211,252,.12);transform:translateY(-1px)}',
      '.scq-link.active{background:#38bdf8;color:#082f49;border-color:#38bdf8;font-weight:700}',
      '.scq-refresh{border:1px solid rgba(148,163,184,.34);background:transparent;color:#f1f5f9;border-radius:999px;padding:5px 10px;font:inherit;font-size:11px;cursor:pointer}',
      '@media (max-width:680px){.scq-nav{margin-top:8px}.scq-actions{width:100%;justify-content:flex-start}}'
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

  function currentInPagesRoute() {
    return currentRoute().indexOf('src/pages/') === 0;
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

  function normalizeHrefRoute(href) {
    var raw = String(href || '').split('#')[0];
    var clean = raw.split('?')[0];
    if (!clean || /^https?:\/\//i.test(clean) || clean.indexOf('mailto:') === 0) return '';
    if (clean === 'index.html' || clean === '../../index.html') return 'index.html';
    if (clean.indexOf('src/pages/') === 0) return clean;
    if (clean.indexOf('../') === 0) {
      var noParents = clean.replace(/^(\.\.\/)+/, '');
      if (noParents.indexOf('src/pages/') === 0) return noParents;
      if (noParents === 'index.html') return 'index.html';
    }
    if (currentInPagesRoute()) return 'src/pages/' + clean;
    return clean;
  }

  function canAccessLink(item, role) {
    if (!item || !item.href) return false;
    if (item.roles && item.roles.length && item.roles.indexOf(role) === -1) return false;
    if (!window.SmartClinicSecurity || typeof SmartClinicSecurity.canAccess !== 'function') return true;
    var route = normalizeHrefRoute(item.href);
    if (!route) return true;
    try {
      return SmartClinicSecurity.canAccess(route, role);
    } catch (err) {
      return true;
    }
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
    var seen = {};
    var cleaned = (links || [])
      .filter(function (item) {
        if (!item || !item.href || !item.label) return false;
        if (!canAccessLink(item, role)) return false;
        var key = String(item.label) + '|' + String(item.href);
        if (seen[key]) return false;
        seen[key] = true;
        return true;
      })
      .slice(0, 10);

    if (cleaned.length > 1) {
      cleaned = cleaned.filter(function (item) {
        return !isSameRoute(item.href);
      });
    }

    return cleaned;
  }

  function normalizeLabel(text) {
    return String(text || '')
      .replace(/\s+/g, ' ')
      .trim()
      .replace(/[^\u0600-\u06FF\w ]/g, '')
      .toLowerCase();
  }

  function collectSectionNavLabels() {
    var seen = {};
    var labels = [];
    document.querySelectorAll('.section-nav .section-btn').forEach(function (btn) {
      var key = normalizeLabel(btn && btn.textContent);
      if (!key || seen[key]) return;
      seen[key] = true;
      labels.push(key);
    });
    return labels;
  }

  function overlapsWithSectionLabel(linkLabel, sectionLabels) {
    var key = normalizeLabel(linkLabel);
    if (!key || !sectionLabels.length) return false;
    return sectionLabels.some(function (label) {
      if (!label) return false;
      return key === label || key.indexOf(label) !== -1 || label.indexOf(key) !== -1;
    });
  }

  function dedupeLinksAgainstSectionNav(links) {
    var sectionLabels = collectSectionNavLabels();
    if (!sectionLabels.length) return links;
    var filtered = (links || []).filter(function (item) {
      return !overlapsWithSectionLabel(item.label, sectionLabels);
    });
    return filtered.length ? filtered : links;
  }

  function compactLegacyTopActions(options) {
    if (options && options.keepLegacyActions) return;
    var groups = [];
    document.querySelectorAll('.topbar-actions').forEach(function (el) { groups.push(el); });
    document.querySelectorAll('.top > div:nth-child(2)').forEach(function (el) { groups.push(el); });
    groups.forEach(function (el) {
      if (!el || el.getAttribute('data-scq-compact') === '1') return;
      el.setAttribute('data-scq-compact', '1');
      el.style.display = 'none';
    });
    document.querySelectorAll('.top > button, .topbar > button').forEach(function (btn) {
      if (!btn || btn.getAttribute('data-scq-compact') === '1') return;
      btn.setAttribute('data-scq-compact', '1');
      btn.style.display = 'none';
    });
    if (!(options && options.keepLegacyRoleChip)) {
      document.querySelectorAll('.top .chip, .topbar .chip').forEach(function (chip) {
        if (!chip || chip.getAttribute('data-scq-compact') === '1') return;
        if (!chip.querySelector('[data-session-role]')) return;
        chip.setAttribute('data-scq-compact', '1');
        chip.style.display = 'none';
      });
    }
  }

  function bindActionButtons(options) {
    var homeBtn = document.getElementById('scq-action-home');
    var roleBtn = document.getElementById('scq-action-role');
    var logoutBtn = document.getElementById('scq-action-logout');

    if (homeBtn) {
      homeBtn.addEventListener('click', function () {
        var homePath = SmartClinicSecurity && SmartClinicSecurity.getHomePath ? SmartClinicSecurity.getHomePath() : 'index.html';
        window.location.href = homePath;
      });
    }
    if (roleBtn) {
      roleBtn.addEventListener('click', function () {
        if (SmartClinicSecurity && SmartClinicSecurity.goToRoleHome) {
          SmartClinicSecurity.goToRoleHome();
        }
      });
    }
    if (logoutBtn) {
      logoutBtn.addEventListener('click', function () {
        if (!SmartClinicSecurity || !SmartClinicSecurity.logout) {
          window.location.href = 'index.html';
          return;
        }
        var finalize = function () {
          var home = SmartClinicSecurity.getHomePath ? SmartClinicSecurity.getHomePath() : 'index.html';
          window.location.href = home;
        };
        try {
          var task = SmartClinicSecurity.logout();
          if (task && typeof task.then === 'function') {
            task.then(finalize, finalize);
          } else {
            finalize();
          }
        } catch (err) {
          finalize();
        }
      });
    }
    if (options && options.hideShellActions) {
      var actionBox = document.getElementById('scq-actions');
      if (actionBox) actionBox.style.display = 'none';
    }
  }

  function mountQuickNav(options) {
    if (!window.SmartClinicSecurity || !SmartClinicSecurity.getSession) return;
    injectStyles();
    document.body.classList.add('sc-apple');
    compactLegacyTopActions(options);

    var existing = document.getElementById(NAV_ID);
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }

    var session = SmartClinicSecurity.getSession();
    var role = session ? session.role : '';
    var links = sanitizeLinks((options && options.links) || defaultLinks(role), role);
    if (!(options && options.keepSectionDuplicates)) {
      links = dedupeLinksAgainstSectionNav(links);
    }
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
        '<div id="scq-actions" class="scq-actions">' +
          '<button id="scq-action-home" class="scq-action" type="button">الرئيسية</button>' +
          '<button id="scq-action-role" class="scq-action" type="button">بوابة الدور</button>' +
          '<button id="scq-action-logout" class="scq-action logout" type="button">تسجيل الخروج</button>' +
        '</div>' +
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
    bindActionButtons(options);

    return nav;
  }

  window.SmartClinicUI = {
    mountQuickNav: mountQuickNav
  };
})();
