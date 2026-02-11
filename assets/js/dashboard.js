(function () {
  'use strict';

  var REFRESH_MS = 15000;

  function safeText(value, fallback) {
    if (value === null || value === undefined || value === '') {
      return fallback || '-';
    }
    return String(value);
  }

  function riskFromSeverity(severity) {
    if (severity === 'critical' || severity === 'high') {
      return { level: 'critical', label: 'خطر' };
    }
    if (severity === 'medium') {
      return { level: 'watch', label: 'متابعة' };
    }
    return { level: 'normal', label: 'طبيعي' };
  }

  function setCounters(counts) {
    var data = counts || {};
    document.getElementById('active-count').textContent = Number(data.active || 0);
    document.getElementById('critical-count').textContent = Number(data.critical || 0);
    document.getElementById('pending-count').textContent = Number(data.pending || 0);
    document.getElementById('completed-count').textContent = Number(data.completed || 0);
  }

  function renderCases(items) {
    var body = document.getElementById('cases-body');
    if (!Array.isArray(items) || !items.length) {
      body.innerHTML = '<tr><td colspan="5">لا توجد حالات مفعلة حاليًا.</td></tr>';
      return;
    }

    body.innerHTML = items.map(function (item) {
      var risk = riskFromSeverity(item.severity);
      var badgeClass = risk.level === 'critical' ? 'badge-critical' : (risk.level === 'watch' ? 'badge-watch' : 'badge-normal');
      var updated = item.updatedAt ? new Date(item.updatedAt).toLocaleTimeString('ar-SA') : '-';
      return '<tr>' +
        '<td>' + safeText(item.studentName) + '</td>' +
        '<td>--</td>' +
        '<td><span class="badge ' + badgeClass + '">' + risk.label + '</span></td>' +
        '<td>' + updated + '</td>' +
        '<td><button class="primary-btn" onclick="openCase(\'' + item.id + '\')">فتح الحالة</button></td>' +
      '</tr>';
    }).join('');
  }

  function renderAlerts(items) {
    var alertsList = document.getElementById('alerts-list');
    if (!Array.isArray(items) || !items.length) {
      alertsList.innerHTML = '<div class="alert-item">لا توجد تنبيهات جديدة.</div>';
      return;
    }

    alertsList.innerHTML = items.slice(0, 8).map(function (item) {
      var text = safeText(item.text, 'تنبيه تشغيلي');
      var when = item.createdAt ? new Date(item.createdAt).toLocaleString('ar-SA') : '-';
      return '<div class="alert-item critical">' +
        '<div class="alert-title">' + text + '</div>' +
        '<div class="alert-meta"><span>' + when + '</span></div>' +
      '</div>';
    }).join('');
  }

  async function loadDashboard() {
    var api = window.SmartClinicSecurity && window.SmartClinicSecurity.apiRequest;
    if (!api) {
      return;
    }

    try {
      var response = await api('/operations/overview');
      var payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || 'load_error');
      }

      setCounters(payload.counts || {});
      renderCases(payload.queue || []);
      renderAlerts(payload.alerts || []);
    } catch (err) {
      setCounters({ active: 0, critical: 0, pending: 0, completed: 0 });
      document.getElementById('cases-body').innerHTML = '<tr><td colspan="5">تعذر تحميل الحالات من الخادم.</td></tr>';
      document.getElementById('alerts-list').innerHTML = '<div class="alert-item">تعذر تحميل التنبيهات.</div>';
    }
  }

  window.openCase = function openCase(id) {
    var caseId = safeText(id);
    if (!/^case_/.test(caseId) && /^\d+$/.test(caseId)) {
      caseId = 'case_' + caseId;
    }
    window.location.href = 'case-details.html?id=' + encodeURIComponent(caseId);
  };

  window.openNewCase = function openNewCase() {
    window.location.href = 'case-details.html?id=case_1';
  };

  window.openStudentSearch = function openStudentSearch() {
    window.location.href = 'student-profile.html';
  };

  window.openEmergencyFlow = function openEmergencyFlow() {
    window.location.href = 'emergency-flow.html?id=case_1';
  };

  window.printReport = function printReport() {
    window.print();
  };

  window.goToDoctorDashboard = function goToDoctorDashboard() {
    window.location.href = 'doctor.html';
  };

  window.openSystemSettings = function openSystemSettings() {
    window.location.href = 'admin-users.html';
  };

  document.addEventListener('DOMContentLoaded', function () {
    loadDashboard();
    setInterval(loadDashboard, REFRESH_MS);
  });
})();
