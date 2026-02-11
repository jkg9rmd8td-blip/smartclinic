const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const HOST = process.env.HOST || '127.0.0.1';
const ROOT_DIR = process.cwd();
const DATA_FILE = path.join(ROOT_DIR, 'backend', 'data.json');

const ROLE_PERMISSIONS = {
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
    'view.doctor', 'view.case', 'view.emergency', 'view.student', 'update.vitals',
    'edit.careplan', 'close.case', 'contact.guardian', 'send.report',
    'prescribe.medication', 'order.labs', 'approve.referral', 'start.telemed',
    'sign.decision', 'export.report', 'view.analytics', 'view.notifications', 'use.ai.assistant'
  ],
  parent: ['view.parent', 'view.student', 'contact.guardian', 'export.report', 'view.alerts', 'send.message', 'view.notifications', 'use.ai.assistant'],
  admin: [
    'view.admin', 'view.doctor', 'view.parent', 'view.case', 'view.emergency', 'view.student',
    'update.vitals', 'edit.careplan', 'close.case', 'contact.guardian', 'send.report',
    'prescribe.medication', 'order.labs', 'approve.referral', 'start.telemed',
    'sign.decision', 'export.report', 'view.analytics', 'manage.users',
    'request.visit', 'view.tips', 'view.alerts', 'send.message', 'view.reports', 'view.cases',
    'view.notifications', 'manage.settings', 'export.executive', 'use.ai.assistant'
  ]
};

const sessions = new Map();
const rateBuckets = new Map();
const sseClients = new Set();
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'SAMEORIGIN',
  'Referrer-Policy': 'same-origin'
};

function withSecurityHeaders(headers) {
  return Object.assign({}, SECURITY_HEADERS, headers || {});
}

function json(res, code, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(code, withSecurityHeaders({
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  }));
  res.end(body);
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', chunk => {
      raw += chunk;
      if (raw.length > 1e6) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.trim()) {
    return fwd.split(',')[0].trim();
  }
  return req.socket && req.socket.remoteAddress ? req.socket.remoteAddress : 'unknown';
}

function enforceRateLimit(req, res, key, max, windowMs) {
  const now = Date.now();
  const bucketKey = `${clientIp(req)}:${key}`;
  const hit = rateBuckets.get(bucketKey) || { count: 0, resetAt: now + windowMs };
  if (now > hit.resetAt) {
    hit.count = 0;
    hit.resetAt = now + windowMs;
  }
  hit.count += 1;
  rateBuckets.set(bucketKey, hit);
  if (hit.count > max) {
    json(res, 429, {
      error: 'Too many requests',
      retryAfterSec: Math.ceil((hit.resetAt - now) / 1000)
    });
    return false;
  }
  return true;
}

function cleanupRateBuckets() {
  const now = Date.now();
  rateBuckets.forEach((value, key) => {
    if (!value || now > (value.resetAt || 0) + 60 * 1000) {
      rateBuckets.delete(key);
    }
  });
}

function ensureString(value, minLen, maxLen, fallback = '') {
  const raw = value === undefined || value === null ? '' : String(value).trim();
  if (!raw) return fallback;
  if (raw.length < minLen) return fallback;
  return raw.slice(0, maxLen);
}

function readData() {
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function nowIso() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(4).toString('hex')}`;
}

function bearerToken(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) {
    const token = auth.slice(7).trim();
    if (token) return token;
  }
  try {
    const urlObj = new URL(req.url, 'http://local');
    const queryToken = urlObj.searchParams.get('token');
    return queryToken ? String(queryToken) : null;
  } catch (err) {
    return null;
  }
}

function authUser(req, data) {
  const token = bearerToken(req);
  if (!token) return null;
  const sess = sessions.get(token);
  const now = Date.now();
  if (!sess || sess.expiresAt < now) {
    sessions.delete(token);
    return null;
  }
  if (sess.lastSeenAt && sess.inactivityMinutes) {
    const idleMs = now - sess.lastSeenAt;
    if (idleMs > sess.inactivityMinutes * 60 * 1000) {
      sessions.delete(token);
      return null;
    }
  }
  sess.lastSeenAt = now;
  sessions.set(token, sess);
  const user = data.users.find(u => u.id === sess.userId && u.active);
  if (!user) return null;
  return { token, user, session: sess };
}

function requireRole(res, auth, roles) {
  if (!auth) {
    json(res, 401, { error: 'Unauthorized' });
    return false;
  }
  if (roles && !roles.includes(auth.user.role)) {
    json(res, 403, { error: 'Forbidden' });
    return false;
  }
  return true;
}

function hasPermission(role, permission) {
  const perms = ROLE_PERMISSIONS[role] || [];
  return perms.includes(permission);
}

function logAction(data, auth, action, target, details = {}) {
  const prev = data.auditLogs.length ? data.auditLogs[data.auditLogs.length - 1] : null;
  const chainBase = JSON.stringify({
    prevHash: prev ? (prev.hash || '') : '',
    action,
    target,
    actorId: auth ? auth.user.id : null,
    createdAt: nowIso()
  });
  const hash = crypto.createHash('sha256').update(chainBase).digest('hex');
  data.auditLogs.push({
    id: id('log'),
    action,
    actorId: auth ? auth.user.id : null,
    actorRole: auth ? auth.user.role : null,
    target,
    details,
    createdAt: nowIso(),
    hash
  });
}

function normalizeCaseId(rawId) {
  if (!rawId) return '';
  const value = String(rawId).trim();
  if (!value) return '';
  if (value.startsWith('case_')) return value;
  if (/^\d+$/.test(value)) return `case_${value}`;
  return value;
}

function getCaseByAnyId(data, rawId) {
  const normalized = normalizeCaseId(rawId);
  return data.cases.find(c => c.id === normalized);
}

function getSettings(data) {
  const fallback = {
    sessionPolicy: { ttlHours: 8, inactivityMinutes: 60 },
    alerts: { minimumLevel: 'info' },
    sla: {
      criticalResponseMinutes: 5,
      highResponseMinutes: 15,
      normalResponseMinutes: 30
    }
  };
  const incoming = data.settings || {};
  return {
    sessionPolicy: Object.assign({}, fallback.sessionPolicy, incoming.sessionPolicy || {}),
    alerts: Object.assign({}, fallback.alerts, incoming.alerts || {}),
    sla: Object.assign({}, fallback.sla, incoming.sla || {})
  };
}

function alertLevelRank(level) {
  const map = { info: 1, operational: 2, critical: 3 };
  return map[level] || 1;
}

function shouldEmitAlert(settings, level) {
  const min = (settings && settings.alerts && settings.alerts.minimumLevel) || 'info';
  return alertLevelRank(level) >= alertLevelRank(min);
}

function pushAlert(data, roles, text, type) {
  const settings = getSettings(data);
  const safeType = ['critical', 'operational', 'info'].includes(type) ? type : 'info';
  if (!shouldEmitAlert(settings, safeType)) {
    return;
  }
  data.alerts.push({
    id: id('al'),
    roles,
    type: safeType,
    text,
    createdAt: nowIso()
  });
}

function normalizeAlert(alert) {
  return Object.assign({ type: 'info' }, alert);
}

function analyticsOverview(data) {
  const statusCounts = { open: 0, in_progress: 0, closed: 0 };
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const roleCounts = { student: 0, parent: 0, doctor: 0, admin: 0 };

  data.cases.forEach(c => {
    statusCounts[c.status] = (statusCounts[c.status] || 0) + 1;
    severityCounts[c.severity] = (severityCounts[c.severity] || 0) + 1;
  });

  data.users.forEach(u => {
    roleCounts[u.role] = (roleCounts[u.role] || 0) + 1;
  });

  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const isToday = (iso) => new Date(iso) >= startOfDay;

  return {
    snapshot: {
      totalUsers: data.users.length,
      activeUsers: data.users.filter(u => u.active).length,
      totalCases: data.cases.length,
      criticalCases: severityCounts.critical || 0,
      pendingVisitRequests: data.visitRequests.filter(v => v.status === 'pending').length,
      openAlerts: data.alerts.length
    },
    distributions: {
      statusCounts,
      severityCounts,
      roleCounts
    },
    today: {
      messages: data.messages.filter(m => isToday(m.createdAt)).length,
      visitRequests: data.visitRequests.filter(v => isToday(v.createdAt)).length,
      actions: data.auditLogs.filter(l => isToday(l.createdAt)).length
    },
    recentLogs: data.auditLogs.slice(-12).reverse()
  };
}

function operationsOverview(data) {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const isToday = (iso) => new Date(iso) >= startOfDay;

  const cases = data.cases || [];
  const visitRequests = data.visitRequests || [];
  const alerts = data.alerts || [];
  const auditLogs = data.auditLogs || [];

  const counts = {
    active: cases.filter(c => c.status === 'in_progress' || c.status === 'open').length,
    critical: cases.filter(c => c.severity === 'critical').length,
    pending: visitRequests.filter(v => v.status === 'pending').length,
    completed: cases.filter(c => c.status === 'closed').length
  };

  return {
    counts,
    today: {
      casesUpdated: cases.filter(c => isToday(c.updatedAt)).length,
      visitRequests: visitRequests.filter(v => isToday(v.createdAt)).length,
      alerts: alerts.filter(a => isToday(a.createdAt)).length,
      actions: auditLogs.filter(l => isToday(l.createdAt)).length
    },
    queue: cases
      .slice()
      .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
      .map(c => ({
        id: c.id,
        studentName: c.studentName,
        title: c.title,
        severity: c.severity,
        status: c.status,
        updatedAt: c.updatedAt
      })),
    alerts: alerts.slice(-12).reverse(),
    recentActions: auditLogs.slice(-20).reverse()
  };
}

function emergencyFlowForCase(data, caseId) {
  const target = getCaseByAnyId(data, caseId);
  if (!target) {
    return null;
  }

  const settings = getSettings(data);
  const logs = (data.auditLogs || []).filter(l => l.target === target.id);
  const hasAction = (name) => logs.some(l => l.action === name);
  const hasOneOf = (names) => names.some(name => hasAction(name));
  const severitySlaMap = {
    critical: Number(settings.sla.criticalResponseMinutes || 5),
    high: Number(settings.sla.highResponseMinutes || 15),
    medium: Number(settings.sla.normalResponseMinutes || 30),
    low: Number(settings.sla.normalResponseMinutes || 30)
  };
  const allowedMin = severitySlaMap[target.severity] || severitySlaMap.low;
  const elapsedMin = Math.max(0, Math.round((Date.now() - new Date(target.updatedAt).getTime()) / 60000));
  const breached = target.status !== 'closed' ? elapsedMin > allowedMin : false;

  const steps = [
    {
      id: 'rapid_assessment',
      label: 'تقييم سريع للوعي والتنفس',
      status: 'done'
    },
    {
      id: 'vitals_monitoring',
      label: 'قياس العلامات الحيوية الأساسية',
      status: hasAction('case.action.vitals_update') ? 'done' : 'in_progress'
    },
    {
      id: 'initial_protocol',
      label: 'تطبيق البروتوكول العلاجي الأولي',
      status: hasOneOf(['case.action.emergency_protocol', 'case.action.bronchodilator', 'case.action.oxygen_support']) ? 'done' : 'todo'
    },
    {
      id: 'guardian_contact',
      label: 'إبلاغ ولي الأمر',
      status: hasAction('case.action.contact_guardian') ? 'done' : 'todo'
    },
    {
      id: 'referral_decision',
      label: 'قرار التحويل الخارجي',
      status: hasOneOf(['case.action.external_referral', 'case.action.ambulance_dispatch']) ? 'done' : 'todo'
    },
    {
      id: 'handover',
      label: 'تسليم الحالة وتوثيق محضر الطوارئ',
      status: hasOneOf(['case.action.handover_complete', 'case.action.close_case']) ? 'done' : 'todo'
    }
  ];

  const startedAt = logs.length ? logs[0].createdAt : target.updatedAt;
  const doneCount = steps.filter(s => s.status === 'done').length;
  const progress = Math.round((doneCount / steps.length) * 100);

  let recommendation = 'استمر في المتابعة وفق البروتوكول الحالي.';
  if (breached && !hasOneOf(['case.action.external_referral', 'case.action.ambulance_dispatch'])) {
    recommendation = 'تجاوز SLA للطوارئ: يوصى بتفعيل التحويل الخارجي أو طلب إسعاف فورًا.';
  } else if (!hasAction('case.action.emergency_protocol')) {
    recommendation = 'يوصى ببدء بروتوكول الطوارئ وتثبيت العلامات الحيوية فورًا.';
  }

  return {
    case: {
      id: target.id,
      studentName: target.studentName,
      title: target.title,
      severity: target.severity,
      status: target.status,
      updatedAt: target.updatedAt
    },
    urgency: {
      triage: target.severity === 'critical' ? 'RED' : (target.severity === 'high' ? 'ORANGE' : 'YELLOW'),
      elapsedMin,
      allowedMin,
      breached
    },
    recommendation,
    progress,
    startedAt,
    steps,
    timeline: logs.slice(-12).reverse()
  };
}

function resolveStudentIdForScope(auth, urlObj) {
  if (!auth) return null;
  if (auth.user.role === 'student') return auth.user.id;
  if (auth.user.role === 'parent') return 'u_student_1';
  if (auth.user.role === 'doctor' || auth.user.role === 'admin') {
    return urlObj.searchParams.get('studentId') || 'u_student_1';
  }
  return null;
}

function aiStudentSupport(data, studentId, input) {
  const text = ensureString(input && input.text, 0, 600, '');
  const context = String(text || '').toLowerCase();
  const overview = studentOverview(data, studentId);
  const latestCase = overview.latestCase || null;
  const pendingVisits = Number((overview.snapshot && overview.snapshot.pendingVisits) || 0);
  const criticalCases = Number((overview.snapshot && overview.snapshot.criticalCases) || 0);
  const operationalAlerts = Number((overview.alerts || []).filter(a => normalizeAlert(a).type === 'operational').length);

  let risk = 'low';
  const triggers = [];
  if (criticalCases > 0 || (latestCase && latestCase.severity === 'critical')) {
    risk = 'critical';
    triggers.push('يوجد سجل حالة حرجة نشطة');
  }
  if (context.includes('ضيق') || context.includes('تنفس') || context.includes('صدر') || context.includes('إغماء')) {
    risk = 'critical';
    triggers.push('تم رصد كلمات خطورة تنفس/وعي');
  }
  if (risk !== 'critical' && (context.includes('حمى') || context.includes('دوخة') || context.includes('دوار') || context.includes('ألم'))) {
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

  const actions = [];
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
  if (operationalAlerts > 0 && risk !== 'critical') {
    actions.push('مراجعة آخر التنبيهات التشغيلية في مركز الإشعارات');
  }

  return {
    role: 'student',
    generatedAt: nowIso(),
    risk,
    confidence: risk === 'critical' ? 0.93 : (risk === 'medium' ? 0.84 : 0.75),
    triggers,
    actions,
    summary: {
      latestCaseSeverity: latestCase ? latestCase.severity : 'none',
      pendingVisits,
      alerts: Number((overview.snapshot && overview.snapshot.alerts) || 0)
    }
  };
}

function aiDoctorSupport(data, caseId, input) {
  const target = getCaseByAnyId(data, caseId);
  if (!target) {
    return null;
  }

  const settings = getSettings(data);
  const note = ensureString(input && input.note, 0, 800, '');
  const context = String(note || '').toLowerCase();
  const flow = emergencyFlowForCase(data, target.id);
  const caseLogs = (data.auditLogs || []).filter(l => l.target === target.id);
  const hasReferral = caseLogs.some(l => l.action === 'case.action.external_referral' || l.action === 'case.action.ambulance_dispatch');
  const hasProtocol = caseLogs.some(l => l.action === 'case.action.emergency_protocol');
  const hasGuardian = caseLogs.some(l => l.action === 'case.action.contact_guardian');
  const urgentWords = ['هبوط', 'فشل', 'نزيف', 'اختناق', 'severe', 'critical'];
  const contextCritical = urgentWords.some(word => context.includes(word));

  let priority = target.severity === 'critical' ? 'immediate' : (target.severity === 'high' ? 'urgent' : 'standard');
  if (flow && flow.urgency && flow.urgency.breached) priority = 'immediate';
  if (contextCritical) priority = 'immediate';

  const checklist = [];
  if (!hasProtocol) checklist.push('تفعيل بروتوكول الطوارئ للحالة');
  checklist.push('تحديث العلامات الحيوية مع توثيق واضح');
  if (!hasGuardian) checklist.push('إشعار ولي الأمر بحالة الطالب');
  if (flow && flow.urgency && flow.urgency.breached && !hasReferral) {
    checklist.push('تفعيل التحويل الخارجي بسبب تجاوز SLA');
  }
  if (!checklist.length) {
    checklist.push('استمرار خطة العلاج الحالية مع مراقبة لصيقة');
  }

  const carePlan = [
    'استقرار أولي: تأمين مجرى التنفس وتقييم ABC',
    'مراقبة مستمرة: قياس SpO2 والنبض والضغط كل 10 دقائق',
    'تواصل: تحديث الحالة للطبيب المناوب وولي الأمر',
    hasReferral ? 'التحويل الخارجي مفعل بالفعل - استكمال التوثيق والتسليم' : 'قرار التحويل الخارجي حسب الاستجابة خلال نافذة SLA'
  ];

  return {
    role: 'doctor',
    generatedAt: nowIso(),
    caseId: target.id,
    triage: flow && flow.urgency ? flow.urgency.triage : 'YELLOW',
    priority,
    confidence: priority === 'immediate' ? 0.95 : (priority === 'urgent' ? 0.88 : 0.8),
    sla: {
      allowedMin: flow && flow.urgency ? flow.urgency.allowedMin : Number(settings.sla.normalResponseMinutes || 30),
      elapsedMin: flow && flow.urgency ? flow.urgency.elapsedMin : 0,
      breached: Boolean(flow && flow.urgency && flow.urgency.breached)
    },
    checklist,
    carePlan,
    recommendation: flow && flow.recommendation ? flow.recommendation : 'متابعة الحالة حسب البروتوكول القياسي.'
  };
}

function studentOverview(data, studentId) {
  const user = data.users.find(u => u.id === studentId) || null;
  const cases = data.cases.filter(c => c.studentId === studentId);
  const reports = data.reports.filter(r => r.studentId === studentId);
  const visitRequests = data.visitRequests.filter(v => v.studentId === studentId);
  const alerts = data.alerts.filter(a => Array.isArray(a.roles) && a.roles.includes('student'));

  const latestCase = cases
    .slice()
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))[0] || null;

  return {
    student: user,
    snapshot: {
      totalCases: cases.length,
      openCases: cases.filter(c => c.status !== 'closed').length,
      criticalCases: cases.filter(c => c.severity === 'critical').length,
      reports: reports.length,
      pendingVisits: visitRequests.filter(v => v.status === 'pending').length,
      alerts: alerts.length
    },
    latestCase,
    cases: cases.slice().sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)),
    reports: reports.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)),
    visitRequests: visitRequests.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)),
    alerts: alerts.slice(-20).reverse()
  };
}

function systemOverview(data) {
  const analytics = analyticsOverview(data);
  const operations = operationsOverview(data);

  return {
    health: {
      api: 'online',
      uptimeSec: Math.floor(process.uptime()),
      serverTime: nowIso()
    },
    snapshot: analytics.snapshot,
    operations: operations.counts,
    today: Object.assign({}, analytics.today, operations.today),
    topAlerts: (data.alerts || []).slice(-5).reverse(),
    lastAuditEvents: (data.auditLogs || []).slice(-8).reverse()
  };
}

function notificationsForRole(data, role) {
  const alerts = (data.alerts || [])
    .filter(a => Array.isArray(a.roles) && a.roles.includes(role))
    .map(a => ({
      id: a.id || id('ntf'),
      source: 'alert',
      type: normalizeAlert(a).type,
      text: a.text,
      createdAt: a.createdAt
    }));

  const derived = [];
  if (role === 'admin' || role === 'doctor') {
    (data.visitRequests || [])
      .filter(v => v.status === 'pending')
      .slice(-10)
      .forEach(v => {
        derived.push({
          id: 'vr_' + v.id,
          source: 'visit_request',
          type: String(v.reason || '').toLowerCase().includes('urgent') ? 'critical' : 'operational',
          text: `طلب زيارة قيد الانتظار: ${v.reason}`,
          createdAt: v.createdAt
        });
      });
  }

  return alerts.concat(derived).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function escapePdfText(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function buildSimplePdf(lines) {
  const cleanLines = (lines || []).slice(0, 34).map(escapePdfText);
  let y = 780;
  const bodyLines = cleanLines.map(line => {
    const chunk = `BT /F1 11 Tf 40 ${y} Td (${line}) Tj ET\n`;
    y -= 18;
    return chunk;
  }).join('');
  const stream = `q\n${bodyLines}Q\n`;

  const objects = [];
  objects.push('1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n');
  objects.push('2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n');
  objects.push('3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n');
  objects.push('4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n');
  objects.push(`5 0 obj << /Length ${Buffer.byteLength(stream, 'utf8')} >> stream\n${stream}endstream endobj\n`);

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach(obj => {
    offsets.push(Buffer.byteLength(pdf, 'utf8'));
    pdf += obj;
  });
  const xrefStart = Buffer.byteLength(pdf, 'utf8');
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let i = 1; i <= objects.length; i++) {
    pdf += String(offsets[i]).padStart(10, '0') + ' 00000 n \n';
  }
  pdf += `trailer << /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;
  return Buffer.from(pdf, 'utf8');
}

function slaMonitor(data) {
  const settings = getSettings(data);
  const now = Date.now();
  const thresholds = {
    critical: Number(settings.sla.criticalResponseMinutes || 5),
    high: Number(settings.sla.highResponseMinutes || 15),
    medium: Number(settings.sla.normalResponseMinutes || 30),
    low: Number(settings.sla.normalResponseMinutes || 30)
  };

  const items = (data.cases || []).map(c => {
    const since = new Date(c.updatedAt || nowIso()).getTime();
    const elapsedMin = Math.max(0, Math.round((now - since) / 60000));
    const allowedMin = thresholds[c.severity] || thresholds.low;
    const breached = c.status !== 'closed' ? elapsedMin > allowedMin : false;
    return {
      id: c.id,
      studentName: c.studentName,
      severity: c.severity,
      status: c.status,
      elapsedMin,
      allowedMin,
      breached
    };
  });

  return {
    summary: {
      totalOpen: items.filter(i => i.status !== 'closed').length,
      breached: items.filter(i => i.breached).length
    },
    items: items.sort((a, b) => Number(b.breached) - Number(a.breached))
  };
}

function emitSse(client, event, payload) {
  try {
    client.res.write(`event: ${event}\n`);
    client.res.write(`data: ${JSON.stringify(payload)}\n\n`);
  } catch (err) {
    // Ignore write failures for closed sockets.
  }
}

function pulseSseNotifications() {
  if (!sseClients.size) return;
  let data;
  try {
    data = readData();
  } catch (err) {
    return;
  }
  sseClients.forEach(client => {
    const all = notificationsForRole(data, client.role);
    const latest = all.length ? all[0].id : '';
    if (latest && latest !== client.lastTopId) {
      client.lastTopId = latest;
      emitSse(client, 'notifications', { latestId: latest });
    } else {
      emitSse(client, 'ping', { time: nowIso() });
    }
  });
}

setInterval(pulseSseNotifications, 15000);
setInterval(cleanupRateBuckets, 60000);

function serveStatic(req, res, urlObj) {
  let pathname = decodeURIComponent(urlObj.pathname);
  if (pathname === '/') pathname = '/  index.html';

  const requested = pathname.replace(/^\/+/, '');
  const resolved = path.resolve(ROOT_DIR, requested);
  if (!resolved.startsWith(ROOT_DIR)) {
    json(res, 403, { error: 'Forbidden path' });
    return;
  }

  fs.readFile(resolved, (err, data) => {
    if (err) {
      json(res, 404, { error: 'Not found' });
      return;
    }

    const ext = path.extname(resolved).toLowerCase();
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.json': 'application/json; charset=utf-8'
    };
    res.writeHead(200, withSecurityHeaders({
      'Content-Type': types[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache'
    }));
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  const { pathname } = urlObj;

  if (pathname === '/api/health' && req.method === 'GET') {
    json(res, 200, { ok: true, time: nowIso() });
    return;
  }

  if (pathname.startsWith('/api/')) {
    const data = readData();
    const auth = authUser(req, data);

    try {
      if (pathname === '/api/auth/login' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'auth.login', 20, 60 * 1000)) return;
        const body = await parseBody(req);
        const role = body.role;
        if (!ROLE_PERMISSIONS[role]) {
          json(res, 400, { error: 'Invalid role' });
          return;
        }
        const user = data.users.find(u => u.role === role && u.active);
        if (!user) {
          json(res, 404, { error: 'No active user for this role' });
          return;
        }

        const token = crypto.randomBytes(24).toString('hex');
        const settings = getSettings(data);
        const ttlHours = Number(settings.sessionPolicy.ttlHours || 8);
        const expiresAt = Date.now() + Math.max(1, ttlHours) * 60 * 60 * 1000;
        sessions.set(token, {
          userId: user.id,
          role: user.role,
          issuedAt: Date.now(),
          expiresAt,
          inactivityMinutes: Math.max(5, Number(settings.sessionPolicy.inactivityMinutes || 60)),
          lastSeenAt: Date.now()
        });
        logAction(data, { user }, 'auth.login', 'session', { role });
        writeData(data);

        json(res, 200, {
          token,
          session: { role: user.role, issuedAt: Date.now(), expiresAt },
          user,
          permissions: ROLE_PERMISSIONS[user.role] || []
        });
        return;
      }

      if (pathname === '/api/auth/me' && req.method === 'GET') {
        if (!requireRole(res, auth)) return;
        json(res, 200, {
          user: auth.user,
          session: auth.session,
          permissions: ROLE_PERMISSIONS[auth.user.role] || []
        });
        return;
      }

      if (pathname === '/api/auth/logout' && req.method === 'POST') {
        if (!requireRole(res, auth)) return;
        sessions.delete(auth.token);
        logAction(data, auth, 'auth.logout', 'session');
        writeData(data);
        json(res, 200, { ok: true });
        return;
      }

      if (pathname === '/api/cases' && req.method === 'GET') {
        if (!requireRole(res, auth, ['doctor', 'admin', 'student', 'parent'])) return;
        let cases = data.cases;
        if (auth.user.role === 'student') {
          cases = cases.filter(c => c.studentId === auth.user.id);
        }
        if (auth.user.role === 'parent') {
          // In this demo, parent sees the linked student feed.
          cases = cases.filter(c => c.studentId === 'u_student_1');
        }
        json(res, 200, { items: cases });
        return;
      }

      if (pathname.startsWith('/api/cases/') && req.method === 'GET') {
        if (!requireRole(res, auth, ['doctor', 'admin', 'student', 'parent'])) return;
        const parts = pathname.split('/').filter(Boolean);
        if (parts.length === 3) {
          const caseId = parts[2];
          const target = getCaseByAnyId(data, caseId);
          if (!target) {
            json(res, 404, { error: 'Case not found' });
            return;
          }
          if (auth.user.role === 'student' && target.studentId !== auth.user.id) {
            json(res, 403, { error: 'Forbidden' });
            return;
          }
          if (auth.user.role === 'parent' && target.studentId !== 'u_student_1') {
            json(res, 403, { error: 'Forbidden' });
            return;
          }

          const timeline = data.auditLogs
            .filter(l => l.target === target.id)
            .slice(-20)
            .reverse();
          json(res, 200, { item: target, timeline });
          return;
        }
      }

      if (pathname.startsWith('/api/cases/') && req.method === 'PATCH') {
        if (!enforceRateLimit(req, res, 'cases.patch', 80, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const caseId = pathname.split('/').pop();
        const body = await parseBody(req);
        const target = getCaseByAnyId(data, caseId);
        if (!target) {
          json(res, 404, { error: 'Case not found' });
          return;
        }
        if (typeof body.status === 'string') target.status = body.status;
        if (typeof body.notes === 'string') target.notes = body.notes;
        if (typeof body.severity === 'string') target.severity = body.severity;
        target.updatedAt = nowIso();
        logAction(data, auth, 'case.update', caseId, body);
        writeData(data);
        json(res, 200, { item: target });
        return;
      }

      if (pathname.startsWith('/api/cases/') && pathname.endsWith('/actions') && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'cases.actions', 120, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const parts = pathname.split('/').filter(Boolean);
        const caseId = parts[2];
        const body = await parseBody(req);
        const target = getCaseByAnyId(data, caseId);
        if (!target) {
          json(res, 404, { error: 'Case not found' });
          return;
        }

        const actionType = ensureString(body.type, 1, 40, 'note');
        const actionNote = ensureString(body.note, 3, 300, 'تم تنفيذ إجراء على الحالة');
        target.updatedAt = nowIso();
        if (actionType === 'close_case') target.status = 'closed';
        if (actionType === 'external_referral') target.status = 'in_progress';
        if (actionType === 'ambulance_dispatch') {
          target.status = 'in_progress';
          target.severity = 'critical';
        }
        if (actionType === 'emergency_protocol') {
          target.status = 'in_progress';
          target.severity = 'critical';
        }
        if (actionType === 'stabilized_case') {
          target.severity = 'medium';
        }
        if (actionType === 'handover_complete') {
          target.status = 'closed';
        }
        if (actionType === 'careplan_save' && body.plan) {
          target.notes = String(body.plan);
        }
        logAction(data, auth, 'case.action.' + actionType, target.id, { note: actionNote });

        pushAlert(
          data,
          ['admin', 'doctor', 'parent', 'student'],
          `تحديث حالة ${target.studentName}: ${actionNote}`,
          ['emergency_protocol', 'external_referral', 'ambulance_dispatch'].includes(actionType) ? 'critical' : 'operational'
        );

        writeData(data);
        json(res, 201, { ok: true });
        return;
      }

      if (pathname === '/api/visit-requests' && req.method === 'GET') {
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const items = data.visitRequests.slice().reverse();
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/visit-requests' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'visit.create', 30, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'admin'])) return;
        const body = await parseBody(req);
        const item = {
          id: id('vr'),
          studentId: auth.user.role === 'student' ? auth.user.id : (body.studentId || 'u_student_1'),
          reason: ensureString(body.reason, 3, 220, 'طلب فحص عام'),
          status: 'pending',
          createdAt: nowIso()
        };
        data.visitRequests.push(item);
        pushAlert(
          data,
          ['doctor', 'admin', 'parent', 'student'],
          `طلب زيارة جديد: ${item.reason}`,
          String(item.reason || '').toLowerCase().includes('urgent') ? 'critical' : 'operational'
        );
        logAction(data, auth, 'visit.request.create', item.id, item);
        writeData(data);
        json(res, 201, { item });
        return;
      }

      if (pathname === '/api/messages' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'message.send', 45, 60 * 1000)) return;
        if (!requireRole(res, auth, ['parent', 'student', 'admin'])) return;
        const body = await parseBody(req);
        const safeText = ensureString(body.text, 1, 1000, '');
        if (!safeText) {
          json(res, 400, { error: 'Message text is required' });
          return;
        }
        const item = {
          id: id('msg'),
          fromUserId: auth.user.id,
          fromRole: auth.user.role,
          text: safeText,
          createdAt: nowIso()
        };
        data.messages.push(item);
        pushAlert(data, ['doctor', 'admin'], `رسالة جديدة من ${auth.user.role}`, 'info');
        logAction(data, auth, 'message.send', item.id);
        writeData(data);
        json(res, 201, { item });
        return;
      }

      if (pathname === '/api/messages' && req.method === 'GET') {
        if (!requireRole(res, auth, ['parent', 'student', 'doctor', 'admin'])) return;
        let items = data.messages;
        if (!['doctor', 'admin'].includes(auth.user.role)) {
          items = items.filter(m => m.fromUserId === auth.user.id);
        }
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/reports' && req.method === 'GET') {
        if (!requireRole(res, auth, ['parent', 'doctor', 'admin', 'student'])) return;
        let items = data.reports;
        if (auth.user.role === 'student') {
          items = items.filter(r => r.studentId === auth.user.id);
        }
        if (auth.user.role === 'parent') {
          items = items.filter(r => r.studentId === 'u_student_1');
        }
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/reports/export' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'report.export', 60, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const body = await parseBody(req);
        const reportId = body.reportId ? String(body.reportId) : null;
        const report = reportId ? data.reports.find(r => r.id === reportId) : null;
        if (reportId && !report) {
          json(res, 404, { error: 'Report not found' });
          return;
        }
        if (report && auth.user.role === 'student' && report.studentId !== auth.user.id) {
          json(res, 403, { error: 'Forbidden' });
          return;
        }
        if (report && auth.user.role === 'parent' && report.studentId !== 'u_student_1') {
          json(res, 403, { error: 'Forbidden' });
          return;
        }

        const exportId = id('exp');
        logAction(data, auth, 'report.export', reportId || 'bulk', { reportId: reportId });
        writeData(data);
        json(res, 200, {
          ok: true,
          exportId,
          message: 'تم تجهيز ملف التقرير للتنزيل.',
          filename: report ? `${report.title}.pdf` : 'student-report.pdf'
        });
        return;
      }

      if (pathname === '/api/reports/executive' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        const system = systemOverview(data);
        const analytics = analyticsOverview(data);
        json(res, 200, {
          generatedAt: nowIso(),
          system,
          analytics
        });
        return;
      }

      if (pathname === '/api/reports/executive/pdf' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        const system = systemOverview(data);
        const analytics = analyticsOverview(data);
        const lines = [
          'Smart Clinic Executive Report',
          'Generated At: ' + nowIso(),
          '---',
          'API Status: ' + system.health.api,
          'Uptime Seconds: ' + system.health.uptimeSec,
          'Active Users: ' + (system.snapshot.activeUsers || 0),
          'Total Cases: ' + (system.snapshot.totalCases || 0),
          'Critical Cases: ' + (system.snapshot.criticalCases || 0),
          'Pending Visits: ' + (system.operations.pending || 0),
          'Open Alerts: ' + (system.snapshot.openAlerts || 0),
          'Today Actions: ' + (analytics.today.actions || 0),
          'Today Messages: ' + (analytics.today.messages || 0),
          'Today Visit Requests: ' + (analytics.today.visitRequests || 0)
        ];
        const pdf = buildSimplePdf(lines);
        logAction(data, auth, 'report.executive.pdf', 'executive_report');
        writeData(data);
        res.writeHead(200, withSecurityHeaders({
          'Content-Type': 'application/pdf',
          'Content-Disposition': 'attachment; filename=\"executive-report.pdf\"',
          'Content-Length': pdf.length,
          'Cache-Control': 'no-store'
        }));
        res.end(pdf);
        return;
      }

      if (pathname === '/api/sla/monitor' && req.method === 'GET') {
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        json(res, 200, slaMonitor(data));
        return;
      }

      if (pathname === '/api/student/overview' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const studentId = resolveStudentIdForScope(auth, urlObj);
        if (!studentId) {
          json(res, 400, { error: 'Student scope is invalid' });
          return;
        }
        json(res, 200, studentOverview(data, studentId));
        return;
      }

      if (pathname === '/api/ai/student-support' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'ai.student', 40, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'admin'])) return;
        if (!hasPermission(auth.user.role, 'use.ai.assistant')) {
          json(res, 403, { error: 'Permission denied for AI assistant' });
          return;
        }
        const body = await parseBody(req);
        const studentId = resolveStudentIdForScope(auth, urlObj);
        if (!studentId) {
          json(res, 400, { error: 'Student scope is invalid' });
          return;
        }
        const result = aiStudentSupport(data, studentId, body || {});
        logAction(data, auth, 'ai.student.support', studentId, { risk: result.risk, text: ensureString((body || {}).text, 0, 200, '') });
        writeData(data);
        json(res, 200, { item: result });
        return;
      }

      if (pathname === '/api/ai/doctor-support' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'ai.doctor', 50, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        if (!hasPermission(auth.user.role, 'use.ai.assistant')) {
          json(res, 403, { error: 'Permission denied for AI assistant' });
          return;
        }
        const body = await parseBody(req);
        const caseId = ensureString(body.caseId, 1, 60, '');
        if (!caseId) {
          json(res, 400, { error: 'caseId is required' });
          return;
        }
        const result = aiDoctorSupport(data, caseId, body || {});
        if (!result) {
          json(res, 404, { error: 'Case not found' });
          return;
        }
        logAction(data, auth, 'ai.doctor.support', result.caseId, { priority: result.priority });
        writeData(data);
        json(res, 200, { item: result });
        return;
      }

      if (pathname === '/api/notifications' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const typeFilter = String(urlObj.searchParams.get('type') || 'all');
        const limit = Math.max(1, Math.min(200, Number(urlObj.searchParams.get('limit') || 100)));
        let items = notificationsForRole(data, auth.user.role);
        if (['critical', 'operational', 'info'].includes(typeFilter)) {
          items = items.filter(n => n.type === typeFilter);
        }
        json(res, 200, { items: items.slice(0, limit) });
        return;
      }

      if (pathname === '/api/stream' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        res.writeHead(200, withSecurityHeaders({
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          Connection: 'keep-alive'
        }));
        const client = { res, role: auth.user.role, lastTopId: '' };
        sseClients.add(client);
        emitSse(client, 'connected', { ok: true, role: auth.user.role, at: nowIso() });
        req.on('close', () => {
          sseClients.delete(client);
        });
        return;
      }

      if (pathname === '/api/system/overview' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        json(res, 200, systemOverview(data));
        return;
      }

      if (pathname === '/api/settings' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        json(res, 200, { settings: getSettings(data) });
        return;
      }

      if (pathname === '/api/settings' && req.method === 'PATCH') {
        if (!enforceRateLimit(req, res, 'settings.patch', 20, 60 * 1000)) return;
        if (!requireRole(res, auth, ['admin'])) return;
        const body = await parseBody(req);
        const current = getSettings(data);
        const incoming = body && body.settings ? body.settings : {};
        const next = {
          sessionPolicy: Object.assign({}, current.sessionPolicy, incoming.sessionPolicy || {}),
          alerts: Object.assign({}, current.alerts, incoming.alerts || {}),
          sla: Object.assign({}, current.sla, incoming.sla || {})
        };

        if (!['info', 'operational', 'critical'].includes(next.alerts.minimumLevel)) {
          json(res, 400, { error: 'Invalid alerts.minimumLevel' });
          return;
        }
        next.sessionPolicy.ttlHours = Math.max(1, Math.min(24, Number(next.sessionPolicy.ttlHours || 8)));
        next.sessionPolicy.inactivityMinutes = Math.max(5, Math.min(480, Number(next.sessionPolicy.inactivityMinutes || 60)));
        next.sla.criticalResponseMinutes = Math.max(1, Number(next.sla.criticalResponseMinutes || 5));
        next.sla.highResponseMinutes = Math.max(1, Number(next.sla.highResponseMinutes || 15));
        next.sla.normalResponseMinutes = Math.max(1, Number(next.sla.normalResponseMinutes || 30));

        data.settings = next;
        logAction(data, auth, 'settings.update', 'platform_settings', next);
        writeData(data);
        json(res, 200, { settings: next });
        return;
      }

      if (pathname === '/api/alerts' && req.method === 'GET') {
        if (!requireRole(res, auth)) return;
        const items = data.alerts
          .filter(a => Array.isArray(a.roles) && a.roles.includes(auth.user.role))
          .map(normalizeAlert);
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/analytics/overview' && req.method === 'GET') {
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        json(res, 200, analyticsOverview(data));
        return;
      }

      if (pathname === '/api/operations/overview' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin', 'doctor'])) return;
        json(res, 200, operationsOverview(data));
        return;
      }

      if (pathname.startsWith('/api/emergency/') && req.method === 'GET') {
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const caseId = pathname.split('/').pop();
        const payload = emergencyFlowForCase(data, caseId);
        if (!payload) {
          json(res, 404, { error: 'Case not found' });
          return;
        }
        json(res, 200, payload);
        return;
      }

      if (pathname === '/api/users' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        json(res, 200, { items: data.users });
        return;
      }

      if (pathname.startsWith('/api/users/') && req.method === 'PATCH') {
        if (!requireRole(res, auth, ['admin'])) return;
        const userId = pathname.split('/').pop();
        const body = await parseBody(req);
        const user = data.users.find(u => u.id === userId);
        if (!user) {
          json(res, 404, { error: 'User not found' });
          return;
        }
        if (typeof body.active === 'boolean') user.active = body.active;
        if (typeof body.role === 'string' && ROLE_PERMISSIONS[body.role]) user.role = body.role;
        logAction(data, auth, 'user.update', user.id, body);
        writeData(data);
        json(res, 200, { item: user });
        return;
      }

      if (pathname === '/api/audit-logs' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        json(res, 200, { items: data.auditLogs.slice(-200).reverse() });
        return;
      }

      json(res, 404, { error: 'API route not found' });
      return;
    } catch (err) {
      json(res, 400, { error: err.message || 'Request error' });
      return;
    }
  }

  serveStatic(req, res, urlObj);
});

server.listen(PORT, HOST, () => {
  console.log(`Smart Clinic server running on http://${HOST}:${PORT}`);
});
