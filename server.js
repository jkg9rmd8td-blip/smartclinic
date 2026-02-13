const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;
const HOST = process.env.HOST || '127.0.0.1';
const ROOT_DIR = process.cwd();
const DATA_SEED_FILE = path.join(ROOT_DIR, 'backend', 'data.json');
const DATA_FILE = process.env.DATA_FILE
  ? (path.isAbsolute(process.env.DATA_FILE) ? process.env.DATA_FILE : path.join(ROOT_DIR, process.env.DATA_FILE))
  : path.join(ROOT_DIR, 'backend', 'data.runtime.json');
const TELEMED_INVITE_TTL_MS = 10 * 60 * 1000;

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

function ensureDataFile() {
  if (fs.existsSync(DATA_FILE)) return;
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  if (DATA_FILE !== DATA_SEED_FILE && fs.existsSync(DATA_SEED_FILE)) {
    fs.copyFileSync(DATA_SEED_FILE, DATA_FILE);
    return;
  }
  fs.writeFileSync(DATA_FILE, '{}');
}

function readData() {
  ensureDataFile();
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function writeData(data) {
  ensureDataFile();
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

function telemedRoomName(caseId) {
  const safe = normalizeCaseId(caseId) || 'case_1';
  return `smartclinic-${safe}-${Date.now().toString(36)}`;
}

function ensureTelemedSessions(data) {
  if (!Array.isArray(data.telemedSessions)) {
    data.telemedSessions = [];
  }
  return data.telemedSessions;
}

function telemedCanManage(auth) {
  return Boolean(auth && auth.user && ['doctor', 'admin'].includes(auth.user.role));
}

function telemedParticipantMatch(participant, auth) {
  return Boolean(
    participant &&
    auth &&
    auth.user &&
    participant.role === auth.user.role &&
    participant.userId === auth.user.id
  );
}

function telemedHasParticipant(session, auth) {
  const participants = Array.isArray(session.participants) ? session.participants : [];
  return participants.some((p) => telemedParticipantMatch(p, auth));
}

function telemedEnsureParticipant(session, auth) {
  if (!auth || !auth.user) return null;
  if (!Array.isArray(session.participants)) {
    session.participants = [];
  }
  const existing = session.participants.find((p) => telemedParticipantMatch(p, auth));
  if (existing) {
    existing.lastSeenAt = nowIso();
    return existing;
  }
  const item = {
    id: id('tp'),
    role: auth.user.role,
    userId: auth.user.id,
    joinedAt: nowIso(),
    lastSeenAt: nowIso()
  };
  session.participants.push(item);
  return item;
}

function telemedCanDiscover(session, auth) {
  if (!session || !auth || !auth.user) return false;
  if (telemedCanManage(auth)) return true;
  if (auth.user.role === 'student') {
    return session.studentId === auth.user.id;
  }
  if (auth.user.role === 'parent') {
    return Boolean(session.allowGuardian);
  }
  return false;
}

function telemedCanView(session, auth) {
  if (!session || !auth || !auth.user) return false;
  if (telemedCanManage(auth)) return true;
  if (auth.user.role === 'student') {
    return session.studentId === auth.user.id && telemedHasParticipant(session, auth);
  }
  if (auth.user.role === 'parent') {
    return Boolean(session.allowGuardian) && telemedHasParticipant(session, auth);
  }
  return false;
}

function telemedSanitize(session, options = {}) {
  const opts = options || {};
  const out = {
    id: session.id,
    caseId: session.caseId,
    studentId: session.studentId,
    roomName: session.roomName,
    title: session.title,
    allowGuardian: Boolean(session.allowGuardian),
    status: session.status,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    createdByRole: session.createdByRole,
    createdByUserId: session.createdByUserId,
    endedAt: session.endedAt || null,
    endReason: session.endReason || null,
    participants: (session.participants || []).map((p) => ({
      id: p.id,
      role: p.role,
      userId: p.userId,
      joinedAt: p.joinedAt,
      lastSeenAt: p.lastSeenAt || null
    }))
  };
  if (opts.includeInvites) {
    out.invites = (session.invites || []).map((inv) => {
      const item = {
        id: inv.id,
        role: inv.role,
        createdAt: inv.createdAt,
        expiresAt: inv.expiresAt,
        usedAt: inv.usedAt || null,
        usedByUserId: inv.usedByUserId || null,
        usedByRole: inv.usedByRole || null,
        revoked: Boolean(inv.revoked)
      };
      if (opts.includeInviteTokens) {
        item.token = inv.token;
      }
      return item;
    });
  }
  return out;
}

function telemedCreateInvite(session, role, auth, ttlMs = TELEMED_INVITE_TTL_MS) {
  if (!Array.isArray(session.invites)) {
    session.invites = [];
  }
  const invite = {
    id: id('tmi'),
    role,
    token: crypto.randomBytes(24).toString('hex'),
    createdAt: nowIso(),
    expiresAt: new Date(Date.now() + Math.max(30 * 1000, Number(ttlMs || TELEMED_INVITE_TTL_MS))).toISOString(),
    createdByUserId: auth.user.id,
    createdByRole: auth.user.role,
    usedAt: null,
    usedByUserId: null,
    usedByRole: null,
    revoked: false
  };
  session.invites.unshift(invite);
  return invite;
}

function telemedFindInvite(data, token) {
  const safeToken = ensureString(token, 8, 200, '');
  if (!safeToken) return null;
  const sessions = ensureTelemedSessions(data);
  for (let i = 0; i < sessions.length; i += 1) {
    const session = sessions[i];
    const invites = Array.isArray(session.invites) ? session.invites : [];
    const invite = invites.find((item) => item.token === safeToken);
    if (invite) {
      return { session, invite };
    }
  }
  return null;
}

function telemedInviteState(invite) {
  if (!invite) return 'invalid';
  if (invite.revoked) return 'revoked';
  if (invite.usedAt) return 'used';
  if (Date.now() > new Date(invite.expiresAt).getTime()) return 'expired';
  return 'active';
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

function normalizeVitalsNumber(value, fallback, min, max, precision = 1) {
  let numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    numeric = Number(fallback);
  }
  if (!Number.isFinite(numeric)) {
    numeric = 0;
  }
  numeric = Math.max(min, Math.min(max, numeric));
  const factor = Math.pow(10, precision);
  return Math.round(numeric * factor) / factor;
}

function ensureVitalsStores(data) {
  if (!Array.isArray(data.vitalsReadings)) {
    data.vitalsReadings = [];
  }
  if (!Array.isArray(data.sensorDevices)) {
    data.sensorDevices = [];
  }
}

function ensureStudentSensors(data, studentId) {
  ensureVitalsStores(data);
  const templates = [
    { key: 'hr', label: 'حساس النبض', battery: 86 },
    { key: 'spo2', label: 'حساس الأكسجين', battery: 82 },
    { key: 'temp', label: 'حساس الحرارة', battery: 91 },
    { key: 'bp', label: 'حساس الضغط', battery: 79 }
  ];
  templates.forEach((tpl) => {
    const sensorId = `sns_${studentId}_${tpl.key}`;
    const exists = data.sensorDevices.some((item) => item.id === sensorId);
    if (!exists) {
      data.sensorDevices.push({
        id: sensorId,
        studentId,
        type: tpl.key,
        label: tpl.label,
        status: 'connected',
        battery: tpl.battery,
        lastSeenAt: nowIso(),
        lastReadingAt: null
      });
    }
  });
  return data.sensorDevices
    .filter((item) => item.studentId === studentId)
    .sort((a, b) => String(a.type || '').localeCompare(String(b.type || '')));
}

function vitalsRiskLevel(reading) {
  if (!reading) return 'unknown';
  const temp = Number(reading.temp || 0);
  const spo2 = Number(reading.spo2 || 0);
  const hr = Number(reading.hr || 0);
  const bpSys = Number(reading.bpSys || 0);
  const bpDia = Number(reading.bpDia || 0);

  if (spo2 < 92 || hr > 130 || temp >= 39.2 || bpSys >= 160 || bpDia >= 100) {
    return 'critical';
  }
  if (spo2 < 95 || hr > 110 || temp >= 37.8 || bpSys >= 145 || bpDia >= 92) {
    return 'warning';
  }
  return 'stable';
}

function normalizeVitalsReading(studentId, input = {}, sourceFallback = 'manual') {
  const measuredAtRaw = ensureString(input.measuredAt, 0, 40, '');
  const parsedAt = measuredAtRaw ? new Date(measuredAtRaw) : null;
  const measuredAt = parsedAt && Number.isFinite(parsedAt.getTime()) ? parsedAt.toISOString() : nowIso();
  const source = ensureString(input.source, 0, 30, sourceFallback);
  const sensorId = ensureString(input.sensorId, 0, 100, '');

  const safe = {
    id: id('vit'),
    studentId,
    temp: normalizeVitalsNumber(input.temp, 36.8, 34, 42, 1),
    spo2: normalizeVitalsNumber(input.spo2, 98, 70, 100, 0),
    hr: normalizeVitalsNumber(input.hr, 78, 30, 220, 0),
    bpSys: normalizeVitalsNumber(input.bpSys, 118, 60, 240, 0),
    bpDia: normalizeVitalsNumber(input.bpDia, 76, 35, 160, 0),
    measuredAt,
    source
  };
  if (sensorId) {
    safe.sensorId = sensorId;
  }
  safe.risk = vitalsRiskLevel(safe);
  return safe;
}

function listVitalsForStudent(data, studentId, limit = 20) {
  ensureVitalsStores(data);
  const max = Math.max(1, Math.min(200, Number(limit) || 20));
  const items = data.vitalsReadings
    .filter((item) => item.studentId === studentId)
    .slice()
    .sort((a, b) => new Date(b.measuredAt || 0) - new Date(a.measuredAt || 0))
    .slice(0, max)
    .map((item) => {
      const safe = Object.assign({}, item);
      safe.risk = vitalsRiskLevel(safe);
      safe.temp = normalizeVitalsNumber(safe.temp, 36.8, 34, 42, 1);
      safe.spo2 = normalizeVitalsNumber(safe.spo2, 98, 70, 100, 0);
      safe.hr = normalizeVitalsNumber(safe.hr, 78, 30, 220, 0);
      safe.bpSys = normalizeVitalsNumber(safe.bpSys, 118, 60, 240, 0);
      safe.bpDia = normalizeVitalsNumber(safe.bpDia, 76, 35, 160, 0);
      safe.source = ensureString(safe.source, 0, 30, 'manual');
      const parsedAt = safe.measuredAt ? new Date(safe.measuredAt) : null;
      safe.measuredAt = parsedAt && Number.isFinite(parsedAt.getTime()) ? parsedAt.toISOString() : nowIso();
      return safe;
    });
  return items;
}

function persistVitalsReading(data, reading) {
  ensureVitalsStores(data);
  data.vitalsReadings.push(reading);
  if (data.vitalsReadings.length > 800) {
    data.vitalsReadings = data.vitalsReadings.slice(data.vitalsReadings.length - 800);
  }
}

function updateSensorAfterReading(data, studentId, reading) {
  const sensors = ensureStudentSensors(data, studentId);
  const chosen = reading.sensorId
    ? sensors.find((item) => item.id === reading.sensorId)
    : sensors.find((item) => item.type === 'hr') || sensors[0];
  if (!chosen) return;
  chosen.status = 'connected';
  chosen.lastSeenAt = nowIso();
  chosen.lastReadingAt = reading.measuredAt;
  chosen.battery = normalizeVitalsNumber(chosen.battery - Math.random() * 0.7, chosen.battery || 80, 25, 100, 0);
  if (!reading.sensorId) {
    reading.sensorId = chosen.id;
  }
}

function generateVitalsReading(data, studentId, options = {}) {
  const profile = ensureString(options.profile, 0, 20, 'normal').toLowerCase();
  const sensors = ensureStudentSensors(data, studentId);
  const latest = listVitalsForStudent(data, studentId, 1)[0] || null;
  const base = latest || {
    temp: 36.8,
    spo2: 98,
    hr: 78,
    bpSys: 118,
    bpDia: 76
  };
  const rand = (range) => (Math.random() * 2 - 1) * range;
  let temp = Number(base.temp) + rand(0.35);
  let spo2 = Number(base.spo2) + rand(1.4);
  let hr = Number(base.hr) + rand(7);
  let bpSys = Number(base.bpSys) + rand(7);
  let bpDia = Number(base.bpDia) + rand(6);

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

  const fallbackSensor = sensors.find((item) => item.type === 'hr') || sensors[0];
  const reading = normalizeVitalsReading(studentId, {
    temp,
    spo2,
    hr,
    bpSys,
    bpDia,
    sensorId: ensureString(options.sensorId, 0, 100, fallbackSensor ? fallbackSensor.id : ''),
    source: ensureString(options.source, 0, 30, 'sensor_simulator'),
    measuredAt: nowIso()
  }, 'sensor_simulator');
  persistVitalsReading(data, reading);
  updateSensorAfterReading(data, studentId, reading);
  return reading;
}

function vitalsPayloadForStudent(data, studentId, limit = 20) {
  const sensors = ensureStudentSensors(data, studentId).map((sensor) => ({
    id: sensor.id,
    studentId: sensor.studentId,
    type: sensor.type,
    label: sensor.label,
    status: sensor.status || 'connected',
    battery: normalizeVitalsNumber(sensor.battery, 80, 0, 100, 0),
    lastSeenAt: sensor.lastSeenAt || null,
    lastReadingAt: sensor.lastReadingAt || null
  }));
  const items = listVitalsForStudent(data, studentId, limit);
  return {
    latest: items[0] || null,
    items,
    sensors
  };
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
  const vitals = vitalsPayloadForStudent(data, studentId, 8);

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
      alerts: alerts.length,
      latestVitalsRisk: vitals.latest ? vitals.latest.risk : 'unknown'
    },
    latestCase,
    latestVitals: vitals.latest,
    vitalsHistory: vitals.items,
    sensors: vitals.sensors,
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

function ensureAdvancedStores(data) {
  const stores = [
    'consents',
    'emergencyCards',
    'homeCarePlans',
    'appointments',
    'tickets',
    'medicationPlans',
    'medicationLogs',
    'referrals',
    'monthlyReports'
  ];
  stores.forEach((key) => {
    if (!Array.isArray(data[key])) {
      data[key] = [];
    }
  });
}

function roleLabel(role) {
  const labels = {
    student: 'الطالب',
    doctor: 'الطبيب',
    parent: 'ولي الأمر',
    admin: 'الإدارة'
  };
  return labels[role] || role;
}

function resolveLinkedStudentId(data, auth, urlObj) {
  if (!auth || !auth.user) return 'u_student_1';
  if (auth.user.role === 'student') return auth.user.id;
  if (auth.user.role === 'parent') return 'u_student_1';
  if (auth.user.role === 'doctor' || auth.user.role === 'admin') {
    const asked = ensureString(urlObj.searchParams.get('studentId'), 0, 80, '');
    if (asked) return asked;
    const firstStudent = (data.users || []).find((item) => item.role === 'student' && item.active);
    return firstStudent ? firstStudent.id : 'u_student_1';
  }
  return 'u_student_1';
}

function canAccessStudentScope(auth, studentId) {
  if (!auth || !auth.user) return false;
  if (auth.user.role === 'admin' || auth.user.role === 'doctor') return true;
  if (auth.user.role === 'student') return auth.user.id === studentId;
  if (auth.user.role === 'parent') return studentId === 'u_student_1';
  return false;
}

function canAccessTicket(auth, ticket) {
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

function monthKeyFromIso(iso) {
  const d = iso ? new Date(iso) : new Date();
  if (!Number.isFinite(d.getTime())) return '';
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  return `${d.getUTCFullYear()}-${mm}`;
}

function normalizeMonthKey(raw) {
  const value = ensureString(raw, 0, 20, '');
  if (/^\d{4}-\d{2}$/.test(value)) {
    const year = Number(value.slice(0, 4));
    const month = Number(value.slice(5, 7));
    if (year >= 2000 && year <= 2100 && month >= 1 && month <= 12) {
      return value;
    }
  }
  return monthKeyFromIso(nowIso());
}

function monthRange(monthKey) {
  const normalized = normalizeMonthKey(monthKey);
  const year = Number(normalized.slice(0, 4));
  const month = Number(normalized.slice(5, 7));
  const start = new Date(Date.UTC(year, month - 1, 1, 0, 0, 0));
  const end = new Date(Date.UTC(year, month, 1, 0, 0, 0));
  return { monthKey: normalized, start, end };
}

function inRange(iso, start, end) {
  const t = new Date(iso || 0).getTime();
  if (!Number.isFinite(t)) return false;
  return t >= start.getTime() && t < end.getTime();
}

function findStudent(data, studentId) {
  return (data.users || []).find((user) => user.id === studentId && user.role === 'student') || null;
}

function emergencyCardPayload(req, data, studentId) {
  ensureAdvancedStores(data);
  const student = findStudent(data, studentId);
  if (!student) return null;
  let card = data.emergencyCards.find((item) => item.studentId === studentId);
  if (!card) {
    card = {
      id: id('emg'),
      studentId,
      token: crypto.randomBytes(12).toString('hex'),
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
    data.emergencyCards.push(card);
  }
  const publicPath = `/api/emergency/public/${card.token}`;
  const protoHeader = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto = protoHeader === 'https' ? 'https' : 'http';
  const host = req.headers.host || `${HOST}:${PORT}`;
  const publicUrl = `${proto}://${host}${publicPath}`;
  const qrImageUrl = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(publicUrl)}`;

  return {
    card: {
      id: card.id,
      token: card.token,
      studentId: student.id,
      studentName: student.name || student.id,
      grade: student.grade || '-',
      allergies: ensureString(student.allergies, 0, 280, 'لا توجد حساسية مسجلة'),
      chronicCondition: ensureString(student.chronicCondition, 0, 280, 'لا توجد حالة مزمنة مسجلة'),
      emergencyContact: ensureString(student.guardianPhone, 0, 60, 'غير متوفر'),
      updatedAt: card.updatedAt || card.createdAt
    },
    publicPath,
    publicUrl,
    qrImageUrl
  };
}

function medicationAdherenceSummary(data, studentId) {
  ensureAdvancedStores(data);
  const now = Date.now();
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const from = now - weekMs;
  const plans = (data.medicationPlans || []).filter((item) => item.studentId === studentId && item.active !== false);
  const logs = (data.medicationLogs || [])
    .filter((item) => item.studentId === studentId && new Date(item.takenAt || item.createdAt || 0).getTime() >= from)
    .sort((a, b) => new Date(b.takenAt || b.createdAt || 0) - new Date(a.takenAt || a.createdAt || 0));

  const expected = plans.reduce((sum, plan) => {
    const dosesPerDay = Math.max(1, Math.min(8, Number(plan.dosesPerDay || 1)));
    const createdAt = new Date(plan.createdAt || nowIso()).getTime();
    const activeFrom = Math.max(createdAt, from);
    const dayCount = Math.max(1, Math.ceil((now - activeFrom) / (24 * 60 * 60 * 1000)));
    return sum + (dosesPerDay * Math.min(7, dayCount));
  }, 0);

  const taken = logs.filter((item) => item.status === 'taken').length;
  const skipped = logs.filter((item) => item.status === 'skipped').length;
  const adherence = expected > 0 ? Math.max(0, Math.min(100, Math.round((taken / expected) * 100))) : 100;

  return {
    studentId,
    weekStart: new Date(from).toISOString(),
    weekEnd: new Date(now).toISOString(),
    expectedDoses: expected,
    takenDoses: taken,
    skippedDoses: skipped,
    adherencePercent: adherence,
    plans: plans.slice().sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0)),
    recentLogs: logs.slice(0, 20),
    alert: adherence < 80 ? 'انخفاض الالتزام الدوائي عن الحد الآمن (80%)' : null
  };
}

function monthlyExecutiveSummary(data, monthKey) {
  ensureAdvancedStores(data);
  const range = monthRange(monthKey);
  const month = range.monthKey;
  const start = range.start;
  const end = range.end;

  const visitRequests = (data.visitRequests || []).filter((item) => inRange(item.createdAt, start, end));
  const appointments = (data.appointments || []).filter((item) => inRange(item.createdAt, start, end));
  const tickets = (data.tickets || []).filter((item) => inRange(item.createdAt, start, end));
  const closedTickets = (data.tickets || []).filter((item) => item.closedAt && inRange(item.closedAt, start, end));
  const criticalCases = (data.cases || []).filter((item) => item.severity === 'critical' && inRange(item.updatedAt, start, end));
  const referrals = (data.referrals || []).filter((item) => inRange(item.createdAt, start, end));
  const consents = (data.consents || []).filter((item) => inRange(item.createdAt, start, end));
  const approvedConsents = consents.filter((item) => item.status === 'approved');

  const resolutionHours = closedTickets.map((item) => {
    const opened = new Date(item.createdAt || 0).getTime();
    const closed = new Date(item.closedAt || 0).getTime();
    if (!Number.isFinite(opened) || !Number.isFinite(closed) || closed <= opened) return null;
    return (closed - opened) / (60 * 60 * 1000);
  }).filter((v) => Number.isFinite(v));
  const avgResolutionHours = resolutionHours.length
    ? Math.round((resolutionHours.reduce((a, b) => a + b, 0) / resolutionHours.length) * 10) / 10
    : 0;

  const closureRate = tickets.length ? Math.round((closedTickets.length / tickets.length) * 100) : 0;
  const completedAppointments = appointments.filter((item) => item.status === 'completed').length;

  return {
    month,
    generatedAt: nowIso(),
    metrics: {
      criticalCases: criticalCases.length,
      visitRequests: visitRequests.length,
      appointmentsTotal: appointments.length,
      appointmentsCompleted: completedAppointments,
      ticketsOpened: tickets.length,
      ticketsClosed: closedTickets.length,
      ticketClosureRate: closureRate,
      avgTicketResolutionHours: avgResolutionHours,
      referrals: referrals.length,
      consentsRequested: consents.length,
      consentsApproved: approvedConsents.length
    }
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
  if (pathname === '/') pathname = '/index.html';

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
    ensureAdvancedStores(data);
    const apiPath = pathname.replace(/^\/api\/?/, '');
    const apiParts = apiPath ? apiPath.split('/').filter(Boolean) : [];

    try {
      if (apiParts[0] === 'emergency' && apiParts[1] === 'public' && apiParts[2] && req.method === 'GET') {
        const token = ensureString(apiParts[2], 8, 120, '');
        const card = data.emergencyCards.find((item) => item.token === token);
        if (!card) {
          json(res, 404, { error: 'Emergency card not found' });
          return;
        }
        const student = findStudent(data, card.studentId);
        if (!student) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        json(res, 200, {
          studentName: student.name || student.id,
          grade: student.grade || '-',
          allergies: ensureString(student.allergies, 0, 280, 'لا توجد حساسية مسجلة'),
          chronicCondition: ensureString(student.chronicCondition, 0, 280, 'لا توجد حالة مزمنة مسجلة'),
          emergencyContact: ensureString(student.guardianPhone, 0, 60, 'غير متوفر'),
          cardUpdatedAt: card.updatedAt || card.createdAt || null
        });
        return;
      }

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
        if (actionType === 'vitals_update') {
          const rawVitals = body && typeof body.vitals === 'object' ? body.vitals : body;
          const reading = normalizeVitalsReading(target.studentId, Object.assign({}, rawVitals || {}, {
            measuredAt: nowIso(),
            source: ensureString((rawVitals || {}).source, 0, 30, 'case_action')
          }), 'case_action');
          persistVitalsReading(data, reading);
          updateSensorAfterReading(data, target.studentId, reading);
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

      if (pathname === '/api/emergency-card' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const studentId = resolveLinkedStudentId(data, auth, urlObj);
        if (!canAccessStudentScope(auth, studentId)) {
          json(res, 403, { error: 'Forbidden student scope' });
          return;
        }
        const payload = emergencyCardPayload(req, data, studentId);
        if (!payload) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        logAction(data, auth, 'student.emergency.card.view', studentId, { studentId });
        writeData(data);
        json(res, 200, payload);
        return;
      }

      if (pathname === '/api/consents' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        let items = (data.consents || []).slice();
        if (auth.user.role === 'student') {
          items = items.filter((item) => item.studentId === auth.user.id);
        } else if (auth.user.role === 'parent') {
          items = items.filter((item) => item.studentId === 'u_student_1');
        } else {
          const studentFilter = ensureString(urlObj.searchParams.get('studentId'), 0, 80, '');
          if (studentFilter) {
            items = items.filter((item) => item.studentId === studentFilter);
          }
        }
        const statusFilter = ensureString(urlObj.searchParams.get('status'), 0, 20, '');
        if (statusFilter) {
          items = items.filter((item) => item.status === statusFilter);
        }
        items = items.sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/consents' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'consent.create', 40, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const body = await parseBody(req);
        const studentId = ensureString(body.studentId, 0, 80, '') || resolveLinkedStudentId(data, auth, urlObj);
        const student = findStudent(data, studentId);
        if (!student) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        const type = ensureString(body.type, 1, 30, 'medication');
        if (!['medication', 'referral', 'telemed'].includes(type)) {
          json(res, 400, { error: 'Invalid consent type' });
          return;
        }
        const item = {
          id: id('cons'),
          studentId,
          studentName: student.name || student.id,
          type,
          title: ensureString(body.title, 3, 220, `طلب موافقة ${type}`),
          details: ensureString(body.details, 3, 900, 'يرجى مراجعة الطلب واتخاذ القرار المناسب.'),
          status: 'pending',
          relatedEntityId: ensureString(body.relatedEntityId, 0, 80, '') || null,
          createdAt: nowIso(),
          updatedAt: nowIso(),
          createdByUserId: auth.user.id,
          createdByRole: auth.user.role,
          decisionNote: null,
          decidedAt: null,
          decidedByUserId: null,
          decidedByRole: null,
          digitalSignature: null,
          legalLog: [
            {
              id: id('legal'),
              event: 'consent_requested',
              at: nowIso(),
              actorUserId: auth.user.id,
              actorRole: auth.user.role,
              note: 'تم إنشاء طلب الموافقة.'
            }
          ]
        };
        data.consents.unshift(item);
        pushAlert(data, ['parent', 'admin', 'doctor'], `طلب موافقة جديد (${type}) للطالب ${item.studentName}`, type === 'referral' ? 'critical' : 'operational');
        logAction(data, auth, 'consent.request.create', item.id, {
          studentId,
          type,
          status: item.status
        });
        writeData(data);
        json(res, 201, { item });
        return;
      }

      if (apiParts[0] === 'consents' && apiParts[2] === 'decision' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'consent.decision', 50, 60 * 1000)) return;
        if (!requireRole(res, auth, ['parent', 'admin'])) return;
        const consentId = ensureString(apiParts[1], 1, 80, '');
        const item = data.consents.find((entry) => entry.id === consentId);
        if (!item) {
          json(res, 404, { error: 'Consent not found' });
          return;
        }
        if (auth.user.role === 'parent' && item.studentId !== 'u_student_1') {
          json(res, 403, { error: 'Forbidden' });
          return;
        }
        if (item.status !== 'pending') {
          json(res, 409, { error: 'Consent already decided' });
          return;
        }
        const body = await parseBody(req);
        const decision = ensureString(body.decision, 1, 20, '').toLowerCase();
        if (!['approve', 'reject'].includes(decision)) {
          json(res, 400, { error: 'Invalid decision' });
          return;
        }
        item.status = decision === 'approve' ? 'approved' : 'rejected';
        item.decidedAt = nowIso();
        item.updatedAt = nowIso();
        item.decidedByUserId = auth.user.id;
        item.decidedByRole = auth.user.role;
        item.decisionNote = ensureString(body.note, 0, 500, '');
        item.digitalSignature = ensureString(body.signature, 0, 120, `${auth.user.id}:${Date.now()}`);
        item.legalLog = Array.isArray(item.legalLog) ? item.legalLog : [];
        item.legalLog.push({
          id: id('legal'),
          event: 'consent_decision',
          at: item.decidedAt,
          actorUserId: auth.user.id,
          actorRole: auth.user.role,
          decision: item.status,
          signature: item.digitalSignature,
          note: item.decisionNote || null
        });
        pushAlert(data, ['doctor', 'admin', 'parent'], `تم ${item.status === 'approved' ? 'اعتماد' : 'رفض'} موافقة ${item.type} للطالب ${item.studentName}`, item.status === 'approved' ? 'operational' : 'info');
        logAction(data, auth, 'consent.request.decide', item.id, {
          decision: item.status,
          signature: item.digitalSignature
        });
        writeData(data);
        json(res, 200, { item });
        return;
      }

      if (pathname === '/api/home-care/plans' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const studentId = resolveLinkedStudentId(data, auth, urlObj);
        if (!canAccessStudentScope(auth, studentId)) {
          json(res, 403, { error: 'Forbidden student scope' });
          return;
        }
        const statusFilter = ensureString(urlObj.searchParams.get('status'), 0, 30, '');
        let items = (data.homeCarePlans || []).filter((item) => item.studentId === studentId);
        if (statusFilter) {
          items = items.filter((item) => item.status === statusFilter);
        }
        items = items.sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0));
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/home-care/plans' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'homecare.create', 40, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const body = await parseBody(req);
        const studentId = ensureString(body.studentId, 0, 80, '') || resolveLinkedStudentId(data, auth, urlObj);
        const student = findStudent(data, studentId);
        if (!student) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        let sourceItems = [];
        if (Array.isArray(body.items)) {
          sourceItems = body.items;
        } else if (typeof body.itemsText === 'string') {
          sourceItems = body.itemsText.split('\n');
        }
        const checklist = sourceItems
          .map((entry) => ensureString(entry, 1, 160, ''))
          .filter(Boolean)
          .slice(0, 12)
          .map((label) => ({
            id: id('chk'),
            label,
            done: false,
            reminderTime: ensureString(body.reminderTime, 0, 20, '19:00'),
            lastDoneAt: null
          }));
        if (!checklist.length) {
          checklist.push({ id: id('chk'), label: 'تأكيد تناول الدواء بالجرعة المحددة', done: false, reminderTime: '19:00', lastDoneAt: null });
          checklist.push({ id: id('chk'), label: 'متابعة السوائل والراحة', done: false, reminderTime: '20:00', lastDoneAt: null });
          checklist.push({ id: id('chk'), label: 'تسجيل أي أعراض جديدة', done: false, reminderTime: '21:00', lastDoneAt: null });
        }
        const plan = {
          id: id('hcp'),
          studentId,
          studentName: student.name || student.id,
          title: ensureString(body.title, 3, 220, 'خطة متابعة منزلية'),
          notes: ensureString(body.notes, 0, 500, ''),
          status: 'active',
          createdAt: nowIso(),
          updatedAt: nowIso(),
          createdByUserId: auth.user.id,
          createdByRole: auth.user.role,
          checklist,
          logs: []
        };
        data.homeCarePlans.unshift(plan);
        pushAlert(data, ['parent', 'student', 'doctor', 'admin'], `تم إنشاء خطة متابعة منزلية للطالب ${plan.studentName}`, 'operational');
        logAction(data, auth, 'homecare.plan.create', plan.id, { studentId, items: checklist.length });
        writeData(data);
        json(res, 201, { item: plan });
        return;
      }

      if (apiParts[0] === 'home-care' && apiParts[1] === 'plans' && apiParts[3] === 'check' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'homecare.check', 120, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'admin'])) return;
        const planId = ensureString(apiParts[2], 1, 80, '');
        const plan = data.homeCarePlans.find((item) => item.id === planId);
        if (!plan) {
          json(res, 404, { error: 'Plan not found' });
          return;
        }
        if (!canAccessStudentScope(auth, plan.studentId)) {
          json(res, 403, { error: 'Forbidden' });
          return;
        }
        const body = await parseBody(req);
        const itemId = ensureString(body.itemId, 0, 80, '');
        const idx = Number(body.index);
        let task = null;
        if (itemId) {
          task = (plan.checklist || []).find((entry) => entry.id === itemId) || null;
        } else if (Number.isInteger(idx) && idx >= 0 && idx < (plan.checklist || []).length) {
          task = plan.checklist[idx];
        }
        if (!task) {
          json(res, 404, { error: 'Checklist item not found' });
          return;
        }
        const done = typeof body.done === 'boolean' ? body.done : !task.done;
        task.done = done;
        task.lastDoneAt = done ? nowIso() : null;
        task.lastNote = ensureString(body.note, 0, 200, '');
        plan.updatedAt = nowIso();
        plan.logs = Array.isArray(plan.logs) ? plan.logs : [];
        plan.logs.unshift({
          id: id('hcl'),
          itemId: task.id,
          itemLabel: task.label,
          done,
          note: task.lastNote || null,
          actorUserId: auth.user.id,
          actorRole: auth.user.role,
          at: nowIso()
        });
        if ((plan.checklist || []).every((entry) => Boolean(entry.done))) {
          plan.status = 'completed';
        } else if (plan.status === 'completed') {
          plan.status = 'active';
        }
        logAction(data, auth, 'homecare.check.update', plan.id, {
          itemId: task.id,
          done
        });
        writeData(data);
        json(res, 200, { item: plan, task });
        return;
      }

      if (pathname === '/api/appointments' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        let items = (data.appointments || []).slice();
        if (auth.user.role === 'doctor' || auth.user.role === 'admin') {
          const all = String(urlObj.searchParams.get('all') || '') === '1';
          if (!all) {
            const studentId = resolveLinkedStudentId(data, auth, urlObj);
            items = items.filter((item) => item.studentId === studentId);
          }
        } else if (auth.user.role === 'student') {
          items = items.filter((item) => item.studentId === auth.user.id);
        } else {
          items = items.filter((item) => item.studentId === 'u_student_1');
        }
        const statusFilter = ensureString(urlObj.searchParams.get('status'), 0, 20, '');
        if (statusFilter) {
          items = items.filter((item) => item.status === statusFilter);
        }
        items = items.sort((a, b) => new Date(a.slotAt || a.createdAt || 0) - new Date(b.slotAt || b.createdAt || 0));
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/appointments' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'appointments.create', 60, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const body = await parseBody(req);
        let studentId = ensureString(body.studentId, 0, 80, '');
        if (!studentId) {
          studentId = resolveLinkedStudentId(data, auth, urlObj);
        }
        if (!canAccessStudentScope(auth, studentId) && !['doctor', 'admin'].includes(auth.user.role)) {
          json(res, 403, { error: 'Forbidden student scope' });
          return;
        }
        const student = findStudent(data, studentId);
        if (!student) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        const slotRaw = ensureString(body.slotAt, 0, 40, '');
        const slotDate = slotRaw ? new Date(slotRaw) : new Date(Date.now() + 24 * 60 * 60 * 1000);
        const slotAt = Number.isFinite(slotDate.getTime()) ? slotDate.toISOString() : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        const appointment = {
          id: id('apt'),
          studentId,
          studentName: student.name || student.id,
          reason: ensureString(body.reason, 3, 260, 'حجز موعد زيارة للعيادة'),
          slotAt,
          status: 'pending',
          requestedByUserId: auth.user.id,
          requestedByRole: auth.user.role,
          createdAt: nowIso(),
          updatedAt: nowIso(),
          notes: ensureString(body.notes, 0, 280, '')
        };
        data.appointments.unshift(appointment);
        pushAlert(data, ['doctor', 'admin', 'parent', 'student'], `تم إنشاء موعد جديد بتاريخ ${new Date(slotAt).toLocaleString('ar-SA')}`, 'operational');
        logAction(data, auth, 'appointment.create', appointment.id, { studentId, slotAt });
        writeData(data);
        json(res, 201, { item: appointment });
        return;
      }

      if (apiParts[0] === 'appointments' && apiParts[2] === 'status' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'appointments.status', 70, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const appointmentId = ensureString(apiParts[1], 1, 80, '');
        const appointment = data.appointments.find((item) => item.id === appointmentId);
        if (!appointment) {
          json(res, 404, { error: 'Appointment not found' });
          return;
        }
        const body = await parseBody(req);
        const status = ensureString(body.status, 1, 20, '').toLowerCase();
        if (!['pending', 'confirmed', 'completed', 'cancelled'].includes(status)) {
          json(res, 400, { error: 'Invalid status' });
          return;
        }
        appointment.status = status;
        appointment.updatedAt = nowIso();
        if (status === 'confirmed') appointment.confirmedAt = nowIso();
        if (status === 'completed') appointment.completedAt = nowIso();
        if (status === 'cancelled') appointment.cancelledAt = nowIso();
        appointment.statusNote = ensureString(body.note, 0, 300, appointment.statusNote || '');
        pushAlert(data, ['student', 'parent', 'doctor', 'admin'], `تحديث الموعد: ${status} (${appointment.reason})`, status === 'cancelled' ? 'info' : 'operational');
        logAction(data, auth, 'appointment.status.update', appointment.id, { status });
        writeData(data);
        json(res, 200, { item: appointment });
        return;
      }

      if (pathname === '/api/tickets' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const statusFilter = ensureString(urlObj.searchParams.get('status'), 0, 20, '');
        let items = (data.tickets || []).filter((item) => canAccessTicket(auth, item));
        if (statusFilter) {
          items = items.filter((item) => item.status === statusFilter);
        }
        items = items
          .slice()
          .sort((a, b) => new Date(b.updatedAt || b.createdAt || 0) - new Date(a.updatedAt || a.createdAt || 0))
          .map((item) => ({
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
          }));
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/tickets' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'tickets.create', 70, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const body = await parseBody(req);
        let studentId = ensureString(body.studentId, 0, 80, '');
        if (!studentId) {
          studentId = resolveLinkedStudentId(data, auth, urlObj);
        }
        if (!canAccessStudentScope(auth, studentId) && !['doctor', 'admin'].includes(auth.user.role)) {
          json(res, 403, { error: 'Forbidden student scope' });
          return;
        }
        const student = findStudent(data, studentId);
        if (!student) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        const firstMessage = ensureString(body.text, 1, 1000, '');
        if (!firstMessage) {
          json(res, 400, { error: 'Ticket text is required' });
          return;
        }
        const ticket = {
          id: id('tkt'),
          number: 'TKT-' + Date.now().toString().slice(-6),
          studentId,
          studentName: student.name || student.id,
          subject: ensureString(body.subject, 3, 220, 'استفسار صحي'),
          priority: ['low', 'normal', 'high', 'critical'].includes(body.priority) ? body.priority : 'normal',
          status: 'open',
          createdByUserId: auth.user.id,
          createdByRole: auth.user.role,
          assignedToUserId: ensureString(body.assignedToUserId, 0, 80, '') || 'u_doctor_1',
          createdAt: nowIso(),
          updatedAt: nowIso(),
          closedAt: null,
          messages: [
            {
              id: id('tmsg'),
              fromUserId: auth.user.id,
              fromRole: auth.user.role,
              text: firstMessage,
              createdAt: nowIso()
            }
          ]
        };
        data.tickets.unshift(ticket);
        pushAlert(data, ['doctor', 'admin'], `تذكرة جديدة ${ticket.number}: ${ticket.subject}`, ticket.priority === 'critical' ? 'critical' : 'operational');
        logAction(data, auth, 'ticket.create', ticket.id, { number: ticket.number, priority: ticket.priority });
        writeData(data);
        json(res, 201, { item: ticket });
        return;
      }

      if (apiParts[0] === 'tickets' && apiParts.length === 3 && apiParts[2] === 'messages' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const ticketId = ensureString(apiParts[1], 1, 80, '');
        const ticket = data.tickets.find((item) => item.id === ticketId);
        if (!ticket) {
          json(res, 404, { error: 'Ticket not found' });
          return;
        }
        if (!canAccessTicket(auth, ticket)) {
          json(res, 403, { error: 'Forbidden' });
          return;
        }
        json(res, 200, { item: ticket, messages: ticket.messages || [] });
        return;
      }

      if (apiParts[0] === 'tickets' && apiParts.length === 3 && apiParts[2] === 'messages' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'tickets.reply', 140, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const ticketId = ensureString(apiParts[1], 1, 80, '');
        const ticket = data.tickets.find((item) => item.id === ticketId);
        if (!ticket) {
          json(res, 404, { error: 'Ticket not found' });
          return;
        }
        if (!canAccessTicket(auth, ticket)) {
          json(res, 403, { error: 'Forbidden' });
          return;
        }
        const body = await parseBody(req);
        const text = ensureString(body.text, 1, 1000, '');
        if (!text) {
          json(res, 400, { error: 'Message text is required' });
          return;
        }
        const message = {
          id: id('tmsg'),
          fromUserId: auth.user.id,
          fromRole: auth.user.role,
          text,
          createdAt: nowIso()
        };
        if (!Array.isArray(ticket.messages)) {
          ticket.messages = [];
        }
        ticket.messages.push(message);
        ticket.updatedAt = nowIso();
        if (ticket.status === 'closed' && ['student', 'parent'].includes(auth.user.role)) {
          ticket.status = 'open';
          ticket.closedAt = null;
        } else if (ticket.status === 'open' && ['doctor', 'admin'].includes(auth.user.role)) {
          ticket.status = 'in_progress';
        }
        if (['closed', 'resolved'].includes(ticket.status) && !ticket.closedAt) {
          ticket.closedAt = nowIso();
        }
        logAction(data, auth, 'ticket.message.send', ticket.id, { messageId: message.id });
        writeData(data);
        json(res, 201, { item: ticket, message });
        return;
      }

      if (apiParts[0] === 'tickets' && apiParts.length === 2 && req.method === 'PATCH') {
        if (!enforceRateLimit(req, res, 'tickets.patch', 100, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const ticketId = ensureString(apiParts[1], 1, 80, '');
        const ticket = data.tickets.find((item) => item.id === ticketId);
        if (!ticket) {
          json(res, 404, { error: 'Ticket not found' });
          return;
        }
        const body = await parseBody(req);
        if (typeof body.assignedToUserId === 'string' && body.assignedToUserId.trim()) {
          ticket.assignedToUserId = ensureString(body.assignedToUserId, 1, 80, ticket.assignedToUserId || '');
        }
        if (typeof body.status === 'string') {
          const status = ensureString(body.status, 1, 20, '').toLowerCase();
          if (['open', 'in_progress', 'closed'].includes(status)) {
            ticket.status = status;
            if (status === 'closed') {
              ticket.closedAt = nowIso();
            } else {
              ticket.closedAt = null;
            }
          }
        }
        ticket.updatedAt = nowIso();
        logAction(data, auth, 'ticket.update', ticket.id, {
          status: ticket.status,
          assignedToUserId: ticket.assignedToUserId
        });
        writeData(data);
        json(res, 200, { item: ticket });
        return;
      }

      if (pathname === '/api/medications/plans' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'medication.plan', 60, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const body = await parseBody(req);
        const studentId = ensureString(body.studentId, 0, 80, '') || resolveLinkedStudentId(data, auth, urlObj);
        const student = findStudent(data, studentId);
        if (!student) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        const name = ensureString(body.name, 2, 140, '');
        if (!name) {
          json(res, 400, { error: 'Medication name is required' });
          return;
        }
        const plan = {
          id: id('medp'),
          studentId,
          studentName: student.name || student.id,
          name,
          dosesPerDay: Math.max(1, Math.min(8, Number(body.dosesPerDay || 1))),
          instructions: ensureString(body.instructions, 0, 400, ''),
          startDate: ensureString(body.startDate, 0, 40, new Date().toISOString().slice(0, 10)),
          endDate: ensureString(body.endDate, 0, 40, ''),
          active: true,
          createdAt: nowIso(),
          createdByUserId: auth.user.id,
          createdByRole: auth.user.role
        };
        data.medicationPlans.unshift(plan);
        pushAlert(data, ['parent', 'student', 'doctor', 'admin'], `تمت إضافة خطة دوائية: ${plan.name}`, 'operational');
        logAction(data, auth, 'medication.plan.create', plan.id, { studentId, dosesPerDay: plan.dosesPerDay });
        writeData(data);
        json(res, 201, { item: plan });
        return;
      }

      if (pathname === '/api/medications/logs' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'medication.log', 160, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const body = await parseBody(req);
        const planId = ensureString(body.planId, 0, 80, '');
        const plan = planId ? data.medicationPlans.find((item) => item.id === planId) : null;
        let studentId = plan ? plan.studentId : ensureString(body.studentId, 0, 80, '');
        if (!studentId) {
          studentId = resolveLinkedStudentId(data, auth, urlObj);
        }
        if (!canAccessStudentScope(auth, studentId) && !['doctor', 'admin'].includes(auth.user.role)) {
          json(res, 403, { error: 'Forbidden student scope' });
          return;
        }
        const status = ensureString(body.status, 1, 20, 'taken').toLowerCase();
        if (!['taken', 'skipped'].includes(status)) {
          json(res, 400, { error: 'Invalid medication log status' });
          return;
        }
        const entry = {
          id: id('medl'),
          studentId,
          planId: plan ? plan.id : null,
          planName: plan ? plan.name : ensureString(body.planName, 0, 140, ''),
          status,
          note: ensureString(body.note, 0, 220, ''),
          takenAt: nowIso(),
          createdAt: nowIso(),
          loggedByUserId: auth.user.id,
          loggedByRole: auth.user.role
        };
        data.medicationLogs.unshift(entry);
        const summary = medicationAdherenceSummary(data, studentId);
        if (summary.alert) {
          pushAlert(data, ['doctor', 'admin', 'parent', 'student'], summary.alert, 'critical');
        }
        logAction(data, auth, 'medication.log.create', entry.id, {
          studentId,
          planId: entry.planId,
          status
        });
        writeData(data);
        json(res, 201, { item: entry, summary });
        return;
      }

      if (pathname === '/api/medications/adherence' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const studentId = resolveLinkedStudentId(data, auth, urlObj);
        if (!canAccessStudentScope(auth, studentId)) {
          json(res, 403, { error: 'Forbidden student scope' });
          return;
        }
        const summary = medicationAdherenceSummary(data, studentId);
        json(res, 200, summary);
        return;
      }

      if (pathname === '/api/referrals' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        let items = (data.referrals || []).slice();
        if (auth.user.role === 'student') {
          items = items.filter((item) => item.studentId === auth.user.id);
        } else if (auth.user.role === 'parent') {
          items = items.filter((item) => item.studentId === 'u_student_1');
        } else {
          const studentFilter = ensureString(urlObj.searchParams.get('studentId'), 0, 80, '');
          if (studentFilter) {
            items = items.filter((item) => item.studentId === studentFilter);
          }
        }
        items = items.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/referrals' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'referrals.create', 40, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const body = await parseBody(req);
        const studentId = ensureString(body.studentId, 0, 80, '') || resolveLinkedStudentId(data, auth, urlObj);
        const student = findStudent(data, studentId);
        if (!student) {
          json(res, 404, { error: 'Student not found' });
          return;
        }
        const reason = ensureString(body.reason, 3, 280, '');
        if (!reason) {
          json(res, 400, { error: 'Referral reason is required' });
          return;
        }
        const referral = {
          id: id('ref'),
          studentId,
          studentName: student.name || student.id,
          destination: ensureString(body.destination, 3, 180, 'مستشفى الطوارئ'),
          reason,
          diagnosis: ensureString(body.diagnosis, 0, 240, ''),
          clinicalSummary: ensureString(body.clinicalSummary, 0, 1000, ''),
          status: 'issued',
          createdAt: nowIso(),
          createdByUserId: auth.user.id,
          createdByRole: auth.user.role
        };
        data.referrals.unshift(referral);
        pushAlert(data, ['parent', 'student', 'doctor', 'admin'], `تم إنشاء إحالة خارجية للطالب ${referral.studentName}`, 'critical');
        logAction(data, auth, 'referral.create', referral.id, { studentId, destination: referral.destination });
        writeData(data);
        json(res, 201, { item: referral });
        return;
      }

      if (apiParts[0] === 'referrals' && apiParts[2] === 'pdf' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const referralId = ensureString(apiParts[1], 1, 80, '');
        const referral = data.referrals.find((item) => item.id === referralId);
        if (!referral) {
          json(res, 404, { error: 'Referral not found' });
          return;
        }
        if (!canAccessStudentScope(auth, referral.studentId)) {
          json(res, 403, { error: 'Forbidden' });
          return;
        }
        const lines = [
          'Smart Clinic External Referral',
          'Referral ID: ' + referral.id,
          'Generated At: ' + nowIso(),
          '---',
          'Student: ' + (referral.studentName || referral.studentId),
          'Student ID: ' + referral.studentId,
          'Destination: ' + (referral.destination || '-'),
          'Reason: ' + (referral.reason || '-'),
          'Diagnosis: ' + (referral.diagnosis || '-'),
          'Clinical Summary: ' + (referral.clinicalSummary || '-'),
          'Issued By: ' + roleLabel(referral.createdByRole) + ' (' + (referral.createdByUserId || '-') + ')',
          'Issued At: ' + (referral.createdAt || '-')
        ];
        const pdf = buildSimplePdf(lines);
        logAction(data, auth, 'referral.pdf.export', referral.id, {});
        writeData(data);
        res.writeHead(200, withSecurityHeaders({
          'Content-Type': 'application/pdf',
          'Content-Disposition': `attachment; filename="referral-${referral.id}.pdf"`,
          'Content-Length': pdf.length,
          'Cache-Control': 'no-store'
        }));
        res.end(pdf);
        return;
      }

      if (pathname === '/api/reports/monthly' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        const month = normalizeMonthKey(urlObj.searchParams.get('month'));
        const summary = monthlyExecutiveSummary(data, month);
        const idx = data.monthlyReports.findIndex((item) => item.month === summary.month);
        if (idx >= 0) {
          data.monthlyReports[idx] = summary;
        } else {
          data.monthlyReports.unshift(summary);
        }
        logAction(data, auth, 'report.monthly.view', summary.month, summary.metrics);
        writeData(data);
        json(res, 200, { item: summary });
        return;
      }

      if (pathname === '/api/reports/monthly/pdf' && req.method === 'GET') {
        if (!requireRole(res, auth, ['admin'])) return;
        const month = normalizeMonthKey(urlObj.searchParams.get('month'));
        const summary = monthlyExecutiveSummary(data, month);
        const lines = [
          'Smart Clinic Monthly Executive Report',
          'Month: ' + summary.month,
          'Generated At: ' + nowIso(),
          '---',
          'Critical Cases: ' + summary.metrics.criticalCases,
          'Visit Requests: ' + summary.metrics.visitRequests,
          'Appointments Total: ' + summary.metrics.appointmentsTotal,
          'Appointments Completed: ' + summary.metrics.appointmentsCompleted,
          'Tickets Opened: ' + summary.metrics.ticketsOpened,
          'Tickets Closed: ' + summary.metrics.ticketsClosed,
          'Ticket Closure Rate: ' + summary.metrics.ticketClosureRate + '%',
          'Avg Ticket Resolution Hours: ' + summary.metrics.avgTicketResolutionHours,
          'Referrals: ' + summary.metrics.referrals,
          'Consents Requested: ' + summary.metrics.consentsRequested,
          'Consents Approved: ' + summary.metrics.consentsApproved
        ];
        const pdf = buildSimplePdf(lines);
        logAction(data, auth, 'report.monthly.pdf', summary.month, summary.metrics);
        writeData(data);
        res.writeHead(200, withSecurityHeaders({
          'Content-Type': 'application/pdf',
          'Content-Disposition': `attachment; filename="monthly-executive-${summary.month}.pdf"`,
          'Content-Length': pdf.length,
          'Cache-Control': 'no-store'
        }));
        res.end(pdf);
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

      if (pathname === '/api/vitals' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const studentId = resolveStudentIdForScope(auth, urlObj);
        if (!studentId) {
          json(res, 400, { error: 'Student scope is invalid' });
          return;
        }
        const limit = Math.max(1, Math.min(200, Number(urlObj.searchParams.get('limit') || 30)));
        const payload = vitalsPayloadForStudent(data, studentId, limit);
        json(res, 200, payload);
        return;
      }

      if (pathname === '/api/vitals/generate' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'vitals.generate', 120, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        if (!hasPermission(auth.user.role, 'update.vitals')) {
          json(res, 403, { error: 'Permission denied for vitals generation' });
          return;
        }
        const body = await parseBody(req);
        const studentId = ensureString(body.studentId, 0, 60, '') || resolveStudentIdForScope(auth, urlObj);
        if (!studentId) {
          json(res, 400, { error: 'Student scope is invalid' });
          return;
        }
        const reading = generateVitalsReading(data, studentId, body || {});
        if (reading.risk === 'critical') {
          pushAlert(
            data,
            ['doctor', 'admin', 'parent', 'student'],
            `قراءة حساسات حرجة للطالب ${studentId} (SpO2 ${reading.spo2}% / HR ${reading.hr})`,
            'critical'
          );
        }
        logAction(data, auth, 'vitals.generate', studentId, {
          studentId,
          readingId: reading.id,
          risk: reading.risk
        });
        writeData(data);
        json(res, 201, {
          item: reading,
          latest: reading,
          sensors: vitalsPayloadForStudent(data, studentId, 1).sensors
        });
        return;
      }

      if (pathname === '/api/vitals/ingest' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'vitals.ingest', 150, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        if (!hasPermission(auth.user.role, 'update.vitals')) {
          json(res, 403, { error: 'Permission denied for vitals ingest' });
          return;
        }
        const body = await parseBody(req);
        const studentId = ensureString(body.studentId, 0, 60, '') || resolveStudentIdForScope(auth, urlObj);
        if (!studentId) {
          json(res, 400, { error: 'Student scope is invalid' });
          return;
        }
        const reading = normalizeVitalsReading(studentId, Object.assign({}, body || {}, {
          source: ensureString((body || {}).source, 0, 30, 'sensor_bridge'),
          measuredAt: ensureString((body || {}).measuredAt, 0, 40, nowIso())
        }), 'sensor_bridge');
        persistVitalsReading(data, reading);
        updateSensorAfterReading(data, studentId, reading);
        if (reading.risk === 'critical') {
          pushAlert(
            data,
            ['doctor', 'admin', 'parent', 'student'],
            `إنذار حيوي: قراءة حرجة للطالب ${studentId}`,
            'critical'
          );
        }
        logAction(data, auth, 'vitals.ingest', studentId, {
          studentId,
          readingId: reading.id,
          sensorId: reading.sensorId || null,
          risk: reading.risk
        });
        writeData(data);
        json(res, 201, {
          item: reading,
          latest: reading,
          sensors: vitalsPayloadForStudent(data, studentId, 1).sensors
        });
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

      if (pathname === '/api/telemed/sessions' && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const caseId = normalizeCaseId(urlObj.searchParams.get('caseId'));
        const includeEnded = String(urlObj.searchParams.get('includeEnded') || '') === '1';
        let items = ensureTelemedSessions(data);
        if (!includeEnded) {
          items = items.filter((s) => s.status !== 'ended');
        }
        if (caseId) {
          items = items.filter((s) => normalizeCaseId(s.caseId) === caseId);
        }
        if (!telemedCanManage(auth)) {
          items = items.filter((s) => telemedCanDiscover(s, auth));
        }
        items = items
          .slice()
          .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
          .map((s) => telemedSanitize(s));
        json(res, 200, { items });
        return;
      }

      if (pathname === '/api/telemed/sessions' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'telemed.create', 40, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        if (!hasPermission(auth.user.role, 'start.telemed')) {
          json(res, 403, { error: 'Permission denied for telemed session creation' });
          return;
        }
        const body = await parseBody(req);
        const caseId = normalizeCaseId(body.caseId || 'case_1');
        const target = getCaseByAnyId(data, caseId);
        if (!target) {
          json(res, 404, { error: 'Case not found' });
          return;
        }
        const session = {
          id: id('tm'),
          caseId: caseId,
          studentId: body.studentId ? String(body.studentId) : target.studentId,
          roomName: ensureString(body.roomName, 3, 120, telemedRoomName(caseId)),
          title: ensureString(body.title, 3, 220, `جلسة طبية مباشرة للحالة ${caseId}`),
          allowGuardian: Boolean(body.allowGuardian),
          status: 'active',
          createdAt: nowIso(),
          updatedAt: nowIso(),
          createdByRole: auth.user.role,
          createdByUserId: auth.user.id,
          participants: [],
          invites: []
        };
        telemedEnsureParticipant(session, auth);
        ensureTelemedSessions(data).unshift(session);
        logAction(data, auth, 'telemed.session.create', session.id, {
          caseId: session.caseId,
          studentId: session.studentId,
          allowGuardian: session.allowGuardian
        });
        writeData(data);
        json(res, 201, { item: telemedSanitize(session) });
        return;
      }

      if (pathname.startsWith('/api/telemed/sessions/') && pathname.endsWith('/end') && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'telemed.end', 40, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const parts = pathname.split('/').filter(Boolean);
        const sessionId = parts[3];
        const sessionsList = ensureTelemedSessions(data);
        const session = sessionsList.find((item) => item.id === sessionId);
        if (!session) {
          json(res, 404, { error: 'Telemed session not found' });
          return;
        }
        const body = await parseBody(req);
        session.status = 'ended';
        session.endReason = ensureString(body.endReason, 1, 240, 'تم إنهاء الجلسة بواسطة الطبيب');
        session.endedAt = nowIso();
        session.updatedAt = nowIso();
        if (Array.isArray(session.invites)) {
          session.invites.forEach((inv) => {
            if (!inv.usedAt) {
              inv.revoked = true;
            }
          });
        }
        logAction(data, auth, 'telemed.session.end', session.id, { endReason: session.endReason });
        writeData(data);
        json(res, 200, { item: telemedSanitize(session, { includeInvites: telemedCanManage(auth) }) });
        return;
      }

      if (pathname.startsWith('/api/telemed/sessions/') && pathname.endsWith('/invites') && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'telemed.invite', 80, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const parts = pathname.split('/').filter(Boolean);
        const sessionId = parts[3];
        const session = ensureTelemedSessions(data).find((item) => item.id === sessionId);
        if (!session) {
          json(res, 404, { error: 'Telemed session not found' });
          return;
        }
        if (session.status === 'ended') {
          json(res, 409, { error: 'Session already ended' });
          return;
        }

        const body = await parseBody(req);
        let inviteRole = '';
        if (telemedCanManage(auth)) {
          inviteRole = ensureString(body.role, 1, 20, '');
          if (!['student', 'parent'].includes(inviteRole)) {
            json(res, 400, { error: 'Invalid invite role' });
            return;
          }
        } else {
          inviteRole = auth.user.role;
          if (body.role && body.role !== inviteRole) {
            json(res, 403, { error: 'Cannot create invite for another role' });
            return;
          }
        }

        if (inviteRole === 'student') {
          if (auth.user.role === 'student' && session.studentId !== auth.user.id) {
            json(res, 403, { error: 'Student invite does not match current account' });
            return;
          }
          if (!session.studentId) {
            json(res, 400, { error: 'Session does not have a student target' });
            return;
          }
        }

        if (inviteRole === 'parent') {
          if (!session.allowGuardian) {
            json(res, 403, { error: 'Guardian participation is disabled for this session' });
            return;
          }
        }

        const ttlMinutes = Math.max(1, Math.min(60, Number(body.ttlMinutes || 10)));
        const invite = telemedCreateInvite(session, inviteRole, auth, ttlMinutes * 60 * 1000);
        session.updatedAt = nowIso();
        logAction(data, auth, 'telemed.invite.create', session.id, {
          inviteId: invite.id,
          role: invite.role,
          expiresAt: invite.expiresAt
        });
        writeData(data);
        json(res, 201, {
          item: {
            id: invite.id,
            role: invite.role,
            token: invite.token,
            expiresAt: invite.expiresAt,
            sessionId: session.id
          }
        });
        return;
      }

      if (pathname === '/api/telemed/invites/redeem' && req.method === 'POST') {
        if (!enforceRateLimit(req, res, 'telemed.redeem', 120, 60 * 1000)) return;
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const body = await parseBody(req);
        const token = ensureString(body.token, 8, 240, '');
        if (!token) {
          json(res, 400, { error: 'Invite token is required' });
          return;
        }
        const found = telemedFindInvite(data, token);
        if (!found) {
          json(res, 404, { error: 'Invite not found' });
          return;
        }
        const { session, invite } = found;
        if (session.status === 'ended') {
          json(res, 409, { error: 'Session already ended' });
          return;
        }
        const state = telemedInviteState(invite);
        if (state === 'expired') {
          json(res, 410, { error: 'Invite expired' });
          return;
        }
        if (state === 'used') {
          json(res, 410, { error: 'Invite already used' });
          return;
        }
        if (state === 'revoked') {
          json(res, 410, { error: 'Invite revoked' });
          return;
        }
        if (!telemedCanManage(auth) && invite.role !== auth.user.role) {
          json(res, 403, { error: 'Invite role mismatch' });
          return;
        }
        if (invite.role === 'student' && auth.user.role === 'student' && session.studentId !== auth.user.id) {
          json(res, 403, { error: 'Invite is not intended for this student account' });
          return;
        }
        if (invite.role === 'parent' && !session.allowGuardian) {
          json(res, 403, { error: 'Guardian participation is disabled for this session' });
          return;
        }

        invite.usedAt = nowIso();
        invite.usedByUserId = auth.user.id;
        invite.usedByRole = auth.user.role;
        telemedEnsureParticipant(session, auth);
        session.updatedAt = nowIso();
        logAction(data, auth, 'telemed.invite.redeem', session.id, {
          inviteId: invite.id,
          role: invite.role
        });
        logAction(data, auth, 'telemed.join.' + auth.user.role, session.id, {
          inviteId: invite.id
        });
        writeData(data);
        json(res, 200, { item: telemedSanitize(session) });
        return;
      }

      if (pathname.startsWith('/api/telemed/sessions/') && req.method === 'GET') {
        if (!requireRole(res, auth, ['student', 'parent', 'doctor', 'admin'])) return;
        const parts = pathname.split('/').filter(Boolean);
        const sessionId = parts[3];
        const session = ensureTelemedSessions(data).find((item) => item.id === sessionId);
        if (!session) {
          json(res, 404, { error: 'Telemed session not found' });
          return;
        }
        if (!telemedCanView(session, auth)) {
          json(res, 403, { error: 'Forbidden' });
          return;
        }
        let changed = false;
        if (telemedCanManage(auth)) {
          const beforeCount = Array.isArray(session.participants) ? session.participants.length : 0;
          telemedEnsureParticipant(session, auth);
          const afterCount = Array.isArray(session.participants) ? session.participants.length : 0;
          changed = afterCount !== beforeCount;
          if (changed) {
            logAction(data, auth, `telemed.join.${auth.user.role}`, session.id, { source: 'session_view' });
          }
        }
        if (changed) {
          session.updatedAt = nowIso();
          writeData(data);
        }
        json(res, 200, { item: telemedSanitize(session, { includeInvites: telemedCanManage(auth) }) });
        return;
      }

      if (pathname.startsWith('/api/telemed/sessions/') && req.method === 'PATCH') {
        if (!enforceRateLimit(req, res, 'telemed.patch', 70, 60 * 1000)) return;
        if (!requireRole(res, auth, ['doctor', 'admin'])) return;
        const parts = pathname.split('/').filter(Boolean);
        const sessionId = parts[3];
        const session = ensureTelemedSessions(data).find((item) => item.id === sessionId);
        if (!session) {
          json(res, 404, { error: 'Telemed session not found' });
          return;
        }
        const body = await parseBody(req);
        if (typeof body.allowGuardian === 'boolean') {
          session.allowGuardian = body.allowGuardian;
        }
        if (typeof body.title === 'string' && body.title.trim()) {
          session.title = ensureString(body.title, 3, 220, session.title);
        }
        if (typeof body.status === 'string' && ['active', 'ended'].includes(body.status)) {
          session.status = body.status;
          if (body.status === 'ended' && !session.endedAt) {
            session.endedAt = nowIso();
          }
        }
        if (typeof body.endReason === 'string' && body.endReason.trim()) {
          session.endReason = ensureString(body.endReason, 1, 240, session.endReason || '');
        }
        session.updatedAt = nowIso();
        logAction(data, auth, 'telemed.session.update', session.id, {
          allowGuardian: session.allowGuardian,
          status: session.status
        });
        writeData(data);
        json(res, 200, { item: telemedSanitize(session, { includeInvites: telemedCanManage(auth) }) });
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

ensureDataFile();

server.listen(PORT, HOST, () => {
  console.log(`Smart Clinic server running on http://${HOST}:${PORT}`);
  console.log(`Smart Clinic data file: ${DATA_FILE}`);
});
