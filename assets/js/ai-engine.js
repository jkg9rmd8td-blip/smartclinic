// محرك بسيط لتحليل المؤشرات الحيوية وتحديد مستوى الخطورة
function evaluateRisk(vitals) {
  const { temp, spo2, hr, bpSys, bpDia } = vitals;

  let level = 'normal';
  let reasons = [];

  if (temp >= 38.5) {
    level = 'critical';
    reasons.push('ارتفاع في درجة الحرارة');
  }

  if (spo2 <= 92) {
    level = 'critical';
    reasons.push('انخفاض في تشبع الأكسجين');
  }

  if (hr >= 130) {
    if (level !== 'critical') level = 'watch';
    reasons.push('ارتفاع في معدل النبض');
  }

  if (bpSys <= 90 || bpDia <= 50) {
    level = 'critical';
    reasons.push('انخفاض في ضغط الدم');
  }

  if (level === 'normal' && reasons.length === 0) {
    reasons.push('المؤشرات الحيوية ضمن النطاق الطبيعي');
  }

  return { level, reasons };
}
