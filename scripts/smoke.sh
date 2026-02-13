#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
SERVER_LOG="${SERVER_LOG:-/tmp/smartclinic_smoke_server.log}"

TOTAL=0
BAD=0
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

http_code() {
  local method="$1"
  local path="$2"
  local auth="${3:-}"
  local code=""
  if [[ -n "$auth" ]]; then
    code="$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -H "Authorization: Bearer $auth" "$BASE_URL$path" 2>/dev/null || true)"
  else
    code="$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" 2>/dev/null || true)"
  fi
  if [[ -z "$code" ]]; then
    code="000"
  fi
  printf "%s" "$code"
}

check_code() {
  local expected="$1"
  local code="$2"
  local label="$3"
  TOTAL=$((TOTAL + 1))
  if [[ "$code" == "$expected" ]]; then
    printf "OK   %s %s\n" "$code" "$label"
  else
    printf "FAIL %s %s\n" "$code" "$label"
    BAD=$((BAD + 1))
  fi
}

start_server() {
  node "$ROOT_DIR/server.js" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 20); do
    local code
    code="$(http_code GET /api/health)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 0.25
  done
  echo "FAIL 000 start-server"
  if [[ -f "$SERVER_LOG" ]]; then
    tail -n 20 "$SERVER_LOG"
  fi
  return 1
}

if ! start_server; then
  exit 1
fi

check_code "200" "$(http_code GET /)" "/"
check_code "200" "$(http_code GET /index.html)" "/index.html"
check_code "200" "$(http_code GET /src/pages/admin-dashboard.html)" "/src/pages/admin-dashboard.html"
check_code "200" "$(http_code GET /assets/js/security.js)" "/assets/js/security.js"
check_code "200" "$(http_code GET /api/health)" "/api/health"

login_response="$(
  curl -s -H "content-type: application/json" -d '{"role":"admin"}' "$BASE_URL/api/auth/login" 2>/dev/null || true
)"
token="$(printf "%s" "$login_response" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
if [[ -z "$token" ]]; then
  check_code "200" "000" "/api/auth/login"
  echo "TOTAL:$TOTAL BAD:$BAD"
  exit 1
fi
check_code "200" "200" "/api/auth/login"

auth_endpoints=(
  /api/auth/me
  /api/cases
  /api/visit-requests
  /api/emergency-card
  /api/consents
  /api/home-care/plans
  /api/appointments
  /api/tickets
  /api/medications/adherence
  /api/referrals
  "/api/reports/monthly?month=2026-02"
  "/api/reports/monthly/pdf?month=2026-02"
  /api/messages
  /api/reports
  /api/reports/executive
  /api/reports/executive/pdf
  /api/sla/monitor
  /api/vitals
  /api/student/overview
  /api/telemed/sessions
  /api/notifications
  /api/system/overview
  /api/settings
  /api/alerts
  /api/analytics/overview
  /api/school-health-index
  /api/operations/overview
  /api/users
  /api/audit-logs
)

for endpoint in "${auth_endpoints[@]}"; do
  check_code "200" "$(http_code GET "$endpoint" "$token")" "$endpoint"
done

triage_code="$(
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H "content-type: application/json" \
    -d '{"caseId":"case_1","complaint":"ضيق تنفس"}' \
    "$BASE_URL/api/ai/triage" 2>/dev/null || true
)"
check_code "200" "${triage_code:-000}" "/api/ai/triage"

doctor_ai_code="$(
  curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer $token" \
    -H "content-type: application/json" \
    -d '{"caseId":"case_1","complaint":"ضيق تنفس","note":"متابعة حالة تنفسية"}' \
    "$BASE_URL/api/ai/doctor-support" 2>/dev/null || true
)"
check_code "200" "${doctor_ai_code:-000}" "/api/ai/doctor-support"

check_code "200" "$(http_code POST /api/auth/logout "$token")" "/api/auth/logout"

echo "TOTAL:$TOTAL BAD:$BAD"
if [[ "$BAD" -gt 0 ]]; then
  exit 1
fi
