#!/usr/bin/env bash
# SAST Link v2 本地 OAuth 全量流程测试
#
# 覆盖：邮箱注册/登录、OAuth Provider 全流程（内置+第三方 client）、Admin 客户端
# CRUD、第三方登录（/oauth/{lark,github} + exchange-code）、第三方绑定
# （POST /user/identities/{lark,github}）、解绑、UserInfo、资料/身份。
#
# 验证码默认 Redis 注入（不发邮件），USE_REAL_SMTP=1 走真实 SMTP。
# 第三方登录/绑定需在飞书或 GitHub 授权页人工授权，脚本会打开浏览器并等粘贴回调链接。

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { printf "${BLUE}[INFO]${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}[OK]${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*"; }
err()   { printf "${RED}[ERR]${NC}   %s\n" "$*"; }
step()  { printf "\n${GREEN}==== %s ====${NC}\n" "$*"; }
json()  { echo "$1" | jq .; }
code()  { echo "$1" | jq -r '.code // empty'; }

# 容器名默认对齐 docker-compose.yml，那里起的容器叫 sastlink-compose-{postgres,redis}。
# psql 与 redis-cli 都是 docker exec 进容器执行的，不走宿主端口，所以这里只需要容器名。
# 连自建容器时用环境变量覆盖，例如 PG_CONTAINER=sastlink-postgres。
PG_CONTAINER="${PG_CONTAINER:-sastlink-compose-postgres}"
REDIS_CONTAINER="${REDIS_CONTAINER:-sastlink-compose-redis}"
# 端口在 source .env 后用 APP_PORT 覆盖，这里先留默认。
API_PORT="8080"; API_PID=""
# 登录后重新赋值，先初始化避免 set -u 报 unbound。
ACCESS_TOKEN=""; REFRESH_TOKEN=""; USER_ID=""
TEST_EMAIL="${TEST_EMAIL:-woshinailong@sast.fun}"
TEST_PASSWORD="${TEST_PASSWORD:-TestPass123!}"
TEST_STUDENT_ID="${TEST_STUDENT_ID:-B24100001}"
TEST_NAME="${TEST_NAME:-Sean}"
TEST_PHONE="${TEST_PHONE:-13800000000}"
TEST_QQ="${TEST_QQ:-123456789}"
TEST_COLLEGE="${TEST_COLLEGE:-计算机学院、软件学院、网络空间安全学院}"
TEST_MAJOR="${TEST_MAJOR:-软件工程}"
USE_REAL_SMTP="${USE_REAL_SMTP:-0}"

for cmd in docker go jq openssl curl lsof; do
  if ! command -v "$cmd" &>/dev/null; then err "缺少依赖：$cmd"; exit 1; fi
done

if ! docker ps -f "name=^/${PG_CONTAINER}$" --format '{{.Names}}' | grep -q "$PG_CONTAINER"; then
  err "PostgreSQL 容器 ${PG_CONTAINER} 未运行"; exit 1
fi
if ! docker ps -f "name=^/${REDIS_CONTAINER}$" --format '{{.Names}}' | grep -q "$REDIS_CONTAINER"; then
  err "Redis 容器 ${REDIS_CONTAINER} 未运行"; exit 1
fi
if [[ ! -f .env ]]; then err "缺少 .env"; exit 1; fi
ok "容器与 .env 就绪"

step "1. 构建与迁移"
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  go build -o bin/api ./cmd/api
  go build -o bin/migrate ./cmd/migrate
  ok "构建完成"
fi
set -a; source .env; set +a
API_PORT="${APP_PORT:-8080}"
# 这几个必须在 source .env 之后取值。放在文件开头会读到空值：REDIS_PREFIX 会退回
# "sastlink" 而实际前缀来自 .env，于是脚本注入的验证码键与服务读取的键不是同一个，
# 而 psql/redis-cli 的凭据也会变成硬编码的猜测。
REDIS_PREFIX="${REDIS_KEY_PREFIX:-sastlink}"
DB_USER_NAME="${DB_USER:-sastlink}"
DB_NAME_VALUE="${DB_NAME:-sastlink}"
REDIS_PASS_VALUE="${REDIS_PASSWORD:-}"
./bin/migrate up >/dev/null 2>&1 || true
ok "迁移完成"

step "2. 启动 API"
# 只认 LISTEN 才算端口占用，CLOSED/ESTABLISHED 残留会让脚本误判复用一个不存在的 API。
if lsof -iTCP:"$API_PORT" -sTCP:LISTEN -nP >/dev/null 2>&1; then
  warn "端口 $API_PORT 已被占用，复用已有 API"
else
  ./bin/api > /tmp/sastlink-api.log 2>&1 &
  API_PID=$!
fi
for i in {1..30}; do
  if curl -sf "http://localhost:$API_PORT/health" >/dev/null 2>&1; then ok "API 健康"; break; fi
  sleep 1
done

api_post()  { curl -s -X POST "http://localhost:$API_PORT$1" -H 'Content-Type: application/json' -d "$2"; }
api_post_auth() { curl -s -X POST "http://localhost:$API_PORT$1" -H "Authorization: Bearer $2" -H 'Content-Type: application/json' -d "$3"; }
api_get_auth()  { curl -s -X GET "http://localhost:$API_PORT$1" -H "Authorization: Bearer $2"; }
api_get()   { curl -s "http://localhost:$API_PORT$1"; }
api_form()  { curl -s -X POST "http://localhost:$API_PORT$1" -H 'Content-Type: application/x-www-form-urlencoded' --data "$2"; }
api_put_auth() { curl -s -X PUT "http://localhost:$API_PORT$1" -H "Authorization: Bearer $2" -H 'Content-Type: application/json' -d "$3"; }
api_delete_auth() { curl -s -X DELETE "http://localhost:$API_PORT$1" -H "Authorization: Bearer $2" -H 'Content-Type: application/json' -d "$3"; }
psql()      { docker exec -i "$PG_CONTAINER" psql -U "$DB_USER_NAME" -d "$DB_NAME_VALUE" -tAc "$1"; }
# compose 用 --requirepass 起 Redis，因此 redis-cli 必须带 -a，否则每条命令都以
# NOAUTH 失败。这里的失败是静默的（redis_del 有 || true，验证码读取有 || echo ""），
# 表现为注册卡在等验证码，所以密码必须传进去。
redis_cli() { docker exec "$REDIS_CONTAINER" redis-cli ${REDIS_PASS_VALUE:+-a "$REDIS_PASS_VALUE"} --no-auth-warning "$@"; }
redis_del() { redis_cli DEL "$@" >/dev/null 2>&1 || true; }
redis_key() { echo "${REDIS_PREFIX}:verify:register:$1"; }

clear_limits() {
  local email="$1"
  redis_del "${REDIS_PREFIX}:ratelimit:send_email:${email}" \
            "${REDIS_PREFIX}:ratelimit:send_email_ip:127.0.0.1" \
            "${REDIS_PREFIX}:ratelimit:register:${email}" \
            "${REDIS_PREFIX}:verify:attempt:register:${email}" \
            "${REDIS_PREFIX}:ratelimit:127.0.0.1:login" \
            "${REDIS_PREFIX}:ratelimit:%3A%3A1:login"
}

# 清掉登录限流计数：一轮里登好几次，不清会撞登录限流上限。IPv6 回环 key 是编码过的。
clear_login_limits() {
  redis_del "${REDIS_PREFIX}:ratelimit:127.0.0.1:login" \
            "${REDIS_PREFIX}:ratelimit:%3A%3A1:login"
}

# ----------------------------- A. 邮箱注册/登录 -----------------------------
step "3. 邮箱注册与登录"
if [[ "$USE_REAL_SMTP" == "1" ]]; then info "模式：真实 SMTP"; else info "模式：Redis 注入验证码（默认）"; fi

EXISTS=$(psql "SELECT 1 FROM public.user WHERE login_email='${TEST_EMAIL}' LIMIT 1;" 2>/dev/null || echo "")
if [[ "$EXISTS" == "1" ]]; then
  warn "${TEST_EMAIL} 已注册，直接登录"
  LOGIN_RESP=$(api_post "/user/login" "{\"login_email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}")
else
  clear_limits "$TEST_EMAIL"
  if [[ "$USE_REAL_SMTP" == "1" ]]; then
    info "A.1 发送真实邮件验证码"
    json "$(api_post "/auth/register/send-code" "{\"login_email\":\"${TEST_EMAIL}\"}")"
    sleep 2
  else
    info "A.1 Redis 注入验证码 123456"
    redis_cli SET "$(redis_key "$TEST_EMAIL")" 123456 PX 300000 >/dev/null
  fi
  # redis-cli 把 NOAUTH 之类的错误写到 stdout 并且仍以 0 退出，所以 || echo "" 兜不住：
  # 不校验的话 CODE 会变成 "NOAUTH Authentication required." 并被当作验证码发出去。
  # 验证码固定是 6 位数字，用它作为判据。
  CODE=$(redis_cli GET "$(redis_key "$TEST_EMAIL")" 2>/dev/null || echo "")
  if [[ ! "$CODE" =~ ^[0-9]{6}$ ]]; then
    err "未读到验证码，Redis 返回：${CODE:-（空）}"
    exit 1
  fi
  ok "验证码: $CODE"

  info "A.2 verify-code 换 register_ticket"
  VERIFY_RESP=$(api_post "/auth/register/verify-code" "{\"login_email\":\"${TEST_EMAIL}\",\"code\":\"${CODE}\"}")
  json "$VERIFY_RESP"
  TICKET=$(echo "$VERIFY_RESP" | jq -r '.data.register_ticket')

  info "A.3 register 创建账号"
  REG_BODY="{\"register_ticket\":\"${TICKET}\",\"password\":\"${TEST_PASSWORD}\",\"name\":\"${TEST_NAME}\",\"student_id\":\"${TEST_STUDENT_ID}\",\"phone_number\":\"${TEST_PHONE}\",\"qq_number\":\"${TEST_QQ}\",\"college\":\"${TEST_COLLEGE}\",\"major\":\"${TEST_MAJOR}\"}"
  REG_RESP=$(api_post "/auth/register" "$REG_BODY")
  json "$REG_RESP"
  if [[ "$(code "$REG_RESP")" != "0" ]]; then err "注册失败"; exit 1; fi
  LOGIN_RESP="$REG_RESP"
fi

ACCESS_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.data.access_token')
REFRESH_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.data.refresh_token')
USER_ID=$(echo "$LOGIN_RESP" | jq -r '.data.user.id')
[[ "$ACCESS_TOKEN" == "null" || -z "$ACCESS_TOKEN" ]] && { err "未拿到 access_token"; exit 1; }
ok "用户已登录，user_id=$USER_ID"

# ----------------------------- B. OAuth Provider（内置 client） -----------------------------
step "4. OAuth 2.1 Provider 流程（内置 sast-link-web）"

info "B.1 Discovery + JWKS"
api_get "/.well-known/openid-configuration" | jq .keys? >/dev/null && ok "discovery"
api_get "/.well-known/jwks.json" | jq .keys? >/dev/null && ok "jwks"

PKCE_VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
PKCE_CHALLENGE=$(printf '%s' "$PKCE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr '+/' '-_' | tr -d '=')
# 登录落地页。provider 回调先由后端 /oauth/{lark,github}/callback 处理，再 302 到这里。
# 缺了它登录后没地方回，直接报错。
if [[ -z "${OAUTH_LOGIN_REDIRECTS:-}" ]]; then
  err "缺少 OAUTH_LOGIN_REDIRECTS（登录落地页，逗号分隔）；请检查 .env"
  exit 1
fi
FIRST_REDIRECT_URI="${OAUTH_LOGIN_REDIRECTS%%,*}"

# 打开浏览器。
open_url() {
  local url="$1"
  if command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 || true
  fi
}

# 从粘贴的回调链接里取参数。兼容完整 URL / 路径+query / 裸 query。
get_query_param() {
  local url="$1" key="$2" value
  value=$(printf '%s' "$url" | sed -n "s/.*[?&]${key}=\([^&]*\).*/\1/p")
  [[ -z "$value" ]] && value=$(printf '%s' "$url" | sed -n "s/^${key}=\([^&]*\).*/\1/p")
  printf '%s' "$value"
}
# authorize builds the first-leg URL. The scope is a parameter rather than a
# constant so a caller can drive the delegated-administration client, whose grant is
# "openid admin:read admin:write" and which would be rejected with the default set.
authorize() {
  local client_id="$1"
  local scope="${2:-openid profile email}"
  local redirect_uri encoded_scope
  redirect_uri=$(printf '%s' "$FIRST_REDIRECT_URI" | jq -sRr @uri)
  encoded_scope=$(printf '%s' "$scope" | jq -sRr @uri)
  echo "http://localhost:${API_PORT}/oauth/authorize?client_id=${client_id}&redirect_uri=${redirect_uri}&response_type=code&scope=${encoded_scope}&state=xyz&code_challenge=${PKCE_CHALLENGE}&code_challenge_method=S256&nonce=abc123"
}

run_provider_flow() {
  local client_id="$1"; local client_secret="${2:-}"; local label="$3"
  local scope="${4:-openid profile email}"
  info "${label} authorize"
  AUTH_LOC=$(curl -s -D - "$(authorize "$client_id" "$scope")" | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
  REQ_ID=$(echo "$AUTH_LOC" | sed 's/.*request_id=\([^&]*\).*/\1/')
  ok "request_id=$REQ_ID"

  info "${label} consent"
  CONSENT_RESP=$(api_post_auth "/oauth/authorize/consent" "$ACCESS_TOKEN" "{\"request_id\":\"${REQ_ID}\",\"approve\":true}")
  json "$CONSENT_RESP"
  AUTH_CODE=$(echo "$CONSENT_RESP" | jq -r '.data.redirect_uri' | sed 's/.*code=\([^&]*\).*/\1/')
  ok "auth_code=$AUTH_CODE"

  info "${label} token"
  TOKEN_FORM="grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${FIRST_REDIRECT_URI}&client_id=${client_id}&code_verifier=${PKCE_VERIFIER}"
  [[ -n "$client_secret" ]] && TOKEN_FORM="${TOKEN_FORM}&client_secret=${client_secret}"
  TOKEN_RESP=$(api_form "/oauth/token" "$TOKEN_FORM")
  json "$TOKEN_RESP"
  OAT=$(echo "$TOKEN_RESP" | jq -r '.access_token')
  ORT=$(echo "$TOKEN_RESP" | jq -r '.refresh_token')
  [[ "$OAT" == "null" || -z "$OAT" ]] && { err "token 失败"; exit 1; }

  info "${label} GET/POST /userinfo"
  json "$(curl -s -X GET "http://localhost:${API_PORT}/userinfo" -H "Authorization: Bearer $OAT")"
  json "$(curl -s -X POST "http://localhost:${API_PORT}/userinfo" -H "Authorization: Bearer $OAT")"

  info "${label} refresh"
  REFRESH_RESP=$(api_form "/oauth/token" "grant_type=refresh_token&refresh_token=${ORT}&client_id=${client_id}${client_secret:+&client_secret=${client_secret}}")
  json "$REFRESH_RESP"
  NEW_ORT=$(echo "$REFRESH_RESP" | jq -r '.refresh_token')

  info "${label} revoke"
  REVOKE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:${API_PORT}/oauth/revoke" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data "token=${ORT}&client_id=${client_id}${client_secret:+&client_secret=${client_secret}}")
  ok "revoke HTTP $REVOKE_HTTP"

  info "${label} replay 旧 refresh_token"
  REPLAY=$(api_form "/oauth/token" "grant_type=refresh_token&refresh_token=${ORT}&client_id=${client_id}${client_secret:+&client_secret=${client_secret}}")
  json "$REPLAY"
  echo "$REPLAY" | grep -q "invalid_grant" && ok "已拒绝" || warn "旧 token 仍可用"
}

run_provider_flow "sast-link-web" "" "B.2"

# ----------------------------- C. Admin OAuth 客户端注册 -----------------------------
step "5. Admin OAuth 客户端注册"

info "C.1 将测试用户提升为 admin"
psql "UPDATE public.user SET role='admin' WHERE login_email='${TEST_EMAIL}';" >/dev/null
ok "角色已改为 admin"

info "C.2 用 admin 身份重新登录拿新 token"
clear_login_limits
ADMIN_LOGIN=$(api_post "/user/login" "{\"login_email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASSWORD}\"}")
ADMIN_TOKEN=$(echo "$ADMIN_LOGIN" | jq -r '.data.access_token')
[[ "$ADMIN_TOKEN" == "null" || -z "$ADMIN_TOKEN" ]] && { err "admin 登录失败"; exit 1; }
ok "admin token 已获取"

info "C.3 GET /admin/oauth-clients"
CLIENTS_RESP=$(api_get_auth "/admin/oauth-clients" "$ADMIN_TOKEN")
json "$CLIENTS_RESP"

info "C.4 POST /admin/oauth-clients 创建第三方 confidential client"
CREATE_BODY='{"client_name":"本地测试第三方应用","client_type":"third_party","redirect_uris":["'"$FIRST_REDIRECT_URI"'"],"grant_types":["authorization_code","refresh_token"],"scopes":["openid","profile","email"]}'
CREATE_RESP=$(api_post_auth "/admin/oauth-clients" "$ADMIN_TOKEN" "$CREATE_BODY")
json "$CREATE_RESP"
CLIENT_PK=$(echo "$CREATE_RESP" | jq -r '.data.id')
THIRD_CLIENT_ID=$(echo "$CREATE_RESP" | jq -r '.data.client_id')
THIRD_CLIENT_SECRET=$(echo "$CREATE_RESP" | jq -r '.data.client_secret')
[[ "$THIRD_CLIENT_ID" == "null" || -z "$THIRD_CLIENT_ID" ]] && { err "创建 client 失败"; exit 1; }
ok "client_id=$THIRD_CLIENT_ID"

info "C.5 PUT /admin/oauth-clients/:id 更新名称"
UPDATE_RESP=$(api_put_auth "/admin/oauth-clients/${CLIENT_PK}" "$ADMIN_TOKEN" '{"client_name":"本地测试第三方应用-已改名"}')
json "$UPDATE_RESP"
if [[ "$(code "$UPDATE_RESP")" == "0" ]]; then ok "更新成功"; else err "更新失败"; exit 1; fi

# ----------------------------- D. Provider 流程（第三方 client） -----------------------------
step "6. OAuth 2.1 Provider 流程（第三方 confidential client）"
run_provider_flow "$THIRD_CLIENT_ID" "$THIRD_CLIENT_SECRET" "D"

# ----------------------------- E. 用户资料与身份 -----------------------------
step "7. 用户资料与身份列表"
info "E.1 GET /user/profile"
json "$(api_get_auth "/user/profile" "$ACCESS_TOKEN")"
info "E.2 GET /user/identities"
IDENTITIES_RESP=$(api_get_auth "/user/identities" "$ACCESS_TOKEN")
json "$IDENTITIES_RESP"
ok "资料与身份列表返回成功"

# ----------------------------- F. 第三方 OAuth 登录（浏览器手动） -----------------------------
step "8. 第三方 OAuth 登录（需浏览器）"
for provider in lark github; do
  # The codebase uses "lark" in routes and models but "feishu" in env vars.
  case "$provider" in
    lark)  enabled_var="OAUTH_FEISHU_ENABLED" ;;
    github) enabled_var="OAUTH_GITHUB_ENABLED" ;;
  esac
  if [[ "${!enabled_var:-false}" != "true" ]]; then
    warn "${provider} 未启用（${enabled_var}=false），跳过"
    continue
  fi
  AUTH_URL="http://localhost:${API_PORT}/oauth/${provider}?redirect=$(printf '%s' "$FIRST_REDIRECT_URI" | jq -sRr @uri)"
  info "请在浏览器打开：${AUTH_URL}"
  open_url "$AUTH_URL"
  info "授权后浏览器会跳回 ${FIRST_REDIRECT_URI}，把地址栏链接粘回来即可"
  read -rp "授权回调链接（空则跳过）: " CALLBACK_URL
  if [[ -n "$CALLBACK_URL" ]]; then
    LC=$(get_query_param "$CALLBACK_URL" "code")
    RS=$(get_query_param "$CALLBACK_URL" "registration_state")
    OS=$(get_query_param "$CALLBACK_URL" "oauth_state")
    if [[ -n "$LC" ]]; then
      info "解析到 login_code，兑换 Token"
      EXCHANGE_RESP=$(api_post "/oauth/exchange-code" "{\"code\":\"${LC}\"}")
      json "$EXCHANGE_RESP"
      # 兑换后会话切到第三方账号绑定的用户，后续步骤用新身份。
      NEW_AT=$(echo "$EXCHANGE_RESP" | jq -r '.data.access_token')
      if [[ -n "$NEW_AT" && "$NEW_AT" != "null" ]]; then
        ACCESS_TOKEN="$NEW_AT"
        NEW_RT=$(echo "$EXCHANGE_RESP" | jq -r '.data.refresh_token')
        [[ -n "$NEW_RT" && "$NEW_RT" != "null" ]] && REFRESH_TOKEN="$NEW_RT"
        NEW_UID=$(echo "$EXCHANGE_RESP" | jq -r '.data.user.id')
        if [[ -n "$NEW_UID" && "$NEW_UID" != "null" ]]; then
          USER_ID="$NEW_UID"
        fi
        ok "已切换会话至第三方登录用户（user_id=${USER_ID:-}）"
      else
        warn "兑换 login_code 未返回 access_token，保持原会话"
      fi
    elif [[ -n "$RS" && -n "$OS" ]]; then
      warn "解析到新账号（registration_state=$RS, oauth_state=$OS）"
      warn "新账号需调用 /auth/register 补全注册，请手动组合参数调用"
    else
      warn "未从回调链接解析出 login_code 或 registration_state，原链接：$CALLBACK_URL"
    fi
  fi
done

# ----------------------------- G. 已登录用户绑定第三方身份（浏览器手动） -----------------------------
step "9. 已登录用户绑定第三方身份（需浏览器）"
# 绑定没有后端回调：前端拼授权 URL（redirect_uri 是前端绑定页），授权后 code 落到前端，
# 前端带 token 调 POST /user/identities/{provider}。redirect_uri 是 OAUTH_*_BIND_REDIRECT_URI，
# 和登录用的后端回调 OAUTH_*_REDIRECT_URI 不是一回事。
info "已登录用户绑定的 provider 授权 URL（redirect_uri 为 OAUTH_*_BIND_REDIRECT_URI）："
for provider in lark github; do
  case "$provider" in
    lark)  enabled_var="OAUTH_FEISHU_ENABLED"; client_id_var="OAUTH_FEISHU_CLIENT_ID"; bind_uri_var="OAUTH_FEISHU_BIND_REDIRECT_URI" ;;
    github) enabled_var="OAUTH_GITHUB_ENABLED"; client_id_var="OAUTH_GITHUB_CLIENT_ID"; bind_uri_var="OAUTH_GITHUB_BIND_REDIRECT_URI" ;;
  esac
  if [[ "${!enabled_var:-false}" != "true" ]]; then
    warn "${provider} 未启用，跳过绑定"
    continue
  fi
  CLIENT_ID="${!client_id_var}"
  BIND_REDIRECT_URI="${!bind_uri_var:-$FIRST_REDIRECT_URI}"
  [[ -z "$CLIENT_ID" ]] && { warn "${provider} 缺少 ${client_id_var}"; continue; }

  # 先解绑当前用户的该 provider 绑定，保证每轮能干净重绑。
  BOUND_ID=""
  if [[ -n "$ACCESS_TOKEN" ]]; then
    IDENTITIES_JSON=$(api_get_auth "/user/identities" "$ACCESS_TOKEN")
    BOUND_ID=$(echo "$IDENTITIES_JSON" | jq -r --arg p "$provider" '.data.identities[]? | select(.provider == $p) | .id' 2>/dev/null | head -1) || BOUND_ID=""
    if [[ -n "${BOUND_ID:-}" ]]; then
      info "当前用户已绑定 ${provider}（id=${BOUND_ID:-}），先解绑以便重绑"
      json "$(api_delete_auth "/user/identities/${BOUND_ID}" "$ACCESS_TOKEN" "{\"password\":\"${TEST_PASSWORD}\"}")"
    fi
  fi

  BIND_STATE="bs_$(openssl rand -hex 8)"
  REDIRECT_ENC=$(printf '%s' "$BIND_REDIRECT_URI" | jq -sRr @uri)
  if [[ "$provider" == "lark" ]]; then
    BIND_URL="https://open.feishu.cn/open-apis/authen/v1/authorize?app_id=${CLIENT_ID}&redirect_uri=${REDIRECT_ENC}&state=${BIND_STATE}"
  else
    BIND_URL="https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_ENC}&scope=read%3Auser&state=${BIND_STATE}&allow_signup=false&response_type=code"
  fi
  info "  ${provider}: ${BIND_URL}"
  open_url "$BIND_URL"
  info "  授权后浏览器跳到 ${BIND_REDIRECT_URI}?code=...&state=...，把地址栏链接粘回来"
  read -rp "${provider} 授权回调链接（空则跳过）: " BIND_URL_CALLBACK
  if [[ -n "$BIND_URL_CALLBACK" ]]; then
    BIND_CODE=$(get_query_param "$BIND_URL_CALLBACK" "code")
    CALLBACK_STATE=$(get_query_param "$BIND_URL_CALLBACK" "state")
    if [[ -n "$CALLBACK_STATE" && "$CALLBACK_STATE" != "$BIND_STATE" ]]; then
      warn "state 校验失败：发起时 ${BIND_STATE}，回调 ${CALLBACK_STATE}（前端应中止绑定）"
    fi
    if [[ -z "$BIND_CODE" ]]; then
      warn "回调链接里没有 code 参数，原链接：$BIND_URL_CALLBACK"
    else
      info "解析到 code，调用绑定接口（带上绑定的 redirect_uri 以换 code）"
      json "$(curl -s -X POST "http://localhost:${API_PORT}/user/identities/${provider}?code=${BIND_CODE}&redirect_uri=${REDIRECT_ENC}" -H "Authorization: Bearer ${ACCESS_TOKEN}")"
    fi
  fi
done
read -rp "是否已完成绑定并继续？(y/n): " CONFIRM
[[ "$CONFIRM" == "y" ]] && json "$(api_get_auth "/user/identities" "$ACCESS_TOKEN")"

# ----------------------------- 完成 -----------------------------
step "10. 本地 OAuth 全量流程测试完成"
ok "关注塔菲喵,关注塔菲谢谢喵"

if [[ "${KEEP_API_RUNNING:-0}" == "1" ]]; then
  warn "API 仍在运行: http://localhost:${API_PORT}"
else
  [[ -n "${API_PID:-}" ]] && kill "$API_PID" 2>/dev/null || true
  ok "API 已停止"
fi
warn "容器未清理，继续复用: docker ps | grep sastlink"

