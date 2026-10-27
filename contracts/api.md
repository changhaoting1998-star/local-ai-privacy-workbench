# Local Privacy Gateway API v1 (dev-r1)

Base same-origin `/api`; backend http://127.0.0.1:8910. Frontend Vite proxy `/api` -> backend; allowed dev origins http://127.0.0.1:5173 and http://localhost:5173, plus 127.0.0.1/localhost:8911. JSON only. UTF-8 text/TXT max 20,000 code points. Backend auto-serves frontend/dist when built.

Authentication: cookie pg_auth (HttpOnly, SameSite=Strict; local HTTP Secure=false). POST `/api/login` {username,password} returns {user:{id,username},csrf_token,mode:"LOCAL_MOCK_ONLY"}; use `credentials:'include'`; all subsequent mutations require `X-CSRF-Token` and trusted Origin (browsers automatically set). GET `/api/me` returns same. POST `/api/logout` {}.

POST `/api/sessions` {title?:string} -> {id,title,created_at}; GET `/api/sessions` -> {sessions:[...]}. GET `/api/sessions/{id}` -> {id,title,messages:[{id,role,content,preview_id?}],mode}; history contains only masked text. DELETE `/api/sessions/{id}` -> {deleted:true}.

POST `/api/sessions/{id}/preview` {text:string,manual_spans:[{start:int,end:int,entity_type?:string}],model:"local-mock"} -> {preview_id,session_id,masked_text,findings:[{start,end,start_utf16,end_utf16,entity_type,source,token}],outbound_messages:[{role,content}],manifest:[{token,entity_type}],blocked:boolean,block_reasons:[string],expires_at,policy_version,model,content_hash,confirmation_phrase:"确认发送脱敏内容",mode:"LOCAL_MOCK_ONLY",limitations:[string]}. `start/end` use Python/Unicode CODE POINTS, exclusive end; UTF16 fields explicitly included for JS selection. JS convert offsets with `[...text.slice(0,selectionStart)].length`. Findings never include original value. Original input stays in the browser for editing and is processed transiently in server memory; DB stores only encrypted token mapping and masked history. Every preview supersedes earlier unused previews in that session; send invalidates other previews. Secrets force blocked; manual spans may add masking but cannot bypass secret block.

POST `/api/sessions/{id}/send` {preview_id,confirmed:true,confirmation_phrase:"确认发送脱敏内容",idempotency_key:string(min 8 chars)} -> {message_id,preview_id,masked_text,assistant_text,model,mode,replayed:boolean}. Sends *only* stored, confirmed preview messages to local mock function (zero network model adapter). No raw text accepted. Preview TTL 10 minutes; identity, session, history version, model and policy bound. Repeating same preview/key returns stored response. Key reuse for another preview returns 409. New key cannot replay consumed preview.

POST `/api/sessions/{id}/restore` {message_id,text:string,authorized:true} -> {restored_text,restored_count,warning:"仅本地展示；请勿自动回写历史"}. Only tokens in that exact sent message's manifest can restore; cross-session/unknown/unsent tokens fail closed 422; ownership checked. Original restoration is returned only on explicit auth and is never persisted in history.

GET `/api/health` -> {status,mode,presidio:true,ner_model:false}. Error JSON {detail:{code,message}}. Common 401 login; 403 CSRF/Origin; 404 object unknown/other owner; 409 stale/consumed/idempotency mismatch; 422 validation/blocked/restore token; 503 detection/encryption failure. No raw text in error/logs.

Account setup: `scripts/bootstrap.py --username demo` prompts local password; server never includes a universal default account. Optional initial account can be provisioned by environment variables on first start; no secrets in source. QA uses isolated temp state and creates two accounts through backend helper.

First run: health includes setup_required. POST /api/setup {username,password} is loopback+trusted Origin+JSON only and transactionally permits first account only; 12–256 character password; auto-login response same as login. Mapping TTL 24h; unused preview mapping cleared after 10min/supersession. Sent maps clear at expiry on next API access (no background scheduler); restore fails closed. Session deletion cascades maps/previews/history/idempotency rows; SQLite secure_delete, DELETE journal (no WAL); filesystem/device backups are outside app erasure guarantee. Session titles are fixed generic labels to avoid persisting unreviewed PII.

## 飞书SSO（本机）

精确契约与官方资料见 `contracts/feishu-sso.md`。GET `/api/auth/feishu/availability` 检查本地配置（不做远端认证）；GET `/api/auth/feishu/start` 作为顶层导航，固定Host `127.0.0.1:8910`，303到飞书官方授权页；GET `/api/auth/feishu/callback` 消费一次性浏览器绑定state和PKCE，身份租户须与官方应用租户固定配置一致。成功303到 `/?sso=success`，前端必须再读 `/api/me` 才可判已登录。失败回首页标准reason，不返回code/provider响应体。`/api/me.user.provider` 为 `local` 或 `feishu`；CSRF机制沿用。
