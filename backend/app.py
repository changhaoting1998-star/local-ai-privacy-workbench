"""Explicit loopback/LAN HTTPS privacy gateway. No remote model adapters or raw-text request logs."""
from __future__ import annotations
import hashlib, hmac, json, os, re, secrets, sqlite3, time, unicodedata
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, ConfigDict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngine, NlpArtifacts

ROOT = Path(__file__).resolve().parents[1]
POLICY = 'zh-rules-v1'
MODE = 'LOCAL_MOCK_ONLY'
PHRASE = '确认发送脱敏内容'
TOKEN_RE = re.compile(r'⟦PG_[0-9a-f]{32}⟧')
LIMITATIONS = ['本地测试模型，仅确定性回显；没有调用真实大模型。', '真实Presidio规则检测；未安装中文NER，姓名、地址、机构及业务秘密可能漏检，请手动补充。', '仅本机单进程SQLite验证版，非企业试点或生产部署。']
ORIGINS = {'http://127.0.0.1:8910','http://localhost:8910','http://127.0.0.1:8911','http://localhost:8911','http://127.0.0.1:5173','http://localhost:5173'}

class RuleNlp(NlpEngine):
    """Explicit no-NER adapter: never downloads models or invokes remote services."""
    def load(self): pass
    def is_loaded(self): return True
    def process_text(self, text, language): return NlpArtifacts([], [], [], [], None, language)
    def process_batch(self, texts, language, **kwargs):
        for text in texts: yield text, self.process_text(text, language)
    def is_stopword(self, word, language): return False
    def is_punct(self, word, language): return False
    def get_supported_entities(self): return []
    def get_supported_languages(self): return ['zh']

RULES = [
    ('PHONE_NUMBER', r'(?<!\d)(?:\+?86[- ]?)?1[3-9]\d{9}(?!\d)'),
    ('EMAIL_ADDRESS', r'(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'),
    ('CN_ID', r'(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)'),
    ('BANK_ACCOUNT', r'(?<!\d)\d{16,19}(?!\d)'),
    ('PERSON', r'(?<=姓名[:：])[\u4e00-\u9fff]{2,4}'),
    ('PERSON', r'(?<=联系人[:：])[\u4e00-\u9fff]{2,4}'),
    ('ADDRESS', r'(?:[\u4e00-\u9fff]{2,8}(?:省|市|区|县)){1,3}[\u4e00-\u9fff]{1,12}(?:路|街|道)\d{1,5}号'),
]
SECRET_PATTERNS = [
    r"(?i)(?:password|passwd|pwd|api[\s_-]*key|access[\s_-]*token|client[\s_-]*secret|secret[\s_-]*key|密码|口令|密钥)[\"']?\s*(?:[:：=]|为|是)\s*[\"']?\S+",
    r'\bsk-[A-Za-z0-9_-]{8,}',
    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    r'\bAKIA[A-Z0-9]{16}\b',
    r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}',
    r'(?i)(?:postgres|mysql|mongodb|redis)://[^\s:@]+:[^\s@]+@',
]


def build_analyzer():
    registry = RecognizerRegistry(supported_languages=['zh'])
    for idx,(kind,pattern) in enumerate(RULES):
        registry.add_recognizer(PatternRecognizer(supported_entity=kind, supported_language='zh', patterns=[Pattern(name=f'{kind}-{idx}', regex=pattern, score=.85)]))
    return AnalyzerEngine(registry=registry, nlp_engine=RuleNlp(), supported_languages=['zh'])

def err(status, code, message):
    raise HTTPException(status_code=status, detail={'code':code,'message':message})
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def dumps(value): return json.dumps(value, ensure_ascii=False, separators=(',',':'), sort_keys=True)
def password_hash(password, salt): return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

def create_app(state_dir=None, key_dir=None, *, sso_provider=None, sso_tenant_config=None, deployment=None):
    from backend.deployment import Deployment
    deployment=deployment or Deployment()
    origins={deployment.origin} if deployment.secure else ORIGINS
    limitations=LIMITATIONS[:-1]+['仅单进程SQLite开发试用；员工原文通过HTTPS送至本机Mac mini处理，未接外部大模型；30并发尚未测。'] if deployment.secure else LIMITATIONS
    state = Path(state_dir or os.getenv('PG_STATE_DIR', ROOT/'backend/runtime'))
    keyroot = Path(key_dir or os.getenv('PG_KEY_DIR', ROOT/'.local-secrets'))
    if keyroot.resolve()==state.resolve() or state.resolve() in keyroot.resolve().parents:
        raise RuntimeError('Mapping keys must be outside database state directory')
    state.mkdir(mode=0o700, parents=True, exist_ok=True); keyroot.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(state,0o700); os.chmod(keyroot,0o700)
    keyfile=keyroot/'mapping.key'; dbfile=state/'gateway.sqlite3'
    # Refuse to regenerate lost keys for a populated database.
    if not keyfile.exists():
        if dbfile.exists() and dbfile.stat().st_size: raise RuntimeError('Mapping key missing; refusing to replace key for existing DB')
        fd=os.open(keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f: f.write(AESGCM.generate_key(bit_length=256))
    if keyfile.stat().st_mode & 0o077: raise RuntimeError('Mapping key must have mode 0600')
    key=keyfile.read_bytes()
    if len(key)!=32: raise RuntimeError('Invalid mapping key')
    aes=AESGCM(key)
    def connect():
        c=sqlite3.connect(dbfile,timeout=10); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA secure_delete=ON'); c.execute('PRAGMA journal_mode=DELETE'); return c
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS auth(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),title TEXT NOT NULL,created REAL NOT NULL,version INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS previews(id TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,user_id TEXT NOT NULL,body TEXT NOT NULL,mapping BLOB,expires REAL NOT NULL,map_expires REAL NOT NULL,version INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,role TEXT NOT NULL,content TEXT NOT NULL,preview_id TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sends(user_id TEXT NOT NULL,idempotency_key TEXT NOT NULL,preview_id TEXT NOT NULL,response TEXT NOT NULL,session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, PRIMARY KEY(user_id,idempotency_key));
        CREATE TABLE IF NOT EXISTS attempts(subject TEXT PRIMARY KEY,count INTEGER NOT NULL,until REAL NOT NULL);
        ''')
    os.chmod(dbfile,0o600)
    analyzer=build_analyzer()
    app=FastAPI(title='Local Privacy Gateway',docs_url='/api/docs',openapi_url='/api/openapi.json')
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=[deployment.host] if deployment.secure else ['127.0.0.1','localhost','testserver'])
    app.state.deployment=deployment
    app.state.connect=connect; app.state.analyzer=analyzer; app.state.dbfile=dbfile
    def encrypt(mapping,sid,pid):
        nonce=secrets.token_bytes(12)
        return nonce+aes.encrypt(nonce,dumps(mapping).encode(),f'{sid}:{pid}'.encode())
    def decrypt(blob,sid,pid):
        if blob is None: err(410,'mapping_expired','映射已到期或被清理，无法还原')
        try:return json.loads(aes.decrypt(blob[:12],blob[12:],f'{sid}:{pid}'.encode()))
        except Exception:err(503,'mapping_unavailable','映射完整性验证失败，操作已关闭')
    def prune(c):
        now=time.time(); c.execute('DELETE FROM auth WHERE expires < ?',(now,)); c.execute('UPDATE previews SET mapping=NULL WHERE map_expires < ? OR (used=0 AND expires < ?)',(now,now))
    @app.middleware('http')
    async def guard(request,call_next):
        if not request.client or not deployment.allows_client(request.client.host):
            return JSONResponse(status_code=403,content={'detail':{'code':'client_network','message':'访问网络不在允许范围内'}})
        if deployment.secure and not deployment.canonical(request):
            return JSONResponse(status_code=403,content={'detail':{'code':'deployment_origin','message':'请使用已配置的HTTPS工作台入口'}})
        if request.method in ('POST','PUT','PATCH','DELETE') and request.url.path.startswith('/api/'):
            if request.headers.get('origin') not in origins:
                return JSONResponse(status_code=403,content={'detail':{'code':'origin','message':'来源校验失败'}})
            if request.url.path!='/api/files/extract' and request.headers.get('content-type','').split(';')[0]!='application/json':
                return JSONResponse(status_code=415,content={'detail':{'code':'json_required','message':'仅接受JSON'}})
            if request.url.path!='/api/files/extract' and int(request.headers.get('content-length','0') or 0)>200000:
                return JSONResponse(status_code=413,content={'detail':{'code':'too_large','message':'请求过大'}})
        response=await call_next(request)
        response.headers['Cache-Control']='no-store'; response.headers['X-Content-Type-Options']='nosniff'; response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response
    @app.exception_handler(RequestValidationError)
    async def validation(request,exc): return JSONResponse(status_code=422,content={'detail':{'code':'validation','message':'字段格式无效，请检查长度、必填项与范围'}})
    @app.exception_handler(Exception)
    async def fail_closed(request,exc): return JSONResponse(status_code=503,content={'detail':{'code':'unavailable','message':'内部服务失败，操作已关闭；未发送原文'}})
    def auth(request:Request):
        token=request.cookies.get('pg_auth','')
        with connect() as c:
            prune(c); user=c.execute('SELECT users.* FROM auth JOIN users ON users.id=auth.user_id WHERE token_hash=? AND expires>?',(digest(token),time.time())).fetchone()
        if not user:err(401,'login_required','请先登录')
        csrf=hmac.new(key,('csrf:'+token).encode(),hashlib.sha256).hexdigest()
        if request.method not in ('GET','HEAD') and not hmac.compare_digest(request.headers.get('x-csrf-token',''),csrf):err(403,'csrf','请求校验失败，请刷新登录')
        with connect() as c:external=c.execute('SELECT provider FROM external_identities WHERE user_id=?',(user['id'],)).fetchone()
        return {'id':user['id'],'username':user['username'],'csrf_token':csrf,'provider':external['provider'] if external else 'local'}
    def own(c,sid,user):
        s=c.execute('SELECT * FROM sessions WHERE id=? AND user_id=?',(sid,user['id'])).fetchone()
        if not s:err(404,'not_found','会话不存在')
        return s
    def account(c,username,password):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}',username):err(422,'username','用户名须为3–40位字母、数字或_.-')
        if len(password)<12 or len(password)>256:err(422,'password','密码长度须为12–256字符')
        uid=secrets.token_hex(16); salt=secrets.token_hex(16)
        c.execute('INSERT INTO users VALUES(?,?,?,?)',(uid,username,salt,password_hash(password,salt)));return {'id':uid,'username':username}
    def create_user(username,password):
        with connect() as c:return account(c,username,password)
    app.state.create_user=create_user
    def logged_in(user, redirect_to=None, replace_token=''):
        token=secrets.token_urlsafe(32);csrf=hmac.new(key,('csrf:'+token).encode(),hashlib.sha256).hexdigest()
        with connect() as c:
            if replace_token:c.execute('DELETE FROM auth WHERE token_hash=?',(digest(replace_token),))
            c.execute('INSERT INTO auth VALUES(?,?,?)',(digest(token),user['id'],time.time()+8*3600))
        from fastapi.responses import RedirectResponse
        res=RedirectResponse(redirect_to,status_code=303) if redirect_to else JSONResponse({'user':{'id':user['id'],'username':user['username']},'csrf_token':csrf,'mode':MODE})
        res.set_cookie('pg_auth',token,httponly=True,samesite='strict',secure=deployment.secure,max_age=8*3600,path='/api');return res
    from backend.feishu_sso import install as install_sso
    install_sso(app,connect,logged_in,state,sso_provider,sso_tenant_config,deployment=deployment)
    @app.post('/api/files/extract')
    async def files_extract(request:Request,user=Depends(auth)):
        from backend.files_extract import bounded_body,parse_multipart,extract_in_worker,FileError,MESSAGES,MAX_REQUEST
        if deployment.secure:err(403,'files_personal_only','文件输入目前仅开放当前Mac个人版本机入口')
        try:
            length=request.headers.get('content-length','0')
            if not length.isdigit():err(422,'file_invalid','文件请求格式无效')
            if int(length)>MAX_REQUEST:err(413,'file_too_large',MESSAGES['file_too_large'])
            body=await bounded_body(request)
            data,fmt=parse_multipart(body,request.headers.get('content-type',''))
            del body
            import asyncio
            return await asyncio.to_thread(extract_in_worker,data,fmt)
        except FileError as exc:err(exc.status,exc.code,MESSAGES.get(exc.code,MESSAGES['extraction_failed']))
    @app.get('/api/files/capabilities')
    def files_capabilities(user=Depends(auth)):
        from backend.files_extract import ROOT
        binary=ROOT/'backend/bin/pdf-vision'
        return {'enabled':not deployment.secure,'formats':['pdf','docx','xlsx'],'local_ocr':binary.is_file() and os.access(binary,os.X_OK),'file_bytes':10485760,'text_characters':20000,'original_format_export':False}
    @app.get('/api/health')
    def health():
        with connect() as c: setup=not c.execute('SELECT 1 FROM users LIMIT 1').fetchone();prune(c)
        return {'status':'ok','mode':MODE,'presidio':True,'ner_model':False,'setup_required':setup and not deployment.secure,'setup_available':not deployment.secure,'deployment_mode':deployment.mode,'public_base_url':deployment.origin,'limitations':limitations}
    @app.post('/api/setup')
    def setup(body:Login):
        if deployment.secure:err(403,'setup_local_only','首次账户仅可由本机管理员在本机入口预置')
        with connect() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT 1 FROM users LIMIT 1').fetchone():err(409,'setup_closed','首次设置已经完成')
            user=account(c,body.username,body.password)
        return logged_in(user)
    @app.post('/api/login')
    def login(body:Login):
        subject='login-global';now=time.time()
        with connect() as c:
            c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT * FROM attempts WHERE subject=?',(subject,)).fetchone()
            if r and r['until']>now and r['count']>=20:err(429,'rate_limit','尝试次数过多，请稍后再试')
            user=c.execute('SELECT * FROM users WHERE username=?',(body.username,)).fetchone()
            salt=user['salt'] if user else '00'*16;result=password_hash(body.password,salt)
            valid=user and hmac.compare_digest(result,user['hash'])
            if valid:c.execute('DELETE FROM attempts WHERE subject=?',(subject,))
            else:c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,?)',(subject,(r['count']+1 if r and r['until']>now else 1),now+300))
        if not valid:err(401,'login_failed','用户名或密码错误')
        return logged_in(user)
    @app.get('/api/me')
    def me(user=Depends(auth)):return {'user':{'id':user['id'],'username':user['username'],'provider':user['provider']},'csrf_token':user['csrf_token'],'mode':MODE}
    @app.post('/api/logout')
    def logout(request:Request,user=Depends(auth)):
        with connect() as c:c.execute('DELETE FROM auth WHERE token_hash=?',(digest(request.cookies.get('pg_auth','')),))
        res=JSONResponse({'logged_out':True});res.delete_cookie('pg_auth',path='/api',secure=deployment.secure,httponly=True,samesite='strict');return res
    @app.post('/api/sessions')
    def new_session(body:SessionInput,user=Depends(auth)):
        sid=secrets.token_hex(16);now=time.time()
        # Titles may contain secrets/PII: persist only a fixed generic label.
        title='本地隐私会话'
        with connect() as c:c.execute('INSERT INTO sessions VALUES(?,?,?,?,0)',(sid,user['id'],title,now))
        return {'id':sid,'title':title,'created_at':now}
    @app.get('/api/sessions')
    def sessions(user=Depends(auth)):
        with connect() as c: rows=c.execute('SELECT id,title,created AS created_at FROM sessions WHERE user_id=? ORDER BY created DESC',(user['id'],)).fetchall()
        return {'sessions':[dict(x) for x in rows]}
    @app.get('/api/sessions/{sid}')
    def session(sid:str,user=Depends(auth)):
        with connect() as c:
            s=own(c,sid,user);messages=c.execute('SELECT id,role,content,preview_id FROM messages WHERE session_id=? ORDER BY created,rowid',(sid,)).fetchall()
        return {'id':sid,'title':s['title'],'messages':[dict(m) for m in messages],'mode':MODE}
    @app.delete('/api/sessions/{sid}')
    def delete_session(sid:str,user=Depends(auth)):
        with connect() as c:own(c,sid,user);c.execute('DELETE FROM sessions WHERE id=?',(sid,))
        return {'deleted':True}
    @app.post('/api/sessions/{sid}/preview')
    def preview(sid:str,body:PreviewInput,user=Depends(auth)):
        if '⟦PG_' in body.text:err(422,'reserved_token','输入不能包含系统保留token，请使用原始输入')
        try: results=analyzer.analyze(text=body.text,language='zh')
        except Exception:err(503,'analysis_failed','检测不可用，已阻断发送')
        spans=[{'start':r.start,'end':r.end,'entity_type':r.entity_type,'source':'presidio-rule'} for r in results]
        for s in body.manual_spans:
            if s.end>len(body.text) or s.start>=s.end:err(422,'span','手动范围无效（使用Unicode代码点）')
            spans.append({'start':s.start,'end':s.end,'entity_type':s.entity_type,'source':'manual'})
        # Merge overlap into a single complete union; never leave part of a sensitive span exposed.
        selected=[]
        for span in sorted(spans,key=lambda x:(x['start'],x['end'])):
            if selected and span['start']<selected[-1]['end']:
                selected[-1]['end']=max(selected[-1]['end'],span['end']);selected[-1]['entity_type']='SENSITIVE';selected[-1]['source']='merged'
            else:selected.append(span.copy())
        credential_probe=''.join(ch for ch in unicodedata.normalize('NFKC',body.text) if unicodedata.category(ch)!='Cf')
        reasons=['检测到密码、密钥或凭据；请移除后重新预览'] if any(re.search(p,credential_probe) for p in SECRET_PATTERNS) else []
        # Credential ranges are forcibly masked in the preview itself as well as blocked.
        if reasons:
            selected=[{'start':0,'end':len(body.text),'entity_type':'CREDENTIAL_BLOCK','source':'security-rule'}]
        pid=secrets.token_hex(16);now=time.time()
        with connect() as c:
            c.execute('BEGIN IMMEDIATE');prune(c);s=own(c,sid,user)
            hist=c.execute('SELECT role,content,preview_id FROM messages WHERE session_id=? ORDER BY created,rowid',(sid,)).fetchall()
            prior_mapping={};kinds={}
            for oldpid in set(m['preview_id'] for m in hist):
                old=c.execute('SELECT * FROM previews WHERE id=?',(oldpid,)).fetchone()
                prior_mapping.update(decrypt(old['mapping'],sid,oldpid))
                kinds.update({item['token']:item['entity_type'] for item in json.loads(old['body'])['manifest']})
            mapping=dict(prior_mapping);findings=[];chunks=[];cursor=0
            for span in selected:
                raw=body.text[span['start']:span['end']]
                # Equality reuse is local to this authenticated session and exact entity type.
                token=next((t for t,v in mapping.items() if v==raw and kinds.get(t)==span['entity_type']),None)
                if not token: token='⟦PG_'+secrets.token_hex(16)+'⟧'
                if not reasons:mapping[token]=raw
                kinds[token]=span['entity_type']
                chunks.extend((body.text[cursor:span['start']],token));cursor=span['end']
                findings.append({**span,'start_utf16':len(body.text[:span['start']].encode('utf-16-le'))//2,'end_utf16':len(body.text[:span['end']].encode('utf-16-le'))//2,'token':token})
            chunks.append(body.text[cursor:]);masked=''.join(chunks)
            if reasons:mapping={}  # Credentials are blocked irreversibly: never put their plaintext in the vault.
            outbound=[{'role':m['role'],'content':m['content']} for m in hist]+[{'role':'user','content':masked}]
            exact_tokens=set(t for m in outbound for t in TOKEN_RE.findall(m['content']))
            mapping={k:v for k,v in mapping.items() if k in exact_tokens}
            manifest=[{'token':t,'entity_type':kinds.get(t,'HISTORY')} for t in sorted(exact_tokens)]
            res={'preview_id':pid,'session_id':sid,'masked_text':masked,'findings':findings,'outbound_messages':outbound,'manifest':manifest,'blocked':bool(reasons),'block_reasons':reasons,'expires_at':now+600,'policy_version':POLICY,'model':body.model,'content_hash':digest(dumps(outbound)),'confirmation_phrase':PHRASE,'mode':MODE,'limitations':LIMITATIONS}
            c.execute('UPDATE previews SET expires=0,mapping=NULL WHERE session_id=? AND used=0',(sid,))
            c.execute('INSERT INTO previews VALUES(?,?,?,?,?,?,?,?,0)',(pid,sid,user['id'],dumps(res),encrypt(mapping,sid,pid),now+600,now+86400,s['version']))
        return res
    @app.post('/api/sessions/{sid}/send')
    def send(sid:str,body:SendInput,user=Depends(auth)):
        if not body.confirmed or body.confirmation_phrase!=PHRASE:err(422,'confirmation','请显式确认所见脱敏预览')
        with connect() as c:
            c.execute('BEGIN IMMEDIATE');prune(c);s=own(c,sid,user)
            prior=c.execute('SELECT * FROM sends WHERE user_id=? AND idempotency_key=?',(user['id'],body.idempotency_key)).fetchone()
            if prior:
                if prior['preview_id']!=body.preview_id or prior['session_id']!=sid:err(409,'idempotency_conflict','幂等键已用于其他请求')
                res=json.loads(prior['response']);res['replayed']=True;return res
            p=c.execute('SELECT * FROM previews WHERE id=? AND session_id=? AND user_id=?',(body.preview_id,sid,user['id'])).fetchone()
            if not p:err(404,'preview_missing','预览不存在')
            data=json.loads(p['body'])
            if p['used'] or p['expires']<time.time() or p['version']!=s['version']:err(409,'stale_preview','预览已使用、过期或上下文改变，请重新预览')
            if data['blocked']:err(422,'credential_blocked','凭据内容已强制阻断，请移除后重试')
            if data['model']!='local-mock' or data['policy_version']!=POLICY or digest(dumps(data['outbound_messages']))!=data['content_hash']:err(409,'binding','预览绑定校验失败')
            decrypt(p['mapping'],sid,p['id'])
            assistant=local_mock(data['outbound_messages'])
            mid=secrets.token_hex(16);now=time.time()
            c.execute('INSERT INTO messages VALUES(?,?,?,?,?,?)',(secrets.token_hex(16),sid,'user',data['masked_text'],p['id'],now))
            c.execute('INSERT INTO messages VALUES(?,?,?,?,?,?)',(mid,sid,'assistant',assistant,p['id'],now+.001))
            res={'message_id':mid,'preview_id':p['id'],'masked_text':data['masked_text'],'assistant_text':assistant,'model':'local-mock','mode':MODE,'replayed':False}
            c.execute('UPDATE previews SET used=1 WHERE id=?',(p['id'],));c.execute('UPDATE previews SET expires=0,mapping=NULL WHERE session_id=? AND used=0',(sid,));c.execute('UPDATE sessions SET version=version+1 WHERE id=?',(sid,))
            c.execute('INSERT INTO sends VALUES(?,?,?,?,?)',(user['id'],body.idempotency_key,p['id'],dumps(res),sid))
        return res
    @app.post('/api/sessions/{sid}/restore')
    def restore(sid:str,body:RestoreInput,user=Depends(auth)):
        if not body.authorized:err(422,'authorization','需明确授权本次本地还原')
        with connect() as c:
            prune(c);own(c,sid,user)
            m=c.execute('SELECT * FROM messages WHERE id=? AND session_id=? AND role=?',(body.message_id,sid,'assistant')).fetchone()
            if not m:err(404,'message_missing','已发送回复不存在')
            p=c.execute('SELECT * FROM previews WHERE id=? AND used=1',(m['preview_id'],)).fetchone()
            data=json.loads(p['body']);allowed={x['token'] for x in data['manifest']};tokens=TOKEN_RE.findall(body.text)
            if set(tokens)-allowed or ('⟦PG_' in TOKEN_RE.sub('',body.text)):err(422,'token_scope','包含未知或非本次已发送manifest的token')
            mapping=decrypt(p['mapping'],sid,p['id'])
            if any(t not in mapping for t in tokens):err(503,'mapping_missing','映射不完整，已关闭还原')
            result=TOKEN_RE.sub(lambda m:mapping[m.group()],body.text)
        return {'restored_text':result,'restored_count':len(tokens),'warning':'仅本地展示；请勿自动回写历史'}
    dist=ROOT/'frontend/dist'
    if dist.exists():
        if (dist/'assets').exists():app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
        @app.get('/')
        def index():return FileResponse(dist/'index.html')
    return app

class StrictModel(BaseModel):
    model_config=ConfigDict(extra='forbid')
class Login(StrictModel):
    username:str=Field(min_length=3,max_length=40)
    password:str=Field(min_length=1,max_length=256)
class SessionInput(StrictModel):
    title:str=Field(default='本地隐私会话',max_length=120)
class Span(StrictModel):
    start:int=Field(ge=0)
    end:int=Field(gt=0)
    entity_type:str=Field(default='MANUAL',pattern=r'^[A-Z_]{2,30}$')
class PreviewInput(StrictModel):
    text:str=Field(min_length=1,max_length=20000)
    manual_spans:list[Span]=Field(default_factory=list,max_length=200)
    model:Literal['local-mock']='local-mock'
class SendInput(StrictModel):
    preview_id:str=Field(min_length=32,max_length=32)
    confirmed:bool
    confirmation_phrase:str
    idempotency_key:str=Field(min_length=8,max_length=128)
class RestoreInput(StrictModel):
    message_id:str=Field(min_length=32,max_length=32)
    text:str=Field(max_length=100000)
    authorized:bool

def local_mock(messages):
    """Only accepts already-masked messages; deliberately has no network or LLM client."""
    return '【本地测试模型 · 未连接大模型】已收到脱敏内容：\n'+messages[-1]['content']+'\n请注意：这只是本机确定性回显，用于验证隐私流程。'
