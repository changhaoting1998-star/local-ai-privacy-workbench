"""Canonical-origin Feishu login. Secrets/tokens never leave this module's process memory.
Official schemas checked 2026-10-19; see contracts/feishu-sso.md.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, re, secrets, ssl, stat, threading, time
import urllib.request, urllib.error
from urllib.parse import urlencode, parse_qs
from pathlib import Path
from fastapi import Request
from fastapi.responses import RedirectResponse

APP_ID=os.getenv('PG_FEISHU_APP_ID','cli_example').strip()
CALLBACK='http://127.0.0.1:8910/api/auth/feishu/callback'
AUTH_URL='https://accounts.feishu.cn/open-apis/authen/v1/authorize'
TOKEN_URL='https://open.feishu.cn/open-apis/authen/v2/oauth/token'
INFO_URL='https://open.feishu.cn/open-apis/authen/v1/user_info'
APP_TOKEN_URL='https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal'
TENANT_URL='https://open.feishu.cn/open-apis/tenant/v2/tenant/query'
CREDENTIALS=Path(os.getenv(
    'PG_FEISHU_CREDENTIALS',
    str(Path.home()/'.config/local-ai-privacy-workbench/feishu.json'),
)).expanduser()
FLOW_COOKIE='pg_feishu_flow'; FLOW_PATH='/api/auth/feishu'; FLOW_TTL=300
ID_RE=re.compile(r'[A-Za-z0-9_-]{1,256}')
ERRORS={'tenant_unconfigured','credentials_unavailable','configuration_invalid','origin','rate_limit','flow_invalid','flow_expired','access_denied','exchange_failed','identity_invalid','tenant_denied','unavailable'}

class SafeError(Exception):
    def __init__(self, code): self.code=code if code in ERRORS else 'unavailable'; super().__init__(self.code)

def secure_json(path):
    try:
        if path.parent.is_symlink() or stat.S_IMODE(path.parent.stat().st_mode)&0o077: raise SafeError('credentials_unavailable')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077: raise SafeError('credentials_unavailable')
            raw=f.read(16385)
        if len(raw)>16384: raise SafeError('configuration_invalid')
        obj=json.loads(raw)
        if not isinstance(obj,dict): raise SafeError('configuration_invalid')
        return obj
    except SafeError: raise
    except Exception: raise SafeError('credentials_unavailable') from None

def credentials(path=CREDENTIALS):
    obj=secure_json(path)
    app,secret=obj.get('app_id'),obj.get('app_secret')
    if not APP_ID or APP_ID=='cli_example':raise SafeError('credentials_unavailable')
    if app!=APP_ID or not isinstance(secret,str) or not 1<=len(secret)<=512 or any(ord(c)<32 for c in secret):raise SafeError('configuration_invalid')
    return app,secret

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise SafeError('exchange_failed')

class Provider:
    """No proxy inheritance, redirects, caller URLs, body logging, persistence or refresh."""
    def __init__(self, credential_path=CREDENTIALS, *, callback_url=CALLBACK): self.credential_path=credential_path; self.callback_url=callback_url
    def request(self,url,body=None,token=None):
        if url not in {TOKEN_URL,INFO_URL,APP_TOKEN_URL,TENANT_URL}:raise SafeError('configuration_invalid')
        headers={'Accept':'application/json'}
        if body is not None: headers['Content-Type']='application/json'
        if token: headers['Authorization']='Bearer '+token
        req=urllib.request.Request(url,data=json.dumps(body).encode() if body is not None else None,headers=headers)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        try:
            try: stream=opener.open(req,timeout=12)
            except urllib.error.HTTPError as e: stream=e
            with stream:
                status=stream.status; raw=stream.read(262145)
            if len(raw)>262144:raise SafeError('exchange_failed')
            obj=json.loads(raw)
            if not isinstance(obj,dict):raise SafeError('exchange_failed')
            code=obj.get('code')
            if not 200<=status<300 or type(code) is not int or code!=0:
                return None,{'http_status':status,'code':code if type(code) is int else None,'ok':False}
            return obj,{'http_status':status,'code':0,'ok':True}
        except SafeError:raise
        except Exception:raise SafeError('exchange_failed') from None
    def check_application(self):
        app,secret=credentials(self.credential_path)
        result,auth_summary=self.request(APP_TOKEN_URL,{'app_id':app,'app_secret':secret})
        if not result:return {'credential_check':auth_summary,'tenant_check':None},None
        token=result.get('tenant_access_token')
        if not isinstance(token,str) or not token or any(ord(c)<33 for c in token):raise SafeError('exchange_failed')
        identity,tenant_summary=self.request(TENANT_URL,token=token)
        tenant=(identity or {}).get('data',{}).get('tenant',{}).get('tenant_key')
        if not isinstance(tenant,str) or not ID_RE.fullmatch(tenant):tenant=None
        return {'credential_check':auth_summary,'tenant_check':tenant_summary},tenant
    def identity(self,code,verifier):
        app,secret=credentials(self.credential_path)
        obj,_=self.request(TOKEN_URL,{'grant_type':'authorization_code','client_id':app,'client_secret':secret,'code':code,'redirect_uri':self.callback_url,'code_verifier':verifier})
        if not obj:raise SafeError('exchange_failed')
        token=obj.get('access_token')
        if not isinstance(token,str) or not token or any(ord(c)<33 for c in token):raise SafeError('exchange_failed')
        # Never retain/refresh a provider token. The only use is this identity request.
        obj,_=self.request(INFO_URL,token=token)
        if not obj or not isinstance(obj.get('data'),dict):raise SafeError('identity_invalid')
        data=obj['data']; tenant=data.get('tenant_key'); oid=data.get('open_id')
        if not isinstance(tenant,str) or not ID_RE.fullmatch(tenant) or not isinstance(oid,str) or not ID_RE.fullmatch(oid):raise SafeError('identity_invalid')
        return {'tenant_key':tenant,'open_id':oid}

def challenge(verifier):return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()

def install(app,connect,logged_in,state_dir,provider=None,tenant_config=None,*,deployment=None):
    from backend.deployment import Deployment
    deployment=deployment or Deployment()
    callback_url=deployment.callback
    provider=provider or Provider(callback_url=callback_url)
    if isinstance(provider,Provider) and provider.callback_url!=callback_url:raise ValueError('Provider callback must match deployment')
    configpath=Path(state_dir)/'feishu-sso.json'
    # Injection and deployment are trusted Python configuration only. No HTTP caller can choose them.
    config=tenant_config
    reason=None
    if config is None:
        try:config=secure_json(configpath)
        except SafeError:config={};reason='tenant_unconfigured'
    tenant=config.get('tenant_key')
    if config.get('app_id')!=APP_ID or not isinstance(tenant,str) or not ID_RE.fullmatch(tenant) or config.get('source')!='official_app_tenant_identity':reason=reason or 'tenant_unconfigured'
    if not reason and isinstance(provider,Provider):
        try:credentials(provider.credential_path)
        except SafeError as e:reason=e.code
    flows={};lock=threading.Lock(); starts=[]
    app.state.sso_flows=flows
    with connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS external_identities(provider TEXT NOT NULL,tenant_key TEXT NOT NULL,open_id TEXT NOT NULL,user_id TEXT NOT NULL UNIQUE REFERENCES users(id),PRIMARY KEY(provider,tenant_key,open_id))')
    def home(error=None):
        r=RedirectResponse('/?sso=error&reason='+error if error else '/?sso=success',status_code=303)
        r.delete_cookie(FLOW_COOKIE,path=FLOW_PATH,samesite='lax',httponly=True,secure=deployment.secure)
        return r
    def canonical(request):return deployment.canonical(request)
    @app.get('/api/auth/feishu/availability')
    def availability():return {'available':reason is None,'reason_code':reason,'callback_url':callback_url,'human_oauth_required':True}
    @app.get('/api/auth/feishu/start')
    def start(request:Request):
        if not canonical(request) or request.url.query:return home('origin')
        if request.headers.get('sec-fetch-site')=='cross-site' or request.headers.get('origin',deployment.origin)!=deployment.origin:return home('origin')
        if reason:return home(reason)
        now=time.time()
        with lock:
            starts[:]=[t for t in starts if t>now-60]
            if len(starts)>=20:return home('rate_limit')
            starts.append(now)
            for key in list(flows):
                if flows[key]['expires']<now:del flows[key]
            # One flow per browser cookie; starting again invalidates its previous pending flow.
            browser=request.cookies.get(FLOW_COOKIE,'')
            for key in list(flows):
                if hmac.compare_digest(flows[key]['browser_hash'],hashlib.sha256(browser.encode()).hexdigest()):del flows[key]
            browser=secrets.token_urlsafe(32);state=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
            flows[state]={'browser_hash':hashlib.sha256(browser.encode()).hexdigest(),'verifier':verifier,'expires':now+FLOW_TTL}
        url=AUTH_URL+'?'+urlencode({'client_id':APP_ID,'response_type':'code','redirect_uri':callback_url,'scope':'','state':state,'code_challenge':challenge(verifier),'code_challenge_method':'S256'})
        r=RedirectResponse(url,status_code=303)
        r.set_cookie(FLOW_COOKIE,browser,max_age=FLOW_TTL,httponly=True,samesite='lax',secure=deployment.secure,path=FLOW_PATH)
        return r
    @app.get('/api/auth/feishu/callback')
    def callback(request:Request):
        if not canonical(request) or len(request.url.query)>8192:return home('flow_invalid')
        try:
            q=parse_qs(request.url.query,keep_blank_values=True,strict_parsing=True,max_num_fields=6)
            if any(len(v)!=1 for v in q.values()):return home('flow_invalid')
        except Exception:return home('flow_invalid')
        state=q.get('state',[''])[0]
        if not re.fullmatch(r'[A-Za-z0-9_-]{43}',state):return home('flow_invalid')
        with lock:
            flow=flows.get(state)
            if not flow:return home('flow_invalid')
            browser=request.cookies.get(FLOW_COOKIE,'')
            if not browser or not hmac.compare_digest(flow['browser_hash'],hashlib.sha256(browser.encode()).hexdigest()):return home('flow_invalid')
            # Consume before exchange, even on denial/network failure; replay cannot retry a code.
            del flows[state]
        if time.time()>=flow['expires']:return home('flow_expired')
        if reason:return home(reason)
        if set(q)=={'state','error'} and q['error'][0]=='access_denied':return home('access_denied')
        if set(q)!={'state','code'} or not re.fullmatch(r'[A-Za-z0-9_-]{1,4096}',q.get('code',[''])[0]):return home('flow_invalid')
        try:
            identity=provider.identity(q['code'][0],flow['verifier'])
            tk,oid=identity.get('tenant_key'),identity.get('open_id')
            if not isinstance(tk,str) or not ID_RE.fullmatch(tk) or not isinstance(oid,str) or not ID_RE.fullmatch(oid):return home('identity_invalid')
            if not hmac.compare_digest(tk,tenant):return home('tenant_denied')
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                row=db.execute('SELECT users.* FROM external_identities e JOIN users ON users.id=e.user_id WHERE provider=? AND tenant_key=? AND open_id=?',('feishu',tk,oid)).fetchone()
                if row:user=dict(row)
                else:
                    uid=secrets.token_hex(16);username='feishu_'+uid
                    # Impossible local password: SSO identities cannot use local password login.
                    db.execute('INSERT INTO users VALUES(?,?,?,?)',(uid,username,secrets.token_hex(16),'!sso-only!'))
                    db.execute('INSERT INTO external_identities VALUES(?,?,?,?)',('feishu',tk,oid,uid));user={'id':uid,'username':username}
            r=logged_in(user,redirect_to='/?sso=success',replace_token=request.cookies.get('pg_auth',''))
            r.delete_cookie(FLOW_COOKIE,path=FLOW_PATH,samesite='lax',httponly=True,secure=deployment.secure)
            return r
        except SafeError as e:return home(e.code)
        except Exception:return home('unavailable')
