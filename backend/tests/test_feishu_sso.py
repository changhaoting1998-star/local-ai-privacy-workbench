"""Synthetic authentication tests. No real credential/network use."""
import hashlib
from urllib.parse import urlsplit,parse_qs
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app
import backend.feishu_sso as sso
from backend.feishu_sso import CALLBACK,AUTH_URL,FLOW_COOKIE,Provider,SafeError,credentials,challenge
TEST_APP_ID='cli_synthetic_test'
CONFIG={'app_id':TEST_APP_ID,'tenant_key':'test_tenant','source':'official_app_tenant_identity'}
class Synthetic:
    def __init__(self):self.calls=[];self.tenant='test_tenant';self.oid='ou_synthetic'
    def identity(self,code,verifier):
        self.calls.append((code,verifier));return {'tenant_key':self.tenant,'open_id':self.oid,'name':'alice','email':'alice@example.com'}
@pytest.fixture
def env(tmp_path):
    sso.APP_ID=TEST_APP_ID
    provider=Synthetic();app=create_app(tmp_path/'db',tmp_path/'keys',sso_provider=provider,sso_tenant_config=CONFIG)
    c=TestClient(app,base_url='http://127.0.0.1:8910');c.headers['Origin']='http://127.0.0.1:8910'
    return app,c,provider

def start(c):
    r=c.get('/api/auth/feishu/start',follow_redirects=False);assert r.status_code==303
    p=parse_qs(urlsplit(r.headers['location']).query,keep_blank_values=True)
    assert r.headers['location'].startswith(AUTH_URL+'?')
    return r,p

def finish(c,p,**kw):
    return c.get('/api/auth/feishu/callback',params={'state':p['state'][0],'code':'synthetic_code'},follow_redirects=False,**kw)

def test_state_pkce_cookies_and_identity(env):
    app,c,provider=env;r,p=start(c)
    assert p['redirect_uri']==[CALLBACK] and p['scope']==[''] and p['code_challenge_method']==['S256']
    assert len(p['state'][0])==43
    assert 'HttpOnly' in r.headers['set-cookie'] and 'SameSite=lax' in r.headers['set-cookie'] and 'Path=/api/auth/feishu' in r.headers['set-cookie']
    flow=app.state.sso_flows[p['state'][0]]
    assert p['code_challenge']==[challenge(flow['verifier'])]
    assert len(flow['verifier'])==64
    r=finish(c,p);assert r.headers['location']=='/?sso=success'
    assert 'SameSite=strict' in r.headers['set-cookie'] and 'Path=/api' in r.headers['set-cookie']
    assert c.get('/api/me').json()['user']['provider']=='feishu'
    assert finish(c,p).headers['location'].endswith('flow_invalid')
    assert len(provider.calls)==1
    raw=app.state.dbfile.read_bytes()
    assert b'synthetic_code' not in raw and flow['verifier'].encode() not in raw
    assert b'alice@example.com' not in raw and b'alice' not in raw

def test_browser_binding_ttl_and_consumption(env):
    app,c,provider=env;_,p=start(c)
    other=TestClient(app,base_url='http://127.0.0.1:8910')
    assert finish(other,p).headers['location'].endswith('flow_invalid')
    assert not provider.calls
    app.state.sso_flows[p['state'][0]]['expires']=0
    assert finish(c,p).headers['location'].endswith('flow_expired')
    assert not app.state.sso_flows and not provider.calls

def test_denial_duplicates_unknown_params_and_mismatch(env):
    app,c,provider=env;_,p=start(c)
    r=c.get('/api/auth/feishu/callback?state='+p['state'][0]+'&state=duplicate&code=hidden',follow_redirects=False)
    assert r.headers['location'].endswith('flow_invalid') and 'hidden' not in r.text
    _,p=start(c)
    r=c.get('/api/auth/feishu/callback',params={'state':p['state'][0],'error':'access_denied'},follow_redirects=False)
    assert r.headers['location'].endswith('access_denied') and not provider.calls
    assert finish(c,p).headers['location'].endswith('flow_invalid')
    _,p=start(c)
    r=c.get('/api/auth/feishu/callback',params={'state':p['state'][0],'code':'x','redirect_uri':'https://evil.invalid'},follow_redirects=False)
    assert r.headers['location'].endswith('flow_invalid') and not provider.calls

def test_immutable_account_and_tenant_isolation(env):
    app,c,provider=env
    local=c.post('/api/setup',json={'username':'alice','password':'Local-Test-Password-123'}).json()
    c.headers['X-CSRF-Token']=local['csrf_token'];sid=c.post('/api/sessions',json={}).json()['id']
    _,p=start(c);finish(c,p);me=c.get('/api/me').json()
    assert me['user']['id']!=local['user']['id']
    assert c.get('/api/sessions/'+sid).status_code==404
    c.headers['X-CSRF-Token']=me['csrf_token']
    assert c.post('/api/sessions',json={}).status_code==200
    first=me['user']['id'];_,p=start(c);finish(c,p)
    assert c.get('/api/me').json()['user']['id']==first
    provider.oid='ou_other';_,p=start(c);finish(c,p)
    assert c.get('/api/me').json()['user']['id']!=first
    provider.tenant='other_tenant';_,p=start(c)
    assert finish(c,p).headers['location'].endswith('tenant_denied')
    with app.state.connect() as db:assert db.execute('SELECT count(*) FROM external_identities').fetchone()[0]==2

def test_fixed_host_routes_origin_rate_limit(env):
    app,c,provider=env
    assert c.get('/api/auth/feishu/start?redirect_uri=https://evil.invalid',follow_redirects=False).headers['location'].endswith('origin')
    assert c.get('/api/auth/feishu/start',headers={'sec-fetch-site':'cross-site'},follow_redirects=False).headers['location'].endswith('origin')
    assert c.get('/api/auth/feishu/start',headers={'host':'localhost:8910'},follow_redirects=False).headers['location'].endswith('origin')
    for i in range(20):start(c)
    assert c.get('/api/auth/feishu/start',follow_redirects=False).headers['location'].endswith('rate_limit')
    assert len(app.state.sso_flows)==1

def test_provider_failure_consumed_and_normalized(env):
    app,c,provider=env;_,p=start(c)
    def fail(*args):raise RuntimeError('PROVIDER_BODY_SECRET')
    provider.identity=fail
    r=finish(c,p)
    assert r.headers['location'].endswith('unavailable') and 'PROVIDER' not in r.text
    assert finish(c,p).headers['location'].endswith('flow_invalid')
    assert c.get('/api/me').status_code==401

def test_missing_tenant_fails_closed(tmp_path):
    app=create_app(tmp_path/'db',tmp_path/'keys',sso_provider=Synthetic())
    c=TestClient(app,base_url='http://127.0.0.1:8910')
    body=c.get('/api/auth/feishu/availability').json()
    assert not body['available'] and body['reason_code']=='tenant_unconfigured'
    assert c.get('/api/auth/feishu/start',follow_redirects=False).headers['location'].endswith('tenant_unconfigured')

def test_protected_credential_loader_and_fixed_endpoints(tmp_path):
    # Synthetic files only; real credential is never opened in the test suite.
    d=tmp_path/'credentials';d.mkdir(mode=0o700);f=d/'synthetic.json'
    sso.APP_ID=TEST_APP_ID
    f.write_text('{"app_id":"'+TEST_APP_ID+'","app_secret":"SYNTHETIC_ONLY"}');f.chmod(0o600)
    assert credentials(f)[0]==TEST_APP_ID
    f.chmod(0o644)
    with pytest.raises(SafeError):credentials(f)
    f.chmod(0o600);link=d/'link';link.symlink_to(f)
    with pytest.raises(SafeError):credentials(link)
    with pytest.raises(SafeError):Provider(f).request('https://evil.invalid')
