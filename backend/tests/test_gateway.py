import json
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app,PHRASE

@pytest.fixture
def env(tmp_path):
 app=create_app(tmp_path/'db',tmp_path/'keys')
 c=TestClient(app);c.headers['Origin']='http://127.0.0.1:8910'
 r=c.post('/api/setup',json={'username':'alice','password':'A-test-password-123'});assert r.status_code==200,r.text
 c.headers['X-CSRF-Token']=r.json()['csrf_token']
 return app,c

def session(c):return c.post('/api/sessions',json={}).json()['id']
def preview(c,s,text='😀姓名：张小明，电话13800138000',spans=[]):
 r=c.post(f'/api/sessions/{s}/preview',json={'text':text,'manual_spans':spans,'model':'local-mock'});assert r.status_code==200,r.text;return r.json()
def send(c,s,p,key='idempotent-test-1'):
 return c.post(f'/api/sessions/{s}/send',json={'preview_id':p['preview_id'],'confirmed':True,'confirmation_phrase':PHRASE,'idempotency_key':key})

def test_roundtrip_manifest_idempotency_and_storage(env):
 app,c=env;s=session(c);p=preview(c,s)
 assert p['findings'][0]['start_utf16']==p['findings'][0]['start']+1
 assert '张小明' not in json.dumps(p,ensure_ascii=False)
 assert '13800138000' not in json.dumps(p)
 r=send(c,s,p);assert r.status_code==200,r.text;r=r.json()
 again=send(c,s,p);assert again.json()['replayed']
 res=c.post(f'/api/sessions/{s}/restore',json={'message_id':r['message_id'],'text':r['assistant_text'],'authorized':True});assert res.status_code==200,res.text
 assert '张小明' in res.json()['restored_text']
 hist=c.get(f'/api/sessions/{s}').json();assert len(hist['messages'])==2
 assert '张小明' not in json.dumps(hist,ensure_ascii=False)
 raw=app.state.dbfile.read_bytes();assert '张小明'.encode() not in raw;assert b'13800138000' not in raw
 assert b'A-test-password-123' not in raw

def test_secrets_are_blocked_and_not_exposed(env):
 app,c=env;s=session(c)
 for idx,text in enumerate(['密码：ExamplePassword123','api_key=verysecret123','sk-abc123456789012','Bearer abc1234567890123','-----BEGIN PRIVATE KEY-----','{\"password\":\"SyntheticCredential9417!\"}','{\"密码\":\"SyntheticCredential9417!\"}','{\"api_key\":\"SyntheticCredential9417!\"}','API Key: SyntheticCredential9417!','ｐａｓｓｗｏｒｄ：SyntheticCredential9417!','pass\u200bword: SyntheticCredential9417!']):
  p=preview(c,s,text);assert p['blocked'];assert text not in json.dumps(p,ensure_ascii=False)
  assert send(c,s,p,'secret-key-'+str(idx)).status_code==422
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  key=(app.state.dbfile.parent.parent/'keys'/'mapping.key').read_bytes()
  with app.state.connect() as db: blob=db.execute('SELECT mapping FROM previews WHERE id=?',(p['preview_id'],)).fetchone()[0]
  assert json.loads(AESGCM(key).decrypt(blob[:12],blob[12:],f"{s}:{p['preview_id']}".encode()))=={}

def test_auth_origin_csrf_and_ownership(env):
 app,c=env;s=session(c);p=preview(c,s)
 stranger=TestClient(app);stranger.headers['Origin']='http://127.0.0.1:8910'
 assert stranger.get(f'/api/sessions/{s}').status_code==401
 app.state.create_user('bob','B-test-password-123')
 r=stranger.post('/api/login',json={'username':'bob','password':'B-test-password-123'});stranger.headers['X-CSRF-Token']=r.json()['csrf_token']
 assert stranger.get(f'/api/sessions/{s}').status_code==404
 assert send(stranger,s,p).status_code==404
 assert stranger.request('DELETE',f'/api/sessions/{s}',json={}).status_code==404
 c.headers['Origin']='http://evil.invalid'
 assert c.post('/api/sessions',json={}).status_code==403
 c.headers['Origin']='http://127.0.0.1:8910';del c.headers['X-CSRF-Token']
 assert c.post('/api/sessions',json={}).status_code==403

def test_stale_expiry_confirmation_and_scope(env):
 app,c=env;s=session(c);p=preview(c,s);p2=preview(c,s,'邮箱demo@example.com')
 assert send(c,s,p).status_code==409
 bad=c.post(f'/api/sessions/{s}/send',json={'preview_id':p2['preview_id'],'confirmed':False,'confirmation_phrase':PHRASE,'idempotency_key':'valid-key'});assert bad.status_code==422
 r=send(c,s,p2).json();foreign=preview(c,session(c),'13800138000')['manifest'][0]['token']
 res=c.post(f'/api/sessions/{s}/restore',json={'message_id':r['message_id'],'text':foreign,'authorized':True});assert res.status_code==422
 assert send(c,s,p2,'different-key').status_code==409
 p3=preview(c,s,'姓名：李小红');assert len(p3['outbound_messages'])==3
 assert 'demo@example.com' not in json.dumps(p3)
 with app.state.connect() as db:db.execute('UPDATE previews SET expires=0 WHERE id=?',(p3['preview_id'],))
 assert send(c,s,p3,'expired-key').status_code==409

def test_detection_and_crypto_fail_closed(env,monkeypatch):
 app,c=env;s=session(c)
 monkeypatch.setattr(app.state.analyzer,'analyze',lambda **k:(_ for _ in ()).throw(RuntimeError('private details')))
 r=c.post(f'/api/sessions/{s}/preview',json={'text':'private text'});assert r.status_code==503;assert 'private' not in r.text
 monkeypatch.undo();p=preview(c,s)
 with app.state.connect() as db:db.execute('UPDATE previews SET mapping=? WHERE id=?',(b'corrupt',p['preview_id']))
 assert send(c,s,p).status_code==503
 assert not c.get(f'/api/sessions/{s}').json()['messages']

def test_delete_expired_mapping_reserved_and_validation(env):
 app,c=env;s=session(c);p=preview(c,s);r=send(c,s,p).json()
 with app.state.connect() as db:db.execute('UPDATE previews SET map_expires=0 WHERE id=?',(p['preview_id'],))
 assert c.post(f'/api/sessions/{s}/restore',json={'message_id':r['message_id'],'text':r['assistant_text'],'authorized':True}).status_code==410
 assert c.post(f'/api/sessions/{s}/preview',json={'text':'⟦PG_unknown⟧'}).status_code==422
 res=c.post(f'/api/sessions/{s}/preview',json={'text':'sensitive-raw','manual_spans':[{'start':100,'end':200}]});assert 'sensitive-raw' not in res.text
 assert c.request('DELETE',f'/api/sessions/{s}',json={}).status_code==200
 with app.state.connect() as db:
  for table in ['previews','messages','sends']:assert db.execute('SELECT count(*) FROM '+table).fetchone()[0]==0
 assert c.post('/api/setup',json={'username':'other','password':'New-password-123'}).status_code==409


def test_token_stability_only_same_session(env):
 app,c=env;s=session(c);p=preview(c,s);send(c,s,p)
 p2=preview(c,s);assert p['findings'][0]['token']==p2['findings'][0]['token']
 p3=preview(c,session(c));assert p['findings'][0]['token']!=p3['findings'][0]['token']


def test_actual_model_input_and_failed_send_transaction(env,monkeypatch):
 import backend.app as module
 app,c=env;s=session(c);p=preview(c,s)
 observed=[]
 original=module.local_mock
 def observe(messages):
  observed.append(messages)
  return original(messages)
 monkeypatch.setattr(module,'local_mock',observe)
 send(c,s,p)
 assert observed[0]==p['outbound_messages']
 assert '张小明' not in json.dumps(observed,ensure_ascii=False)
 assert '13800138000' not in json.dumps(observed)
 p2=preview(c,s,'姓名：李小红')
 assert len(p2['outbound_messages'])==3
 def fail(messages): raise RuntimeError('adapter unavailable')
 monkeypatch.setattr(module,'local_mock',fail)
 safe=TestClient(app,raise_server_exceptions=False)
 safe.cookies.update(c.cookies);safe.headers.update(c.headers)
 assert send(safe,s,p2,'failed-send-key').status_code==503
 assert len(c.get(f'/api/sessions/{s}').json()['messages'])==2
 with app.state.connect() as db:
  assert db.execute('SELECT used FROM previews WHERE id=?',(p2['preview_id'],)).fetchone()[0]==0
  assert not db.execute('SELECT 1 FROM sends WHERE idempotency_key=?',('failed-send-key',)).fetchone()


def test_ordinary_language_is_not_secret_block(env):
 app,c=env;s=session(c)
 for text in ['请讨论密码安全策略，不包含真实凭据。','请介绍API调用的错误处理。','请联系姓名：张小明。']:
  assert not preview(c,s,text)['blocked']
