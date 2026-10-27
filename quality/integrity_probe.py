"""Independent in-process fault and persistence checks; actual ASGI route execution."""
from pathlib import Path
import sys,json,secrets,uuid,hashlib,concurrent.futures,copy
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend.app as gw
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from unittest.mock import patch
runid=uuid.uuid4().hex;runtime=ROOT/'quality/integrity-runtime'/runid;keys=ROOT/'quality/integrity-separate-keys'/runid
app=gw.create_app(runtime,keys)
results=[];calls=[]
def check(name,ok,detail=''):
    results.append({'name':name,'passed':bool(ok),'detail':str(detail)[:400]})
    if not ok: print('FAIL',name,detail)
def new_client():return TestClient(app,raise_server_exceptions=False,headers={'Origin':'http://127.0.0.1:8910'})
def setup(c,name):
    r=c.post('/api/setup',json={'username':name,'password':'QaSyntheticOnly!9417'});return r
clients=[new_client(),new_client()]
with concurrent.futures.ThreadPoolExecutor(2) as pool: responses=list(pool.map(lambda x:setup(x[1],f'first-{x[0]}'),enumerate(clients)))
check('concurrent first setup exactly one success',sorted(r.status_code for r in responses)==[200,409],[r.status_code for r in responses])
i=next(i for i,r in enumerate(responses) if r.status_code==200);c=clients[i];c.headers['X-CSRF-Token']=responses[i].json()['csrf_token']
check('first setup now permanently closed',setup(new_client(),'third-user').status_code==409)
check('no universal default account',new_client().post('/api/login',json={'username':'admin','password':'admin'}).status_code==401)
def session():return c.post('/api/sessions',json={}).json()['id']
def preview(s,text,spans=[]):return c.post(f'/api/sessions/{s}/preview',json={'text':text,'manual_spans':spans,'model':'local-mock'})
def send(s,p,key=None,**extra):return c.post(f'/api/sessions/{s}/send',json={'preview_id':p,'confirmed':True,'confirmation_phrase':gw.PHRASE,'idempotency_key':key or uuid.uuid4().hex,**extra})
def restore(s,m,t):return c.post(f'/api/sessions/{s}/restore',json={'message_id':m,'text':t,'authorized':True})
orig_mock=gw.local_mock
def capture(body):calls.append(copy.deepcopy(body));return orig_mock(body)
gw.local_mock=capture
s=session();pr=preview(s,'姓名：陈一星，电话13900139001').json();r=send(s,pr['preview_id']).json();m=r['message_id'];tok=pr['findings'][0]['token']
check('actual model body equals confirmed preview',calls[-1]==pr['outbound_messages'])
check('actual model body has no recognized original',all(x not in json.dumps(calls,ensure_ascii=False) for x in ['陈一星','13900139001']))
unknown='⟦PG_'+('0'*32)+'⟧'
check('unknown token fails closed',restore(s,m,unknown).status_code==422)
check('malformed token fails closed',restore(s,m,'⟦PG_garbage⟧').status_code==422)
s2=session();p2=preview(s2,'姓名：陈一星').json();t2=p2['findings'][0]['token']
check('cross session random tokens differ',t2!=tok)
check('cross session token cannot restore current message',restore(s,m,t2).status_code==422)
unsent=preview(s,'姓名：李二月').json();ut=unsent['findings'][0]['token']
check('unsent token cannot restore current message',restore(s,m,ut).status_code==422)
# Same value and type must remain stable within one session and still use exact sent manifest.
same=preview(s,'姓名：陈一星，电话13900139001').json()
check('same-session repeated value stable tokens',{x['token'] for x in same['findings']}=={x['token'] for x in pr['findings']})
r2=send(s,same['preview_id']).json()
check('masked multi-turn actual model body',len(calls[-1])==3 and all(x not in json.dumps(calls[-1],ensure_ascii=False) for x in ['陈一星','13900139001']))
check('history token exact current manifest restore',restore(s,r2['message_id'],tok).status_code==200)
# Expiry, body binding and mapping integrity mutations are confined to disposable QA DB.
def modify(pid,sql,*args):
    with app.state.connect() as db:db.execute(sql,(*args,pid))
e=preview(s2,'电话13700137002').json();modify(e['preview_id'],'UPDATE previews SET expires=? WHERE id=?',0)
check('expired preview cannot send',send(s2,e['preview_id']).status_code==409)
for field,value in [('model','evil-model'),('policy_version','old-policy'),('content_hash','0'*64)]:
    p=preview(s2,'普通合成文本').json();body={**p,field:value};modify(p['preview_id'],'UPDATE previews SET body=? WHERE id=?',gw.dumps(body))
    check('stored preview binding rejects '+field,send(s2,p['preview_id']).status_code==409)
p=preview(s2,'电话13700137002').json()
with app.state.connect() as db:blob=db.execute('SELECT mapping FROM previews WHERE id=?',(p['preview_id'],)).fetchone()[0]
bad=blob[:-1]+bytes([blob[-1]^1]);modify(p['preview_id'],'UPDATE previews SET mapping=? WHERE id=?',bad)
check('tampered authenticated mapping fails closed',send(s2,p['preview_id']).status_code==503)
# Detect/encrypt/model exceptions must make no successful sends/history.
s3=session();before=len(calls)
with patch.object(app.state.analyzer,'analyze',side_effect=RuntimeError('synthetic detection failure')):
    x=preview(s3,'姓名：王三辰');check('detector failure returns closed 503',x.status_code==503,x.text)
check('detector failure no model call',len(calls)==before)
p=preview(s3,'姓名：王三辰').json()
with patch.object(gw,'local_mock',side_effect=RuntimeError('synthetic model failure')):
    x=send(s3,p['preview_id']);check('model failure returns closed 503',x.status_code==503,x.text)
check('failed model leaves no committed history',c.get('/api/sessions/'+s3).json()['messages']==[])
p=preview(s3,'姓名：王三辰').json();key=uuid.uuid4().hex;before=len(calls)
with concurrent.futures.ThreadPoolExecutor(2) as pool:rs=list(pool.map(lambda _:send(s3,p['preview_id'],key),range(2)))
check('concurrent same-key send calls model once',len(calls)==before+1 and all(x.status_code==200 for x in rs))
check('concurrent same-key gives same message',len({x.json().get('message_id') for x in rs})==1)
check('extra original text rejected in send schema',send(s3,p['preview_id'],text='原文').status_code==422)
# Blocked credentials must not be retrievable even using the QA-held encryption key.
secret='password=SyntheticCredential9417!';p=preview(s3,secret).json()
with app.state.connect() as db:
    row=db.execute('SELECT mapping,body FROM previews WHERE id=?',(p['preview_id'],)).fetchone();blob=row['mapping'];plain=AESGCM((keys/'mapping.key').read_bytes()).decrypt(blob[:12],blob[12:],f"{s3}:{p['preview_id']}".encode())
check('blocked credentials have empty encrypted vault',json.loads(plain)=={},plain.decode())
check('blocked credential absent preview persistence',secret not in row['body'])
allfiles=list(runtime.glob('*'))
check('recognized originals absent persisted database bytes',all(x not in f.read_bytes() for f in allfiles if f.is_file() for x in ['陈一星'.encode(),'13900139001'.encode(),'王三辰'.encode(),secret.encode()]))
check('keys physically separated from database',keys.resolve()!=runtime.resolve() and not list(runtime.glob('*.key')))
check('key and db restrictive permissions',(keys/'mapping.key').stat().st_mode&0o777==0o600 and app.state.dbfile.stat().st_mode&0o777==0o600)
with app.state.connect() as db:
    titles=[r[0] for r in db.execute('SELECT title FROM sessions')]
check('session title never stores user raw',all(t=='本地隐私会话' for t in titles))
# State deletion revokes history and encrypted mapping objects.
check('owner can delete session',c.request('DELETE','/api/sessions/'+s,json={}).status_code==200)
with app.state.connect() as db:check('delete cascades mappings and messages',db.execute('SELECT count(*) FROM previews WHERE session_id=?',(s,)).fetchone()[0]==0 and db.execute('SELECT count(*) FROM messages WHERE session_id=?',(s,)).fetchone()[0]==0)
check('deleted session unavailable',c.get('/api/sessions/'+s).status_code==404)
(ROOT/'quality/evidence/integrity-results.json').write_text(json.dumps({'results':results,'passed':sum(x['passed'] for x in results),'total':len(results),'actual_model_calls':calls},ensure_ascii=False,indent=2))
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
sys.exit(not all(x['passed'] for x in results))
