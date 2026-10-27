from pathlib import Path
import sys,json,uuid,shutil
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import backend.app as gw
from fastapi.testclient import TestClient
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RealAES
run=ROOT/'quality/fault-runtime'/uuid.uuid4().hex;results=[]
def check(n,ok):results.append({'name':n,'passed':bool(ok)})
class BrokenEncrypt:
    generate_key=staticmethod(RealAES.generate_key)
    def __init__(self,k):self.delegate=RealAES(k)
    def encrypt(self,*a):raise RuntimeError('synthetic encryption unavailable')
    def decrypt(self,*a):return self.delegate.decrypt(*a)
with patch.object(gw,'AESGCM',BrokenEncrypt):app=gw.create_app(run/'db',run/'key')
c=TestClient(app,raise_server_exceptions=False,headers={'Origin':'http://127.0.0.1:8910'})
r=c.post('/api/setup',json={'username':'qa-fault','password':'QaSyntheticOnly!9417'});c.headers['X-CSRF-Token']=r.json()['csrf_token']
s=c.post('/api/sessions',json={}).json()['id']
r=c.post(f'/api/sessions/{s}/preview',json={'text':'姓名：虚构人','model':'local-mock'})
check('encryption exception preview fails closed',r.status_code==503)
with app.state.connect() as db:
    check('encryption exception creates no preview',db.execute('SELECT count(*) FROM previews').fetchone()[0]==0)
    check('encryption exception creates no message',db.execute('SELECT count(*) FROM messages').fetchone()[0]==0)
# Existing populated DB plus missing key must not generate a replacement key.
shutil.copytree(run/'db',run/'lost-key-db')
try:gw.create_app(run/'lost-key-db',run/'missing-key');missing=False
except RuntimeError:missing=True
check('missing key refuses populated database',missing)
check('lost key never silently regenerated',not (run/'missing-key/mapping.key').exists())
# Error bodies must not echo original input on validation failure.
x=c.post(f'/api/sessions/{s}/preview',json={'text':'密码：QaRawNeverInError','manual_spans':[{'start':0,'end':1000}],'model':'local-mock'})
check('validation error contains no original',x.status_code>=400 and 'QaRawNeverInError' not in x.text)
(ROOT/'quality/evidence/failure-results.json').write_text(json.dumps({'results':results,'passed':sum(x['passed'] for x in results),'total':len(results)},indent=2))
print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
sys.exit(not all(x['passed'] for x in results))
