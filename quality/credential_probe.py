from pathlib import Path
import sys,json,uuid
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from backend.app import create_app
from fastapi.testclient import TestClient
run=ROOT/'quality/credential-runtime'/uuid.uuid4().hex
app=create_app(run/'db',run/'key');c=TestClient(app,headers={'Origin':'http://127.0.0.1:8910'})
r=c.post('/api/setup',json={'username':'qa-secret','password':'QaSyntheticOnly!9417'});c.headers['X-CSRF-Token']=r.json()['csrf_token'];sid=c.post('/api/sessions',json={}).json()['id']
fixtures=[
 ('JSON password','{"password":"SyntheticCredential9417!"}'),
 ('JSON Chinese password','{"密码":"SyntheticCredential9417!"}'),
 ('JSON API key','{"api_key":"SyntheticCredential9417!"}'),
 ('spaced API Key','API Key: SyntheticCredential9417!'),
 ('NFKC full width password','ｐａｓｓｗｏｒｄ：SyntheticCredential9417!'),
 ('Cf zero-width credential label','pass\u200bword: SyntheticCredential9417!'),
 ('password ordinary label','password: SyntheticCredential9417!'),
 ('Chinese ordinary label','密码：SyntheticCredential9417!')]
results=[]
for name,text in fixtures:
 r=c.post(f'/api/sessions/{sid}/preview',json={'text':text,'manual_spans':[{'start':0,'end':len(text),'entity_type':'PERSON'}],'model':'local-mock'});d=r.json();results.append({'name':name,'passed':r.status_code==200 and d.get('blocked') is True,'status':r.status_code,'blocked':d.get('blocked')})
(ROOT/'quality/evidence/credential-results-final.json').write_text(json.dumps({'results':results,'passed':sum(x['passed'] for x in results),'total':len(results)},indent=2))
print(json.dumps(results))
