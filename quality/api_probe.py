"""Independent black-box gateway checks. Synthetic data and loopback HTTP only."""
import urllib.request, urllib.error, http.cookiejar, json, uuid, sys, os
BASE=os.environ.get('QA_BASE','http://127.0.0.1:8911')
results=[]
def record(name,ok,detail=''):
    results.append({'name':name,'passed':bool(ok),'detail':str(detail)[:500]})
def check(name,condition,detail=''):
    record(name,condition,detail)
    if not condition: print('FAIL',name,detail)
class Client:
    def __init__(self):
        self.jar=http.cookiejar.CookieJar(); self.http=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar)); self.csrf=''
    def call(self,path,body=None,method=None,headers=None):
        h={'Origin':'http://127.0.0.1:8911','X-CSRF-Token':self.csrf}
        if body is not None:h['Content-Type']='application/json'
        if headers:h.update(headers)
        req=urllib.request.Request(BASE+path,data=None if body is None else json.dumps(body).encode(),headers=h,method=method)
        try:
            with self.http.open(req) as r: return r.status,json.load(r)
        except urllib.error.HTTPError as e:
            try:return e.code,json.load(e)
            except:return e.code,{}
    def login(self,user):
        status,data=self.call('/api/login',{'username':user,'password':'QaSyntheticOnly!9417'})
        check('login '+user,status==200,data);self.csrf=data.get('csrf_token','');return data

def run():
    a,b,anon=Client(),Client(),Client()
    check('unauthenticated sessions denied',anon.call('/api/sessions')[0]==401)
    a.login('qa-alice');b.login('qa-bob')
    check('wrong password denied',anon.call('/api/login',{'username':'qa-alice','password':'wrong'})[0]==401)
    st,s=a.call('/api/sessions',{});check('create session',st==200,s);sid=s['id'];p='/api/sessions/'+sid
    check('other user cannot read',b.call(p)[0]==404)
    check('other user cannot delete',b.call(p,{},'DELETE')[0]==404)
    check('missing csrf denied',a.call('/api/sessions',{},headers={'X-CSRF-Token':''})[0]==403)
    check('untrusted origin denied',a.call('/api/sessions',{},headers={'Origin':'https://evil.invalid'})[0]==403)
    raw='😀请联系张小明，电话13800138000，邮箱qa-alice@example.test。'
    span_start=raw.index('张小明')
    body={'text':raw,'manual_spans':[{'start':span_start,'end':span_start+3,'entity_type':'PERSON'}],'model':'local-mock'}
    st,pr=a.call(p+'/preview',body);check('preview created',st==200,pr)
    check('known raw absent in preview outbound',all(v not in json.dumps(pr.get('outbound_messages',[]),ensure_ascii=False) for v in ['张小明','13800138000','qa-alice@example.test']))
    check('findings no original value',all('value' not in f and 'text' not in f for f in pr.get('findings',[])))
    man=next((f for f in pr['findings'] if f['start']==span_start),{})
    check('UTF16 offset accounts emoji',man.get('start_utf16')==span_start+1,man)
    check('other user preview denied',b.call(p+'/preview',body)[0]==404)
    payload={'preview_id':pr['preview_id'],'confirmed':True,'confirmation_phrase':'确认发送脱敏内容','idempotency_key':'qa-'+uuid.uuid4().hex}
    check('send needs explicit confirmation',a.call(p+'/send',{**payload,'confirmed':False})[0]>=400)
    check('send wrong phrase denied',a.call(p+'/send',{**payload,'confirmation_phrase':'yes'})[0]>=400)
    st,sent=a.call(p+'/send',payload);check('confirmed send',st==200,sent)
    st,replayed=a.call(p+'/send',payload);check('idempotent same response',st==200 and replayed.get('message_id')==sent.get('message_id') and replayed.get('replayed') is True,replayed)
    check('consumed preview new key denied',a.call(p+'/send',{**payload,'idempotency_key':'qa-'+uuid.uuid4().hex})[0]==409)
    check('other user send denied',b.call(p+'/send',payload)[0]==404)
    restore={'message_id':sent['message_id'],'text':sent['assistant_text'],'authorized':True}
    check('restore explicit auth needed',a.call(p+'/restore',{**restore,'authorized':False})[0]>=400)
    st,restored=a.call(p+'/restore',restore);check('restore current exact manifest',st==200 and '张小明' in restored.get('restored_text',''),restored)
    check('other user restore denied',b.call(p+'/restore',restore)[0]==404)
    st,h=a.call(p);check('history stays masked after restore',all(v not in json.dumps(h,ensure_ascii=False) for v in ['张小明','13800138000','qa-alice@example.test']))
    st,s2=a.call('/api/sessions',{});p2='/api/sessions/'+s2['id']
    check('cross session send denied',a.call(p2+'/send',payload)[0]>=400)
    check('cross session restore denied',a.call(p2+'/restore',restore)[0]>=400)
    st,pr2=a.call(p+'/preview',{'text':'新一轮询问如何联系','manual_spans':[],'model':'local-mock'})
    check('multi turn outbound masked history',st==200 and len(pr2.get('outbound_messages',[]))>=3 and all(v not in json.dumps(pr2.get('outbound_messages',[]),ensure_ascii=False) for v in ['张小明','13800138000','qa-alice@example.test']))
    st,pr3=a.call(p+'/preview',{'text':'最新内容','manual_spans':[],'model':'local-mock'})
    check('superseded preview denied',a.call(p+'/send',{**payload,'preview_id':pr2['preview_id'],'idempotency_key':'qa-'+uuid.uuid4().hex})[0]==409)
    check('unknown model denied',a.call(p+'/preview',{'text':'文本','manual_spans':[],'model':'external'})[0]>=400)
    check('invalid span denied',a.call(p+'/preview',{'text':'😀测试','manual_spans':[{'start':1,'end':99}],'model':'local-mock'})[0]>=400)
    check('oversized text denied',a.call(p+'/preview',{'text':'长'*20001,'manual_spans':[],'model':'local-mock'})[0]>=400)
    secret_cases=['password=SynThetic9417!', '密码：SynThetic9417!', 'api_key=sk-'+'A'*32, 'Authorization: Bearer '+'A'*40]
    for idx,text in enumerate(secret_cases):
        st,r=a.call(p+'/preview',{'text':text,'manual_spans':[{'start':0,'end':len(text),'entity_type':'PERSON'}],'model':'local-mock'})
        check('credential mandatory block '+str(idx),st==200 and r.get('blocked') is True,r)
        if st==200:check('blocked preview unsendable '+str(idx),a.call(p+'/send',{**payload,'preview_id':r['preview_id'],'idempotency_key':'qa-'+uuid.uuid4().hex})[0]>=400)
    check('logout',a.call('/api/logout',{})[0]==200)
    check('logout invalidates access',a.call(p)[0]==401)
    os.makedirs('quality/evidence',exist_ok=True)
    with open('quality/evidence/api-results.json','w') as f:json.dump({'base':BASE,'results':results,'passed':sum(x['passed'] for x in results),'total':len(results)},f,ensure_ascii=False,indent=2)
    print(json.dumps({'passed':sum(x['passed'] for x in results),'total':len(results)}))
    return not all(x['passed'] for x in results)
if __name__=='__main__':sys.exit(run())
