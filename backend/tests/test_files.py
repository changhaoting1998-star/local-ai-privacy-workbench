"""Synthetic file boundaries and existing text-workflow integration; no real documents."""
import io,json,sys,zipfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from backend.app import create_app,PHRASE
from backend import files_extract as f

W=f.W

def make_doc(text='姓名：张小明 电话13800138000',extras=None):
    parts={'[Content_Types].xml':'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
           'word/document.xml':f'<w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>'}
    parts.update(extras or {})
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_STORED) as z:
        for name,data in parts.items():z.writestr(name,data)
    return out.getvalue()

@pytest.fixture
def env(tmp_path):
    app=create_app(tmp_path/'db',tmp_path/'keys',sso_tenant_config={})
    c=TestClient(app);c.headers['Origin']='http://127.0.0.1:8910'
    login=c.post('/api/setup',json={'username':'filetest','password':'Synthetic-test-pass-321'}).json();c.headers['X-CSRF-Token']=login['csrf_token']
    return app,c

def upload(c,data=None,name='synthetic.docx',mime=f.MIMES['docx']):
    return c.post('/api/files/extract',files={'file':(name,make_doc() if data is None else data,mime)})

def test_upload_real_worker_then_existing_mask_send_restore(env):
    app,c=env
    result=upload(c,name='SENSITIVE-filename-13900139000.docx')
    assert result.status_code==200,result.text
    extracted=result.json();assert extracted['coverage']['complete'] and '13800138000' in extracted['text']
    assert '13900139000' not in result.text
    sid=c.post('/api/sessions',json={}).json()['id']
    p=c.post(f'/api/sessions/{sid}/preview',json={'text':extracted['text']}).json()
    assert '张小明' not in json.dumps(p,ensure_ascii=False) and '13800138000' not in json.dumps(p)
    sent=c.post(f'/api/sessions/{sid}/send',json={'preview_id':p['preview_id'],'confirmed':True,'confirmation_phrase':PHRASE,'idempotency_key':'files-synthetic-send'}).json()
    restored=c.post(f'/api/sessions/{sid}/restore',json={'message_id':sent['message_id'],'text':sent['assistant_text'],'authorized':True})
    assert restored.status_code==200 and '13800138000' in restored.json()['restored_text']
    raw=app.state.dbfile.read_bytes()
    assert all(v.encode() not in raw for v in ['13800138000','张小明','SENSITIVE-filename'])

def test_auth_origin_csrf_before_extract(env):
    app,c=env
    foreign=TestClient(app);foreign.headers['Origin']=c.headers['Origin']
    assert upload(foreign).status_code==401
    c.headers['Origin']='https://evil.invalid';assert upload(c).status_code==403
    c.headers['Origin']='http://127.0.0.1:8910';del c.headers['X-CSRF-Token'];assert upload(c).status_code==403

@pytest.mark.parametrize('data,name,mime,code',[
 (b'not zip','file.docx',f.MIMES['docx'],'file_type'),
 (b'old ole','file.doc','application/octet-stream','legacy_format'),
 (b'%PDF-1.7','file.docx',f.MIMES['docx'],'file_type'),
 (b'PK\x03\x04corrupt','file.docx',f.MIMES['docx'],'file_invalid'),
 (b'PK\x03\x04corrupt','file.docx','image/png','file_type'),
])
def test_safe_errors_no_raw_paths_or_original(env,data,name,mime,code):
    _,c=env;r=upload(c,data,name,mime)
    assert r.status_code>=400 and r.json()['detail']['code']==code
    assert data.decode() not in r.text and name not in r.text and 'text' not in r.json()

def test_exact_multipart_and_magic(env):
    _,c=env
    for fields in [[('other',('a.docx',make_doc(),f.MIMES['docx']))],[('file',('a.docx',make_doc(),f.MIMES['docx'])),('file',('b.docx',make_doc(),f.MIMES['docx']))]]:
        r=c.post('/api/files/extract',files=fields);assert r.status_code==422 and 'text' not in r.json()
    r=c.post('/api/files/extract',content=b'broken',headers={'Content-Type':'multipart/form-data; boundary=bad'})
    assert r.status_code==422

def test_zip_and_text_caps_and_partial_not_silent(env):
    _,c=env
    assert upload(c,make_doc('中'*20001)).json()['detail']['code']=='text_too_large'
    assert upload(c,b'x'*(f.MAX_FILE+1)).status_code==413
    with pytest.raises(f.FileError):f.Package(make_doc(extras={'../escape':'invalid'}))
    dtd=make_doc(extras={'docProps/core.xml':'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///never-read">]><x>&secret;</x>'})
    assert upload(c,dtd).status_code==422
    macro=make_doc(extras={'word/vbaProject.bin':b'never execute'})
    assert upload(c,macro).json()['detail']['code']=='unsupported_content'
    r=upload(c,make_doc(extras={'word/media/image1.png':b'fake synthetic image'}));j=r.json()
    assert r.status_code==200 and not j['coverage']['complete'] and j['coverage']['requires_acknowledgement'] and j['warnings']
    assert '13800138000' in j['text']

def test_timeout_busy_and_temporary_cleanup(tmp_path,monkeypatch):
    import tempfile
    real=f.tempfile.TemporaryDirectory;created=[]
    def tmp(**kwargs):
        obj=real(dir=tmp_path,**kwargs);created.append(Path(obj.name));return obj
    monkeypatch.setattr(f.tempfile,'TemporaryDirectory',tmp)
    monkeypatch.setattr(f,'WORKER_COMMAND',[sys.executable,'-c','import time;time.sleep(20)'])
    monkeypatch.setattr(f,'WORKER_SECONDS',.01)
    with pytest.raises(f.FileError) as exc:f.extract_in_worker(b'synthetic','docx')
    assert exc.value.code=='extraction_timeout' and not any(p.exists() for p in created)
    assert f.SLOTS.acquire(False);assert f.SLOTS.acquire(False)
    try:
        with pytest.raises(f.FileError) as exc:f.extract_in_worker(b'synthetic','docx')
        assert exc.value.code=='extraction_busy'
    finally:f.SLOTS.release();f.SLOTS.release()
