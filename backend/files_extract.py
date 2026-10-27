"""Bounded local extraction. No raw text, filenames, or parser exceptions are logged."""
from __future__ import annotations
import asyncio, io, json, os, re, signal, subprocess, sys, threading, zipfile, tempfile, time, logging
from pathlib import Path, PurePosixPath
from defusedxml import ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
MAX_FILE=10*1024*1024
MAX_REQUEST=MAX_FILE+65536
MAX_TEXT=20000
WORKER_SECONDS=45
WORKER_COMMAND=[sys.executable,'-m','backend.files_worker']
SLOTS=threading.BoundedSemaphore(2)
MAX_WORKER_RSS_KIB=768*1024
logging.getLogger('python_multipart').disabled=True
logging.getLogger('python_multipart.multipart').disabled=True
MIMES={'pdf':'application/pdf','docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
MESSAGES={
'file_too_large':'文件超过10 MiB，请拆分后重试。','text_too_large':'提取内容（含来源标签）超过20000字，请拆分文件；未截断或发送。',
'archive_limits':'压缩文档超过安全解压限制，请缩小或另存后重试。','document_limits':'文件页数、工作表、单元格或复杂度超过安全限制，请拆分。',
'file_type':'仅支持PDF、.docx和.xlsx；文件扩展名、类型与实际内容须一致。','legacy_format':'旧版.doc/.xls暂不支持，请先另存为.docx/.xlsx。',
'file_invalid':'文件损坏、格式不一致或结构无法完整核验，请重新导出后重试。','file_encrypted':'加密或受密码保护的文件暂不支持，请在本机解除保护后重试。',
'unsupported_content':'文件含宏、活动内容、外部数据连接或不支持的结构，请另存为简单文档后重试。','no_readable_text':'没有提取到可读文字。请手动粘贴内容或重新导出可搜索文档。',
'ocr_unavailable':'本机OCR不可用，无法读取此扫描PDF；请转换为可搜索PDF或手动粘贴。',
'extraction_busy':'已有文件正在解析，请稍后重试。','extraction_failed':'本机解析失败，未保留或发送文件内容。','extraction_timeout':'本机解析超过45秒，已终止；请拆分文件后重试。'}
class FileError(Exception):
    def __init__(self,code,status=422): self.code=code; self.status=status; super().__init__(code)

def fail(code,status=422): raise FileError(code,status)

def parse_multipart(body:bytes,content_type:str):
    from python_multipart import MultipartParser
    from python_multipart.multipart import parse_options_header
    try:
        kind,opts=parse_options_header(content_type)
        boundary=opts.get(b'boundary',b'')
        if kind!=b'multipart/form-data' or not 1<=len(boundary)<=200: fail('file_type',415)
        headers={}; field=bytearray(); value=bytearray(); payload=bytearray(); meta={}; parts=0; done=False; begun=False
        def on_begin():
            nonlocal parts,begun
            parts+=1;begun=True
            if parts!=1: fail('file_invalid')
        def on_field(data,start,end):
            field.extend(data[start:end])
            if len(field)>2048: fail('file_invalid')
        def on_value(data,start,end):
            value.extend(data[start:end])
            if len(value)>8192: fail('file_invalid')
        def on_header_end():
            key=bytes(field).lower()
            if key in headers: fail('file_invalid')
            headers[key]=bytes(value);field.clear();value.clear()
        def on_headers_finished():
            disposition,options=parse_options_header(headers.get(b'content-disposition',b''))
            if disposition!=b'form-data' or options.get(b'name')!=b'file' or b'filename' not in options: fail('file_invalid')
            name=options[b'filename'].decode('utf-8','strict')
            suffix=Path(name).suffix.lower().lstrip('.')
            if suffix in ('doc','xls'): fail('legacy_format',415)
            if suffix not in MIMES: fail('file_type',415)
            mime=headers.get(b'content-type',b'application/octet-stream').decode('ascii').split(';')[0].lower()
            if mime not in (MIMES[suffix],'application/octet-stream'): fail('file_type',415)
            meta['format']=suffix
        def on_data(data,start,end):
            if len(payload)+end-start>MAX_FILE: fail('file_too_large',413)
            payload.extend(data[start:end])
        def on_end():
            nonlocal done
            done=True
        parser=MultipartParser(boundary,{'on_part_begin':on_begin,'on_header_field':on_field,'on_header_value':on_value,'on_header_end':on_header_end,'on_headers_finished':on_headers_finished,'on_part_data':on_data,'on_end':on_end},max_size=MAX_REQUEST)
        parser.write(body);parser.finalize()
        if not begun or not done or not payload or 'format' not in meta: fail('file_invalid')
        data=bytes(payload);fmt=meta['format']
        if fmt=='pdf' and not data.startswith(b'%PDF-'): fail('file_type',415)
        if fmt!='pdf' and not data.startswith(b'PK\x03\x04'): fail('file_type',415)
        return data,fmt
    except FileError: raise
    except Exception: fail('file_invalid')

async def bounded_body(request):
    chunks=[];size=0
    try:
        async def read():
            nonlocal size
            async for chunk in request.stream():
                size+=len(chunk)
                if size>MAX_REQUEST: fail('file_too_large',413)
                chunks.append(chunk)
            return b''.join(chunks)
        return await asyncio.wait_for(read(),timeout=30)
    except asyncio.TimeoutError: fail('extraction_timeout',504)


def extract_in_worker(data:bytes,fmt:str):
    if not SLOTS.acquire(False): fail('extraction_busy',429)
    process=None;private_tmp=tempfile.TemporaryDirectory(prefix='pg-extract-')
    try:
        os.chmod(private_tmp.name,0o700)
        # No credentials/proxy/provider environment is passed to third-party parsers.
        env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'en_US.UTF-8','PYTHONDONTWRITEBYTECODE':'1','TMPDIR':private_tmp.name,'HOME':private_tmp.name}
        process=subprocess.Popen(WORKER_COMMAND+[fmt],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,env=env)
        deadline=time.monotonic()+WORKER_SECONDS;first=True
        while True:
            try:
                raw,_=process.communicate(data if first else None,timeout=.25);break
            except subprocess.TimeoutExpired:
                first=False
                if time.monotonic()>=deadline:
                    os.killpg(process.pid,signal.SIGKILL);process.communicate();fail('extraction_timeout',504)
                # Numeric process-group RSS only; no command lines, user data or filenames.
                probe=subprocess.run(['/bin/ps','-axo','pgid=,rss='],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=2)
                if probe.returncode:os.killpg(process.pid,signal.SIGKILL);process.communicate();fail('extraction_failed',503)
                rss=sum(int(cols[1]) for line in probe.stdout.splitlines() if len(cols:=line.split())==2 and cols[0]==str(process.pid).encode())
                if rss>MAX_WORKER_RSS_KIB:
                    os.killpg(process.pid,signal.SIGKILL);process.communicate();fail('document_limits',413)
        if process.returncode or len(raw)>500000: fail('extraction_failed',503)
        result=json.loads(raw)
        if 'error' in result: fail(result['error'],result.get('status',422))
        if not isinstance(result.get('text'),str) or len(result['text'])>MAX_TEXT: fail('extraction_failed',503)
        return result
    except FileError: raise
    except Exception: fail('extraction_failed',503)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid,signal.SIGKILL);process.communicate()
        private_tmp.cleanup()
        SLOTS.release()

class Content:
    def __init__(self):self.chunks=[];self.size=0;self.warnings=[];self.complete=True
    def add(self,label,text):
        if not text or not text.strip():return
        text=f'[{label}]\n{text.strip()}'
        self.size+=len(text)+(2 if self.chunks else 0)
        if self.size>MAX_TEXT:fail('text_too_large',413)
        self.chunks.append(text)
    def gap(self,message):
        self.complete=False
        if message not in self.warnings:self.warnings.append(message)
    def result(self,fmt,units,ocr=False):
        text='\n\n'.join(self.chunks)
        if not text.strip(): fail('no_readable_text')
        if not self.complete:self.warnings.append('仅使用已提取内容；未读取部分未脱敏，也不会发送原文件。请回原件核对，必要时手动补充。')
        return {'text':text,'format':fmt,'character_count':len(text),'coverage':{'complete':self.complete,'requires_acknowledgement':not self.complete,'summary':('已提取可读取文字；另有未读取内容，请核对覆盖提示。' if not self.complete else '已按支持范围提取全部文字，请人工核对。'),'units':units,'ocr_used':ocr},'warnings':self.warnings,'limits':{'file_bytes':MAX_FILE,'text_characters':MAX_TEXT}}

W='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
X='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
R='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
def tag(name):return name.rsplit('}',1)[-1]
class Package:
    def __init__(self,data):
        self.zip=zipfile.ZipFile(io.BytesIO(data));entries=self.zip.infolist()
        if len(entries)>2000: fail('archive_limits',413)
        names=set();total=0
        for e in entries:
            path=PurePosixPath(e.filename)
            if e.filename in names or path.is_absolute() or '..' in path.parts or '\\' in e.filename or e.flag_bits&1 or (e.external_attr>>16)&0o170000==0o120000:fail('file_invalid')
            names.add(e.filename);total+=e.file_size
            if e.file_size>15*1024*1024 or total>40*1024*1024 or e.file_size/max(1,e.compress_size)>150: fail('archive_limits',413)
        self.names=names;self.xml={};elements=0;actual_total=0
        self.parts={}
        for entry in entries:
            if entry.is_dir():continue
            with self.zip.open(entry) as member:
                raw=member.read(15*1024*1024+1)
            actual_total+=len(raw)
            if len(raw)>15*1024*1024 or actual_total>40*1024*1024:fail('archive_limits',413)
            if len(raw)!=entry.file_size:fail('file_invalid')
            self.parts[entry.filename]=raw
        for name in names:
            if name.endswith(('.xml','.rels')):
                root=ET.fromstring(self.parts[name],forbid_dtd=True,forbid_entities=True,forbid_external=True)
                elements+=sum(1 for _ in root.iter())
                if elements>500000:fail('document_limits',413)
                self.xml[name]=root
        if '[Content_Types].xml' not in self.xml: fail('file_invalid')
        for node in self.xml['[Content_Types].xml']:
            value=node.attrib.get('ContentType','').lower()
            if any(word in value for word in ('macroenabled','vbaproject','activex','oleobject')): fail('unsupported_content')
        for name in names:
            low=name.lower()
            if any(word in low for word in ('vbaproject','activex','embeddings/','externallinks/','connections.xml','querytables/','altchunk')):fail('unsupported_content')
        for name,root in self.xml.items():
            if name.endswith('.rels'):
                for rel in root:
                    relation=rel.attrib.get('Type','').lower().rsplit('/',1)[-1]
                    if any(kind in relation for kind in ('vbaproject','oleobject','package','activex','afchunk')):fail('unsupported_content')
                    if rel.attrib.get('TargetMode','Internal') not in ('Internal','External'):fail('file_invalid')
                    if rel.attrib.get('TargetMode')=='External' and not rel.attrib.get('Type','').endswith('/hyperlink'):fail('unsupported_content')
    def props(self,c):
        for name in ('docProps/core.xml','docProps/app.xml','docProps/custom.xml'):
            if name in self.xml:
                for el in self.xml[name].iter():
                    if el.text and el.text.strip():c.add('文档属性 · '+tag(el.tag),el.text)
    def extras(self,c,fmt):
        # Generic unknown XML is shown as a coverage gap, never silently treated as protected.
        for name in self.names:
            if name.endswith('/') or name.startswith(('_rels/','docProps/')) or name=='[Content_Types].xml':continue
            if name.endswith('.rels'):continue
            low=name.lower()
            if any(part in low for part in ('/media/','/drawings/','/charts/','/diagrams/','/pivot','/printersettings/')):
                c.gap('图片、图表、绘图或透视对象未提取；请在原文件核对并手动补充其中内容。')
            elif fmt=='docx' and name.startswith('customXml/'):
                c.gap('文档自定义XML/数据绑定未完整解释；其可读取文字已列出，请回原件核对附属内容。')
            elif fmt=='docx' and not re.fullmatch(r'word/(document|header\d*|footer\d*|footnotes|endnotes|comments|styles|stylesWithEffects|settings|webSettings|fontTable|numbering)\.xml|word/theme/theme\d+\.xml',name):
                c.gap('文档包含尚未识别的附属部分；仅使用已显示文字，须回原件核对。')
            elif fmt=='xlsx' and not re.fullmatch(r'xl/(workbook|sharedStrings|styles|calcChain|metadata)\.xml|xl/theme/theme\d+\.xml|xl/worksheets/sheet\d+\.xml|xl/(?:comments\d+|comments/comment\d+)\.xml|xl/tables/table\d+\.xml',name):
                c.gap('工作簿包含尚未识别的附属部分；仅使用已显示文字，须回原件核对。')


def docx(data):
    p=Package(data);c=Content()
    if 'word/document.xml' not in p.xml or 'xl/workbook.xml' in p.xml:fail('file_type',415)
    count=0
    for name in sorted(p.xml,key=lambda n:(n!='word/document.xml',n)):
        if not re.fullmatch(r'word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml',name):continue
        root=p.xml[name]
        if not root.tag.startswith('{'+W+'}'):fail('unsupported_content')
        parents={child:parent for parent in root.iter() for child in parent}
        table_ids={el:i for i,el in enumerate(root.iter('{'+W+'}tbl'),1)}
        if any(tag(el.tag) in ('altChunk','object','control') for el in root.iter()):fail('unsupported_content')
        if any(tag(el.tag) in ('drawing','pict','sym') for el in root.iter()):c.gap('Word图片、符号或绘图未提取，含其中的文字；请在原件核对并手动补充。')
        role='正文' if name=='word/document.xml' else ('页眉' if '/header' in name else '页脚' if '/footer' in name else '脚注' if '/footnotes' in name else '尾注' if '/endnotes' in name else '批注')
        for index,para in enumerate(root.iter('{'+W+'}p'),1):
            pieces=[]
            for el in para.iter():
                local=tag(el.tag)
                if local in ('t','delText','instrText') and el.text: pieces.append(el.text)
                elif local=='tab':pieces.append('\t')
                elif local in ('br','cr'):pieces.append('\n')
            text=''.join(pieces)
            if text.strip():
                count+=1;location=f'{role} · 段{index}'
                ancestor=parents.get(para);cell=None;row=None;table=None
                while ancestor is not None:
                    if tag(ancestor.tag)=='tc' and cell is None:cell=ancestor
                    if tag(ancestor.tag)=='tr' and row is None:row=ancestor
                    if tag(ancestor.tag)=='tbl':table=ancestor;break
                    ancestor=parents.get(ancestor)
                if table is not None and row is not None and cell is not None:
                    location=f'{role} · 表{table_ids[table]}行{list(table.findall("{"+W+"}tr")).index(row)+1}列{list(row.findall("{"+W+"}tc")).index(cell)+1} · 段{index}'
                c.add(location,text)
        if any(tag(el.tag) in ('del','ins','fldSimple','fldChar') for el in root.iter()):c.warnings.append('Word修订和域按当前XML文字（含删除文字或域代码）列出，未执行域或接受修订。')
    for name,root in p.xml.items():
        if name.endswith('.rels'):
            for rel in root:
                if rel.attrib.get('TargetMode')=='External':c.add('超链接目标（未访问）',rel.attrib.get('Target',''))
    for name,root in p.xml.items():
        if name.startswith('customXml/') and not name.endswith('.rels'):
            text='\n'.join(el.text.strip() for el in root.iter() if el.text and el.text.strip())
            if text:c.add('自定义XML附属文字',text);c.gap('自定义XML仅列出文字，未重建其语义或数据绑定。')
        if re.fullmatch(r'word/comments.*\.xml',name):
            for el in root.iter():
                for key in ('author','initials'):
                    if el.attrib.get('{'+W+'}'+key):c.add('批注属性 · '+key,el.attrib['{'+W+'}'+key])
    p.props(c);p.extras(c,'docx')
    return c.result('docx',count)

def xlsx(data):
    p=Package(data);c=Content()
    if 'xl/workbook.xml' not in p.xml or 'word/document.xml' in p.xml:fail('file_type',415)
    book=p.xml['xl/workbook.xml']
    if book.tag!='{'+X+'}workbook':fail('unsupported_content')
    rels=p.xml.get('xl/_rels/workbook.xml.rels')
    if rels is None:fail('file_invalid')
    targets={r.attrib['Id']:r.attrib.get('Target','') for r in rels}
    shared=[]
    if 'xl/sharedStrings.xml' in p.xml:
        if p.xml['xl/sharedStrings.xml'].tag!='{'+X+'}sst':fail('unsupported_content')
        for si in p.xml['xl/sharedStrings.xml']:shared.append(''.join(el.text or '' for el in si.iter('{'+X+'}t')))
    sheets=list(book.iter('{'+X+'}sheet'))
    if len(sheets)>30:fail('document_limits',413)
    if not sheets:fail('file_invalid')
    seen=set();cells=0;has_formula=False
    for sn,sheet in enumerate(sheets,1):
        target=targets.get(sheet.attrib.get('{'+R+'}id',''),'')
        path=target.lstrip('/') if target.startswith('/') else 'xl/'+target
        path=str(PurePosixPath(path))
        if '..' in PurePosixPath(path).parts or path not in p.xml or path in seen:fail('file_invalid')
        seen.add(path);root=p.xml[path]
        if root.tag!='{'+X+'}worksheet':fail('unsupported_content')
        hidden=sheet.attrib.get('state','visible')
        c.add(f'工作表{sn} · 名称与状态',sheet.attrib.get('name','')+' / '+hidden)
        for cell in root.iter('{'+X+'}c'):
            cells+=1
            if cells>100000:fail('document_limits',413)
            address=cell.attrib.get('r','?')
            if not re.fullmatch(r'[A-Z]{1,3}[1-9][0-9]{0,6}',address):fail('file_invalid')
            formula=cell.find('{'+X+'}f');value=cell.find('{'+X+'}v');kind=cell.attrib.get('t','n')
            if formula is not None:
                has_formula=True
                if not formula.text or formula.attrib.get('t') in ('shared','array','dataTable'):fail('unsupported_content')
                text='公式（未执行）：='+formula.text
                if value is not None and value.text:text+='\n存储的旧缓存值（未核验）：'+value.text
            elif kind=='s':
                if value is None or value.text is None:fail('file_invalid')
                try:
                    idx=int(value.text)
                    if not 0<=idx<len(shared):fail('file_invalid')
                    text=shared[idx]
                except (ValueError,IndexError):fail('file_invalid')
            elif kind=='inlineStr':text=''.join(el.text or '' for el in cell.iter('{'+X+'}t'))
            elif kind in ('n','b','e','str','d'):text=value.text if value is not None else ''
            else:fail('unsupported_content')
            c.add(f'工作表{sn} · {address}',text or '')
    for el in book.iter('{'+X+'}definedName'):
        c.add('工作簿定义名称（未执行）',el.attrib.get('name','')+'\n'+(el.text or ''))
    for name,root in p.xml.items():
        if re.fullmatch(r'xl/tables/table\d+\.xml',name):
            for col in root.iter('{'+X+'}tableColumn'):
                c.add('工作簿表格列名',col.attrib.get('name',''))
    actual={name for name in p.xml if re.fullmatch(r'xl/worksheets/sheet\d+\.xml',name)}
    if actual-seen:c.gap('存在未关联工作表，未提取；请在原文件核对。')
    for name,root in p.xml.items():
        if re.fullmatch(r'xl/(?:comments\d+|comments/comment\d+)\.xml',name):
            authors=[el.text or '' for el in root.iter('{'+X+'}author')]
            for comment in root.iter('{'+X+'}comment'):
                text=''.join(el.text or '' for el in comment.iter('{'+X+'}t'))
                aid=int(comment.attrib.get('authorId','0'))
                if 0<=aid<len(authors):text=authors[aid]+'\n'+text
                c.add('工作簿批注 · '+comment.attrib.get('ref','?'),text)
        if name.endswith('.rels'):
            for rel in root:
                if rel.attrib.get('TargetMode')=='External':c.add('超链接目标（未访问）',rel.attrib.get('Target',''))
    c.warnings.append('数字和日期以文件存储值显示，未套用Excel日期/货币等显示样式；合并单元格只列出存有值的锚点，未重建合并布局。')
    if has_formula:c.warnings.append('公式仅显示字面代码与文件已有缓存，不执行、不更新、不访问外链；数字以存储值列出，日期/样式未重排。')
    c.warnings.append('已遍历全部工作表（含隐藏/非常隐藏）、存储的隐藏行列和单元格；按单元格坐标显示，非原格式导出。')
    p.props(c);p.extras(c,'xlsx');return c.result('xlsx',len(sheets))


def pdf(data):
    from pypdf import PdfReader
    import logging
    logging.getLogger('pypdf').disabled=True
    from pypdf import filters
    # Native image raster cap and Python text-stream decompression caps are separate.
    for cap in ('ZLIB_MAX_OUTPUT_LENGTH','LZW_MAX_OUTPUT_LENGTH','RUN_LENGTH_MAX_OUTPUT_LENGTH','JBIG2_MAX_OUTPUT_LENGTH'):
        setattr(filters,cap,15*1024*1024)
    original_decode=getattr(filters,'_pg_original_decode',filters.decode_stream_data);filters._pg_original_decode=original_decode;stream_total=[0]
    def bounded_decode(stream):
        try:output=original_decode(stream)
        except __import__('pypdf.errors',fromlist=['LimitReachedError']).LimitReachedError:fail('document_limits',413)
        stream_total[0]+=len(output)
        if len(output)>15*1024*1024 or stream_total[0]>40*1024*1024:fail('document_limits',413)
        return output
    filters.decode_stream_data=bounded_decode
    reader=PdfReader(io.BytesIO(data),strict=True)
    if reader.is_encrypted:fail('file_encrypted')
    if len(reader.pages)>40:fail('document_limits',413)
    if int(reader.trailer.get('/Size',0))>100000 or sum(len(v) for v in reader.xref.values())>100000:fail('document_limits',413)
    from pypdf.generic import IndirectObject,DictionaryObject,ArrayObject,StreamObject
    seen=set();budget=[0]
    def inspect(value,depth=0):
        if depth>100:fail('document_limits',413)
        if isinstance(value,IndirectObject):
            key=(value.idnum,value.generation)
            if key in seen:return
            seen.add(key);value=value.get_object()
        budget[0]+=1
        if budget[0]>200000:fail('document_limits',413)
        if isinstance(value,StreamObject):
            if value.get('/Subtype')=='/Image':
                width=int(value.get('/Width',0));height=int(value.get('/Height',0));bpc=int(value.get('/BitsPerComponent',8))
                if width<=0 or height<=0 or width*height>12000000 or bpc>16:fail('document_limits',413)
            value.get_data()
        if isinstance(value,DictionaryObject):
            if any(key in value for key in ('/JavaScript','/JS','/Launch','/RichMediaContent','/EmbeddedFiles','/EF','/AF','/AA','/OpenAction','/AcroForm')):fail('unsupported_content')
            if value.get('/S') in ('/Launch','/JavaScript','/SubmitForm','/ImportData','/GoToR','/Rendition','/RichMediaExecute'):fail('unsupported_content')
            for child in value.values():inspect(child,depth+1)
        elif isinstance(value,ArrayObject):
            for child in value:inspect(child,depth+1)
    inspect(reader.trailer)
    root=reader.trailer['/Root']
    if any(key in root for key in ('/AcroForm','/OpenAction','/AA','/Collection')):fail('unsupported_content')
    names=root.get('/Names',{})
    if hasattr(names,'get_object'):names=names.get_object()
    if any(key in names for key in ('/EmbeddedFiles','/JavaScript')):fail('unsupported_content')
    c=Content();texts=[];needs_ocr=[]
    if '/Outlines' in root:c.gap('PDF书签/目录结构未提取；只使用页面提取文字，请回原件核对。')
    for page in reader.pages:
        if page.get('/Annots'):fail('unsupported_content')
        if any(key in page for key in ('/AA','/AF')):fail('unsupported_content')
        box=page.mediabox
        if float(box.width)<=0 or float(box.height)<=0 or float(box.width)*float(box.height)*4>12000000:fail('document_limits',413)
        text=page.extract_text() or '';texts.append(text)
        # Full raster OCR detects both scans and text embedded in figures on otherwise textual pages.
        resources=page.get('/Resources',{})
        if hasattr(resources,'get_object'):resources=resources.get_object()
        xobj=resources.get('/XObject',{})
        if hasattr(xobj,'get_object'):xobj=xobj.get_object()
        needs_ocr.append(not text.strip() or bool(xobj))
    binary=ROOT/'backend/bin/pdf-vision';ocr=None
    if binary.exists() and os.access(binary,os.X_OK):
        run=subprocess.run([str(binary)],input=data,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=35)
        if run.returncode==0:
            try:
                ocr=json.loads(run.stdout)
                if len(ocr)!=len(texts):ocr=None
            except Exception:ocr=None
    if ocr is None and any(needs_ocr):fail('ocr_unavailable')
    if ocr is None:c.gap('本机OCR不可用；仅提取PDF文字层，未核对页面视觉内容。')
    else:c.warnings.append('已对全部PDF页面运行本机Vision OCR，文字层与OCR分别列出可能重复；OCR可能误识别或漏识别，请对照原件逐页审阅。')
    for i,text in enumerate(texts):
        c.add(f'第{i+1}页 · PDF文字',text)
        recognized=ocr[i].get('text','') if ocr else ''
        c.add(f'第{i+1}页 · 本机OCR',recognized)
        if not text.strip() and not recognized.strip():c.gap('至少一页未识别到文字，可能为空白页或不可读图像；请回原件核对并手动补充。')
    # Metadata is reviewable text as well, never hidden outbound request metadata.
    if reader.metadata:
        for key,value in reader.metadata.items():
            if isinstance(value,str) and value.strip():c.add('PDF属性 · '+str(key).lstrip('/'),value)
    return c.result('pdf',len(texts),ocr is not None)

def extract_local(data,fmt):
    if len(data)>MAX_FILE:fail('file_too_large',413)
    try:return {'pdf':pdf,'docx':docx,'xlsx':xlsx}[fmt](data)
    except FileError:raise
    except Exception:fail('file_invalid')
