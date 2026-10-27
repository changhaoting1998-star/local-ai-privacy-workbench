import React, { Component, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { api, ApiError, errorMessage, extractFile, setCsrf } from './api';
import type { Auth, ExtractedFile, Finding, Health, ManualSpan, Message, Preview, Sent, Session } from './api';
import { consumeSsoResult, feishuAvailability, ssoMessage, ssoRequestError } from './sso';
import type { FeishuAvailability } from './sso';
import './styles.css';
import './collaboration.css';

function Icon({ name, size = 20 }: { name: 'shield' | 'arrow' | 'file' | 'plus' | 'check' | 'lock' | 'logout' | 'clock' | 'close' | 'eye' | 'alert' | 'upload' | 'document'; size?: number }) {
  const paths: Record<string, React.ReactNode> = {
    shield: <><path d="M12 3 4 6v6c0 4 4 7 8 9 4-2 8-5 8-9V6l-8-3Z"/><path d="m8.5 12 2.5 2.5 4.5-5"/></>,
    arrow: <><path d="M5 12h14m-5-5 5 5-5 5"/></>, file: <><path d="M14 3H6v18h12V7l-4-4Z"/><path d="M14 3v5h4M9 12h6m-6 4h6"/></>,
    plus: <path d="M12 5v14M5 12h14"/>, check: <path d="m5 12 4 4L19 6"/>, lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3"/></>,
    logout: <><path d="M9 4H4v16h5m6-12 4 4-4 4M9 12h10"/></>, clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>, close: <path d="m6 6 12 12M6 18 18 6"/>,
    upload: <><path d="M12 16V3m-5 5 5-5 5 5M4 16v5h16v-5"/></>, document: <><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8m-8 4h8m-8 4h5"/></>,
    eye: <><path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></>, alert: <><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5m0 3h.01"/></>,
  };
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]}</svg>;
}
function Brand() { return <div className="brand"><span className="brand-symbol"><Icon name="shield" size={25}/></span><div><strong>隐私网关</strong><span>PRIVACY GATEWAY</span></div></div>; }
function Notice({ children, kind = 'info' }: { children: React.ReactNode; kind?: 'info' | 'error' | 'warning' | 'success' }) {
  return <div className={`notice ${kind}`} role={kind === 'error' ? 'alert' : 'status'}><Icon name={kind === 'error' || kind === 'warning' ? 'alert' : 'shield'}/><div>{children}</div></div>;
}
class ErrorBoundary extends Component<{ children: React.ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  render() { return this.state.failed ? <main className="fatal"><Brand/><h1>页面遇到异常</h1><p>请刷新重新登录。浏览器中的未发送原文将被清除。</p><button onClick={() => location.reload()}>重新加载</button></main> : this.props.children; }
}
const labels: Record<string, string> = { PERSON: '姓名', PHONE_NUMBER: '电话号码', EMAIL_ADDRESS: '电子邮箱', CN_ID: '身份证号', CN_ID_CARD: '身份证号', ID_CARD: '身份证号', CREDIT_CARD: '银行卡号', BANK_ACCOUNT: '银行账户', IP_ADDRESS: 'IP 地址', MANUAL: '手动范围', CUSTOM: '手动范围', SECRET: '密钥/密码', PASSWORD: '密码', API_KEY: 'API密钥' };
const label = (type: string) => labels[type] || type;
const sample = '以下内容完全为合成示例，请帮我整理一段联系提醒：\n客户张小明的手机号是13800138000，邮箱是demo@example.com。\n项目代号为“青禾计划”，请在回复中保留联系人的对应关系。';
function App() {
  const [ssoResult] = useState(consumeSsoResult);
  const [ssoError, setSsoError] = useState(ssoResult.error);
  const [health, setHealth] = useState<Health | null>(null);
  const [auth, setAuth] = useState<Auth | null>(null);
  const [boot, setBoot] = useState(true);
  const [error, setError] = useState('');
  const bootup = useCallback(async () => {
    setBoot(true); setError('');
    try {
      const h = await api<Health>('/health'); setHealth(h);
      try { const a = await api<Auth>('/me'); setCsrf(a.csrf_token); setAuth(a); }
      catch (e) {
        if (!(e instanceof ApiError && e.status === 401)) throw e;
        if (ssoResult.success) setSsoError('飞书认证未能建立工作台会话。请重新发起登录。');
      }
    } catch (e) { setError(errorMessage(e)); }
    finally { setBoot(false); }
  }, [ssoResult.success]);
  useEffect(() => { void bootup(); }, [bootup]);
  const signedIn = (a: Auth) => { setCsrf(a.csrf_token); setAuth(a); setSsoError(''); setHealth(h => h ? { ...h, setup_required: false } : h); };
  const signedOut = () => { setCsrf(''); setAuth(null); };
  if (boot) return <div className="boot"><Brand/><p role="status">正在连接工作台服务…</p></div>;
  if (!health) return <main className="fatal"><Brand/><h1>工作台服务尚未就绪</h1><Notice kind="error">{error}</Notice><button onClick={() => void bootup()}>重新连接</button><p>连接恢复前，无法识别、发送或还原内容。</p></main>;
  if (!auth) return <Login health={health} ssoError={ssoError && ssoResult.reason === 'origin' ? ssoMessage('origin', health) : ssoError} onSuccess={signedIn}/>;
  return <Workspace auth={auth} health={health} authNotice={ssoError} onSignedOut={signedOut}/>;
}
function Login({ health, ssoError, onSuccess }: { health: Health; ssoError: string; onSuccess: (auth: Auth) => void }) {
  const lan = health.deployment_mode === 'lan_https';
  const setup = health.deployment_mode === 'loopback' && health.setup_available && health.setup_required;
  const [username, setUsername] = useState(''); const [password, setPassword] = useState(''); const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const [feishu, setFeishu] = useState<FeishuAvailability | null>(null);
  const [ssoStatus, setSsoStatus] = useState('正在检查飞书登录配置…');
  const [checkingSso, setCheckingSso] = useState(true); const [openingSso, setOpeningSso] = useState(false);
  const loginLock = useRef(false);
  const checkSso = useCallback(async () => {
    setCheckingSso(true);
    try { const value = await feishuAvailability(); setFeishu(value); setSsoStatus(value.available ? '将前往飞书官方认证页面完成身份授权，再返回当前工作台。' : ssoMessage(value.reason_code, health)); }
    catch (e) { setFeishu(null); setSsoStatus(ssoRequestError(e, health)); }
    finally { setCheckingSso(false); }
  }, [health]);
  useEffect(() => { void checkSso(); }, [checkSso]);
  // A back navigation from the provider must not leave the local form disabled.
  useEffect(() => { const resume = () => { loginLock.current = false; setOpeningSso(false); void checkSso(); }; window.addEventListener('pageshow', resume); return () => window.removeEventListener('pageshow', resume); }, [checkSso]);
  async function startFeishu() {
    if (loginLock.current || busy || !feishu?.available) return;
    loginLock.current = true; setOpeningSso(true); setError('');
    let navigating = false;
    try {
      const value = await feishuAvailability(); setFeishu(value);
      if (!value.available) { setSsoStatus(ssoMessage(value.reason_code, health)); return; }
      // Fixed same-origin endpoint; callback and authorization URLs belong to the backend.
      location.assign('/api/auth/feishu/start'); navigating = true;
    } catch (e) { setSsoStatus(ssoRequestError(e, health)); setFeishu(null); }
    finally { if (!navigating) { loginLock.current = false; setOpeningSso(false); } }
  }
  async function submit(e: React.FormEvent) {
    e.preventDefault(); if (loginLock.current) return; setError('');
    if (setup && password !== repeat) { setError('两次输入的密码不一致。'); return; }
    loginLock.current = true; setBusy(true);
    try { const a = await api<Auth>(setup ? '/setup' : '/login', { username, password }); setPassword(''); setRepeat(''); onSuccess(a); }
    catch (e) { setError(errorMessage(e)); setPassword(''); setRepeat(''); }
    finally { loginLock.current = false; setBusy(false); }
  }
  return <div className="collab-login"><a className="skip-link" href="#login-main">跳到登录</a>
    <header className="collab-header"><div className="product-identity"><Brand/><span className="environment-tag">{lan ? '局域网试用版' : '个人本机版'}</span></div><span className="header-caption">隐私协作工作台</span></header>
    <main id="login-main" className="collab-login-main" tabIndex={-1}>
      <section className="auth-card" aria-labelledby="login-heading">
        <div className="auth-heading"><span className="auth-kicker">欢迎使用隐私网关</span><h1 id="login-heading">登录，开始安全协作</h1><p>先核对隐私，再由你确认发送。</p></div>
        <Notice kind="warning"><strong>当前为本地测试模式</strong>未连接外部大模型，请仅使用合成数据验证。</Notice>
        {ssoError && <Notice kind="error">{ssoError}</Notice>}
        <div className="sso-login" aria-labelledby="feishu-heading"><h2 id="feishu-heading">使用飞书身份继续</h2><button className="primary full sso-primary" type="button" disabled={!feishu?.available || checkingSso || busy || openingSso} onClick={() => void startFeishu()} aria-describedby="feishu-status">{openingSso ? '正在前往飞书…' : '使用飞书登录'}<Icon name="arrow" size={18}/></button><p id="feishu-status" className="field-hint" role="status">{checkingSso ? '正在检查飞书登录配置…' : ssoStatus}</p>{!checkingSso && !feishu?.available && <button className="text-button" type="button" disabled={busy || openingSso} onClick={() => void checkSso()}>重新检查配置</button>}</div>
        <details className="password-choice"><summary>使用密码账户<span>备选登录方式</span></summary><form className="password-form" onSubmit={submit}><h2>{setup ? '设置首个本地账户' : '密码账户登录'}</h2><p className="field-hint">{lan ? '局域网入口不开放注册，请使用管理员已预置的账户。' : setup ? '尚无本地账户，可在此独立创建；使用飞书登录无需先创建本地账户。' : '使用本机已创建的账户继续，无通用默认密码。'}</p>
          <label htmlFor="username">用户名</label><input id="username" name="username" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} required minLength={3} maxLength={40} pattern="[A-Za-z0-9_.-]{3,40}" disabled={busy || openingSso} aria-describedby="username-help"/><p id="username-help" className="field-hint">3–40位字母、数字或 _ . -</p>
          <label htmlFor="password">{setup ? '设置密码（至少12字符）' : '密码'}</label><input id="password" name="password" type="password" autoComplete={setup ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} required minLength={setup ? 12 : undefined} disabled={busy || openingSso}/>
          {setup && <><label htmlFor="repeat">再次输入密码</label><input id="repeat" type="password" autoComplete="new-password" value={repeat} onChange={e => setRepeat(e.target.value)} required minLength={12} disabled={busy || openingSso}/></>}
          {error && <Notice kind="error">{error}</Notice>}
          <button className="secondary full" type="submit" disabled={busy || openingSso}>{busy ? '正在验证…' : setup ? '创建账户并进入' : '登录并进入'}<Icon name="arrow" size={18}/></button>
        </form></details>
        <p className="auth-account-note">飞书与密码账户相互独立，不按姓名自动关联。</p>
      </section>
      <p className="auth-data-boundary"><Icon name="lock" size={16}/><span>{lan ? '原文经局域网 HTTPS 送往 Mac mini 处理。' : '文件与原文仅在本机处理。'}飞书仅用于身份认证，不接收原文与脱敏占位符。</span></p>
      <p className="auth-footer">支持 PDF / DOCX / XLSX / TXT · 规则可能漏检，发送前须人工核对</p>
    </main>
  </div>;
}
function Workspace({ auth, health, authNotice, onSignedOut }: { auth: Auth; health: Health; authNotice: string; onSignedOut: () => void }) {
  const lan = health.deployment_mode === 'lan_https';
  const [sessions, setSessions] = useState<Session[]>([]); const [session, setSession] = useState<Session | null>(null);
  const [messages, setMessages] = useState<Message[]>([]); const [text, setText] = useState('');
  const [manual, setManual] = useState<ManualSpan[]>([]); const [selection, setSelection] = useState({ start: 0, end: 0 });
  const [manualType, setManualType] = useState('PERSON'); const [preview, setPreview] = useState<Preview | null>(null);
  const [outbound, setOutbound] = useState(false); const [confirmed, setConfirmed] = useState(false);
  const [sent, setSent] = useState<Sent | null>(null); const [restoreAuth, setRestoreAuth] = useState(false); const [restored, setRestored] = useState('');
  const [busy, setBusy] = useState(''); const [error, setError] = useState(''); const [info, setInfo] = useState(''); const [now, setNow] = useState(Date.now());
  const [historyOpen, setHistoryOpen] = useState(false);
  const [inputOpen, setInputOpen] = useState(false);
  const [sourceFile, setSourceFile] = useState<{ name: string; result: ExtractedFile } | null>(null);
  const [fileReviewed, setFileReviewed] = useState(false);
  const [fileError, setFileError] = useState(''); const [pendingName, setPendingName] = useState('');
  const upload = useRef<{ id: number; controller: AbortController } | null>(null);
  const uploadSequence = useRef(0); const picker = useRef<HTMLInputElement>(null);
  const uploading = busy === '解析文件';
  const fileNeedsReview = !!sourceFile && !fileReviewed;
  useEffect(() => () => { upload.current?.controller.abort(); }, []);
  const revision = useRef(0); const actionLock = useRef(false); const idempotency = useRef(''); const textarea = useRef<HTMLTextAreaElement>(null); const focusHeading = useRef<HTMLHeadingElement>(null);
  const expired = !!preview && preview.expires_at * 1000 <= now;
  const phase = sent ? 3 : outbound ? 2 : preview ? 1 : 0;
  const clearDerived = useCallback(() => { revision.current++; setPreview(null); setOutbound(false); setConfirmed(false); setInfo(''); setSent(null); setRestored(''); setRestoreAuth(false); idempotency.current = ''; }, []);
  const refreshList = useCallback(async () => { const r = await api<{ sessions: Session[] }>('/sessions'); setSessions(r.sessions); }, []);
  useEffect(() => { void refreshList().catch(e => setError(errorMessage(e))); }, [refreshList]);
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, []);
  useEffect(() => { if (phase > 0) requestAnimationFrame(() => focusHeading.current?.focus()); }, [phase]);
  useEffect(() => { if (expired) { setConfirmed(false); setInfo('预览已过期，请重新生成识别预览后再发送。'); } }, [expired]);
  function handleError(e: unknown) {
    setError(errorMessage(e));
    if (e instanceof ApiError && e.status === 401) onSignedOut();
    if (e instanceof ApiError && e.status === 409) clearDerived();
  }
  async function run(name: string, action: () => Promise<void>) {
    if (actionLock.current) return; actionLock.current = true; setBusy(name); setError(''); setInfo('');
    try { await action(); } catch (e) { handleError(e); } finally { actionLock.current = false; setBusy(''); }
  }
  function cancelUpload(announce = true) {
    if (!upload.current) return;
    upload.current.controller.abort(); upload.current = null; uploadSequence.current++;
    actionLock.current = false; setBusy(''); setPendingName('');
    if (announce) setInfo('已取消本次文件导入，原草稿保持不变。');
  }
  function edit(value: string) { cancelUpload(false); setFileReviewed(false); setFileError(''); if (!value) setSourceFile(null); clearDerived(); setText(value); setManual([]); setSelection({ start: 0, end: 0 }); setInfo('修改已保留，请重新检查隐私。'); setError(''); }
  async function selectSession(item: Session) {
    await run('打开会话', async () => {
      clearDerived(); setSourceFile(null); setFileReviewed(false); setFileError(''); setText(''); setManual([]); setSelection({ start: 0, end: 0 });
      const r = await api<{ messages: Message[] }>(`/sessions/${item.id}`); setSession(item); setMessages(r.messages); setHistoryOpen(true);
    });
  }
  function newDraft() { if (busy) return; setSourceFile(null); setFileReviewed(false); setFileError(''); clearDerived(); setText(''); setManual([]); setMessages([]); setSession(null); setError(''); setInfo('已开始新的本地草稿。'); setHistoryOpen(false); textarea.current?.focus(); }
  async function createPreview() {
    if (fileNeedsReview || upload.current) { setError('请先核对提取内容并确认已完成文件审阅。'); return; }
    if (!text.trim()) { setError('请先输入文字或导入文件。'); textarea.current?.focus(); return; }
    if ([...text].length > 20000) { setError('内容超过20,000字符，请缩短后再识别。'); return; }
    await run('生成识别预览', async () => {
      clearDerived(); const currentRevision = revision.current;
      let active = session;
      if (!active) { active = await api<Session>('/sessions', { title: '隐私协作会话' }); setSession(active); await refreshList(); }
      const result = await api<Preview>(`/sessions/${active.id}/preview`, { text, manual_spans: manual, model: 'local-mock' });
      if (currentRevision !== revision.current) { setInfo('内容已变化，本次响应已作废，请重新识别。'); return; }
      setPreview(result); idempotency.current = crypto.randomUUID(); setNow(Date.now());
      setInfo(result.blocked ? '检测到强制拦截项，发送已关闭。请删除密钥或密码后重新识别。' : '请核对高亮。确认无遗漏后进入最后一步。');
      requestAnimationFrame(() => focusHeading.current?.focus());
    });
  }
  function addManual() {
    if (selection.start === selection.end) { setError('请先在原文输入框选中要脱敏的文字，可使用 Shift + 方向键。'); textarea.current?.focus(); return; }
    const start = [...text.slice(0, selection.start)].length; const end = [...text.slice(0, selection.end)].length;
    if (manual.some(s => s.start === start && s.end === end)) { setError('这个范围已添加。'); return; }
    clearDerived(); setManual(s => [...s, { start, end, entity_type: manualType }]); setInfo('已补充手动范围，请重新生成预览使其生效。'); setError('');
  }
  async function importFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]; e.target.value = ''; if (!file) return;
    if (actionLock.current && !upload.current) return;
    cancelUpload(false); clearDerived(); setFileReviewed(false); setError(''); setFileError(''); setInfo('');
    const extension = file.name.split('.').pop()?.toLowerCase();
    if (extension === 'doc' || extension === 'xls') { setFileError('暂不支持旧版 .doc / .xls，请先另存为 .docx / .xlsx。原草稿保持不变。'); return; }
    if (!['txt', 'pdf', 'docx', 'xlsx'].includes(extension || '') || (lan && extension !== 'txt')) { setFileError(lan ? '文件上传仅支持当前 Mac 个人版；此入口仅保留 TXT。' : '请选择 PDF、DOCX、XLSX 或 UTF-8 TXT。原草稿保持不变。'); return; }
    if (file.size > (extension === 'txt' ? 100000 : 10485760)) { setFileError(extension === 'txt' ? 'TXT 文件不能超过100KB。原草稿保持不变。' : '文件不能超过10 MiB。原草稿保持不变。'); return; }
    const controller = new AbortController(); const id = ++uploadSequence.current;
    upload.current = { id, controller }; actionLock.current = true; setBusy('解析文件'); setPendingName(file.name);
    const currentRevision = revision.current;
    const timeout = window.setTimeout(() => controller.abort(), 55000);
    try {
      let result: ExtractedFile | null = null; let content: string;
      if (extension === 'txt') {
        const buffer = await file.arrayBuffer(); const bytes = new Uint8Array(buffer);
        if ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff) || bytes.includes(0)) throw new Error('TXT 必须为 UTF-8 编码，不能包含 UTF-16 或空字符。');
        try { content = new TextDecoder('utf-8', { fatal: true }).decode(buffer); } catch { throw new Error('TXT 必须为有效 UTF-8 编码，请转换编码后重试。'); }
        if ([...content].length > 20000) throw new Error('TXT 超过20,000字符，未截断导入。请缩短后重试。');
      } else { result = await extractFile(file, controller.signal); content = result.text; }
      if (upload.current?.id !== id || currentRevision !== revision.current || controller.signal.aborted) return;
      setText(content); setManual([]); setSelection({ start: 0, end: 0 });
      setSourceFile(result ? { name: file.name, result } : null); setFileReviewed(false);
      setInfo(result ? '文件已读取。请核对文字，补充遗漏后检查隐私。' : 'TXT已读取。可修改文字后检查隐私。');
      textarea.current?.focus();
    } catch (e) {
      if (upload.current?.id !== id || currentRevision !== revision.current) return;
      if (e instanceof ApiError && e.status === 401) { onSignedOut(); return; }
      setFileError(controller.signal.aborted ? '文件解析等待超时，未导入。原草稿保持不变，请拆分文件后重试。' : e instanceof ApiError ? e.message : e instanceof Error && extension === 'txt' ? `${e.message} 原草稿保持不变。` : '无法连接本机文件解析服务，未导入。原草稿保持不变。');
    } finally {
      clearTimeout(timeout);
      if (upload.current?.id === id) { upload.current = null; actionLock.current = false; setBusy(''); setPendingName(''); }
    }
  }
  async function send() {
    if (!preview || preview.blocked || expired || !confirmed || fileNeedsReview || upload.current) return;
    await run('发送脱敏内容', async () => {
      const r = await api<Sent>(`/sessions/${session!.id}/send`, { preview_id: preview.preview_id, confirmed: true, confirmation_phrase: preview.confirmation_phrase, idempotency_key: idempotency.current });
      setSent(r); setConfirmed(false); setRestored(''); setRestoreAuth(false); setInfo('已将确认后的脱敏内容交给本地测试函数。未调用外部大模型。');
      const history = await api<{ messages: Message[] }>(`/sessions/${session!.id}`); setMessages(history.messages);
    });
  }
  async function restore() {
    if (!sent || !restoreAuth) return;
    await run('授权还原', async () => { const r = await api<{ restored_text: string; restored_count: number }>(`/sessions/${session!.id}/restore`, { message_id: sent.message_id, text: sent.assistant_text, authorized: true }); setRestored(r.restored_text); setRestoreAuth(false); setInfo(`仅在本页还原${r.restored_count}个占位符；不会写回历史。`); });
  }
  async function removeSession() {
    if (!session || !window.confirm('删除当前会话的脱敏历史、预览和还原映射？此操作无法撤销。')) return;
    await run('删除会话', async () => { await api(`/sessions/${session.id}`, {}, 'DELETE'); clearDerived(); setSourceFile(null); setFileReviewed(false); setFileError(''); setSession(null); setMessages([]); setText(''); setManual([]); await refreshList(); setInfo('会话与对应还原映射已删除。'); });
  }
  const sourceEditor = <><label htmlFor="source-text" className="source-label">{sourceFile ? '核对提取文字，可直接修改补充' : '原文输入'}</label><textarea ref={textarea} id="source-text" value={text} disabled={!!busy && !uploading} onChange={e => edit(e.target.value)} onSelect={e => setSelection({ start: e.currentTarget.selectionStart, end: e.currentTarget.selectionEnd })} placeholder="在这里粘贴或输入需要协作的文字…" spellCheck={false} aria-describedby="editor-help"/><div className="editor-foot"><span id="editor-help">仅本页暂存 · 修改后需重新检查</span><span className={[...text].length > 20000 ? 'danger-text' : ''}>{[...text].length.toLocaleString()} / 20,000</span></div></>;
  const advancedProtection = <details className="simple-disclosure advanced-protection"><summary>高级保护选项 · 手动补充 / 修改原文{manual.length > 0 ? `（${manual.length}处）` : ''}</summary><p>选中下方原文中的姓名、地址或业务秘密，再添加保护范围。修改后会返回第1步重新检查。</p>{phase === 1 && sourceEditor}<div className="manual-tools"><div className="manual-controls"><label className="sr-only" htmlFor="manual-type">手动范围信息类型</label><select id="manual-type" value={manualType} onChange={e => setManualType(e.target.value)} disabled={!!busy}><option value="PERSON">姓名</option><option value="MANUAL">其他敏感信息</option></select><button className="secondary" onClick={addManual} disabled={!!busy || !text}>添加选中范围</button></div></div>{manual.length > 0 && <ul className="manual-list">{manual.map((s, i) => <li key={`${s.start}-${s.end}`}><span>{label(s.entity_type)} · 字符{s.start + 1}–{s.end}</span><button className="icon-button" aria-label={`移除第${i + 1}个手动范围`} disabled={!!busy} onClick={() => { clearDerived(); setManual(a => a.filter((_, j) => i !== j)); }}><Icon name="close" size={15}/></button></li>)}</ul>}</details>;
  return <div className="simple-app"><a className="skip-link" href="#main">跳到主要内容</a>
    <header className="simple-header collab-header"><div className="product-identity"><Brand/><span className="environment-tag">{lan ? '局域网试用版' : '个人本机版'}</span></div><div className="simple-account"><span className="account-avatar" aria-hidden="true">{auth.user.username.slice(0, 1).toUpperCase()}</span><span className="account-name" title={auth.user.username}>{auth.user.username}</span><button className="icon-button" aria-label="退出登录并清空本页原文" title="退出登录" disabled={!!busy} onClick={() => void run('退出登录', async () => { await api('/logout', {}); onSignedOut(); })}><Icon name="logout"/></button></div></header>
    <main id="main" className="simple-main" tabIndex={-1}>
      <div className="simple-title"><div><span className="eyebrow">本次处理</span><h1>先保护隐私，再开始对话</h1></div><button className="text-button" onClick={() => { setInputOpen(false); newDraft(); }} disabled={!!busy}><Icon name="plus" size={17}/>新建</button></div>
      <ol className="simple-steps" aria-label="三步使用流程">{['选择内容', '核对隐私', '确认发送'].map((name, i) => <li key={name} className={phase > i ? 'done' : phase === i ? 'active' : ''} aria-current={phase === i ? 'step' : undefined}><span>{phase > i ? <Icon name="check" size={16}/> : i + 1}</span><div><strong>{name}</strong><small className="step-state">{phase > i ? '已完成' : phase === i ? '进行中' : '待开始'}</small></div></li>)}</ol>
      <div className="simple-mode"><Icon name="lock" size={16}/><span>本地测试模型 · 未连接外部大模型，请仅使用合成数据</span></div>
      {authNotice && <Notice kind="error">{authNotice}</Notice>}{error && <Notice kind="error">{error}</Notice>}
      {info && <p className="status-line" role="status">{info}</p>}{phase > 0 && sourceFile && !sourceFile.result.coverage.complete && <Notice kind="warning"><strong>仅使用已提取文字</strong><span>此文件有未读取的图片、图表等内容，不受本次保护，也不会发送原文件。</span>{sourceFile.result.warnings.map((warning, i) => <span key={i}>{warning}</span>)}</Notice>}
      {phase === 0 && <section className="panel editor-panel" aria-labelledby="input-heading"><div className="panel-heading"><div><h2 id="input-heading">先放入需要协作的内容</h2></div></div>
        <div className="simple-entry"><button className={`entry-button ${!text && !inputOpen ? 'primary' : 'secondary'}`} onClick={() => picker.current?.click()} disabled={!!busy && !uploading} aria-describedby="file-help"><Icon name="upload" size={23}/><span>{text ? '更换文件' : '选择文件'}<small>PDF / Word / Excel / TXT</small></span></button><button className="entry-button secondary" onClick={() => { setInputOpen(true); requestAnimationFrame(() => textarea.current?.focus()); }} disabled={!!busy && !uploading}><Icon name="file" size={23}/><span>粘贴文字<small>也可以直接输入</small></span></button></div>
        <input className="sr-only" ref={picker} type="file" tabIndex={-1} accept={lan ? '.txt,text/plain' : '.pdf,.docx,.xlsx,.txt,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,text/plain'} aria-label="导入PDF、DOCX、XLSX或UTF-8 TXT文件" aria-describedby={fileError ? 'file-help file-error' : 'file-help'} onChange={e => void importFile(e)} disabled={!!busy && !uploading}/>
        <p className="simple-file-hint" id="file-help">{lan ? '此入口仅保留 UTF-8 TXT。' : '支持 .pdf / .docx / .xlsx / .txt · 只处理提取文字，不改写原文件'}</p>
        {uploading && <div className="file-progress" role="status"><div><strong>正在本机读取文件…</strong><span>{pendingName}</span><small>原草稿保留，可取消或继续编辑。</small></div><button className="secondary" onClick={() => cancelUpload()}><Icon name="close" size={17}/>取消导入</button></div>}
        {fileError && <div className="file-inline-error" id="file-error" role="alert"><Icon name="alert" size={18}/><div><p>{fileError}</p><p>可重新选择文件，或点击“粘贴文字”人工整理。</p></div></div>}
        {sourceFile && <div className={`file-coverage ${sourceFile.result.coverage.complete ? '' : 'partial'}`} aria-labelledby="file-coverage-heading"><div className="file-coverage-title"><Icon name="document" size={19}/><strong id="file-coverage-heading">{sourceFile.result.coverage.complete ? '文字提取完成' : '存在未提取内容'} · {sourceFile.result.format.toUpperCase()}</strong><span>{sourceFile.name}</span></div><p>{sourceFile.result.coverage.summary}</p>{!sourceFile.result.coverage.complete && <p className="file-warning"><strong>图片、图表等未读取部分未包含在草稿中，也未受本次保护。</strong>请对照原件补充必要信息；仅下方文字会继续处理，原文件不会发送。</p>}{sourceFile.result.warnings.map((warning, i) => <p className="file-warning" key={i}>{warning}</p>)}</div>}
        {(inputOpen || !!text || !!sourceFile) && <div className="simple-source">{sourceEditor}<div className="simple-editor-tools"><button className="text-button" onClick={() => edit('')} disabled={!!busy || !text}>清空文字</button></div>{sourceFile && <label className="file-review"><input type="checkbox" checked={fileReviewed} onChange={e => { clearDerived(); setFileReviewed(e.target.checked); }} disabled={!!busy}/><span>{sourceFile.result.coverage.complete ? '我已对照文件核对文字并补充遗漏。' : '我确认仅使用已提取内容，已核对并补充必要文字；未提取部分不受保护，原文件不会发送。'}</span></label>}{advancedProtection}<div className="panel-action"><span>检查只在本机进行，不会发送给模型</span><button className="primary" onClick={() => void createPreview()} disabled={!!busy || !text.trim() || fileNeedsReview}>{busy === '生成识别预览' ? '正在检查…' : '检查隐私'}<Icon name="arrow" size={18}/></button></div></div>}
        <details className="simple-disclosure file-limits"><summary>格式限制与使用示例</summary><p>PDF / DOCX / XLSX最多10 MiB；UTF-8 TXT最多100KB。含定位文字最多20,000字符，超限不截断；成功读取会替换当前草稿。旧 .doc / .xls 请先另存为新格式。</p><p>PDF扫描使用本机OCR，可能误识别；Word读取正文、表格及受支持的附属文字；Excel包含隐藏工作表、单元格和公式原文。请保留页、段落、工作表与单元格位置供核对。</p><p>不执行公式、宏、HTML或外链。未读取的图片、图表会明确提醒；宏、活动内容、外部数据连接、损坏、加密和不支持的结构会拒绝导入。</p><button className="text-button" onClick={() => { setInputOpen(true); edit(sample); }} disabled={!!busy}>试试合成示例<Icon name="arrow" size={16}/></button></details>
      </section>}
      {phase === 1 && preview && <section className="panel review-panel" aria-labelledby="review-heading"><div className="panel-heading"><div><h2 id="review-heading" ref={focusHeading} tabIndex={-1}>核对这些隐私信息</h2></div><span className={`badge ${preview.blocked ? 'red' : 'blue'}`}>{preview.blocked ? '已拦截' : `${preview.findings.length}处待保护`}</span></div><p className="panel-description">高亮文字将在发送时换成占位符。请检查是否还有遗漏，再进入最后确认。</p><div className="highlight-preview" aria-label="原文识别高亮"><Highlight text={text} findings={preview.findings}/></div>
        {preview.findings.length > 0 && <div className="finding-legend">{[...new Set(preview.findings.map(f => f.entity_type))].map(type => <span key={type}><i/>{label(type)} · {preview.findings.filter(f => f.entity_type === type).length}</span>)}</div>}
        <Notice kind="warning">{preview.findings.length === 0 ? '未识别到隐私不代表安全。' : ''}姓名、地址和业务秘密可能漏检，可在下方“高级保护选项”中手动补充。</Notice>
        {preview.blocked && <Notice kind="error"><strong>检测到密钥或密码，禁止发送。</strong>{preview.block_reasons.map((r, i) => <span key={i}>{r}</span>)}<span>请返回内容删除相关文字后重新检查，手动替换不能绕过拦截。</span></Notice>}
        {expired && <Notice kind="error">预览已过期。请重新检查隐私，再次核对后发送。</Notice>}
        {advancedProtection}
        <div className="panel-action"><button className="text-button" disabled={!!busy} onClick={() => { clearDerived(); setInputOpen(true); setInfo('内容已保留，可修改后重新检查。'); }}>返回修改</button>{expired ? <button className="primary" disabled={!!busy} onClick={() => void createPreview()}>重新检查隐私<Icon name="arrow" size={18}/></button> : <button className="primary" onClick={() => { setOutbound(true); setConfirmed(false); setInfo(''); }} disabled={!!busy || preview.blocked}>核对好了，继续<Icon name="arrow" size={18}/></button>}</div>
      </section>}
      {phase === 2 && preview && <section className="panel outbound-panel" aria-labelledby="outbound-heading"><div className="panel-heading"><div><h2 id="outbound-heading" ref={focusHeading} tabIndex={-1}>确认这次发送的内容</h2></div><span className={`badge ${expired ? 'red' : 'blue'}`}>{expired ? '预览已过期' : '最后一步'}</span></div><p className="panel-description">以下是完整发送内容，包含本会话已有的脱敏上下文。确认后只交给本机测试模型。</p><div className="outbound-messages">{preview.outbound_messages.map((m, i) => <div key={i} className="outbound-message"><span className="message-role">{m.role === 'user' ? '用户内容' : m.role === 'assistant' ? '历史测试回答' : m.role}</span><pre>{m.content}</pre></div>)}</div><p className="simple-preview-time">预览有效至 {new Date(preview.expires_at * 1000).toLocaleTimeString('zh-CN')} · local-mock</p>
        {expired && <Notice kind="error">预览已过期，发送已关闭。请重新检查隐私。</Notice>}
        <label className="consent"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} disabled={!!busy || expired || preview.blocked}/><span>我已检查全部发送内容，确认使用以上脱敏版本。</span></label><div className="panel-action"><button className="text-button" disabled={!!busy} onClick={() => { setOutbound(false); setConfirmed(false); setInfo(''); }}>返回核对</button>{expired ? <button className="primary" disabled={!!busy} onClick={() => void createPreview()}>重新检查隐私<Icon name="arrow" size={18}/></button> : <button className="primary" onClick={() => void send()} disabled={!!busy || !confirmed || preview.blocked || fileNeedsReview}>{busy === '发送脱敏内容' ? '正在发送…' : '确认并发送'}<Icon name="arrow" size={18}/></button>}</div>
      </section>}
      {phase === 3 && sent && <section className="panel answer-panel" aria-labelledby="answer-heading"><div className="panel-heading"><div><Icon name="check"/><h2 id="answer-heading" ref={focusHeading} tabIndex={-1}>本地测试回答</h2></div><span className="badge blue">已完成</span></div><p className="panel-description">这是本地测试函数的回答，未调用外部大模型。默认只显示脱敏内容。</p><pre className="answer-text">{sent.assistant_text}</pre><details className="simple-disclosure restore-area"><summary><Icon name="eye" size={17}/>授权查看对应原文</summary><p>只还原本条回答中已授权的占位符，仅本页显示，不写回历史。映射过期后无法还原。</p><label className="consent"><input type="checkbox" checked={restoreAuth} onChange={e => setRestoreAuth(e.target.checked)} disabled={!!busy}/><span>{lan ? '我授权 Mac mini 后端本次还原并返回当前页面。' : '我授权本次仅在本机还原此条回答中的敏感信息。'}</span></label><button className="secondary" onClick={() => void restore()} disabled={!restoreAuth || !!busy}>{busy === '授权还原' ? '正在还原…' : '授权并仅本次还原'}<Icon name="eye" size={17}/></button>{restored && <div className="restored-result"><div><strong>已授权还原 · 仅本页</strong><button className="text-button" onClick={() => setRestored('')}>隐藏原文</button></div><pre>{restored}</pre></div>}</details><div className="panel-action"><span>历史只保存脱敏版本</span><button className="primary" disabled={!!busy} onClick={() => { setInputOpen(false); newDraft(); }}>开始新内容<Icon name="plus" size={18}/></button></div></section>}
      <div className="simple-secondary"><details className="simple-disclosure"><summary>隐私边界与使用说明</summary><p>文件和原文仅在本机解析、识别。文件名只在本页显示，不自动进入对话；原文、文件与还原结果不存入浏览器持久存储。退出或刷新会清空原文草稿。</p><p>只处理核对过的提取文字，不生成原格式脱敏或还原副本。OCR与规则可能漏检，未读取内容不受保护。请核对原件并人工补充。</p><p>识别引擎：{health.presidio ? 'Presidio + 中文规则' : '不可用，发送将关闭'}；中文语义NER：{health.ner_model ? '已配置' : '未配置'}。占位符映射加密保存24小时，发送历史只保存脱敏内容。</p><p>飞书登录仅访问官方身份认证域名，原文与占位符不发给飞书。本页未接入真实模型。</p></details><details className="simple-disclosure history-disclosure"><summary><Icon name="clock" size={16}/>会话历史（{sessions.length}）</summary>{sessions.length === 0 ? <p>还没有会话，原文草稿不会保存。</p> : <div className="session-list">{sessions.map(item => <button key={item.id} className={session?.id === item.id ? 'selected' : ''} onClick={() => void selectSession(item)} disabled={!!busy}><span>{item.title || '隐私协作会话'}<small>{new Date(item.created_at * 1000).toLocaleString('zh-CN')}</small></span></button>)}</div>}{session && messages.length > 0 && <div className="history-panel"><button className="text-button" onClick={() => setHistoryOpen(v => !v)} aria-expanded={historyOpen}>{historyOpen ? '收起' : '展开'}当前会话消息</button>{historyOpen && <div className="history-messages">{messages.map(m => <div key={m.id}><span className="message-role">{m.role === 'user' ? '用户 · 脱敏内容' : '本地测试回答'}</span><pre>{m.content}</pre></div>)}</div>}<button className="danger-button" onClick={() => void removeSession()} disabled={!!busy}>删除当前会话及映射</button></div>}</details></div>
      <footer className="page-footer">仅供本机开发验证 · 尚未完成企业试点验收</footer>
    </main>
  </div>;
}
function Highlight({ text, findings }: { text: string; findings: Finding[] }) {
  const sorted = [...findings].sort((a, b) => a.start_utf16 - b.start_utf16 || b.end_utf16 - a.end_utf16);
  const nodes: React.ReactNode[] = []; let cursor = 0;
  for (const f of sorted) {
    if (f.start_utf16 < cursor || f.end_utf16 > text.length) continue;
    if (f.start_utf16 > cursor) nodes.push(text.slice(cursor, f.start_utf16));
    nodes.push(<mark key={`${f.start_utf16}-${f.end_utf16}`} title={`${label(f.entity_type)} · ${f.source}`}><span className="sr-only">{label(f.entity_type)}：</span>{text.slice(f.start_utf16, f.end_utf16)}</mark>); cursor = f.end_utf16;
  }
  nodes.push(text.slice(cursor)); return <>{nodes}</>;
}
createRoot(document.getElementById('root')!).render(<ErrorBoundary><App/></ErrorBoundary>);
