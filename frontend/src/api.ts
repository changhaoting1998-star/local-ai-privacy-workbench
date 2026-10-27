export type User = { id: string; username: string; provider?: 'feishu' };
export type Auth = { user: User; csrf_token: string; mode: string };
export type Health = { status: string; mode: string; presidio: boolean; ner_model: boolean; setup_required: boolean; setup_available: boolean; deployment_mode: 'loopback' | 'lan_https'; public_base_url: string };
export type Session = { id: string; title: string; created_at: number };
export type Message = { id: string; role: string; content: string; preview_id?: string };
export type ManualSpan = { start: number; end: number; entity_type: string };
export type Finding = ManualSpan & { start_utf16: number; end_utf16: number; source: string; token: string };
export type Preview = {
  preview_id: string; session_id: string; masked_text: string; findings: Finding[];
  outbound_messages: { role: string; content: string }[]; manifest: { token: string; entity_type: string }[];
  blocked: boolean; block_reasons: string[]; expires_at: number; policy_version: string; model: string;
  content_hash: string; confirmation_phrase: string; mode: string; limitations: string[];
};
export type Sent = { message_id: string; preview_id: string; masked_text: string; assistant_text: string; model: string; mode: string; replayed: boolean };
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}
let csrf = '';
export function setCsrf(value: string) { csrf = value; }
export async function api<T>(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST', signal?: AbortSignal): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method, credentials: 'include', cache: 'no-store', signal,
    headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(method !== 'GET' ? { 'X-CSRF-Token': csrf } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: unknown;
  try { data = await response.json(); } catch { throw new ApiError(response.status, 'INVALID_RESPONSE', '服务未返回有效响应，请检查工作台后端服务。'); }
  if (!response.ok) {
    const detail = (data as { detail?: { code?: string; message?: string } }).detail;
    throw new ApiError(response.status, detail?.code || 'REQUEST_FAILED', typeof detail?.message === 'string' ? detail.message : '请求失败，操作未完成。');
  }
  return data as T;
}
export function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === 'deployment_origin') return '当前入口与服务配置不匹配，请使用管理员提供的 HTTPS 工作台地址重新打开。';
    if (error.status === 401) return '登录已过期，请重新登录。本页原文将被清空。';
    if (error.status === 409) return `预览或会话状态已变化，请重新生成预览。${error.message}`;
    return error.message;
  }
  return '无法连接工作台服务，操作未完成。请检查网络与服务状态后重试。';
}

export type ExtractedFile = {
  text: string; format: 'pdf' | 'docx' | 'xlsx'; character_count: number;
  coverage: { complete: boolean; requires_acknowledgement?: boolean; summary: string; units: number; ocr_used: boolean };
  warnings: string[]; limits: { file_bytes: number; text_characters: number };
};
const fileErrors: Record<string, string> = {
  files_personal_only: '文件上传仅支持当前 Mac 的个人版入口。',
  file_too_large: '文件超过10 MiB，请缩小后重试。草稿保持不变。',
  text_too_large: '提取内容超过20,000字符，未截断导入。请拆分文件后重试。',
  archive_limits: '文件解压后的体积或条目超过安全限制，未导入。',
  document_limits: '文件页数、工作表或单元格数量超过安全限制，未导入。',
  file_type: '文件格式或内容不匹配。请选择 PDF、DOCX 或 XLSX。',
  legacy_format: '暂不支持旧版 .doc / .xls，请先另存为 .docx / .xlsx。',
  file_invalid: '文件损坏或格式无效，无法完整读取。草稿保持不变。',
  file_encrypted: '文件已加密或受密码保护，请在本机解除保护后重试。',
  unsupported_content: '文件含宏、活动内容、外部数据连接或不支持的结构，请另存为简单文档后重试。',
  no_readable_text: '未能读取文件中的文字，未导入。请检查扫描质量或人工整理内容。',
  ocr_unavailable: '本机 OCR 当前不可用，扫描内容无法完整读取，已阻止导入。',
  extraction_busy: '本机解析任务繁忙，请稍后重试。草稿保持不变。',
  extraction_failed: '本机文件解析失败，未导入。请检查文件后重试。',
  extraction_timeout: '文件解析超时，未导入。请拆分文件或人工整理内容。',
  csrf: '本次上传未通过安全校验，请刷新并重新登录。',
  origin: '本次上传入口未通过安全校验，请使用当前 Mac 的个人版地址。',
};
export async function extractFile(file: File, signal: AbortSignal): Promise<ExtractedFile> {
  const form = new FormData(); form.append('file', file);
  const response = await fetch('/api/files/extract', {
    method: 'POST', credentials: 'include', cache: 'no-store', signal,
    // The browser must supply the multipart boundary. Do not set Content-Type.
    headers: { 'X-CSRF-Token': csrf }, body: form,
  });
  let data: unknown;
  try { data = await response.json(); } catch { throw new ApiError(response.status, 'file_response', '文件服务返回无效响应，未导入。'); }
  if (!response.ok) {
    const code = (data as { detail?: { code?: string } })?.detail?.code || '';
    throw new ApiError(response.status, code, fileErrors[code] || '文件未能导入。请检查文件与本机服务后重试。');
  }
  const value = data as ExtractedFile;
  if (!value?.coverage || typeof value.coverage.complete !== 'boolean' || (value.coverage.complete === false && (value.coverage.requires_acknowledgement !== true || !Array.isArray(value.warnings) || value.warnings.length === 0)) || typeof value.text !== 'string' || !value.text.trim() ||
      !['pdf', 'docx', 'xlsx'].includes(value.format) || [...value.text].length > 20000 ||
      typeof value.coverage.summary !== 'string' || !Array.isArray(value.warnings) || value.warnings.some(x => typeof x !== 'string')) {
    throw new ApiError(422, 'file_incomplete', '无法确认文件已完整提取，已阻止导入。草稿保持不变。');
  }
  return value;
}
