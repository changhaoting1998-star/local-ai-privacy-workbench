import { api, ApiError } from './api';
import type { Health } from './api';

export type FeishuAvailability = { available: boolean; reason_code: string | null };

// Only application-owned codes may become UI copy. Provider text is never rendered.
const messages: Record<string, string> = {
  credentials_unavailable: '飞书登录尚未配置或服务端配置不可用。请联系管理员核对。',
  configuration_invalid: '飞书应用配置未通过验证。请联系管理员核对配置。',
  tenant_unconfigured: '飞书登录待配置：尚未设置允许登录的企业租户，请联系管理员。',
  access_denied: '你已取消或拒绝飞书授权，本次未登录。可重新尝试或使用本地账户。',
  origin: '请使用管理员提供的工作台入口重新打开，再发起飞书登录。',
  rate_limit: '飞书登录尝试过于频繁。请稍后重试。',
  flow_invalid: '登录验证已失效或与当前浏览器不匹配。请重新发起飞书登录。',
  flow_expired: '飞书登录已超时。请重新发起登录。',
  exchange_failed: '飞书授权未完成。本次未登录，请重试；若应用未发布或账号不在可用范围内，请联系管理员。',
  identity_invalid: '飞书身份未通过验证，本次未登录。请联系管理员。',
  tenant_denied: '当前飞书账号不在允许登录的企业范围内。请使用获准账号。',
  unavailable: '暂时无法连接飞书认证服务，本次未登录。请稍后重试。',
};
const fallback = '飞书登录未完成。请重新尝试，或联系管理员检查应用配置与可用范围。';
export function ssoMessage(code: unknown, health?: Health): string {
  if ((code === 'origin' || code === 'deployment_origin') && health) {
    return `请使用${health.deployment_mode === 'lan_https' ? '局域网 HTTPS' : '本机'}入口 ${health.public_base_url} 打开工作台，再发起飞书登录。`;
  }
  return typeof code === 'string' && Object.hasOwn(messages, code) ? messages[code] : fallback;
}
export function ssoRequestError(error: unknown, health?: Health): string {
  return error instanceof ApiError ? ssoMessage(error.code, health) : messages.unavailable;
}
export async function feishuAvailability(): Promise<FeishuAvailability> {
  const value = await api<FeishuAvailability>('/auth/feishu/availability', undefined, 'GET', AbortSignal.timeout(10000));
  if (typeof value?.available !== 'boolean' || !(value.reason_code === null || typeof value.reason_code === 'string')) {
    throw new ApiError(502, 'INVALID_RESPONSE', '');
  }
  return value;
}

export function consumeSsoResult(): { success: boolean; error: string; reason: string | null } {
  const params = new URLSearchParams(location.search);
  const status = params.get('sso');
  const result = { success: status === 'success', error: status === 'error' ? ssoMessage(params.get('reason')) : '', reason: status === 'error' ? params.get('reason') : null };
  // This app has no query-based routes. Remove callback markers and any accidental
  // auth material before requests or rendering; never retain it in browser storage.
  if (location.search || location.hash) history.replaceState(null, '', location.pathname);
  return result;
}
