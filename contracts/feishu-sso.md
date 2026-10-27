# Optional Feishu/Lark SSO contract

Fixed callback: `http://127.0.0.1:8910/api/auth/feishu/callback`.

SSO is disabled until all of the following are configured locally:

1. `PG_FEISHU_APP_ID` contains the public application ID.
2. `PG_FEISHU_CREDENTIALS` points to a regular mode-`0600` JSON file inside a mode-`0700` directory.
3. The credential file contains matching `app_id` and `app_secret` values.
4. `backend/runtime/feishu-sso.json` pins the verified tenant:

```json
{
  "app_id": "cli_your_app_id",
  "tenant_key": "tenant_key_from_your_verified_app",
  "source": "official_app_tenant_identity"
}
```

The runtime file is deliberately ignored by Git.

## Routes

- `GET /api/auth/feishu/availability` reports local configuration availability.
- `GET /api/auth/feishu/start` creates a 300-second browser-bound state and PKCE challenge, then redirects to the official authorization endpoint.
- `GET /api/auth/feishu/callback` consumes state once, exchanges the code, verifies tenant and open ID, and creates or resumes an isolated local SSO identity.
- `GET /api/me` is the final source of truth for local login state.

Provider access tokens and authorization codes are never persisted. Refresh and offline access are not requested. OAuth errors are normalized and do not include provider response bodies.

## Local configuration requirements

The credential loader rejects symbolic links, group/world-readable directories, group/world-readable files, non-regular files, oversized JSON, and an App ID that differs from `PG_FEISHU_APP_ID`.

Register the exact callback in the Feishu/Lark developer console. Application publication, user consent, and organization policy remain the deployer's responsibility.
