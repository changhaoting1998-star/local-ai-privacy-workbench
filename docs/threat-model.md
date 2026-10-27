# Threat model

Protected path:

`input -> extraction -> detection -> human review -> exact preview -> explicit send -> optional exact restoration`

| Threat | Control |
| --- | --- |
| Raw content sent before review | Send accepts only a stored preview ID |
| Preview changed after approval | User, session, history, policy, model, and content binding |
| Duplicate side effects | Idempotency key bound to the preview |
| Cross-user/session restoration | Object ownership and message-manifest checks |
| Database disclosure | AES-256-GCM mappings with a key outside the database |
| Credential leakage | Mandatory credential-pattern block |
| Malicious documents | Type/magic checks, bounded workers, archive/XML/PDF limits |
| OAuth replay or tenant confusion | PKCE, one-time state, browser binding, expiry, and tenant pinning |

Out of scope: perfect PII or trade-secret detection, a compromised operating system, swap/backups/snapshots/crash dumps, multi-node deployment, enterprise KMS, format-preserving redaction, and production remote-model integration.

The app fails closed on detector, encryption, mapping-integrity, and extraction errors, but human review remains mandatory.
