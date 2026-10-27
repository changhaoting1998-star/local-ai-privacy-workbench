# Contributing

1. Describe the problem or proposed behavior.
2. Use synthetic data only.
3. Keep network access, persistence, and security-boundary changes explicit.
4. Add focused tests for security-relevant behavior.
5. Run the backend tests and frontend build.

```bash
.venv/bin/python -m pytest backend/tests -q
cd frontend && pnpm build
```

Do not commit runtime databases, keys, OAuth secrets, provider tokens, real documents, local paths, or generated evidence containing user data.
