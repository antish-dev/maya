# Security baseline

- Production startup fails without `MAYA_SECRET_KEY`.
- Passwords use Werkzeug adaptive password hashing.
- Sessions are HTTP-only, SameSite=Lax and Secure when HTTPS is enabled.
- State-changing API calls require a per-session CSRF token.
- Role-based authorization applies to governance, employee, partner, incident and audit APIs.
- CSP, HSTS, no-sniff, referrer and permissions-policy headers are enabled.
- Request bodies are limited to 1 MB.
- Login attempts are rate-limited in-process. Use a gateway or Redis-backed limiter for multi-instance deployment.
- Audit logs record allowed and denied sensitive operations.
- Restricted records should be stored on encrypted managed storage with backups and access monitoring.
- Replace local SQLite with managed PostgreSQL before multi-user production deployment.
- Connect Microsoft Entra ID before production; local accounts are a deployment bootstrap only.
