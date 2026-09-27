# Maya v2.0 Compiled

A deployable Engage Lynk governance and HR operating-system MVP compiled from the supplied Maya dashboard and this workstream.

## Included

- Original 35-LYNK dashboard and HR desk
- Secure Flask API
- Governance registry
- Employee and BD partner registries
- Incident management
- Review schema
- RBAC and audit logs
- CSRF protection, secure sessions and security headers
- SQLite persistence for a single-instance deployment
- Docker deployment

## Start locally

```bash
cp .env.example .env
# Replace every value in .env
docker compose --env-file .env up --build
```

Open `http://localhost:8080`. With `MAYA_HTTPS=false`, local cookies work over HTTP. Production must use HTTPS and `MAYA_HTTPS=true`.

## Production gate

Before real employee information is loaded: integrate Microsoft Entra ID, move to managed PostgreSQL, use a managed secrets vault, configure encrypted backups, instrument centralized monitoring, complete a privacy impact assessment, have Indian employment/privacy counsel review workflows, and perform penetration testing.

## API areas

- `/api/auth/*`
- `/api/dashboard`
- `/api/documents`
- `/api/people`
- `/api/partners`
- `/api/incidents`
- `/api/audit`
- `/api/chat`
