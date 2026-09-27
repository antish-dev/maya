# Maya

Maya is an HR governance and operations assistant for Engage Lynk.

## Features

- Secure Flask-based HR operations dashboard
- Role-based access control for employees, managers, HR, partners, and auditors
- Document, incident, and audit logging
- Local SQLite database with seeded default documents
- Session security and CSRF protections

## Local development

1. Create a virtual environment.
2. Install dependencies:
   `pip install -r requirements.txt`
3. Set required environment variables:
   `export MAYA_SECRET_KEY=change-me`
   `export MAYA_ADMIN_EMAIL=admin@example.com`
   `export MAYA_ADMIN_PASSWORD=change-me`
4. Run the app:
   `python app.py`

The app listens on port 8080 by default.

## Production deployment

Deploy with Docker or Render using the provided configuration files.
Keep `MAYA_SECRET_KEY` in a secret environment variable and never commit real credentials to the repository.
