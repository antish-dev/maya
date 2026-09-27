# Maya v10 Gemini Connected

Rebuilt Engage Lynk Maya with a Gemini server endpoint, embedded controlled knowledge retrieval, page citations, empathy/social modes, local fallback, human approval gates, rate limiting, and security headers.

## Deploy
1. Put the project in a private Git repository.
2. Create a Render Blueprint or Docker web service.
3. Add a newly generated private `GEMINI_API_KEY` in the service environment.
4. Keep `GEMINI_MODEL=gemini-2.5-flash`.
5. Deploy and open the service URL.

Revoke any key previously shared in chat. Never commit a real key to this project.
