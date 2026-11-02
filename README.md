# rv-cti-dashboard

A Flask-based CTI dashboard for threat intelligence feeds, OSINT, sandbox analysis, knowledge graph generation, and related security workflows.

## Prerequisites

- Python 3.11+
- Git

## Local setup

1. Clone the repository:
   ```bash
   git clone https://github.com/rvganesh95-pixel/rv-cti-dashboard.git
   cd rv-cti-dashboard
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # macOS/Linux
   # or
   .venv\Scripts\activate      # Windows PowerShell
   ```

3. Install dependencies:
   ```bash
   pip install -r rss_reader/requirements.txt
   ```

4. Create local environment variables:
   ```bash
   copy .env.example .env
   ```
   Then update `.env` with your own API keys.

5. Start the app:
   ```bash
   cd rss_reader
   python app.py
   ```

6. Open the dashboard:
   - http://localhost:5000

## Required environment variables

Set the following values in `.env` before running features that depend on external APIs:

- `OPENAI_API_KEY`
- `GITHUB_TOKEN`
- `VT_API_KEY`
- `HA_API_KEY`
- `ANYRUN_API_KEY`
- `ABUSEIPDB_API_KEY`
- `URLSCAN_API_KEY`

## GitHub-safe workflow

This repository follows a secure-by-default workflow:

- No real secrets are committed to source control
- `.env` is ignored by Git
- `.env.example` exists as a template for onboarding
- API keys are loaded from environment variables at runtime
- Fresh clones can be set up by copying `.env.example` to `.env`

## Security reminders

- Never commit `.env` files
- Rotate keys if they ever appear in Git history or logs
- Prefer short-lived credentials where supported
- Use repo secrets in CI/CD instead of local env files for automation

## Project layout

- `rss_reader/app.py` — Flask application
- `rss_reader/templates/` — dashboard pages
- `rss_reader/static/` — CSS and static assets
- `rss_reader/requirements.txt` — Python dependencies
- `.env.example` — template for local configuration
