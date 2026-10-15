# Secure Gateway

Secure Gateway is a Flask application for authenticated file uploads, malware scanning, AES-GCM encryption, controlled sharing, and audit logging. It supports MySQL for local development and Supabase-hosted PostgreSQL for the application database.

## Requirements

- Python 3.10 or newer
- MySQL for local development, or a Supabase project with the provided tables already created
- VirusTotal API key for malware scanning

## Local Setup

Create and activate a virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Create a `.env` file in the project root. Keep secrets out of source control:

```dotenv
SECRET_KEY=replace-with-a-long-random-value
DATABASE_BACKEND=mysql
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=root
MYSQL_PASSWORD=your-mysql-password
MYSQL_DB=secure_gateway
VIRUSTOTAL_API_KEY=your-private-virustotal-api-key
SESSION_COOKIE_SECURE=false
```

Create the local MySQL database using [`database/schema.sql`](database/schema.sql), then start the app:

```powershell
python app.py
```

Open `http://127.0.0.1:5000`.

## VirusTotal Scanning

Uploads and rescans submit plaintext files to VirusTotal API v3. The API key is read only by the Flask server from `VIRUSTOTAL_API_KEY`; never use a `NEXT_PUBLIC_` variable or commit the key.

VirusTotal states that submitted files may be shared with its security community. The upload and rescan forms therefore require explicit consent. Do not submit confidential, personal, or otherwise sensitive documents. If the API key is missing, the API is rate-limited, or an analysis is not completed, the file stays pending and is not marked safe.

VirusTotal's direct file-upload endpoint accepts files up to 32 MB. Larger files use its one-time upload URL endpoint. This project allows uploads up to 50 MB.

## Supabase Database

The application uses direct PostgreSQL connections for its SQL queries and transactions. The Supabase project URL and publishable key are not database credentials. In the Supabase dashboard, copy the database connection string from **Project Settings > Database > Connection string** (use the direct connection or session pooler as appropriate), then store it privately as `SUPABASE_DB_URL`. Do not commit it or paste it into public messages.

Set these server-side environment variables:

```dotenv
DATABASE_BACKEND=supabase
SUPABASE_DB_URL=postgresql://postgres:<database-password>@<host>:5432/postgres
```

The database must contain the `users`, `files`, `encryption_keys`, `shared_files`, and `audit_logs` tables matching the schema supplied for this project. The legacy MySQL schema is not the Supabase schema. The URL and publishable key can be set as `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` (or their `NEXT_PUBLIC_` equivalents) when Supabase API features are used. Never expose a service-role/secret key in browser code.

With the private database URL configured, verify the connection with:

```powershell
python test_supabase_connection.py
```

File bytes are currently stored on the application server's local filesystem; configuring Supabase PostgreSQL does not move uploaded files into Supabase Storage. The server-side Supabase Storage test is separate from the app's current upload/download path.

## Deployment

**Render is the better fit for the current application.** It runs Flask as a persistent web service and can connect to Supabase PostgreSQL. Vercel is designed around serverless functions, while this app expects writable local directories for uploads, encryption, quarantine, and logs. Those local files are not durable on either platform's ephemeral filesystem.

For Render, use `pip install -r requirements.txt` as the build command and `gunicorn app:app --bind 0.0.0.0:$PORT --timeout 120` as the start command. Configure `SUPABASE_DB_URL`, `SECRET_KEY`, and `VIRUSTOTAL_API_KEY` as private environment variables. Add a persistent disk and set `UPLOAD_FOLDER`, `ENCRYPTED_FOLDER`, and `QUARANTINE_FOLDER` to paths on that disk. For scalable production storage, implement and use Supabase Storage in the upload, download, sharing, and deletion flows before relying on ephemeral application storage.

This repository includes a Render Blueprint in [`render.yaml`](render.yaml). Push the project to a GitHub repository, then create a Blueprint in the Render dashboard from that repository. Set `SUPABASE_DB_URL` and `VIRUSTOTAL_API_KEY` in the Render service's private environment settings before the first deploy. The Blueprint uses a paid web-service plan and persistent disk. VirusTotal scanning is unavailable until a valid API key is configured. The application will not be fully useful for production file security until scanning is available and uploaded files are stored durably.
"# secure-storing-and-sharing-system" 
