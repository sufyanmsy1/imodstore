# iModStore backend starter

This package is the next development step for your custom-domain app marketplace. It includes a frontend and a small Node.js backend with account registration/login, SQLite database, APK/icon upload, and an admin approval queue.

## Run on a computer (recommended for first setup)
Requirements: Node.js 20+ and npm.

1. Extract the ZIP.
2. Open a terminal in the `iModStore_Backend_Starter` folder.
3. Install dependencies:
   ```bash
   npm install
   ```
4. Copy `.env.example` to `.env`.
5. Replace `SESSION_SECRET` with a random secret of at least 32 characters.
6. Start the server:
   ```bash
   npm start
   ```
7. Open `http://localhost:8080`.

## Make the first account an admin
1. Register an account in the website.
2. Stop the server.
3. Open `data/imodstore.sqlite` with a SQLite browser or CLI.
4. Find your user ID:
   ```sql
   SELECT id, email, is_admin FROM users;
   ```
5. Promote only your own account:
   ```sql
   UPDATE users SET is_admin = 1 WHERE email = 'YOUR-EMAIL-HERE';
   ```
6. Restart the server and log in again. The Admin panel will appear.

Do not expose an unauthenticated admin setup route on a public server.

## Current functionality
- User registration and login using hashed passwords
- Session cookies (HttpOnly, SameSite=Lax)
- App metadata and uploaded APK/icon files stored on server
- Every user submission starts as `pending`
- Public store only shows `approved` listings
- Admin-only pending queue with approve/reject actions
- Download route serves only approved APKs
- SQLite database and health endpoint (`/api/health`)

## Important security and production limitations
This is a starter, not production-ready. Before public launch:
- Add CSRF protection and rate limiting for authentication and uploads.
- Put the app behind HTTPS; set `NODE_ENV=production` and configure secure cookies.
- Scan APKs with a maintained malware scanner before review/approval.
- Verify APK content/signature rather than trusting the `.apk` extension.
- Use a durable object storage service for APKs and icons; local disk may be ephemeral on cloud hosts.
- Add moderation audit logs, report/takedown workflow, privacy policy, terms, and data deletion flow.
- Set strict upload limits, quotas, monitoring, backups, and database migrations.
- Add anti-spam/email verification and password reset.
- Review the deployment platform's support for SQLite and persistent disk.
- For multiple server instances, use shared session storage and shared file storage.
- Never allow unauthorized users to mark their own submissions approved.

## Domain and hosting
A domain is not included or purchased by this ZIP. First deploy to a host that supports Node.js and persistent storage (or adapt this to a managed database/object storage), then connect your domain DNS and enable HTTPS. Domain availability and pricing must be checked with a registrar.

## Upload limits
The server currently allows an APK up to 100 MB and an optional icon up to 100 MB due to a global multer limit. For production, lower icon limits to about 2 MB and tune the APK limit to your needs. Run security checks before serving any uploaded APK.

## API overview
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET /api/apps` (approved listings only)
- `POST /api/apps` (authenticated multipart submission)
- `GET /api/admin/apps` (admin only)
- `PATCH /api/admin/apps/:id` (admin only)
- `GET /api/apps/:id/download` (approved apps only)
- `GET /api/health`


## All-in-one UI features included
- Responsive iPhone-inspired glass UI and mobile bottom navigation
- 19 app categories, search, Top charts, Kids and New & updated views
- Device-local favorites/wishlist and app reviews with star ratings
- App detail views and download-start progress animation
- Profile overview, settings, dark mode, privacy center and update notices
- Admin review panel with pending-submission summary

## Important prototype limitations
Favorites and reviews are stored in the visitor's browser only; the update panel is an in-app list, not push notifications. The download progress bar is a UI animation while the browser handles the real download. This starter does not yet include production malware scanning, email verification, rate limiting, CSRF protection, durable cloud object storage, or a self-service account deletion flow. Do not launch publicly until those are added and tested.


Android/GitHub note: this bundle keeps the website file at the repository root so the files can be selected together from a mobile file picker. Do not upload the ZIP itself as the only repository file; extract it first and upload the extracted files.
