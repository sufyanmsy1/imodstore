iModStore Firebase Firestore OTP backend

Files:
- server.js: Express backend updated to store OTP challenges in Firestore and send email using configured SMTP.
- package.json: includes firebase-admin and nodemailer.
- public/index.html: existing OTP-capable frontend.

Before deploying:
1. Commit these files to your GitHub repository, keeping the existing project structure.
2. Render Environment variables:
   - SESSION_SECRET: existing secret, minimum 32 characters.
   - FIREBASE_SERVICE_ACCOUNT_PATH=/etc/secrets/firebase-service-account.json
   - SMTP_HOST=smtp.gmail.com
   - SMTP_PORT=587
   - SMTP_USER=your Gmail address
   - SMTP_PASS=your Google App Password (not normal Gmail password)
   - SMTP_FROM=your Gmail address
3. Render Secret Files:
   - Filename: firebase-service-account.json
   - Contents: the full Firebase service-account JSON downloaded from Firebase Console.
4. Ensure Firebase project ID in the service account JSON is "imodestore".
5. In Firestore, server-side Admin SDK uses the collection "otp_challenges". Do not create public read/write rules; Admin SDK accesses Firestore with service-account privileges.
6. Deploy latest commit and inspect Render logs.

OTP behavior:
- 6-digit codes
- 10-minute expiry
- 60-second resend cooldown
- maximum 5 verification attempts
- OTP hashes stored in Firestore; the raw code is only sent by email.

Important:
- This code does not use Firebase Authentication's built-in email OTP (Firebase does not provide a built-in custom 6-digit email OTP flow). It uses Firestore for OTP challenge storage and SMTP for delivery.
- Existing SQLite user/app data remains in SQLite; this change only moves OTP challenge records to Firestore.
- Never commit the service-account JSON, SMTP app password, or SESSION_SECRET to GitHub.
iModStore Admin Panel

Files:
- server.js (updated with ADMIN_EMAIL bootstrap and admin stats endpoint)
- public/admin.html (responsive admin dashboard)

Setup:
1. Replace repository root server.js with this server.js.
2. Put public/admin.html in your repository's public/ folder.
3. Ensure your normal website files remain in public/.
4. In Render > Environment, add ADMIN_EMAIL with the exact email of an account already registered on iModStore. Do not put secrets in HTML or GitHub.
5. Save changes and deploy. The server promotes only that exact existing account to admin when it starts. If the account is not registered yet, register it first, then restart/redeploy.
6. Log in on the normal website, then open https://imodstore.onrender.com/admin.html

Features: admin-only pending queue, app approve/reject with review note, counts for users/submissions/approved/rejected. API endpoints remain protected by server-side requireAdmin middleware.
