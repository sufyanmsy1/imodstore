require("dotenv").config();

const express = require("express");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const admin = require("firebase-admin");
const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");

const PORT = Number(process.env.PORT || 8080);
const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(ROOT, "uploads");

fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(UPLOADS, { recursive: true });

const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret || sessionSecret.length < 32) {
  console.error("ERROR: SESSION_SECRET must be at least 32 characters.");
  process.exit(1);
}

const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "/etc/secrets/firebase-service-account.json";
if (!fs.existsSync(serviceAccountPath)) {
  console.error("ERROR: Firebase service account secret file was not found:", serviceAccountPath);
  process.exit(1);
}
const serviceAccount = require(serviceAccountPath);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const firestore = admin.firestore();
const otpCollection = firestore.collection("otp_challenges");

// Persistent application data lives in Firestore. SQLite is used only by the
// express-session store on Render Free; sessions may expire after restarts.
const usersCollection = firestore.collection("users");
const appsCollection = firestore.collection("apps");
const bucketName = String(process.env.SUPABASE_BUCKET || "imodstore-files").trim();
const supabaseUrl = String(process.env.SUPABASE_URL || "").replace(/\/$/, "");
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

function userDocId(email) {
  return crypto.createHash("sha256").update(normalizeEmail(email)).digest("hex");
}
function userFromDoc(doc) {
  if (!doc || !doc.exists) return null;
  return { id: doc.id, ...doc.data(), isAdmin: doc.get("is_admin") === true || doc.get("is_admin") === 1 };
}
async function userByEmail(email) {
  const normalized = normalizeEmail(email);
  const direct = await usersCollection.doc(userDocId(normalized)).get();
  if (direct.exists) return userFromDoc(direct);
  const snap = await usersCollection.where("email", "==", normalized).limit(1).get();
  return snap.empty ? null : userFromDoc(snap.docs[0]);
}
async function userById(id) {
  if (!id) return null;
  const snap = await usersCollection.doc(String(id)).get();
  return userFromDoc(snap);
}
async function createUser(email, passwordHash, isAdmin = false) {
  const normalized = normalizeEmail(email);
  const id = userDocId(normalized);
  const ref = usersCollection.doc(id);
  return firestore.runTransaction(async tx => {
    const existing = await tx.get(ref);
    if (existing.exists) {
      const error = new Error("EMAIL_EXISTS");
      throw error;
    }
    const user = {
      email: normalized,
      password_hash: passwordHash,
      is_admin: !!isAdmin || (!!configuredAdminEmail && normalized === configuredAdminEmail),
      created_at: new Date().toISOString()
    };
    tx.create(ref, user);
    return { id, ...user };
  });
}
async function promoteConfiguredAdmin() {
  if (!configuredAdminEmail) return;
  const user = await userByEmail(configuredAdminEmail);
  if (!user) {
    console.log(`ADMIN_EMAIL is configured; register ${configuredAdminEmail} first, then restart.`);
    return;
  }
  await usersCollection.doc(user.id).set({ is_admin: true }, { merge: true });
  console.log(`Admin access enabled for ${configuredAdminEmail}`);
}
async function listApps() {
  const snap = await appsCollection.get();
  return snap.docs.map(d => ({ id: d.id, ...d.data() }));
}
async function getAppById(id) {
  const snap = await appsCollection.doc(String(id)).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}
async function saveApp(appRow) {
  await appsCollection.doc(appRow.id).create(appRow);
}
async function updateAppReview(id, status, note) {
  const ref = appsCollection.doc(String(id));
  return firestore.runTransaction(async tx => {
    const snap = await tx.get(ref);
    if (!snap.exists || snap.get("status") !== "pending") return false;
    tx.update(ref, { status, review_note: note, reviewed_at: new Date().toISOString() });
    return true;
  });
}
async function uploadToSupabase(localFile, storagePath, contentType) {
  if (!supabaseUrl || !supabaseServiceKey) throw new Error("SUPABASE_NOT_CONFIGURED");
  const encodedPath = storagePath.split("/").map(encodeURIComponent).join("/");
  const response = await fetch(`${supabaseUrl}/storage/v1/object/${encodeURIComponent(bucketName)}/${encodedPath}`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${supabaseServiceKey}`,
      "apikey": supabaseServiceKey,
      "Content-Type": contentType || "application/octet-stream",
      "x-upsert": "false"
    },
    body: await fs.promises.readFile(localFile)
  });
  const body = await response.text();
  if (!response.ok) {
    console.error("Supabase Storage upload error:", response.status, body.slice(0, 500));
    throw new Error("SUPABASE_UPLOAD_FAILED");
  }
  return storagePath;
}
async function createStorageSignedUrl(storagePath, expiresIn = 300) {
  if (!supabaseUrl || !supabaseServiceKey) throw new Error("SUPABASE_NOT_CONFIGURED");
  const encodedPath = String(storagePath).split("/").map(encodeURIComponent).join("/");
  const response = await fetch(`${supabaseUrl}/storage/v1/object/sign/${encodeURIComponent(bucketName)}/${encodedPath}`, {
    method: "POST",
    headers: { "Authorization": `Bearer ${supabaseServiceKey}`, "apikey": supabaseServiceKey, "Content-Type": "application/json" },
    body: JSON.stringify({ expiresIn })
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.signedURL) {
    console.error("Supabase signed URL error:", response.status, JSON.stringify(body).slice(0, 500));
    throw new Error("SUPABASE_SIGNED_URL_FAILED");
  }
  return body.signedURL.startsWith("http") ? body.signedURL : `${supabaseUrl}/storage/v1${body.signedURL}`;
}
async function deleteSupabaseObjects(paths) {
  const objects = (paths || []).filter(Boolean).map(name => ({ name }));
  if (!objects.length || !supabaseUrl || !supabaseServiceKey) return;
  try {
    await fetch(`${supabaseUrl}/storage/v1/object/${encodeURIComponent(bucketName)}`, {
      method: "DELETE",
      headers: { "Authorization": `Bearer ${supabaseServiceKey}`, "apikey": supabaseServiceKey, "Content-Type": "application/json" },
      body: JSON.stringify({ prefixes: objects.map(o => o.name) })
    });
  } catch (_) {}
}

// Promote the configured account now and on every successful registration.
const configuredAdminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
promoteConfiguredAdmin().catch(error => console.error("Admin promotion check failed:", error.message));

const allowedCats = new Set([
  "Games", "Productivity", "Photography", "Education",
  "Entertainment", "Tools", "Kids", "Social", "Health & fitness",
  "Finance", "Travel", "Lifestyle", "Music & audio",
  "Books & reference", "Business", "News", "Food & drink",
  "Maps & navigation", "Personalization"
]);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "DENY");
  next();
});

app.use(express.json({ limit: "30kb" }));

app.use(session({
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: DATA
  }),
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// Email delivery uses Resend HTTPS API (avoids SMTP connection timeouts).
const resendApiKey = process.env.RESEND_API_KEY;
const resendFrom = process.env.RESEND_FROM || process.env.EMAIL_FROM;

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    && email.length <= 254;
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }
  next();
}

async function currentUser(req) {
  return req.session.userId ? userById(req.session.userId) : null;
}

function requireAdmin(req, res, next) {
  currentUser(req).then(user => {
    if (!user || !(user.is_admin === true || user.is_admin === 1)) {
      return res.status(403).json({ error: "Admin access required." });
    }
    req.currentUser = user;
    next();
  }).catch(error => {
    console.error("Admin check failed:", error.message);
    res.status(500).json({ error: "Could not verify admin access." });
  });
}

function safeUser(user) {
  return { id: user.id, email: user.email, isAdmin: user.is_admin === true || user.is_admin === 1 };
}
function publicApp(appRow) {
  return { id: appRow.id, name: appRow.name, category: appRow.category, description: appRow.description, version: appRow.version || "", rating: appRow.rating || "New", size: appRow.download_url ? "MediaFire" : (Number(appRow.size_bytes || 0) / 1024 / 1024).toFixed(1) + " MB", iconUrl: appRow.icon_file ? "/api/icons/" + encodeURIComponent(appRow.id) + "/" + encodeURIComponent(path.basename(appRow.icon_file)) : null };
}

function removeFiles(files) {
  for (const file of Object.values(files || {}).flat()) {
    if (file && file.path) {
      fs.promises.unlink(file.path).catch(() => {});
    }
  }
}

// OTP helpers
function hashOtp(email, purpose, otp) {
  return crypto
    .createHmac("sha256", sessionSecret)
    .update(`${email}|${purpose}|${otp}`)
    .digest("hex");
}

function safeHashCompare(a, b) {
  const first = Buffer.from(String(a), "hex");
  const second = Buffer.from(String(b), "hex");

  return first.length === second.length &&
    first.length > 0 &&
    crypto.timingSafeEqual(first, second);
}

async function getChallenge(email, purpose) {
  const id = `${purpose}_${crypto.createHash("sha256").update(email).digest("hex")}`;
  const snap = await otpCollection.doc(id).get();
  return snap.exists ? snap.data() : null;
}
async function putChallenge(email, purpose, data) {
  const id = `${purpose}_${crypto.createHash("sha256").update(email).digest("hex")}`;
  await otpCollection.doc(id).set({ email, purpose, ...data });
}
async function removeChallenge(email, purpose) {
  const id = `${purpose}_${crypto.createHash("sha256").update(email).digest("hex")}`;
  await otpCollection.doc(id).delete();
}
async function incrementChallengeAttempts(email, purpose) {
  const id = `${purpose}_${crypto.createHash("sha256").update(email).digest("hex")}`;
  await firestore.runTransaction(async (tx) => {
    const ref = otpCollection.doc(id);
    const snap = await tx.get(ref);
    if (snap.exists) tx.update(ref, { attempts: Number(snap.get("attempts") || 0) + 1 });
  });
}
async function sendOtp(email, purpose, otp) {
  if (!resendApiKey || !resendFrom) throw new Error("RESEND_NOT_CONFIGURED");

  const subject = purpose === "register" ? "Your iModStore verification code"
    : purpose === "login" ? "Your iModStore login code" : "Your iModStore password reset code";

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${resendApiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: resendFrom,
      to: [email],
      subject,
      text: `Your iModStore verification code is ${otp}.\n\nIt expires in 10 minutes. Do not share this code with anyone.`,
      html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto"><h2>iModStore</h2><p>Your verification code is:</p><div style="font-size:32px;font-weight:bold;letter-spacing:8px">${otp}</div><p>This code expires in 10 minutes.</p><p>If you did not request this code, ignore this email.</p></div>`
    })
  });

  const responseText = await response.text();
  if (!response.ok) {
    console.error("Resend API error:", response.status, responseText.slice(0, 1000));
    const err = new Error("RESEND_API_ERROR");
    err.status = response.status;
    throw err;
  }
}

async function createAndSendOtp(email, purpose, passwordHash = null) {
  const now = Date.now();
  const existing = await getChallenge(email, purpose);
  if (existing && now - Number(existing.last_sent_at) < 60000) {
    return { ok: false, error: "Please wait before requesting another OTP." };
  }
  const otp = crypto.randomInt(0, 1000000).toString().padStart(6, "0");
  await putChallenge(email, purpose, {
    otp_hash: hashOtp(email, purpose, otp), password_hash: passwordHash,
    expires_at: now + 10 * 60 * 1000, last_sent_at: now, attempts: 0
  });
  try {
    await sendOtp(email, purpose, otp);
  } catch (error) {
    await removeChallenge(email, purpose);
    throw error;
  }
  return { ok: true };
}

function emailSendError(res, error) {
  console.error("Email OTP error:", error.message);

  if (error.message === "RESEND_NOT_CONFIGURED") {
    return res.status(503).json({
      error: "Resend email service is not configured. Please contact the administrator."
    });
  }

  return res.status(502).json({
    error: "Could not send the email. Check Render logs for the Resend API error."
  });
}

// Request registration OTP
app.post("/api/auth/request-otp", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "Password must be between 8 and 128 characters."
      });
    }

    if (await userByEmail(email)) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await createAndSendOtp(
      email,
      "register",
      passwordHash
    );

    if (!result.ok) {
      return res.status(429).json({
        error: result.error
      });
    }

    return res.json({
      ok: true,
      message: "Verification code sent to your email."
    });
  } catch (error) {
    return emailSendError(res, error);
  }
});

// Verify registration OTP
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();

    if (!validEmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        error: "Enter a valid email and 6-digit OTP."
      });
    }

    const challenge = await getChallenge(email, "register");

    if (!challenge) {
      return res.status(400).json({
        error: "OTP not found. Please request a new code."
      });
    }

    if (Date.now() > challenge.expires_at) {
      await removeChallenge(email, "register");

      return res.status(400).json({
        error: "OTP expired. Please request a new code."
      });
    }

    if (challenge.attempts >= 5) {
      await removeChallenge(email, "register");

      return res.status(429).json({
        error: "Too many incorrect attempts. Request a new OTP."
      });
    }

    const submittedHash = hashOtp(email, "register", otp);

    if (!safeHashCompare(challenge.otp_hash, submittedHash)) {
      await incrementChallengeAttempts(email, "register");

      return res.status(400).json({
        error: "Incorrect OTP."
      });
    }

    if (!challenge.password_hash) {
      await removeChallenge(email, "register");

      return res.status(400).json({
        error: "Registration session expired. Request a new OTP."
      });
    }

    let user;
    try {
      user = await createUser(email, challenge.password_hash, email === configuredAdminEmail);
    } catch (error) {
      if (error.message === "EMAIL_EXISTS") {
        return res.status(409).json({ error: "An account with this email already exists." });
      }
      throw error;
    }

    await removeChallenge(email, "register");
    req.session.userId = user.id;
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
    if (email === configuredAdminEmail) console.log(`Admin access enabled for ${email}`);
    return res.json({ ok: true, message: "Account created successfully.", user: safeUser(user) });
  } catch (error) {
    console.error("OTP verification error:", error.message);

    return res.status(500).json({
      error: "Could not verify OTP. Please try again."
    });
  }
});
// Request login OTP (passwordless email login)
app.post("/api/auth/request-login-otp", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    if (!validEmail(email)) return res.status(400).json({ error: "Enter a valid email address." });
    const user = await userByEmail(email);
    if (!user) return res.json({ ok: true, message: "If an account exists, a login code will be sent." });
    const result = await createAndSendOtp(email, "login");
    if (!result.ok) return res.status(429).json({ error: result.error });
    return res.json({ ok: true, message: "If an account exists, a login code will be sent." });
  } catch (error) {
    return emailSendError(res, error);
  }
});

// Verify login OTP and create a session
app.post("/api/auth/verify-login-otp", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();
    if (!validEmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "Enter a valid email address and 6-digit OTP." });
    }
    const challenge = await getChallenge(email, "login");
    if (!challenge) return res.status(400).json({ error: "Login code not found. Request a new code." });
    if (Date.now() > challenge.expires_at) {
      await removeChallenge(email, "login");
      return res.status(400).json({ error: "Login code expired. Request a new code." });
    }
    if (challenge.attempts >= 5) {
      await removeChallenge(email, "login");
      return res.status(429).json({ error: "Too many incorrect attempts. Request a new OTP." });
    }
    if (!safeHashCompare(challenge.otp_hash, hashOtp(email, "login", otp))) {
      await incrementChallengeAttempts(email, "login");
      return res.status(400).json({ error: "Incorrect login code." });
    }
    const user = await userByEmail(email);
    await removeChallenge(email, "login");
    if (!user) return res.status(400).json({ error: "Account not found. Please create an account first." });
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: "Could not create a login session." });
      req.session.userId = user.id;
      req.session.save((saveError) => {
        if (saveError) return res.status(500).json({ error: "Could not save your login session." });
        return res.json({ ok: true, message: "Login successful.", user: safeUser(user) });
      });
    });
  } catch (error) {
    console.error("OTP login error:", error.message);
    return res.status(500).json({ error: "Could not verify login code. Please try again." });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!validEmail(email) || !password) {
      return res.status(400).json({
        error: "Enter your email and password."
      });
    }

    const user = await userByEmail(email);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session error:", err.message);

        return res.status(500).json({
          error: "Could not create a login session."
        });
      }

      req.session.userId = user.id;

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError.message);

          return res.status(500).json({
            error: "Could not save your login session."
          });
        }

        return res.json({
          ok: true,
          message: "Login successful.",
          user: safeUser(user)
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "Login failed. Please try again."
    });
  }
});

// Current logged-in user
app.get("/api/auth/me", async (req, res) => {
  const user = await currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  return res.json({
    ok: true,
    user: safeUser(user)
  });
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Could not log out."
      });
    }

    res.clearCookie("connect.sid");

    return res.json({
      ok: true,
      message: "Logged out successfully."
    });
  });
});

// Request password-reset OTP
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);

    if (!validEmail(email)) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    const user = await userByEmail(email);

    // Avoid revealing whether an email is registered.
    if (!user) {
      return res.json({
        ok: true,
        message: "If the account exists, a reset code will be sent."
      });
    }

    const result = await createAndSendOtp(email, "reset");

    if (!result.ok) {
      return res.status(429).json({
        error: result.error
      });
    }

    return res.json({
      ok: true,
      message: "If the account exists, a reset code will be sent."
    });
  } catch (error) {
    return emailSendError(res, error);
  }
});

// Verify password-reset OTP and set a new password
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();
    const newPassword = String(req.body.newPassword || "");

    if (!validEmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        error: "Enter a valid email and 6-digit OTP."
      });
    }

    if (newPassword.length < 8 || newPassword.length > 128) {
      return res.status(400).json({
        error: "New password must be between 8 and 128 characters."
      });
    }

    const challenge = await getChallenge(email, "reset");

    if (!challenge) {
      return res.status(400).json({
        error: "Reset code not found. Request a new code."
      });
    }

    if (Date.now() > challenge.expires_at) {
      await removeChallenge(email, "reset");

      return res.status(400).json({
        error: "Reset code expired. Request a new code."
      });
    }

    if (challenge.attempts >= 5) {
      await removeChallenge(email, "reset");

      return res.status(429).json({
        error: "Too many incorrect attempts. Request a new code."
      });
    }

    const submittedHash = hashOtp(email, "reset", otp);

    if (!safeHashCompare(challenge.otp_hash, submittedHash)) {
      await incrementChallengeAttempts(email, "reset");

      return res.status(400).json({
        error: "Incorrect reset code."
      });
    }

    const user = await userByEmail(email);

    if (!user) {
      await removeChallenge(email, "reset");

      return res.status(400).json({
        error: "Account not found."
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    await usersCollection.doc(user.id).set({ password_hash: passwordHash }, { merge: true });
    await removeChallenge(email, "reset");

    return res.json({
      ok: true,
      message: "Password reset successfully. You can now log in."
    });
  } catch (error) {
    console.error("Password reset error:", error.message);

    return res.status(500).json({
      error: "Could not reset your password. Please try again."
    });
  }
});

// Disable old direct registration endpoint.
// Registration must use email OTP.
app.post("/api/auth/register", (req, res) => {
  return res.status(410).json({
    error: "Direct registration is disabled. Use email OTP verification."
  });
});
// Public apps
app.get("/api/apps", async (req, res) => {
  try {
    const rows = (await listApps()).filter(row => row.status === "approved").sort((a,b) => String(b.created_at || "").localeCompare(String(a.created_at || "")));
    res.json({ apps: rows.map(publicApp) });
  } catch (error) {
    console.error("Public apps query failed:", error.message);
    res.status(500).json({ error: "Could not load apps." });
  }
});

// App icons
app.get("/api/icons/:id/:file", async (req, res) => {
  try {
    const id = path.basename(req.params.id);
    const file = path.basename(req.params.file);
    const storagePath = `${id}/${file}`;
    if (!id || !file || id.includes("..") || file.includes("..")) return res.sendStatus(404);
    const signedUrl = await createStorageSignedUrl(storagePath, 3600);
    res.redirect(302, signedUrl);
  } catch (error) {
    console.error("Icon retrieval failed:", error.message);
    res.sendStatus(error.message === "SUPABASE_NOT_CONFIGURED" ? 503 : 404);
  }
});

// Upload configuration
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS),

    filename: (req, file, cb) => {
      cb(
        null,
        crypto.randomUUID() +
        path.extname(file.originalname).toLowerCase()
      );
    }
  }),

  limits: {
    fileSize: 100 * 1024 * 1024,
    files: 2
  },

  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();

    if (file.fieldname === "apk" && ext === ".apk") {
      return cb(null, true);
    }

    if (
      file.fieldname === "icon" &&
      [".png", ".jpg", ".jpeg", ".webp"].includes(ext)
    ) {
      return cb(null, true);
    }

    cb(new Error(
      "Invalid file type. APK must end in .apk; icon must be PNG, JPG, or WebP."
    ));
  }
});

// Submit app using a MediaFire share URL instead of uploading the APK.
app.post("/api/apps", requireAuth, (req, res) => {
  upload.fields([{ name: "icon", maxCount: 1 }])(req, res, async err => {
    if (err) {
      removeFiles(req.files);
      return res.status(400).json({ error: err.code === "LIMIT_FILE_SIZE" ? "File too large. Maximum upload size is 100 MB." : err.message });
    }

    let iconPath = null;
    try {
      const name = String(req.body.name || "").trim();
      const category = String(req.body.category || "");
      const description = String(req.body.description || "").trim();
      const version = String(req.body.version || "").trim();
      const downloadUrl = String(req.body.downloadUrl || "").trim();
      const icon = req.files?.icon?.[0];

      let parsedUrl;
      try { parsedUrl = new URL(downloadUrl); } catch (_) {}
      if (!parsedUrl || parsedUrl.protocol !== "https:" || !["mediafire.com", "www.mediafire.com", "mfi.re"].includes(parsedUrl.hostname.toLowerCase())) {
        removeFiles(req.files);
        return res.status(400).json({ error: "Enter a valid HTTPS MediaFire share link." });
      }
      if (!name || name.length > 70 || !allowedCats.has(category) || !description || description.length > 500 || downloadUrl.length > 2048) {
        removeFiles(req.files);
        return res.status(400).json({ error: "Check the app name, category, description, and MediaFire link." });
      }
      if (icon && icon.size > 2 * 1024 * 1024) {
        removeFiles(req.files);
        return res.status(400).json({ error: "App icon must be 2 MB or smaller." });
      }

      const id = crypto.randomUUID();
      if (icon) {
        if (!supabaseUrl || !supabaseServiceKey) throw new Error("SUPABASE_NOT_CONFIGURED");
        iconPath = `${id}/${crypto.randomUUID()}${path.extname(icon.originalname).toLowerCase()}`;
        await uploadToSupabase(icon.path, iconPath, icon.mimetype || "application/octet-stream");
      }
      const owner = await userById(req.session.userId);
      if (!owner) throw new Error("SESSION_USER_NOT_FOUND");
      await saveApp({
        id, owner_id: req.session.userId, owner_email: owner.email,
        name, category, description, version: version.slice(0, 30),
        icon_file: iconPath, apk_file: null, download_url: downloadUrl,
        apk_original_name: "", size_bytes: 0, status: "pending", rating: "New",
        review_note: "", created_at: new Date().toISOString(), reviewed_at: null
      });
      removeFiles(req.files);
      return res.status(201).json({ ok: true, id, status: "pending" });
    } catch (error) {
      removeFiles(req.files);
      if (iconPath) await deleteSupabaseObjects([iconPath]);
      console.error("App submission error:", error.message);
      return res.status(error.message === "SUPABASE_NOT_CONFIGURED" ? 503 : 500).json({ error: error.message === "SUPABASE_NOT_CONFIGURED" ? "Supabase Storage is not configured for app icons." : "Could not save submission. Check server logs." });
    }
  });
});

// Admin dashboard summary
app.get("/api/admin/stats", requireAuth, requireAdmin, async (req, res) => {
  try {
    const [usersSnap, rows] = await Promise.all([usersCollection.get(), listApps()]);
    res.json({ stats: { totalUsers: usersSnap.size, totalApps: rows.length, pendingApps: rows.filter(a=>a.status==="pending").length, approvedApps: rows.filter(a=>a.status==="approved").length, rejectedApps: rows.filter(a=>a.status==="rejected").length } });
  } catch (error) {
    console.error("Admin stats failed:", error.message);
    res.status(500).json({ error: "Could not load admin statistics." });
  }
});

// Admin pending apps
app.get("/api/admin/apps", requireAuth, requireAdmin, async (req, res) => {
  try {
    const rows = (await listApps()).filter(a => a.status === "pending").sort((a,b) => String(a.created_at || "").localeCompare(String(b.created_at || "")));
    res.json({ apps: rows.map(a => ({ id:a.id, name:a.name, category:a.category, description:a.description, version:a.version, createdAt:a.created_at, ownerEmail:a.owner_email || "" })) });
  } catch (error) {
    console.error("Admin app list failed:", error.message);
    res.status(500).json({ error: "Could not load pending submissions." });
  }
});

// Admin review
app.patch("/api/admin/apps/:id", requireAuth, requireAdmin, async (req, res) => {
  const status = String(req.body.status || "");

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({
      error: "Status must be approved or rejected."
    });
  }

  const note = String(req.body.reviewNote || "").slice(0, 500);

  try {
    const changed = await updateAppReview(req.params.id, status, note);
    if (!changed) return res.status(404).json({ error: "Pending submission not found." });
    return res.json({ ok: true, status });
  } catch (error) {
    console.error("Admin review failed:", error.message);
    return res.status(500).json({ error: "Could not update app review." });
  }
});

// Download approved app: redirect to its validated MediaFire share URL.
app.get("/api/apps/:id/download", async (req, res) => {
  try {
    const appRow = await getAppById(req.params.id);
    if (!appRow || appRow.status !== "approved") return res.status(404).json({ error: "Approved app not found." });
    let target;
    try { target = new URL(String(appRow.download_url || "")); } catch (_) {}
    if (!target || target.protocol !== "https:" || !["mediafire.com", "www.mediafire.com", "mfi.re"].includes(target.hostname.toLowerCase())) {
      return res.status(404).json({ error: "MediaFire download link unavailable." });
    }
    return res.redirect(302, target.toString());
  } catch (error) {
    console.error("APK download redirect failed:", error.message);
    return res.status(500).json({ error: "Could not open the download link." });
  }
});

// Render health check
app.get("/api/health", async (req, res) => {
  const configured = !!(supabaseUrl && supabaseServiceKey);
  try {
    await firestore.collection("_health").doc("check").set({ lastCheckAt: new Date().toISOString() }, { merge: true });
    res.status(configured ? 200 : 503).json({ ok: configured, status: configured ? "healthy" : "storage_not_configured", database: "firestore", fileStorage: configured ? "supabase" : "not_configured" });
  } catch (error) {
    console.error("Health check failed:", error.message);
    res.status(503).json({ ok: false, status: "unhealthy", database: "firestore", fileStorage: configured ? "supabase" : "not_configured" });
  }
});

// Frontend
app.use(express.static(path.join(ROOT, "public")));
app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(ROOT, "public", "admin.html"));
});
// Error handler
app.use((err, req, res, next) => {
  console.error(err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    error: "Unexpected server error."
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`iModStore server running on port ${PORT}`);
});
