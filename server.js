require("dotenv").config();

const express = require("express");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const admin = require("firebase-admin");
const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");

const PORT = Number(process.env.PORT || 8080);
const ROOT = __dirname;
const DATA = process.env.DATA_DIR || path.join(ROOT, "data");
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

const db = new Database(path.join(DATA, "imodstore.sqlite"));

db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  version TEXT,
  icon_file TEXT,
  apk_file TEXT NOT NULL,
  apk_original_name TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  rating TEXT DEFAULT 'New',
  review_note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  FOREIGN KEY(owner_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS otp_challenges (
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  password_hash TEXT,
  expires_at INTEGER NOT NULL,
  last_sent_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(email, purpose)
);

CREATE INDEX IF NOT EXISTS idx_apps_status
ON apps(status);
`);

const q = {
  userByEmail: db.prepare(
    "SELECT * FROM users WHERE email = ?"
  ),

  userById: db.prepare(
    "SELECT id,email,is_admin AS isAdmin FROM users WHERE id = ?"
  ),

  insertUser: db.prepare(
    "INSERT INTO users(email,password_hash,is_admin) VALUES(?,?,?)"
  ),

  insertApp: db.prepare(`
    INSERT INTO apps(
      id,owner_id,name,category,description,version,
      icon_file,apk_file,apk_original_name,size_bytes,status
    )
    VALUES(
      @id,@owner_id,@name,@category,@description,@version,
      @icon_file,@apk_file,@apk_original_name,@size_bytes,'pending'
    )
  `),

  publicApps: db.prepare(`
    SELECT id,name,category,description,version,rating,
    size_bytes,icon_file
    FROM apps
    WHERE status='approved'
    ORDER BY created_at DESC
  `),

  appById: db.prepare(
    "SELECT * FROM apps WHERE id=?"
  ),

  pending: db.prepare(`
    SELECT a.id,a.name,a.category,a.description,a.version,
    a.created_at AS createdAt,u.email AS ownerEmail
    FROM apps a
    JOIN users u ON u.id=a.owner_id
    WHERE a.status='pending'
    ORDER BY a.created_at ASC
  `),

  review: db.prepare(`
    UPDATE apps
    SET status=?,review_note=?,reviewed_at=CURRENT_TIMESTAMP
    WHERE id=? AND status='pending'
  `)
};

// Promote only the explicitly configured account to admin.
// Set ADMIN_EMAIL in Render to an email that has already registered.
const configuredAdminEmail = normalizeEmail(process.env.ADMIN_EMAIL);
if (configuredAdminEmail) {
  const promoteAdmin = db.prepare("UPDATE users SET is_admin=1 WHERE email=?");
  const result = promoteAdmin.run(configuredAdminEmail);
  if (result.changes) console.log(`Admin access enabled for ${configuredAdminEmail}`);
  else console.log(`ADMIN_EMAIL is configured; register ${configuredAdminEmail} first, then redeploy/restart.`);
}

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

function currentUser(req) {
  return req.session.userId
    ? q.userById.get(req.session.userId)
    : null;
}

function requireAdmin(req, res, next) {
  const user = currentUser(req);

  if (!user || !user.isAdmin) {
    return res.status(403).json({
      error: "Admin access required."
    });
  }

  next();
}

function safeUser(user) {
  return {
    id: user.id,
    email: user.email,
    isAdmin: !!user.is_admin
  };
}
function publicApp(appRow) {
  return {
    id: appRow.id,
    name: appRow.name,
    category: appRow.category,
    description: appRow.description,
    version: appRow.version || "",
    rating: appRow.rating || "New",
    size: (appRow.size_bytes / 1024 / 1024).toFixed(1) + " MB",
    iconUrl: appRow.icon_file
      ? "/api/icons/" + path.basename(appRow.icon_file)
      : null
  };
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

    if (q.userByEmail.get(email)) {
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

    const insert = db.transaction(() => {
      if (q.userByEmail.get(email)) {
        throw new Error("EMAIL_EXISTS");
      }

      // Grant admin only to the email explicitly configured on the server.
      const isAdmin = email === normalizeEmail(process.env.ADMIN_EMAIL) ? 1 : 0;
      const result = q.insertUser.run(
        email,
        challenge.password_hash,
        isAdmin
      );

      return result.lastInsertRowid;
    });

    let userId;

    try {
      userId = insert();
    } catch (error) {
      if (error.message === "EMAIL_EXISTS") {
        return res.status(409).json({
          error: "An account with this email already exists."
        });
      }

      throw error;
    }

    await removeChallenge(email, "register");

    // Persist the login session before telling the browser registration succeeded.
    req.session.regenerate((sessionError) => {
      if (sessionError) {
        console.error("Registration session error:", sessionError.message);
        return res.status(500).json({
          error: "Account was created, but login session could not be created. Please log in."
        });
      }

      req.session.userId = userId;
      req.session.save((saveError) => {
        if (saveError) {
          console.error("Registration session save error:", saveError.message);
          return res.status(500).json({
            error: "Account was created, but login session could not be saved. Please log in."
          });
        }

        return res.json({
          ok: true,
          message: "Account created successfully.",
          user: {
            id: userId,
            email,
            isAdmin: email === normalizeEmail(process.env.ADMIN_EMAIL)
          }
        });
      });
    });
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
    const user = q.userByEmail.get(email);
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
    const user = q.userByEmail.get(email);
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

    const user = q.userByEmail.get(email);

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
app.get("/api/auth/me", (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  return res.json({
    ok: true,
    user
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

    const user = q.userByEmail.get(email);

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

    const user = q.userByEmail.get(email);

    if (!user) {
      await removeChallenge(email, "reset");

      return res.status(400).json({
        error: "Account not found."
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    const updatePassword = db.transaction(() => {
      db.prepare(`
        UPDATE users
        SET password_hash=?
        WHERE email=?
      `).run(passwordHash, email);

    });

    updatePassword();
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
app.get("/api/apps", (req, res) => {
  res.json({
    apps: q.publicApps.all().map(publicApp)
  });
});

// App icons
app.get("/api/icons/:file", (req, res) => {
  const file = path.basename(req.params.file);
  const filePath = path.join(UPLOADS, file);

  if (!fs.existsSync(filePath)) {
    return res.sendStatus(404);
  }

  res.setHeader("Cache-Control", "public, max-age=86400");
  res.sendFile(filePath);
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

// Submit app
app.post("/api/apps", requireAuth, (req, res) => {
  upload.fields([
    { name: "apk", maxCount: 1 },
    { name: "icon", maxCount: 1 }
  ])(req, res, err => {
    if (err) {
      removeFiles(req.files);

      return res.status(400).json({
        error: err.code === "LIMIT_FILE_SIZE"
          ? "File too large. Maximum upload size is 100 MB."
          : err.message
      });
    }

    try {
      const name = String(req.body.name || "").trim();
      const category = String(req.body.category || "");
      const description = String(req.body.description || "").trim();
      const version = String(req.body.version || "").trim();

      const apk = req.files?.apk?.[0];
      const icon = req.files?.icon?.[0];

      if (icon && icon.size > 2 * 1024 * 1024) {
        removeFiles(req.files);

        return res.status(400).json({
          error: "App icon must be 2 MB or smaller."
        });
      }

      if (
        !name ||
        name.length > 70 ||
        !allowedCats.has(category) ||
        !description ||
        description.length > 500 ||
        !apk
      ) {
        removeFiles(req.files);

        return res.status(400).json({
          error: "Check required fields and file uploads."
        });
      }

      const id = crypto.randomUUID();

      q.insertApp.run({
        id,
        owner_id: req.session.userId,
        name,
        category,
        description,
        version: version.slice(0, 30),
        icon_file: icon ? icon.filename : null,
        apk_file: apk.filename,
        apk_original_name: path.basename(apk.originalname),
        size_bytes: apk.size
      });

      res.status(201).json({
        ok: true,
        id,
        status: "pending"
      });
    } catch (error) {
      removeFiles(req.files);
      console.error("App submission error:", error.message);

      res.status(500).json({
        error: "Could not save submission."
      });
    }
  });
});

// Admin dashboard summary
app.get("/api/admin/stats", requireAuth, requireAdmin, (req, res) => {
  const count = (sql) => db.prepare(sql).get().count;
  res.json({
    stats: {
      totalUsers: count("SELECT COUNT(*) AS count FROM users"),
      totalApps: count("SELECT COUNT(*) AS count FROM apps"),
      pendingApps: count("SELECT COUNT(*) AS count FROM apps WHERE status='pending'"),
      approvedApps: count("SELECT COUNT(*) AS count FROM apps WHERE status='approved'"),
      rejectedApps: count("SELECT COUNT(*) AS count FROM apps WHERE status='rejected'")
    }
  });
});

// Admin pending apps
app.get("/api/admin/apps", requireAuth, requireAdmin, (req, res) => {
  res.json({
    apps: q.pending.all()
  });
});

// Admin review
app.patch("/api/admin/apps/:id", requireAuth, requireAdmin, (req, res) => {
  const status = String(req.body.status || "");

  if (!["approved", "rejected"].includes(status)) {
    return res.status(400).json({
      error: "Status must be approved or rejected."
    });
  }

  const note = String(req.body.reviewNote || "").slice(0, 500);

  const result = q.review.run(status, note, req.params.id);

  if (!result.changes) {
    return res.status(404).json({
      error: "Pending submission not found."
    });
  }

  res.json({
    ok: true,
    status
  });
});

// Download approved APK
app.get("/api/apps/:id/download", (req, res) => {
  const appRow = q.appById.get(req.params.id);

  if (!appRow || appRow.status !== "approved") {
    return res.status(404).json({
      error: "Approved app not found."
    });
  }

  const filePath = path.join(
    UPLOADS,
    path.basename(appRow.apk_file)
  );

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      error: "APK file missing."
    });
  }

  res.download(
    filePath,
    appRow.apk_original_name.replace(/[^a-zA-Z0-9._-]/g, "_")
  );
});

// Render health check
app.get("/api/health", (req, res) => {
  res.status(200).json({
    ok: true,
    status: "healthy"
  });
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
