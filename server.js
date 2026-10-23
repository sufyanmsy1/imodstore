require("dotenv").config();

const express = require("express");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const nodemailer = require("nodemailer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

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

// Email configuration
const smtpPort = Number(process.env.SMTP_PORT || 587);

let transporter = null;

if (
  process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS &&
  process.env.SMTP_FROM
) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

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

async function sendOtp(email, purpose, otp) {
  if (!transporter) {
    throw new Error("SMTP_NOT_CONFIGURED");
  }

  await transporter.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: purpose === "register"
      ? "Your iModStore verification code"
      : "Your iModStore password reset code",
    text:
      `Your iModStore verification code is ${otp}.\n\n` +
      "It expires in 10 minutes. Do not share this code with anyone.",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto">
        <h2>iModStore</h2>
        <p>Your verification code is:</p>
        <div style="font-size:32px;font-weight:bold;letter-spacing:8px">
          ${otp}
        </div>
        <p>This code expires in 10 minutes.</p>
        <p>If you did not request this code, ignore this email.</p>
      </div>
    `
  });
}

const findChallenge = db.prepare(`
  SELECT * FROM otp_challenges
  WHERE email=? AND purpose=?
`);

const saveChallenge = db.prepare(`
  INSERT INTO otp_challenges(
    email,purpose,otp_hash,password_hash,
    expires_at,last_sent_at,attempts
  )
  VALUES(?,?,?,?,?,?,0)
  ON CONFLICT(email,purpose) DO UPDATE SET
    otp_hash=excluded.otp_hash,
    password_hash=excluded.password_hash,
    expires_at=excluded.expires_at,
    last_sent_at=excluded.last_sent_at,
    attempts=0
`);

const deleteChallenge = db.prepare(`
  DELETE FROM otp_challenges
  WHERE email=? AND purpose=?
`);

async function createAndSendOtp(email, purpose, passwordHash = null) {
  const now = Date.now();
  const existing = findChallenge.get(email, purpose);

  if (existing && now - existing.last_sent_at < 60_000) {
    return {
      ok: false,
      status: 429,
      error: "Please wait 60 seconds before requesting another OTP."
    };
  }

  const otp = String(crypto.randomInt(0, 1_000_000))
    .padStart(6, "0");

  // Send first; do not save a new challenge if email delivery fails.
  await sendOtp(email, purpose, otp);

  saveChallenge.run(
    email,
    purpose,
    hashOtp(email, purpose, otp),
    passwordHash,
    now + 10 * 60_000,
    now
  );

  return { ok: true };
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "iModStore API"
  });
});

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
        error: "Password must be 8–128 characters."
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
      return res.status(result.status).json({
        error: result.error
      });
    }

    res.json({
      ok: true,
      message: "Verification code sent to your email."
    });
  } catch (error) {
    console.error("Registration OTP error:", error.message);

    res.status(500).json({
      error: "Could not send OTP. Check email configuration."
    });
  }
});

// Verify registration OTP and create account
app.post("/api/auth/verify-otp", (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();

    if (!validEmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        error: "Enter a valid email and 6-digit OTP."
      });
    }

    const challenge = findChallenge.get(email, "register");

    if (!challenge) {
      return res.status(400).json({
        error: "Request a new verification code."
      });
    }

    if (Date.now() > challenge.expires_at) {
      deleteChallenge.run(email, "register");

      return res.status(400).json({
        error: "OTP expired. Request a new code."
      });
    }

    if (challenge.attempts >= 5) {
      deleteChallenge.run(email, "register");

      return res.status(429).json({
        error: "Too many attempts. Request a new OTP."
      });
    }

    const suppliedHash = hashOtp(email, "register", otp);

    if (!safeHashCompare(suppliedHash, challenge.otp_hash)) {
      db.prepare(`
        UPDATE otp_challenges
        SET attempts=attempts+1
        WHERE email=? AND purpose='register'
      `).run(email);

      return res.status(400).json({
        error: "Incorrect OTP."
      });
    }

    if (q.userByEmail.get(email)) {
      deleteChallenge.run(email, "register");

      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const createAccount = db.transaction(() => {
      const result = q.insertUser.run(
        email,
        challenge.password_hash,
        0
      );

      deleteChallenge.run(email, "register");

      return Number(result.lastInsertRowid);
    });

    const userId = createAccount();

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          error: "Account created, but session could not start. Please log in."
        });
      }

      req.session.userId = userId;

      req.session.save(saveErr => {
        if (saveErr) {
          return res.status(500).json({
            error: "Account created, but session could not start. Please log in."
          });
        }

        const user = db.prepare(
          "SELECT * FROM users WHERE id=?"
        ).get(userId);

        res.json({
          ok: true,
          user: safeUser(user)
        });
      });
    });
  } catch (error) {
    console.error("Registration verification error:", error.message);

    res.status(500).json({
      error: "Could not verify OTP."
    });
  }
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

    // Use a generic response to avoid exposing account existence.
    if (!user) {
      return res.json({
        ok: true,
        message: "If the account exists, a verification code will be sent."
      });
    }

    const result = await createAndSendOtp(email, "reset");

    if (!result.ok) {
      return res.status(result.status).json({
        error: result.error
      });
    }

    res.json({
      ok: true,
      message: "If the account exists, a verification code will be sent."
    });
  } catch (error) {
    console.error("Password reset OTP error:", error.message);

    res.status(500).json({
      error: "Could not send OTP. Check email configuration."
    });
  }
});

// Verify reset OTP and set new password
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();
    const password = String(req.body.password || "");

    if (!validEmail(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        error: "Enter a valid email and 6-digit OTP."
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: "New password must be 8–128 characters."
      });
    }

    const challenge = findChallenge.get(email, "reset");

    if (!challenge) {
      return res.status(400).json({
        error: "Request a new password reset code."
      });
    }

    if (Date.now() > challenge.expires_at) {
      deleteChallenge.run(email, "reset");

      return res.status(400).json({
        error: "OTP expired. Request a new code."
      });
    }

    if (challenge.attempts >= 5) {
      deleteChallenge.run(email, "reset");

      return res.status(429).json({
        error: "Too many attempts. Request a new OTP."
      });
    }

    const suppliedHash = hashOtp(email, "reset", otp);

    if (!safeHashCompare(suppliedHash, challenge.otp_hash)) {
      db.prepare(`
        UPDATE otp_challenges
        SET attempts=attempts+1
        WHERE email=? AND purpose='reset'
      `).run(email);

      return res.status(400).json({
        error: "Incorrect OTP."
      });
    }

    const user = q.userByEmail.get(email);

    if (!user) {
      deleteChallenge.run(email, "reset");

      return res.status(400).json({
        error: "Unable to reset password. Request a new code."
      });
    }

    const newHash = await bcrypt.hash(password, 12);

    const resetPassword = db.transaction(() => {
      db.prepare(
        "UPDATE users SET password_hash=? WHERE id=?"
      ).run(newHash, user.id);

      deleteChallenge.run(email, "reset");
    });

    resetPassword();

    res.json({
      ok: true,
      message: "Password changed successfully. Please log in again."
    });
  } catch (error) {
    console.error("Password reset error:", error.message);

    res.status(500).json({
      error: "Could not reset password."
    });
  }
});

// Disable direct registration to prevent OTP bypass.
app.post("/api/auth/register", (req, res) => {
  res.status(410).json({
    error: "Use Email OTP registration."
  });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    const user = q.userByEmail.get(email);

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Email or password is incorrect."
      });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({
          error: "Could not start session."
        });
      }

      req.session.userId = user.id;

      req.session.save(saveErr => {
        if (saveErr) {
          return res.status(500).json({
            error: "Could not start session."
          });
        }

        res.json({
          user: safeUser(user)
        });
      });
    });
  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

// Current user
app.get("/api/auth/me", (req, res) => {
  const user = currentUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  res.json({ user });
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ ok: true });
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

// Frontend
app.use(express.static(path.join(ROOT, "public")));

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

app.listen(PORT, () => {
  console.log(`iModStore server running on port ${PORT}`);
});
