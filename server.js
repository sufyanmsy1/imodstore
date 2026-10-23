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

const app = express();
app.set("trust proxy", 1);
const PORT = Number(process.env.PORT || 8080);
const ROOT = __dirname;
const DATA = path.join(ROOT, "data");
const UPLOADS = path.join(ROOT, "uploads");
fs.mkdirSync(UPLOADS, { recursive: true });
fs.mkdirSync(DATA, {recursive:true}); fs.mkdirSync(UPLOADS, {recursive:true});
const db = new Database(path.join(DATA, "imodstore.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS apps(id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, name TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL, version TEXT, icon_file TEXT, apk_file TEXT NOT NULL, apk_original_name TEXT NOT NULL, size_bytes INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', rating TEXT DEFAULT 'New', review_note TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, reviewed_at TEXT, FOREIGN KEY(owner_id) REFERENCES users(id));
`);
const q = {
 userByEmail: db.prepare("SELECT * FROM users WHERE email=?"),
 userById: db.prepare("SELECT id,email,is_admin AS isAdmin FROM users WHERE id=?"),
 insertUser: db.prepare("INSERT INTO users(email,password_hash,is_admin) VALUES(?,?,?)"),
 insertApp: db.prepare(`INSERT INTO apps(id,owner_id,name,category,description,version,icon_file,apk_file,apk_original_name,size_bytes,status) VALUES(@id,@owner_id,@name,@category,@description,@version,@icon_file,@apk_file,@apk_original_name,@size_bytes,'pending')`),

publicApps: db.prepare(`SELECT id,name,category,description,version,rating,size_bytes,icon_file FROM apps WHERE status='approved' ORDER BY created_at DESC`),

 appById: db.prepare("SELECT * FROM apps WHERE id=?"),
 pending: db.prepare(`SELECT a.id,a.name,a.category,a.description,a.version,a.created_at AS createdAt,u.email AS ownerEmail FROM apps a JOIN users u ON u.id=a.owner_id WHERE a.status='pending' ORDER BY a.created_at ASC`),
 review: db.prepare("UPDATE apps SET status=?,review_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'")
};
const allowedCats = new Set(["Games","Productivity","Photography","Education","Entertainment","Tools","Kids","Social","Health & fitness","Finance","Travel","Lifestyle","Music & audio","Books & reference","Business","News","Food & drink","Maps & navigation","Personalization"]);
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret || sessionSecret.length < 32) {
  console.error("ERROR: Set SESSION_SECRET in .env to a random secret of at least 32 characters.");
  process.exit(1);
}
app.disable("x-powered-by");
app.use((req,res,next)=>{res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");res.setHeader("X-Frame-Options","DENY");next()});
app.use(express.json({limit:"30kb"}));
app.use(session({
  store:new SQLiteStore({db:"sessions.sqlite",dir:DATA}),
  secret:sessionSecret,resave:false,saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:1000*60*60*24*7}
}));
const upload = multer({
  storage:multer.diskStorage({
    destination:(req,file,cb)=>cb(null,UPLOADS),
    filename:(req,file,cb)=>cb(null,crypto.randomUUID()+path.extname(file.originalname).toLowerCase())
  }),
  limits:{fileSize:100*1024*1024,files:2},
  fileFilter:(req,file,cb)=>{
    const ext=path.extname(file.originalname).toLowerCase();
    if(file.fieldname==="apk" && ext===".apk") return cb(null,true);
    if(file.fieldname==="icon" && [".png",".jpg",".jpeg",".webp"].includes(ext)) return cb(null,true);
    cb(new Error("Invalid file type. APK must end in .apk; icon must be PNG, JPG, or WebP."));
  }
});
function requireAuth(req,res,next){if(!req.session.userId)return res.status(401).json({error:"Please log in first."});next()}
function currentUser(req){return req.session.userId?q.userById.get(req.session.userId):null}
function requireAdmin(req,res,next){const u=currentUser(req);if(!u||!u.isAdmin)return res.status(403).json({error:"Admin access required."});next()}
function safeUser(u){return {id:u.id,email:u.email,isAdmin:!!u.is_admin}}
function removeFiles(files){for(const f of Object.values(files||{}).flat())if(f&&f.path)fs.promises.unlink(f.path).catch(()=>{})}
function publicApp(a){return {id:a.id,name:a.name,category:a.category,description:a.description,version:a.version||"",rating:a.rating||"New",size:(a.size_bytes/1024/1024).toFixed(1)+" MB",iconUrl:a.icon_file?"/api/icons/"+path.basename(a.icon_file):null}}
app.get("/api/health",(req,res)=>res.json({ok:true,service:"iModStore API"}));
app.post("/api/auth/register",async(req,res)=>{try{const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:"Enter a valid email address."});if(password.length<8||password.length>128)return res.status(400).json({error:"Password must be 8–128 characters."});if(q.userByEmail.get(email))return res.status(409).json({error:"An account with this email already exists."});const hash=await bcrypt.hash(password,12);const result=q.insertUser.run(email,hash,0);req.session.userId=Number(result.lastInsertRowid);req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Could not start session."});req.session.userId=Number(result.lastInsertRowid);res.json({user:safeUser(db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId))})})}catch(e){res.status(500).json({error:"Registration failed."})}});
app.post("/api/auth/login",async(req,res)=>{try{const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");const u=q.userByEmail.get(email);if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Email or password is incorrect."});req.session.regenerate(err=>{if(err)return res.status(500).json({error:"Could not start session."});req.session.userId=u.id;res.json({user:safeUser(u)})})}catch(e){res.status(500).json({error:"Login failed."})}});
app.get("/api/auth/me",(req,res)=>{const u=currentUser(req);if(!u)return res.status(401).json({error:"Not logged in."});res.json({user:u})});
app.post("/api/auth/logout",(req,res)=>req.session.destroy(()=>{res.clearCookie("connect.sid");res.json({ok:true})}));
app.get("/api/apps",(req,res)=>res.json({apps:q.publicApps.all().map(publicApp)}));
app.get("/api/icons/:file",(req,res)=>{const file=path.basename(req.params.file),p=path.join(UPLOADS,file);if(!fs.existsSync(p))return res.sendStatus(404);res.setHeader("Cache-Control","public, max-age=86400");res.sendFile(p)});
app.post("/api/apps",requireAuth,(req,res)=>{upload.fields([{name:"apk",maxCount:1},{name:"icon",maxCount:1}])(req,res,err=>{if(err){removeFiles(req.files);return res.status(400).json({error:err.code==="LIMIT_FILE_SIZE"?"File too large. Maximum upload size is 100 MB.":err.message})}try{const name=String(req.body.name||"").trim(),category=String(req.body.category||""),description=String(req.body.description||"").trim(),version=String(req.body.version||"").trim();const apk=req.files?.apk?.[0],icon=req.files?.icon?.[0];if(icon && icon.size > 2*1024*1024){removeFiles(req.files);return res.status(400).json({error:"App icon must be 2 MB or smaller."})}if(!name||name.length>70||!allowedCats.has(category)||!description||description.length>500||!apk){removeFiles(req.files);return res.status(400).json({error:"Check required fields and file uploads."})}const id=crypto.randomUUID();q.insertApp.run({id,owner_id:req.session.userId,name,category,description,version:version.slice(0,30),icon_file:icon?icon.filename:null,apk_file:apk.filename,apk_original_name:path.basename(apk.originalname),size_bytes:apk.size});res.status(201).json({ok:true,id,status:"pending"})}catch(e){removeFiles(req.files);console.error(e);res.status(500).json({error:"Could not save submission."})}})});
app.get("/api/admin/apps",requireAuth,requireAdmin,(req,res)=>res.json({apps:q.pending.all()}));
app.patch("/api/admin/apps/:id",requireAuth,requireAdmin,(req,res)=>{const status=String(req.body.status||"");if(!["approved","rejected"].includes(status))return res.status(400).json({error:"Status must be approved or rejected."});const note=String(req.body.reviewNote||"").slice(0,500);const r=q.review.run(status,note,req.params.id);if(!r.changes)return res.status(404).json({error:"Pending submission not found."});res.json({ok:true,status})});
app.get("/api/apps/:id/download",(req,res)=>{const a=q.appById.get(req.params.id);if(!a||a.status!=="approved")return res.status(404).json({error:"Approved app not found."});const p=path.join(UPLOADS,path.basename(a.apk_file));if(!fs.existsSync(p))return res.status(404).json({error:"APK file missing."});res.download(p,a.apk_original_name.replace(/[^a-zA-Z0-9._-]/g,"_"))});
app.use(express.static(path.join(ROOT,"public")));
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:"Unexpected server error."})});
app.listen(PORT,()=>console.log(`iModStore server running at http://localhost:${PORT}`));
