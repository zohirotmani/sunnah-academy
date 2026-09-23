
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const Database = require("better-sqlite3");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const PDF_DIR = path.join(PUBLIC_DIR, "pdf");
const DB_PATH = path.join(ROOT, "academy.db");

fs.mkdirSync(PDF_DIR, { recursive: true });
for (let i = 1; i <= 10; i++) fs.mkdirSync(path.join(PDF_DIR, `level-${i}`), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS levels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  sort_order INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS subjects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scholars (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  biography TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  author TEXT DEFAULT '',
  scholar_id INTEGER,
  subject_id INTEGER,
  level_id INTEGER,
  description TEXT DEFAULT '',
  pdf_path TEXT NOT NULL,
  page_count INTEGER DEFAULT 0,
  visible INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scholar_id) REFERENCES scholars(id) ON DELETE SET NULL,
  FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL,
  FOREIGN KEY (level_id) REFERENCES levels(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'student',
  current_level_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (current_level_id) REFERENCES levels(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS reading_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  book_id INTEGER NOT NULL,
  last_page INTEGER DEFAULT 1,
  completed INTEGER DEFAULT 0,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, book_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  book_id INTEGER,
  level_id INTEGER,
  pass_score INTEGER DEFAULT 70,
  question_count INTEGER DEFAULT 10,
  option_count INTEGER DEFAULT 10,
  visible INTEGER DEFAULT 1,
  FOREIGN KEY (book_id) REFERENCES books(id) ON DELETE SET NULL,
  FOREIGN KEY (level_id) REFERENCES levels(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  test_id INTEGER NOT NULL,
  question_text TEXT NOT NULL,
  options_json TEXT NOT NULL,
  correct_index INTEGER NOT NULL,
  explanation TEXT DEFAULT '',
  sort_order INTEGER DEFAULT 0,
  FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  test_id INTEGER NOT NULL,
  score INTEGER NOT NULL,
  correct_count INTEGER NOT NULL,
  total_count INTEGER NOT NULL,
  passed INTEGER DEFAULT 0,
  answers_json TEXT DEFAULT '{}',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE
);
`);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

const sessions = new Map();

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, storedHash] = stored.split(":");
    const computed = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(computed, "hex"), Buffer.from(storedHash, "hex"));
  } catch {
    return false;
  }
}


// Admin bootstrap
// Local defaults keep development simple. On Render/production, set
// ADMIN_EMAIL and ADMIN_PASSWORD in the service Environment variables.
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "admin@academy.local").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "Admin@12345");
const HAS_ADMIN_PASSWORD_ENV = Boolean(process.env.ADMIN_PASSWORD);

const existingAdmin = db.prepare("SELECT * FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1").get();

if (!existingAdmin) {
  db.prepare(`
    INSERT INTO users(name, email, password_hash, role)
    VALUES (?, ?, ?, 'admin')
  `).run("مدير الأكاديمية", ADMIN_EMAIL, hashPassword(ADMIN_PASSWORD));

  console.log("Admin account created:");
  console.log(`Email: ${ADMIN_EMAIL}`);
  if (HAS_ADMIN_PASSWORD_ENV) console.log("Password: taken from ADMIN_PASSWORD environment variable");
  else console.log("Password: local development default");
} else if (HAS_ADMIN_PASSWORD_ENV) {
  // Allows an administrator who forgot the password to reset it from Render's
  // Environment page, without needing Shell/SSH access.
  const duplicate = db.prepare("SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1").get(ADMIN_EMAIL, existingAdmin.id);
  if (!duplicate) {
    db.prepare(`
      UPDATE users
      SET email = ?, password_hash = ?
      WHERE id = ? AND role = 'admin'
    `).run(ADMIN_EMAIL, hashPassword(ADMIN_PASSWORD), existingAdmin.id);
    console.log("Admin account synchronized from environment variables.");
  } else {
    console.warn("ADMIN_EMAIL is already used by another account; admin email was not changed.");
  }
}

function setCookie(res, token) {
  res.setHeader("Set-Cookie", `session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400`);
}

function getSessionUser(req) {
  const raw = req.headers.cookie || "";
  const match = raw.match(/(?:^|;\s*)session=([^;]+)/);
  if (!match) return null;
  const userId = sessions.get(match[1]);
  if (!userId) return null;
  return db.prepare(`
    SELECT id, name, email, role, current_level_id
    FROM users WHERE id = ?
  `).get(userId) || null;
}

function requireStudent(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: "يجب تسجيل الدخول" });
  req.user = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getSessionUser(req);
  if (!user || user.role !== "admin") return res.status(403).json({ error: "غير مصرح" });
  req.user = user;
  next();
}

function safeLevelSlug(value) {
  const v = String(value || "level-1").toLowerCase();
  return /^level-\d+$/.test(v) ? v : "level-1";
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = safeLevelSlug(req.body.level);
    const destination = path.join(PDF_DIR, folder);
    fs.mkdirSync(destination, { recursive: true });
    cb(null, destination);
  },
  filename: (req, file, cb) => {
    const safeName = file.originalname.replace(/[^a-zA-Z0-9\u0600-\u06FF._-]/g, "_");
    cb(null, `${Date.now()}-${safeName}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 150 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") cb(null, true);
    else cb(new Error("PDF files only"));
  }
});

app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(ROOT, "admin", "index.html")));

app.get("/api/health", (req, res) => res.json({ status: "ok", app: "Sunnah Academy" }));

// ---------- Levels ----------
app.get("/api/levels", (req, res) => {
  res.json(db.prepare("SELECT * FROM levels ORDER BY sort_order ASC, id ASC").all());
});

app.post("/api/levels", requireAdmin, (req, res) => {
  const { name, description = "", sort_order = 0 } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "اسم المستوى مطلوب" });
  const result = db.prepare(`
    INSERT INTO levels(name, description, sort_order) VALUES (?, ?, ?)
  `).run(name.trim(), description, Number(sort_order) || 0);
  res.json({ success: true, id: result.lastInsertRowid });
});

// ---------- Subjects ----------
app.get("/api/subjects", (req, res) => {
  res.json(db.prepare("SELECT * FROM subjects ORDER BY id ASC").all());
});

app.post("/api/subjects", requireAdmin, (req, res) => {
  const { name, description = "" } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "اسم المادة مطلوب" });
  const result = db.prepare(`
    INSERT INTO subjects(name, description) VALUES (?, ?)
  `).run(name.trim(), description);
  res.json({ success: true, id: result.lastInsertRowid });
});

// ---------- Scholars ----------
app.get("/api/scholars", (req, res) => {
  res.json(db.prepare("SELECT * FROM scholars ORDER BY name ASC").all());
});

app.post("/api/scholars", requireAdmin, (req, res) => {
  const { name, biography = "" } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "اسم العالم مطلوب" });
  const result = db.prepare(`
    INSERT INTO scholars(name, biography) VALUES (?, ?)
  `).run(name.trim(), biography);
  res.json({ success: true, id: result.lastInsertRowid });
});

// ---------- Books ----------
app.get("/api/books", (req, res) => {
  const books = db.prepare(`
    SELECT b.*, l.name AS level_name, s.name AS subject_name, sc.name AS scholar_name
    FROM books b
    LEFT JOIN levels l ON b.level_id = l.id
    LEFT JOIN subjects s ON b.subject_id = s.id
    LEFT JOIN scholars sc ON b.scholar_id = sc.id
    WHERE b.visible = 1
    ORDER BY b.created_at DESC
  `).all();
  res.json(books);
});

app.post("/api/books", requireAdmin, upload.single("pdf"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "ملف PDF مطلوب" });
    const { title, author = "", scholar_id = null, subject_id = null, level_id = null, description = "", page_count = 0 } = req.body;
    if (!title?.trim()) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "اسم الكتاب مطلوب" });
    }

    const relative = "/" + path.relative(PUBLIC_DIR, req.file.path).replace(/\\/g, "/");
    const result = db.prepare(`
      INSERT INTO books(title, author, scholar_id, subject_id, level_id, description, pdf_path, page_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      title.trim(), author, scholar_id || null, subject_id || null, level_id || null,
      description, relative, Number(page_count) || 0
    );

    res.json({ success: true, id: result.lastInsertRowid, pdf_path: relative });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "حدث خطأ أثناء رفع الكتاب" });
  }
});

app.delete("/api/books/:id", requireAdmin, (req, res) => {
  const book = db.prepare("SELECT pdf_path FROM books WHERE id = ?").get(req.params.id);
  if (!book) return res.status(404).json({ error: "الكتاب غير موجود" });
  const filePath = path.join(PUBLIC_DIR, book.pdf_path.replace(/^[/\\]/, ""));
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  db.prepare("DELETE FROM books WHERE id = ?").run(req.params.id);
  res.json({ success: true });
});

// ---------- Authentication ----------
app.post("/api/auth/register", (req, res) => {
  const { name, email, password, level_id = null } = req.body;
  if (!name?.trim() || !email?.trim() || !password || password.length < 8) {
    return res.status(400).json({ error: "أدخل الاسم والبريد وكلمة مرور لا تقل عن 8 أحرف" });
  }

  try {
    const result = db.prepare(`
      INSERT INTO users(name, email, password_hash, current_level_id)
      VALUES (?, ?, ?, ?)
    `).run(name.trim(), email.trim().toLowerCase(), hashPassword(password), level_id || null);

    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, Number(result.lastInsertRowid));
    setCookie(res, token);
    res.json({ success: true, user: getSessionUser({ headers: { cookie: `session=${token}` } }) });
  } catch {
    res.status(409).json({ error: "البريد الإلكتروني مستخدم من قبل" });
  }
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(String(email || "").trim().toLowerCase());
  if (!user || !verifyPassword(password || "", user.password_hash)) {
    return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
  }
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, user.id);
  setCookie(res, token);
  res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, current_level_id: user.current_level_id } });
});

app.post("/api/auth/logout", (req, res) => {
  const raw = req.headers.cookie || "";
  const match = raw.match(/(?:^|;\s*)session=([^;]+)/);
  if (match) sessions.delete(match[1]);
  res.setHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
  res.json({ success: true });
});

app.get("/api/auth/me", requireStudent, (req, res) => {
  res.json(req.user);
});

// ---------- Student dashboard / progress ----------
app.get("/api/student/dashboard", requireStudent, (req, res) => {
  const user = req.user;
  const level = user.current_level_id
    ? db.prepare("SELECT * FROM levels WHERE id = ?").get(user.current_level_id)
    : null;

  const progress = db.prepare(`
    SELECT rp.*, b.title, b.page_count, b.pdf_path, b.level_id,
           l.name AS level_name, s.name AS subject_name
    FROM reading_progress rp
    JOIN books b ON b.id = rp.book_id
    LEFT JOIN levels l ON l.id = b.level_id
    LEFT JOIN subjects s ON s.id = b.subject_id
    WHERE rp.user_id = ?
    ORDER BY rp.updated_at DESC
  `).all(user.id);

  const attempts = db.prepare(`
    SELECT a.*, t.title AS test_title
    FROM attempts a JOIN tests t ON t.id = a.test_id
    WHERE a.user_id = ?
    ORDER BY a.created_at DESC LIMIT 10
  `).all(user.id);

  res.json({ user, level, progress, attempts });
});

app.post("/api/student/progress", requireStudent, (req, res) => {
  const { book_id, last_page = 1, completed = 0 } = req.body;
  if (!book_id) return res.status(400).json({ error: "الكتاب مطلوب" });
  const page = Math.max(1, Number(last_page) || 1);
  db.prepare(`
    INSERT INTO reading_progress(user_id, book_id, last_page, completed, updated_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id, book_id)
    DO UPDATE SET last_page=excluded.last_page, completed=excluded.completed, updated_at=CURRENT_TIMESTAMP
  `).run(req.user.id, book_id, page, completed ? 1 : 0);
  res.json({ success: true });
});

// ---------- Tests ----------
app.get("/api/tests", (req, res) => {
  const tests = db.prepare(`
    SELECT t.id, t.title, t.description, t.book_id, t.level_id, t.pass_score,
           t.question_count, t.option_count,
           b.title AS book_title, l.name AS level_name
    FROM tests t
    LEFT JOIN books b ON b.id = t.book_id
    LEFT JOIN levels l ON l.id = t.level_id
    WHERE t.visible = 1
    ORDER BY t.id DESC
  `).all();
  res.json(tests);
});

app.get("/api/tests/:id", (req, res) => {
  const test = db.prepare(`
    SELECT t.*, b.title AS book_title, l.name AS level_name
    FROM tests t
    LEFT JOIN books b ON b.id = t.book_id
    LEFT JOIN levels l ON l.id = t.level_id
    WHERE t.id = ? AND t.visible = 1
  `).get(req.params.id);
  if (!test) return res.status(404).json({ error: "الاختبار غير موجود" });

  const questions = db.prepare(`
    SELECT id, question_text, options_json, sort_order
    FROM questions WHERE test_id = ? ORDER BY sort_order ASC, id ASC
  `).all(test.id).map(q => ({
    id: q.id,
    question_text: q.question_text,
    options: JSON.parse(q.options_json)
  }));

  res.json({ ...test, questions });
});

app.post("/api/tests", requireAdmin, (req, res) => {
  const { title, description = "", book_id = null, level_id = null, pass_score = 70 } = req.body;
  if (!title?.trim()) return res.status(400).json({ error: "عنوان الاختبار مطلوب" });

  const result = db.prepare(`
    INSERT INTO tests(title, description, book_id, level_id, pass_score)
    VALUES (?, ?, ?, ?, ?)
  `).run(title.trim(), description, book_id || null, level_id || null, Math.min(100, Math.max(0, Number(pass_score) || 70)));

  res.json({ success: true, id: result.lastInsertRowid });
});

app.post("/api/tests/:id/questions", requireAdmin, (req, res) => {
  const { question_text, options, correct_index, explanation = "", sort_order = 0 } = req.body;
  if (!question_text?.trim() || !Array.isArray(options) || options.length !== 10) {
    return res.status(400).json({ error: "السؤال يجب أن يحتوي على 10 خيارات بالضبط" });
  }
  if (Number(correct_index) < 0 || Number(correct_index) > 9) {
    return res.status(400).json({ error: "الإجابة الصحيحة يجب أن تكون ضمن الخيارات العشرة" });
  }

  const test = db.prepare("SELECT id FROM tests WHERE id = ?").get(req.params.id);
  if (!test) return res.status(404).json({ error: "الاختبار غير موجود" });

  const result = db.prepare(`
    INSERT INTO questions(test_id, question_text, options_json, correct_index, explanation, sort_order)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(req.params.id, question_text.trim(), JSON.stringify(options.map(String)), Number(correct_index), explanation, Number(sort_order) || 0);

  db.prepare("UPDATE tests SET question_count = (SELECT COUNT(*) FROM questions WHERE test_id = ?) WHERE id = ?")
    .run(req.params.id, req.params.id);

  res.json({ success: true, id: result.lastInsertRowid });
});

app.post("/api/tests/:id/submit", requireStudent, (req, res) => {
  const test = db.prepare("SELECT * FROM tests WHERE id = ? AND visible = 1").get(req.params.id);
  if (!test) return res.status(404).json({ error: "الاختبار غير موجود" });

  const questions = db.prepare(`
    SELECT id, correct_index FROM questions
    WHERE test_id = ? ORDER BY sort_order ASC, id ASC
  `).all(test.id);

  const answers = req.body.answers || {};
  let correct = 0;

  for (const q of questions) {
    const userAnswer = Number(answers[q.id]);
    if (Number.isInteger(userAnswer) && userAnswer === q.correct_index) correct++;
  }

  const total = questions.length;
  const score = total ? Math.round((correct / total) * 100) : 0;
  const passed = score >= test.pass_score ? 1 : 0;

  const result = db.prepare(`
    INSERT INTO attempts(user_id, test_id, score, correct_count, total_count, passed, answers_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(req.user.id, test.id, score, correct, total, passed, JSON.stringify(answers));

  // Unlock next level only when the test is passed and the test is associated with a level.
  if (passed && test.level_id) {
    const current = db.prepare("SELECT current_level_id FROM users WHERE id = ?").get(req.user.id);
    const level = db.prepare("SELECT sort_order FROM levels WHERE id = ?").get(test.level_id);
    if (level && (!current.current_level_id || Number(level.sort_order) >= Number(
      (db.prepare("SELECT sort_order FROM levels WHERE id = ?").get(current.current_level_id) || { sort_order: 0 }).sort_order
    ))) {
      const next = db.prepare(`
        SELECT id FROM levels
        WHERE sort_order > ?
        ORDER BY sort_order ASC LIMIT 1
      `).get(level.sort_order);
      if (next) db.prepare("UPDATE users SET current_level_id = ? WHERE id = ?").run(next.id, req.user.id);
    }
  }

  const review = db.prepare(`
    SELECT id, question_text, options_json, correct_index, explanation
    FROM questions WHERE test_id = ? ORDER BY sort_order ASC, id ASC
  `).all(test.id).map(q => ({
    id: q.id,
    question_text: q.question_text,
    options: JSON.parse(q.options_json),
    correct_index: q.correct_index,
    selected_index: Number.isInteger(Number(answers[q.id])) ? Number(answers[q.id]) : null,
    explanation: q.explanation || ""
  }));

  res.json({
    attempt_id: result.lastInsertRowid,
    score, correct_count: correct, total_count: total, passed,
    pass_score: test.pass_score,
    review
  });
});

app.get("/api/attempts/:id", requireStudent, (req, res) => {
  const attempt = db.prepare(`
    SELECT a.*, t.title AS test_title
    FROM attempts a JOIN tests t ON t.id = a.test_id
    WHERE a.id = ? AND a.user_id = ?
  `).get(req.params.id, req.user.id);
  if (!attempt) return res.status(404).json({ error: "المحاولة غير موجودة" });
  res.json(attempt);
});


// ---------- Admin account ----------
app.put("/api/admin/account", requireAdmin, (req, res) => {
  const { email, current_password, new_password, name } = req.body;

  if (!email?.trim() || !current_password) {
    return res.status(400).json({ error: "البريد الإلكتروني وكلمة المرور الحالية مطلوبان" });
  }

  const admin = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'admin'").get(req.user.id);
  if (!admin || !verifyPassword(current_password, admin.password_hash)) {
    return res.status(401).json({ error: "كلمة المرور الحالية غير صحيحة" });
  }

  const normalizedEmail = email.trim().toLowerCase();

  const duplicate = db.prepare(
    "SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1"
  ).get(normalizedEmail, admin.id);

  if (duplicate) {
    return res.status(409).json({ error: "هذا البريد مستخدم من حساب آخر" });
  }

  if (new_password !== undefined && String(new_password).length > 0 && String(new_password).length < 8) {
    return res.status(400).json({ error: "كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف" });
  }

  let passwordHash = admin.password_hash;

  if (new_password && String(new_password).length >= 8) {
    passwordHash = hashPassword(String(new_password));
  }

  db.prepare(`
    UPDATE users
    SET name = ?, email = ?, password_hash = ?
    WHERE id = ? AND role = 'admin'
  `).run(
    name?.trim() || admin.name,
    normalizedEmail,
    passwordHash,
    admin.id
  );

  res.json({
    success: true,
    user: db.prepare(`
      SELECT id, name, email, role, current_level_id
      FROM users WHERE id = ?
    `).get(admin.id)
  });
});

// ---------- Admin quick endpoint ----------
app.get("/api/admin/summary", requireAdmin, (req, res) => {
  const count = table => db.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get().c;
  res.json({
    levels: count("levels"), subjects: count("subjects"), scholars: count("scholars"),
    books: count("books"), students: db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='student'").get().c,
    tests: count("tests"), questions: count("questions")
  });
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: error.message || "Server error" });
});

app.listen(PORT, () => {
  console.log("=================================");
  console.log("Sunnah Academy is running");
  console.log(`http://localhost:${PORT}`);
  console.log(`http://localhost:${PORT}/admin`);
  console.log("=================================");
});
