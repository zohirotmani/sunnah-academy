const express = require("express");
const path = require("path");
const crypto = require("crypto");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, "public");
const ADMIN_DIR = path.join(ROOT, "admin");

const SUPABASE_URL = String(process.env.SUPABASE_URL || "").trim();
const SUPABASE_SECRET_KEY = String(process.env.SUPABASE_SECRET_KEY || "").trim();
const STORAGE_BUCKET = "books";
const SCHOLARS_BUCKET = "scholars";

if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  throw new Error("SUPABASE_URL and SUPABASE_SECRET_KEY are required in production.");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: { autoRefreshToken: false, persistSession: false }
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

const sessions = new Map();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 150 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") cb(null, true);
    else cb(new Error("PDF files only"));
  }
});

const scholarUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype && file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Image files only"));
  }
});

function publicStoragePath(publicUrl, bucket) {
  const marker = `/storage/v1/object/public/${bucket}/`;
  const index = String(publicUrl || "").indexOf(marker);
  return index >= 0 ? String(publicUrl).slice(index + marker.length) : null;
}

async function uploadScholarImage(file) {
  if (!file) return null;
  const ext = (file.originalname || "image").split(".").pop().toLowerCase().replace(/[^a-z0-9]/g, "");
  const filePath = `scholars/${Date.now()}-${crypto.randomBytes(6).toString("hex")}.${ext || "jpg"}`;
  const { error } = await supabase.storage.from(SCHOLARS_BUCKET).upload(filePath, file.buffer, {
    contentType: file.mimetype,
    upsert: false
  });
  if (error) throw error;
  const { data } = supabase.storage.from(SCHOLARS_BUCKET).getPublicUrl(filePath);
  return data.publicUrl;
}

async function deleteScholarImage(publicUrl) {
  const path = publicStoragePath(publicUrl, SCHOLARS_BUCKET);
  if (!path) return;
  const { error } = await supabase.storage.from(SCHOLARS_BUCKET).remove([path]);
  if (error && !String(error.message || "").toLowerCase().includes("not found")) throw error;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, storedHash] = String(stored || "").split(":");
    const computed = crypto.scryptSync(password, salt, 64).toString("hex");
    return crypto.timingSafeEqual(Buffer.from(computed, "hex"), Buffer.from(storedHash, "hex"));
  } catch {
    return false;
  }
}

function cleanInt(value, fallback = null) {
  if (value === null || value === undefined || value === "") return fallback;
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function setCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400`
  );
}

function getSessionToken(req) {
  const raw = req.headers.cookie || "";
  const match = raw.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? match[1] : null;
}

async function getSessionUser(req) {
  const token = getSessionToken(req);
  if (!token) return null;
  const userId = sessions.get(token);
  if (!userId) return null;

  const { data, error } = await supabase
    .from("users")
    .select("id,name,email,role,current_level_id")
    .eq("id", userId)
    .maybeSingle();

  if (error) throw error;
  return data || null;
}

async function requireStudent(req, res, next) {
  try {
    const user = await getSessionUser(req);
    if (!user) return res.status(401).json({ error: "يجب تسجيل الدخول" });
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

async function requireAdmin(req, res, next) {
  try {
    const user = await getSessionUser(req);
    if (!user || user.role !== "admin") return res.status(403).json({ error: "غير مصرح" });
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

function safeFileName(originalName) {
  return String(originalName || "book.pdf").replace(/[^a-zA-Z0-9\u0600-\u06FF._-]/g, "_");
}

function levelFolder(value) {
  const match = String(value || "level-1").match(/^level-(\d+)$/i);
  return match ? `level-${Number(match[1])}` : "level-1";
}

async function ensureAdmin() {
  const adminEmail = String(process.env.ADMIN_EMAIL || "admin@academy.local").trim().toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || "Admin@12345");
  const hasAdminPasswordEnv = Boolean(process.env.ADMIN_PASSWORD);

  const { data: existingAdmin, error } = await supabase
    .from("users")
    .select("*")
    .eq("role", "admin")
    .order("id", { ascending: true })
    .limit(1)
    .maybeSingle();

  if (error) throw error;

  if (!existingAdmin) {
    const { error: insertError } = await supabase.from("users").insert({
      name: "مدير الأكاديمية",
      email: adminEmail,
      password_hash: hashPassword(adminPassword),
      role: "admin"
    });
    if (insertError) throw insertError;
    console.log("Admin account created.");
    console.log(`Email: ${adminEmail}`);
    console.log(hasAdminPasswordEnv ? "Password: from ADMIN_PASSWORD" : "Password: local default");
    return;
  }

  if (hasAdminPasswordEnv) {
    const { data: duplicate, error: duplicateError } = await supabase
      .from("users")
      .select("id")
      .eq("email", adminEmail)
      .neq("id", existingAdmin.id)
      .limit(1)
      .maybeSingle();
    if (duplicateError) throw duplicateError;

    if (!duplicate) {
      const { error: updateError } = await supabase
        .from("users")
        .update({ email: adminEmail, password_hash: hashPassword(adminPassword) })
        .eq("id", existingAdmin.id)
        .eq("role", "admin");
      if (updateError) throw updateError;
      console.log("Admin account synchronized from environment variables.");
    } else {
      console.warn("ADMIN_EMAIL is already used by another account; admin email was not changed.");
    }
  }
}

async function getLevels() {
  const { data, error } = await supabase
    .from("levels")
    .select("*")
    .order("sort_order", { ascending: true })
    .order("id", { ascending: true });
  if (error) throw error;
  return data || [];
}

async function getSubjects() {
  const { data, error } = await supabase.from("subjects").select("*").order("id", { ascending: true });
  if (error) throw error;
  return data || [];
}

async function getScholars() {
  const { data, error } = await supabase.from("scholars").select("*").order("name", { ascending: true });
  if (error) throw error;
  return data || [];
}

async function getBooks() {
  const [{ data: books, error: booksError }, { data: levels, error: levelsError }, { data: subjects, error: subjectsError }, { data: scholars, error: scholarsError }] = await Promise.all([
    supabase.from("books").select("*").eq("visible", true).order("created_at", { ascending: false }),
    supabase.from("levels").select("id,name"),
    supabase.from("subjects").select("id,name"),
    supabase.from("scholars").select("id,name")
  ]);

  if (booksError) throw booksError;
  if (levelsError) throw levelsError;
  if (subjectsError) throw subjectsError;
  if (scholarsError) throw scholarsError;

  const levelMap = new Map((levels || []).map(x => [Number(x.id), x.name]));
  const subjectMap = new Map((subjects || []).map(x => [Number(x.id), x.name]));
  const scholarMap = new Map((scholars || []).map(x => [Number(x.id), x.name]));

  return (books || []).map(book => ({
    ...book,
    level_name: levelMap.get(Number(book.level_id)) || null,
    subject_name: subjectMap.get(Number(book.subject_id)) || null,
    scholar_name: scholarMap.get(Number(book.scholar_id)) || null,
    pdf_path: `/api/books/${book.id}/pdf`
  }));
}

async function getBookRow(id) {
  const { data, error } = await supabase.from("books").select("*").eq("id", id).maybeSingle();
  if (error) throw error;
  return data || null;
}

async function getTests() {
  const [{ data: tests, error: testsError }, { data: books, error: booksError }, { data: levels, error: levelsError }] = await Promise.all([
    supabase.from("tests").select("*").eq("visible", true).order("id", { ascending: false }),
    supabase.from("books").select("id,title"),
    supabase.from("levels").select("id,name")
  ]);
  if (testsError) throw testsError;
  if (booksError) throw booksError;
  if (levelsError) throw levelsError;

  const bookMap = new Map((books || []).map(x => [Number(x.id), x.title]));
  const levelMap = new Map((levels || []).map(x => [Number(x.id), x.name]));
  return (tests || []).map(t => ({
    id: t.id,
    title: t.title,
    description: t.description,
    book_id: t.book_id,
    level_id: t.level_id,
    pass_score: t.pass_score,
    question_count: t.question_count,
    option_count: t.option_count,
    book_title: bookMap.get(Number(t.book_id)) || null,
    level_name: levelMap.get(Number(t.level_id)) || null
  }));
}

app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(ADMIN_DIR, "index.html")));
app.get("/api/health", (req, res) => res.json({ status: "ok", app: "Sunnah Academy", storage: "supabase" }));

// ---------- Levels ----------
app.get("/api/levels", async (req, res, next) => {
  try { res.json(await getLevels()); } catch (e) { next(e); }
});

app.post("/api/levels", requireAdmin, async (req, res, next) => {
  try {
    const { name, description = "", sort_order = 0 } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "اسم المستوى مطلوب" });
    const { data, error } = await supabase.from("levels").insert({
      name: name.trim(), description, sort_order: cleanInt(sort_order, 0)
    }).select("id").single();
    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch (e) { next(e); }
});

app.put("/api/levels/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const { name, description = "", sort_order = 0 } = req.body;
    if (!Number.isInteger(id) || !name?.trim()) {
      return res.status(400).json({ error: "بيانات المستوى غير صحيحة" });
    }
    const { data: current, error: currentError } = await supabase
      .from("levels").select("id").eq("id", id).maybeSingle();
    if (currentError) throw currentError;
    if (!current) return res.status(404).json({ error: "المستوى غير موجود" });

    const { error } = await supabase.from("levels").update({
      name: name.trim(),
      description,
      sort_order: cleanInt(sort_order, 0)
    }).eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { next(e); }
});

app.delete("/api/levels/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: "معرّف المستوى غير صحيح" });
    const { error } = await supabase.from("levels").delete().eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { next(e); }
});

// ---------- Subjects ----------
app.get("/api/subjects", async (req, res, next) => {
  try { res.json(await getSubjects()); } catch (e) { next(e); }
});

app.post("/api/subjects", requireAdmin, async (req, res, next) => {
  try {
    const { name, description = "" } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "اسم المادة مطلوب" });
    const { data, error } = await supabase.from("subjects").insert({ name: name.trim(), description }).select("id").single();
    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch (e) { next(e); }
});

app.put("/api/subjects/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const { name, description = "" } = req.body;
    if (!Number.isInteger(id) || !name?.trim()) {
      return res.status(400).json({ error: "بيانات المادة غير صحيحة" });
    }
    const { data: current, error: currentError } = await supabase
      .from("subjects").select("id").eq("id", id).maybeSingle();
    if (currentError) throw currentError;
    if (!current) return res.status(404).json({ error: "المادة غير موجودة" });

    const { error } = await supabase.from("subjects").update({
      name: name.trim(),
      description
    }).eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { next(e); }
});

app.delete("/api/subjects/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: "معرّف المادة غير صحيح" });
    const { error } = await supabase.from("subjects").delete().eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { next(e); }
});

// ---------- Scholars ----------
app.get("/api/scholars", async (req, res, next) => {
  try { res.json(await getScholars()); } catch (e) { next(e); }
});

app.post("/api/scholars", requireAdmin, scholarUpload.single("image"), async (req, res, next) => {
  try {
    const { name, biography = "" } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: "اسم العالم مطلوب" });
    const image_url = await uploadScholarImage(req.file);
    const { data, error } = await supabase.from("scholars").insert({
      name: name.trim(),
      biography,
      image_url: image_url || ""
    }).select("id").single();
    if (error) {
      if (image_url) await deleteScholarImage(image_url).catch(() => {});
      throw error;
    }
    res.json({ success: true, id: data.id });
  } catch (e) { next(e); }
});

app.put("/api/scholars/:id", requireAdmin, scholarUpload.single("image"), async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const { name, biography = "" } = req.body;
    if (!Number.isInteger(id) || !name?.trim()) return res.status(400).json({ error: "بيانات العالم غير صحيحة" });

    const { data: current, error: currentError } = await supabase
      .from("scholars")
      .select("id,name,biography,image_url")
      .eq("id", id)
      .maybeSingle();
    if (currentError) throw currentError;
    if (!current) return res.status(404).json({ error: "العالم غير موجود" });

    let image_url = current.image_url || "";
    if (req.file) image_url = await uploadScholarImage(req.file);

    const { error } = await supabase.from("scholars").update({
      name: name.trim(),
      biography,
      image_url
    }).eq("id", id);
    if (error) {
      if (req.file && image_url) await deleteScholarImage(image_url).catch(() => {});
      throw error;
    }

    if (req.file && current.image_url && current.image_url !== image_url) {
      await deleteScholarImage(current.image_url).catch(() => {});
    }
    res.json({ success: true });
  } catch (e) { next(e); }
});

app.delete("/api/scholars/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id)) return res.status(400).json({ error: "معرّف العالم غير صحيح" });
    const { data: current, error: currentError } = await supabase
      .from("scholars")
      .select("id,image_url")
      .eq("id", id)
      .maybeSingle();
    if (currentError) throw currentError;
    if (!current) return res.status(404).json({ error: "العالم غير موجود" });

    const { error } = await supabase.from("scholars").delete().eq("id", id);
    if (error) throw error;
    if (current.image_url) await deleteScholarImage(current.image_url).catch(() => {});
    res.json({ success: true });
  } catch (e) { next(e); }
});

// ---------- Books ----------
app.get("/api/books", async (req, res, next) => {
  try { res.json(await getBooks()); } catch (e) { next(e); }
});

app.post("/api/books", requireAdmin, upload.single("pdf"), async (req, res, next) => {
  let objectPath = null;
  try {
    if (!req.file) return res.status(400).json({ error: "ملف PDF مطلوب" });
    const {
      title,
      author = "",
      scholar_id = null,
      subject_id = null,
      level_id = null,
      description = "",
      page_count = 0,
      level = "level-1"
    } = req.body;

    if (!title?.trim()) return res.status(400).json({ error: "اسم الكتاب مطلوب" });

    objectPath = `${levelFolder(level)}/${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${safeFileName(req.file.originalname)}`;
    const { error: uploadError } = await supabase.storage
      .from(STORAGE_BUCKET)
      .upload(objectPath, req.file.buffer, { contentType: "application/pdf", upsert: false });
    if (uploadError) throw uploadError;

    const { data, error } = await supabase.from("books").insert({
      title: title.trim(),
      author,
      scholar_id: cleanInt(scholar_id),
      subject_id: cleanInt(subject_id),
      level_id: cleanInt(level_id),
      description,
      pdf_path: objectPath,
      page_count: cleanInt(page_count, 0),
      visible: true
    }).select("id,pdf_path").single();

    if (error) {
      await supabase.storage.from(STORAGE_BUCKET).remove([objectPath]);
      throw error;
    }

    res.json({ success: true, id: data.id, pdf_path: `/api/books/${data.id}/pdf` });
  } catch (e) { next(e); }
});

app.get("/api/books/:id/pdf", async (req, res, next) => {
  try {
    const book = await getBookRow(req.params.id);
    if (!book) return res.status(404).send("الكتاب غير موجود");
    const { data, error } = await supabase.storage
      .from(STORAGE_BUCKET)
      .createSignedUrl(book.pdf_path, 3600);
    if (error) throw error;
    res.redirect(data.signedUrl);
  } catch (e) { next(e); }
});

app.delete("/api/books/:id", requireAdmin, async (req, res, next) => {
  try {
    const book = await getBookRow(req.params.id);
    if (!book) return res.status(404).json({ error: "الكتاب غير موجود" });

    if (book.pdf_path) {
      const { error: storageError } = await supabase.storage.from(STORAGE_BUCKET).remove([book.pdf_path]);
      if (storageError) console.warn("Storage delete warning:", storageError.message);
    }

    const { error } = await supabase.from("books").delete().eq("id", req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { next(e); }
});

// ---------- Authentication ----------
app.post("/api/auth/register", async (req, res, next) => {
  try {
    const { name, email, password, level_id = null } = req.body;
    if (!name?.trim() || !email?.trim() || !password || password.length < 8) {
      return res.status(400).json({ error: "أدخل الاسم والبريد وكلمة مرور لا تقل عن 8 أحرف" });
    }

    const { data, error } = await supabase.from("users").insert({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      password_hash: hashPassword(password),
      role: "student",
      current_level_id: cleanInt(level_id)
    }).select("id,name,email,role,current_level_id").single();

    if (error) {
      if (String(error.code) === "23505") return res.status(409).json({ error: "البريد الإلكتروني مستخدم من قبل" });
      throw error;
    }

    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, Number(data.id));
    setCookie(res, token);
    res.json({ success: true, user: data });
  } catch (e) { next(e); }
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const { data: user, error } = await supabase.from("users").select("*").eq("email", String(email || "").trim().toLowerCase()).maybeSingle();
    if (error) throw error;
    if (!user || !verifyPassword(password || "", user.password_hash)) {
      return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
    }
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, Number(user.id));
    setCookie(res, token);
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, role: user.role, current_level_id: user.current_level_id } });
  } catch (e) { next(e); }
});

app.post("/api/auth/logout", (req, res) => {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);
  res.setHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
  res.json({ success: true });
});

app.get("/api/auth/me", requireStudent, (req, res) => res.json(req.user));

// ---------- Student dashboard / progress ----------
app.get("/api/student/dashboard", requireStudent, async (req, res, next) => {
  try {
    const user = req.user;
    const [{ data: level, error: levelError }, { data: progressRows, error: progressError }, { data: attemptsRows, error: attemptsError }] = await Promise.all([
      user.current_level_id ? supabase.from("levels").select("*").eq("id", user.current_level_id).maybeSingle() : Promise.resolve({ data: null, error: null }),
      supabase.from("reading_progress").select("*").eq("user_id", user.id).order("updated_at", { ascending: false }),
      supabase.from("attempts").select("*").eq("user_id", user.id).order("created_at", { ascending: false }).limit(10)
    ]);
    if (levelError) throw levelError;
    if (progressError) throw progressError;
    if (attemptsError) throw attemptsError;

    const [books, subjects, levels] = await Promise.all([getBooks(), getSubjects(), getLevels()]);
    const bookMap = new Map(books.map(b => [Number(b.id), b]));
    const subjectMap = new Map(subjects.map(s => [Number(s.id), s.name]));
    const levelMap = new Map(levels.map(l => [Number(l.id), l.name]));

    const progress = (progressRows || []).map(rp => {
      const b = bookMap.get(Number(rp.book_id)) || {};
      return {
        ...rp,
        title: b.title,
        page_count: b.page_count,
        pdf_path: b.pdf_path,
        level_id: b.level_id,
        level_name: levelMap.get(Number(b.level_id)) || null,
        subject_name: subjectMap.get(Number(b.subject_id)) || null
      };
    });

    const testIds = [...new Set((attemptsRows || []).map(a => Number(a.test_id)))];
    let tests = [];
    if (testIds.length) {
      const { data: testRows, error: testError } = await supabase.from("tests").select("id,title").in("id", testIds);
      if (testError) throw testError;
      tests = testRows || [];
    }
    const testMap = new Map(tests.map(t => [Number(t.id), t.title]));
    const attempts = (attemptsRows || []).map(a => ({ ...a, test_title: testMap.get(Number(a.test_id)) || null }));

    res.json({ user, level, progress, attempts });
  } catch (e) { next(e); }
});

app.post("/api/student/progress", requireStudent, async (req, res, next) => {
  try {
    const { book_id, last_page = 1, completed = 0 } = req.body;
    if (!book_id) return res.status(400).json({ error: "الكتاب مطلوب" });
    const page = Math.max(1, Number(last_page) || 1);
    const { error } = await supabase.from("reading_progress").upsert({
      user_id: req.user.id,
      book_id: cleanInt(book_id),
      last_page: page,
      completed: Boolean(completed),
      updated_at: new Date().toISOString()
    }, { onConflict: "user_id,book_id" });
    if (error) throw error;
    res.json({ success: true });
  } catch (e) { next(e); }
});

// ---------- Tests ----------
app.get("/api/tests", async (req, res, next) => {
  try { res.json(await getTests()); } catch (e) { next(e); }
});

app.get("/api/tests/:id", async (req, res, next) => {
  try {
    const { data: test, error: testError } = await supabase.from("tests").select("*").eq("id", req.params.id).eq("visible", true).maybeSingle();
    if (testError) throw testError;
    if (!test) return res.status(404).json({ error: "الاختبار غير موجود" });

    const [{ data: questions, error: qError }, { data: books }, { data: levels }] = await Promise.all([
      supabase.from("questions").select("id,question_text,options_json,sort_order").eq("test_id", test.id).order("sort_order", { ascending: true }).order("id", { ascending: true }),
      supabase.from("books").select("id,title"),
      supabase.from("levels").select("id,name")
    ]);
    if (qError) throw qError;

    const book = (books || []).find(b => Number(b.id) === Number(test.book_id));
    const level = (levels || []).find(l => Number(l.id) === Number(test.level_id));
    const normalizedQuestions = (questions || []).map(q => ({
      id: q.id,
      question_text: q.question_text,
      options: JSON.parse(q.options_json)
    }));

    res.json({ ...test, book_title: book?.title || null, level_name: level?.name || null, questions: normalizedQuestions });
  } catch (e) { next(e); }
});

app.post("/api/tests", requireAdmin, async (req, res, next) => {
  try {
    const { title, description = "", book_id = null, level_id = null, pass_score = 70 } = req.body;
    if (!title?.trim()) return res.status(400).json({ error: "عنوان الاختبار مطلوب" });
    const { data, error } = await supabase.from("tests").insert({
      title: title.trim(), description, book_id: cleanInt(book_id), level_id: cleanInt(level_id),
      pass_score: Math.min(100, Math.max(0, Number(pass_score) || 70)), question_count: 0, option_count: 10
    }).select("id").single();
    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch (e) { next(e); }
});

app.post("/api/tests/:id/questions", requireAdmin, async (req, res, next) => {
  try {
    const { question_text, options, correct_index, explanation = "", sort_order = 0 } = req.body;
    if (!question_text?.trim() || !Array.isArray(options) || options.length !== 10) {
      return res.status(400).json({ error: "السؤال يجب أن يحتوي على 10 خيارات بالضبط" });
    }
    if (Number(correct_index) < 0 || Number(correct_index) > 9) {
      return res.status(400).json({ error: "الإجابة الصحيحة يجب أن تكون ضمن الخيارات العشرة" });
    }

    const { data: test, error: testError } = await supabase.from("tests").select("id").eq("id", req.params.id).maybeSingle();
    if (testError) throw testError;
    if (!test) return res.status(404).json({ error: "الاختبار غير موجود" });

    const { data, error } = await supabase.from("questions").insert({
      test_id: Number(req.params.id), question_text: question_text.trim(), options_json: JSON.stringify(options.map(String)),
      correct_index: Number(correct_index), explanation, sort_order: Number(sort_order) || 0
    }).select("id").single();
    if (error) throw error;

    const { count, error: countError } = await supabase.from("questions").select("id", { count: "exact", head: true }).eq("test_id", req.params.id);
    if (countError) throw countError;
    const { error: updateError } = await supabase.from("tests").update({ question_count: count || 0 }).eq("id", req.params.id);
    if (updateError) throw updateError;

    res.json({ success: true, id: data.id });
  } catch (e) { next(e); }
});

app.post("/api/tests/:id/submit", requireStudent, async (req, res, next) => {
  try {
    const { data: test, error: testError } = await supabase.from("tests").select("*").eq("id", req.params.id).eq("visible", true).maybeSingle();
    if (testError) throw testError;
    if (!test) return res.status(404).json({ error: "الاختبار غير موجود" });

    const { data: questions, error: qError } = await supabase.from("questions").select("id,correct_index,question_text,options_json,explanation,sort_order").eq("test_id", test.id).order("sort_order", { ascending: true }).order("id", { ascending: true });
    if (qError) throw qError;

    const answers = req.body.answers || {};
    let correct = 0;
    for (const q of (questions || [])) {
      const userAnswer = Number(answers[q.id]);
      if (Number.isInteger(userAnswer) && userAnswer === q.correct_index) correct++;
    }

    const total = (questions || []).length;
    const score = total ? Math.round((correct / total) * 100) : 0;
    const passed = score >= test.pass_score;

    const { data: attempt, error: attemptError } = await supabase.from("attempts").insert({
      user_id: req.user.id, test_id: test.id, score, correct_count: correct, total_count: total,
      passed, answers_json: JSON.stringify(answers)
    }).select("id").single();
    if (attemptError) throw attemptError;

    if (passed && test.level_id) {
      const { data: current, error: currentError } = await supabase.from("users").select("current_level_id").eq("id", req.user.id).single();
      if (currentError) throw currentError;
      const { data: level, error: levelError } = await supabase.from("levels").select("id,sort_order").eq("id", test.level_id).single();
      if (levelError) throw levelError;

      let currentSort = 0;
      if (current.current_level_id) {
        const { data: currentLevel, error: currentLevelError } = await supabase.from("levels").select("sort_order").eq("id", current.current_level_id).maybeSingle();
        if (currentLevelError) throw currentLevelError;
        currentSort = Number(currentLevel?.sort_order || 0);
      }

      if (!current.current_level_id || Number(level.sort_order) >= currentSort) {
        const { data: next, error: nextError } = await supabase.from("levels").select("id,sort_order").gt("sort_order", level.sort_order).order("sort_order", { ascending: true }).limit(1).maybeSingle();
        if (nextError) throw nextError;
        if (next) {
          const { error: updateError } = await supabase.from("users").update({ current_level_id: next.id }).eq("id", req.user.id);
          if (updateError) throw updateError;
        }
      }
    }

    const review = (questions || []).map(q => ({
      id: q.id,
      question_text: q.question_text,
      options: JSON.parse(q.options_json),
      correct_index: q.correct_index,
      selected_index: Number.isInteger(Number(answers[q.id])) ? Number(answers[q.id]) : null,
      explanation: q.explanation || ""
    }));

    res.json({
      attempt_id: attempt.id,
      score, correct_count: correct, total_count: total, passed,
      pass_score: test.pass_score,
      review
    });
  } catch (e) { next(e); }
});

app.get("/api/attempts/:id", requireStudent, async (req, res, next) => {
  try {
    const { data: attempt, error } = await supabase.from("attempts").select("*").eq("id", req.params.id).eq("user_id", req.user.id).maybeSingle();
    if (error) throw error;
    if (!attempt) return res.status(404).json({ error: "المحاولة غير موجودة" });
    const { data: test, error: testError } = await supabase.from("tests").select("title").eq("id", attempt.test_id).maybeSingle();
    if (testError) throw testError;
    res.json({ ...attempt, test_title: test?.title || null });
  } catch (e) { next(e); }
});

// ---------- Admin students ----------
app.get("/api/admin/students", requireAdmin, async (req, res, next) => {
  try {
    const { data: students, error: studentsError } = await supabase
      .from("users")
      .select("id,name,email,current_level_id,created_at")
      .eq("role", "student")
      .order("created_at", { ascending: false });

    if (studentsError) throw studentsError;

    const { data: levels, error: levelsError } = await supabase
      .from("levels")
      .select("id,name");

    if (levelsError) throw levelsError;

    const levelMap = new Map(
      (levels || []).map(level => [Number(level.id), level.name])
    );

    res.json(
      (students || []).map(student => ({
        ...student,
        level_name:
          levelMap.get(Number(student.current_level_id)) || "لم يحدد"
      }))
    );
  } catch (e) {
    next(e);
  }
});

app.delete("/api/admin/students/:id", requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: "معرّف الطالب غير صحيح" });
    }

    const { data: student, error: studentError } = await supabase
      .from("users")
      .select("id,role")
      .eq("id", id)
      .maybeSingle();

    if (studentError) throw studentError;

    if (!student) {
      return res.status(404).json({ error: "الطالب غير موجود" });
    }

    if (student.role !== "student") {
      return res.status(403).json({ error: "لا يمكن حذف هذا الحساب من هنا" });
    }

    const { error } = await supabase
      .from("users")
      .delete()
      .eq("id", id)
      .eq("role", "student");

    if (error) throw error;

    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

// ---------- Admin account ----------
app.put("/api/admin/account", requireAdmin, async (req, res, next) => {
  try {
    const { email, current_password, new_password, name } = req.body;
    if (!email?.trim() || !current_password) return res.status(400).json({ error: "البريد الإلكتروني وكلمة المرور الحالية مطلوبان" });

    const { data: admin, error: adminError } = await supabase.from("users").select("*").eq("id", req.user.id).eq("role", "admin").maybeSingle();
    if (adminError) throw adminError;
    if (!admin || !verifyPassword(current_password, admin.password_hash)) return res.status(401).json({ error: "كلمة المرور الحالية غير صحيحة" });

    const normalizedEmail = email.trim().toLowerCase();
    const { data: duplicate, error: duplicateError } = await supabase.from("users").select("id").eq("email", normalizedEmail).neq("id", admin.id).limit(1).maybeSingle();
    if (duplicateError) throw duplicateError;
    if (duplicate) return res.status(409).json({ error: "هذا البريد مستخدم من حساب آخر" });

    if (new_password !== undefined && String(new_password).length > 0 && String(new_password).length < 8) {
      return res.status(400).json({ error: "كلمة المرور الجديدة يجب ألا تقل عن 8 أحرف" });
    }

    const patch = { name: name?.trim() || admin.name, email: normalizedEmail };
    if (new_password && String(new_password).length >= 8) patch.password_hash = hashPassword(String(new_password));

    const { data: updated, error } = await supabase.from("users").update(patch).eq("id", admin.id).eq("role", "admin").select("id,name,email,role,current_level_id").single();
    if (error) throw error;
    res.json({ success: true, user: updated });
  } catch (e) { next(e); }
});

// ---------- Admin summary ----------
app.get("/api/admin/summary", requireAdmin, async (req, res, next) => {
  try {
    const tables = ["levels", "subjects", "scholars", "books", "tests", "questions"];
    const counts = await Promise.all(tables.map(async table => {
      const { count, error } = await supabase.from(table).select("id", { head: true, count: "exact" });
      if (error) throw error;
      return [table, count || 0];
    }));

    const { count: students, error: studentsError } = await supabase.from("users").select("id", { head: true, count: "exact" }).eq("role", "student");
    if (studentsError) throw studentsError;

    const map = Object.fromEntries(counts);
    res.json({
      levels: map.levels || 0,
      subjects: map.subjects || 0,
      scholars: map.scholars || 0,
      books: map.books || 0,
      students: students || 0,
      tests: map.tests || 0,
      questions: map.questions || 0
    });
  } catch (e) { next(e); }
});

app.use((error, req, res, next) => {
  console.error(error);
  if (error && error.code === "LIMIT_FILE_SIZE") return res.status(400).json({ error: "حجم ملف PDF كبير جدًا" });
  res.status(500).json({ error: error.message || "Server error" });
});

(async () => {
  try {
    await ensureAdmin();
    app.listen(PORT, () => {
      console.log("=================================");
      console.log("Sunnah Academy is running");
      console.log(`http://localhost:${PORT}`);
      console.log(`http://localhost:${PORT}/admin`);
      console.log("Storage: Supabase");
      console.log("=================================");
    });
  } catch (error) {
    console.error("Failed to start Sunnah Academy:", error);
    process.exit(1);
  }
})();
