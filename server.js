// Keep local development on SQLite, while Render uses persistent Supabase storage.
if (process.env.SUPABASE_URL && process.env.SUPABASE_SECRET_KEY) {
  require("./server-supabase.js");
} else {
  require("./server-sqlite.js");
}
