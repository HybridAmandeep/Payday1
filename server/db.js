const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', 'data', 'payout.db');

let db = null;

async function initDB() {
    const SQL = await initSqlJs();
    const dataDir = path.dirname(DB_PATH);
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
    }

    if (fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
    } else {
        db = new SQL.Database();
    }

    // Create tables
    db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      must_change_password INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      primary_account TEXT DEFAULT '',
      alt_account_1 TEXT DEFAULT '',
      alt_account_2 TEXT DEFAULT '',
      alt_account_3 TEXT DEFAULT '',
      reddit_cqs TEXT NOT NULL DEFAULT 'Moderate',
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      task_date TEXT NOT NULL,
      task_url TEXT NOT NULL,
      account_used TEXT NOT NULL,
      task_type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending',
      post_status TEXT NOT NULL DEFAULT 'Live',
      submitted_at TEXT NOT NULL DEFAULT (datetime('now')),
      verified_at TEXT,
      verified_by INTEGER,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS payout_rates (
      category TEXT PRIMARY KEY,
      rate REAL NOT NULL
    )
  `);

    db.run(`
    CREATE TABLE IF NOT EXISTS payouts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      gross_amount REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending',
      snapshot_json TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      paid_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

    // ─── MIGRATIONS (handle existing databases) ──────────────────
    // Helper: check if column exists
    function hasColumn(table, column) {
        try {
            const info = db.exec(`PRAGMA table_info(${table})`);
            if (info.length === 0) return false;
            return info[0].values.some(row => row[1] === column);
        } catch (e) { return false; }
    }

    // Add post_status to tasks if missing
    if (!hasColumn('tasks', 'post_status')) {
        try {
            db.run("ALTER TABLE tasks ADD COLUMN post_status TEXT NOT NULL DEFAULT 'Live'");
            console.log('✔ Migration: added post_status column to tasks');
        } catch (e) { /* column may already exist */ }
    }

    // Drop old activities table if it exists
    try { db.run("DROP TABLE IF EXISTS activities"); } catch (e) { }

    // Seed default rates if empty
    const rateCount = db.exec("SELECT COUNT(*) FROM payout_rates");
    if (rateCount[0].values[0][0] === 0) {
        db.run("INSERT INTO payout_rates (category, rate) VALUES ('Post', 75)");
        db.run("INSERT INTO payout_rates (category, rate) VALUES ('Comment', 15)");
        db.run("INSERT INTO payout_rates (category, rate) VALUES ('Support Comment', 15)");
    } else {
        // Ensure 'Support Comment' rate exists (old DBs may have different categories)
        const scCheck = db.exec("SELECT COUNT(*) FROM payout_rates WHERE category = 'Support Comment'");
        if (scCheck[0].values[0][0] === 0) {
            db.run("INSERT OR IGNORE INTO payout_rates (category, rate) VALUES ('Support Comment', 15)");
            console.log('✔ Migration: added Support Comment rate');
        }
    }

    // Seed default admin if no admin exists
    const adminCount = db.exec("SELECT COUNT(*) FROM users WHERE role = 'admin'");
    if (adminCount[0].values[0][0] === 0) {
        const hash = bcrypt.hashSync('Amandeep@3583', 12);
        db.run(
            "INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, 'admin', 0)",
            ['Amandeep3583', hash]
        );
        console.log('✔ Default admin created: Amandeep3583');
    }

    saveDB();
    console.log('✔ Database initialized');
    return db;
}

function saveDB() {
    if (db) {
        const data = db.export();
        const buffer = Buffer.from(data);
        fs.writeFileSync(DB_PATH, buffer);
    }
}

function getDB() {
    return db;
}

module.exports = { initDB, getDB, saveDB };
