const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { initDB, getDB, saveDB } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'payout_sheet_secret_key_2024_change_in_prod';
const JWT_EXPIRY = '24h';

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// ─── RATE LIMITING ────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts. Try again later.' } });

// ─── MIDDLEWARE ───────────────────────────────────────────
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
    next();
}

// ─── AUTH ROUTES ──────────────────────────────────────────
app.post('/api/auth/register', authLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 3 || username.length > 30) return res.status(400).json({ error: 'Username must be 3-30 characters' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const db = getDB();
    const existing = db.exec("SELECT id FROM users WHERE username = ?", [username]);
    if (existing.length > 0 && existing[0].values.length > 0) return res.status(409).json({ error: 'Username already taken' });

    const hash = bcrypt.hashSync(password, 12);
    db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, hash]);
    const userId = db.exec("SELECT last_insert_rowid()")[0].values[0][0];
    db.run("INSERT INTO accounts (user_id) VALUES (?)", [userId]);
    saveDB();

    const token = jwt.sign({ id: userId, username, role: 'user' }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({ token, user: { id: userId, username, role: 'user' } });
});

app.post('/api/auth/login', authLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const db = getDB();
    const result = db.exec("SELECT id, username, password_hash, role, must_change_password FROM users WHERE username = ?", [username]);
    if (result.length === 0 || result[0].values.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const [id, uname, hash, role, mustChange] = result[0].values[0];
    if (!bcrypt.compareSync(password, hash)) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id, username: uname, role }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
    res.json({ token, user: { id, username: uname, role, must_change_password: mustChange } });
});

// Only admin can change passwords
app.post('/api/auth/change-password', authenticateToken, requireAdmin, (req, res) => {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
    const db = getDB();
    const newHash = bcrypt.hashSync(newPassword, 12);
    db.run("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?", [newHash, req.user.id]);
    saveDB();
    res.json({ message: 'Password changed successfully' });
});

// ─── ACCOUNT ROUTES ──────────────────────────────────────
app.get('/api/account', authenticateToken, (req, res) => {
    const db = getDB();
    let result = db.exec("SELECT * FROM accounts WHERE user_id = ?", [req.user.id]);
    // Auto-create accounts row if missing (handles old DB users)
    if (result.length === 0 || result[0].values.length === 0) {
        db.run("INSERT OR IGNORE INTO accounts (user_id) VALUES (?)", [req.user.id]);
        saveDB();
        result = db.exec("SELECT * FROM accounts WHERE user_id = ?", [req.user.id]);
        if (result.length === 0 || result[0].values.length === 0) {
            return res.json({ primary_account: '', alt_account_1: '', alt_account_2: '', alt_account_3: '', reddit_cqs: 'Moderate' });
        }
    }
    const cols = result[0].columns;
    const vals = result[0].values[0];
    const account = {};
    cols.forEach((c, i) => account[c] = vals[i]);
    res.json(account);
});

app.put('/api/account', authenticateToken, (req, res) => {
    const { primary_account, alt_account_1, alt_account_2, alt_account_3, reddit_cqs } = req.body;
    const validCQS = ['Highest', 'High', 'Moderate', 'Low'];
    const cqs = validCQS.includes(reddit_cqs) ? reddit_cqs : 'Moderate';
    const db = getDB();
    // Ensure row exists first (upsert)
    db.run("INSERT OR IGNORE INTO accounts (user_id) VALUES (?)", [req.user.id]);
    db.run(
        `UPDATE accounts SET primary_account = ?, alt_account_1 = ?, alt_account_2 = ?, alt_account_3 = ?, reddit_cqs = ? WHERE user_id = ?`,
        [primary_account || '', alt_account_1 || '', alt_account_2 || '', alt_account_3 || '', cqs, req.user.id]
    );
    saveDB();
    res.json({ message: 'Account updated' });
});

// Helper: get user's accounts as list
function getUserAccounts(userId) {
    const db = getDB();
    const result = db.exec("SELECT primary_account, alt_account_1, alt_account_2, alt_account_3 FROM accounts WHERE user_id = ?", [userId]);
    if (result.length === 0 || result[0].values.length === 0) return [];
    const [primary, alt1, alt2, alt3] = result[0].values[0];
    return [primary, alt1, alt2, alt3].filter(a => a && a.trim() !== '');
}

// ─── TASK ROUTES ─────────────────────────────────────────
// User submits a task
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { task_date, task_url, account_used, task_type } = req.body;
    if (!task_date || !task_url || !account_used || !task_type)
        return res.status(400).json({ error: 'All fields are required: date, URL, account, task type' });

    const validTypes = ['Post', 'Comment', 'Support Comment'];
    if (!validTypes.includes(task_type)) return res.status(400).json({ error: 'Invalid task type' });

    const accounts = getUserAccounts(req.user.id);
    if (accounts.length === 0) return res.status(400).json({ error: 'Please set up your account information first' });
    if (!accounts.includes(account_used)) return res.status(400).json({ error: 'Selected account is not registered to your profile' });

    const db = getDB();
    db.run(
        "INSERT INTO tasks (user_id, task_date, task_url, account_used, task_type) VALUES (?, ?, ?, ?, ?)",
        [req.user.id, task_date, task_url, account_used, task_type]
    );
    saveDB();
    res.json({ message: 'Task submitted for verification' });
});

// User views own tasks
app.get('/api/tasks', authenticateToken, (req, res) => {
    const db = getDB();
    const result = db.exec("SELECT * FROM tasks WHERE user_id = ? ORDER BY submitted_at DESC", [req.user.id]);
    if (result.length === 0) return res.json([]);
    const cols = result[0].columns;
    const tasks = result[0].values.map(row => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = row[i]);
        return obj;
    });
    res.json(tasks);
});

// User deletes own pending task
app.delete('/api/tasks/:id', authenticateToken, (req, res) => {
    const taskId = parseInt(req.params.id);
    const db = getDB();
    const check = db.exec("SELECT user_id, status FROM tasks WHERE id = ?", [taskId]);
    if (check.length === 0 || check[0].values.length === 0) return res.status(404).json({ error: 'Task not found' });
    const [userId, status] = check[0].values[0];
    if (userId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
    if (status !== 'Pending' && req.user.role !== 'admin') return res.status(400).json({ error: 'Can only delete pending tasks' });

    db.run("DELETE FROM tasks WHERE id = ?", [taskId]);
    saveDB();
    res.json({ message: 'Task deleted' });
});

// ─── ADMIN: TASK VERIFICATION & MANAGEMENT ───────────────
// Admin views all tasks
app.get('/api/admin/tasks', authenticateToken, requireAdmin, (req, res) => {
    const db = getDB();
    const statusFilter = req.query.status;
    let query = `SELECT t.*, u.username FROM tasks t JOIN users u ON t.user_id = u.id`;
    const params = [];
    if (statusFilter) {
        query += ` WHERE t.status = ?`;
        params.push(statusFilter);
    }
    query += ` ORDER BY t.submitted_at DESC`;

    const result = db.exec(query, params);
    if (result.length === 0) return res.json([]);
    const cols = result[0].columns;
    const tasks = result[0].values.map(row => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = row[i]);
        return obj;
    });
    res.json(tasks);
});

// Admin updates task status (Verified/Rejected/Pending)
app.put('/api/admin/tasks/:id/status', authenticateToken, requireAdmin, (req, res) => {
    const taskId = parseInt(req.params.id);
    const { status } = req.body;
    const validStatuses = ['Verified', 'Rejected', 'Pending'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const db = getDB();
    const check = db.exec("SELECT id FROM tasks WHERE id = ?", [taskId]);
    if (check.length === 0 || check[0].values.length === 0) return res.status(404).json({ error: 'Task not found' });

    const verifiedAt = status === 'Verified' ? new Date().toISOString() : null;
    const verifiedBy = status === 'Verified' ? req.user.id : null;
    db.run("UPDATE tasks SET status = ?, verified_at = ?, verified_by = ? WHERE id = ?", [status, verifiedAt, verifiedBy, taskId]);
    saveDB();
    res.json({ message: `Task ${status.toLowerCase()}` });
});

// Admin changes task type
app.put('/api/admin/tasks/:id/type', authenticateToken, requireAdmin, (req, res) => {
    const taskId = parseInt(req.params.id);
    const { task_type } = req.body;
    const validTypes = ['Post', 'Comment', 'Support Comment'];
    if (!validTypes.includes(task_type)) return res.status(400).json({ error: 'Invalid task type' });

    const db = getDB();
    const check = db.exec("SELECT id FROM tasks WHERE id = ?", [taskId]);
    if (check.length === 0 || check[0].values.length === 0) return res.status(404).json({ error: 'Task not found' });

    db.run("UPDATE tasks SET task_type = ? WHERE id = ?", [task_type, taskId]);
    saveDB();
    res.json({ message: `Task type changed to ${task_type}` });
});

// Admin changes post_status (Live/Deleted)
app.put('/api/admin/tasks/:id/post-status', authenticateToken, requireAdmin, (req, res) => {
    const taskId = parseInt(req.params.id);
    const { post_status } = req.body;
    const validStatuses = ['Live', 'Deleted'];
    if (!validStatuses.includes(post_status)) return res.status(400).json({ error: 'Invalid post status' });

    const db = getDB();
    const check = db.exec("SELECT id FROM tasks WHERE id = ?", [taskId]);
    if (check.length === 0 || check[0].values.length === 0) return res.status(404).json({ error: 'Task not found' });

    db.run("UPDATE tasks SET post_status = ? WHERE id = ?", [post_status, taskId]);
    saveDB();
    res.json({ message: `Post marked as ${post_status}` });
});

// Admin bulk verify
app.post('/api/admin/tasks/bulk-verify', authenticateToken, requireAdmin, (req, res) => {
    const { taskIds, status } = req.body;
    if (!taskIds || !Array.isArray(taskIds) || taskIds.length === 0) return res.status(400).json({ error: 'Task IDs required' });
    const validStatuses = ['Verified', 'Rejected'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const db = getDB();
    const verifiedAt = status === 'Verified' ? new Date().toISOString() : null;
    const verifiedBy = status === 'Verified' ? req.user.id : null;

    for (const id of taskIds) {
        db.run("UPDATE tasks SET status = ?, verified_at = ?, verified_by = ? WHERE id = ? AND status = 'Pending'", [status, verifiedAt, verifiedBy, id]);
    }
    saveDB();
    res.json({ message: `${taskIds.length} task(s) ${status.toLowerCase()}` });
});

// ─── PAYOUT RATES ────────────────────────────────────────
app.get('/api/rates', authenticateToken, (req, res) => {
    const db = getDB();
    const result = db.exec("SELECT * FROM payout_rates");
    if (result.length === 0) return res.json([]);
    const cols = result[0].columns;
    const rates = result[0].values.map(row => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = row[i]);
        return obj;
    });
    res.json(rates);
});

app.put('/api/rates', authenticateToken, requireAdmin, (req, res) => {
    const { rates } = req.body;
    if (!rates || !Array.isArray(rates)) return res.status(400).json({ error: 'Invalid rates format' });
    const db = getDB();
    for (const r of rates) {
        const rate = Math.max(0, parseFloat(r.rate) || 0);
        db.run("UPDATE payout_rates SET rate = ? WHERE category = ?", [rate, r.category]);
    }
    saveDB();
    res.json({ message: 'Rates updated' });
});

// ─── PAYOUT CALCULATION ──────────────────────────────────
// Only count tasks that are Verified AND Live
app.get('/api/payout/calculate', authenticateToken, (req, res) => {
    const db = getDB();
    const targetUserId = req.query.userId && req.user.role === 'admin' ? parseInt(req.query.userId) : req.user.id;

    // Verified + Live tasks
    const tasksResult = db.exec(
        "SELECT task_type, COUNT(*) as cnt FROM tasks WHERE user_id = ? AND status = 'Verified' AND post_status = 'Live' GROUP BY task_type",
        [targetUserId]
    );
    const taskCounts = {};
    if (tasksResult.length > 0) {
        tasksResult[0].values.forEach(([type, count]) => { taskCounts[type] = count; });
    }

    // Total submitted
    const totalResult = db.exec(
        "SELECT task_type, COUNT(*) as cnt FROM tasks WHERE user_id = ? GROUP BY task_type",
        [targetUserId]
    );
    const totalCounts = {};
    if (totalResult.length > 0) {
        totalResult[0].values.forEach(([type, count]) => { totalCounts[type] = count; });
    }

    // Pending count
    const pendingResult = db.exec(
        "SELECT COUNT(*) FROM tasks WHERE user_id = ? AND status = 'Pending'",
        [targetUserId]
    );
    const pendingCount = pendingResult.length > 0 ? pendingResult[0].values[0][0] : 0;

    // Rates
    const ratesResult = db.exec("SELECT category, rate FROM payout_rates");
    const rateMap = {};
    if (ratesResult.length > 0) {
        ratesResult[0].values.forEach(([cat, rate]) => { rateMap[cat] = rate; });
    }

    const categories = ['Post', 'Comment', 'Support Comment'];
    let total = 0;
    const breakdown = [];

    categories.forEach(cat => {
        const verified = taskCounts[cat] || 0;
        const submitted = totalCounts[cat] || 0;
        const rate = rateMap[cat] || 0;
        const amount = verified * rate;
        total += amount;
        breakdown.push({ category: cat, verified, submitted, rate, amount });
    });

    res.json({ eligible: true, total, breakdown, pendingCount });
});

// ─── PAYOUT RECORDS (ADMIN ONLY) ─────────────────────────
app.get('/api/payouts', authenticateToken, (req, res) => {
    const db = getDB();
    const result = db.exec("SELECT * FROM payouts WHERE user_id = ? ORDER BY created_at DESC", [req.user.id]);
    if (result.length === 0) return res.json([]);
    const cols = result[0].columns;
    const payouts = result[0].values.map(row => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = row[i]);
        try { obj.snapshot_json = JSON.parse(obj.snapshot_json); } catch (e) { }
        return obj;
    });
    res.json(payouts);
});

// Admin creates a payout record for a user
app.post('/api/payouts', authenticateToken, requireAdmin, (req, res) => {
    const { status, userId } = req.body;
    const validStatuses = ['Pending', 'Due', 'Paid'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const targetUserId = userId || req.user.id;
    const db = getDB();

    // Calculate from verified + live tasks
    const tasksResult = db.exec(
        "SELECT task_type, COUNT(*) as cnt FROM tasks WHERE user_id = ? AND status = 'Verified' AND post_status = 'Live' GROUP BY task_type",
        [targetUserId]
    );
    const taskCounts = {};
    if (tasksResult.length > 0) {
        tasksResult[0].values.forEach(([type, count]) => { taskCounts[type] = count; });
    }

    const ratesResult = db.exec("SELECT category, rate FROM payout_rates");
    const rateMap = {};
    if (ratesResult.length > 0) {
        ratesResult[0].values.forEach(([cat, rate]) => { rateMap[cat] = rate; });
    }

    const categories = ['Post', 'Comment', 'Support Comment'];
    let total = 0;
    const breakdown = [];
    categories.forEach(cat => {
        const verified = taskCounts[cat] || 0;
        const rate = rateMap[cat] || 0;
        const amount = verified * rate;
        total += amount;
        breakdown.push({ category: cat, verified, rate, amount });
    });

    if (total <= 0) return res.status(400).json({ error: 'No verified tasks to create payout' });

    const snapshot = JSON.stringify({ breakdown, total });
    const paidAt = status === 'Paid' ? new Date().toISOString() : null;
    db.run("INSERT INTO payouts (user_id, gross_amount, status, snapshot_json, paid_at) VALUES (?, ?, ?, ?, ?)",
        [targetUserId, total, status, snapshot, paidAt]);

    // If paid, clear verified tasks
    if (status === 'Paid') {
        db.run("DELETE FROM tasks WHERE user_id = ? AND status = 'Verified'", [targetUserId]);
    }

    saveDB();
    res.json({ message: `Payout recorded as ${status}`, total, status });
});

// Admin updates payout status — this just updates the existing record, no duplication
app.put('/api/payouts/:id/status', authenticateToken, requireAdmin, (req, res) => {
    const { status } = req.body;
    const payoutId = parseInt(req.params.id);
    const validStatuses = ['Pending', 'Due', 'Paid'];
    if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    const db = getDB();
    const result = db.exec("SELECT user_id, status FROM payouts WHERE id = ?", [payoutId]);
    if (result.length === 0 || result[0].values.length === 0) return res.status(404).json({ error: 'Payout not found' });

    const [userId, currentStatus] = result[0].values[0];
    if (currentStatus === 'Paid') return res.status(400).json({ error: 'Cannot modify a paid payout' });

    const paidAt = status === 'Paid' ? new Date().toISOString() : null;
    db.run("UPDATE payouts SET status = ?, paid_at = ? WHERE id = ?", [status, paidAt, payoutId]);

    // If marking as paid, clear verified tasks for that user
    if (status === 'Paid') {
        db.run("DELETE FROM tasks WHERE user_id = ? AND status = 'Verified'", [userId]);
    }

    saveDB();
    res.json({ message: `Payout status updated to ${status}` });
});

// ─── ADMIN ROUTES ────────────────────────────────────────
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const db = getDB();
    const result = db.exec(`
        SELECT u.id, u.username, u.role, u.created_at,
               a.primary_account, a.reddit_cqs
        FROM users u
        LEFT JOIN accounts a ON a.user_id = u.id
        ORDER BY u.created_at DESC
    `);
    if (result.length === 0) return res.json([]);
    const cols = result[0].columns;
    const users = result[0].values.map(row => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = row[i]);
        return obj;
    });
    res.json(users);
});

app.get('/api/admin/user/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = parseInt(req.params.id);
    const db = getDB();

    const userResult = db.exec("SELECT id, username, role, created_at FROM users WHERE id = ?", [userId]);
    if (userResult.length === 0 || userResult[0].values.length === 0) return res.status(404).json({ error: 'User not found' });
    const [id, username, role, created_at] = userResult[0].values[0];

    const accResult = db.exec("SELECT * FROM accounts WHERE user_id = ?", [userId]);
    const account = {};
    if (accResult.length > 0 && accResult[0].values.length > 0) {
        accResult[0].columns.forEach((c, i) => account[c] = accResult[0].values[0][i]);
    }

    const taskStats = db.exec(`
        SELECT task_type, status, post_status, COUNT(*) as cnt FROM tasks WHERE user_id = ? GROUP BY task_type, status, post_status
    `, [userId]);
    const stats = [];
    if (taskStats.length > 0) {
        taskStats[0].values.forEach(([type, status, postStatus, cnt]) => stats.push({ type, status, postStatus, count: cnt }));
    }

    // Current payout total (verified + live only)
    const verifiedResult = db.exec(
        "SELECT task_type, COUNT(*) FROM tasks WHERE user_id = ? AND status = 'Verified' AND post_status = 'Live' GROUP BY task_type",
        [userId]
    );
    const ratesResult = db.exec("SELECT category, rate FROM payout_rates");
    const rateMap = {};
    if (ratesResult.length > 0) ratesResult[0].values.forEach(([cat, rate]) => rateMap[cat] = rate);

    let currentTotal = 0;
    if (verifiedResult.length > 0) {
        verifiedResult[0].values.forEach(([type, cnt]) => { currentTotal += (cnt * (rateMap[type] || 0)); });
    }

    const payoutResult = db.exec("SELECT * FROM payouts WHERE user_id = ? ORDER BY created_at DESC", [userId]);
    const payouts = [];
    if (payoutResult.length > 0) {
        payoutResult[0].values.forEach(row => {
            const obj = {};
            payoutResult[0].columns.forEach((c, i) => obj[c] = row[i]);
            payouts.push(obj);
        });
    }

    res.json({ user: { id, username, role, created_at }, account, taskStats: stats, currentTotal, payouts });
});

app.delete('/api/admin/user/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = parseInt(req.params.id);
    if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });

    const db = getDB();
    const check = db.exec("SELECT role FROM users WHERE id = ?", [userId]);
    if (check.length === 0 || check[0].values.length === 0) return res.status(404).json({ error: 'User not found' });

    db.run("DELETE FROM payouts WHERE user_id = ?", [userId]);
    db.run("DELETE FROM tasks WHERE user_id = ?", [userId]);
    db.run("DELETE FROM accounts WHERE user_id = ?", [userId]);
    db.run("DELETE FROM users WHERE id = ?", [userId]);
    saveDB();
    res.json({ message: 'User deleted' });
});

app.put('/api/admin/user/:id/password', authenticateToken, requireAdmin, (req, res) => {
    const userId = parseInt(req.params.id);
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const db = getDB();
    const check = db.exec("SELECT id FROM users WHERE id = ?", [userId]);
    if (check.length === 0 || check[0].values.length === 0) return res.status(404).json({ error: 'User not found' });

    const newHash = bcrypt.hashSync(newPassword, 12);
    db.run("UPDATE users SET password_hash = ? WHERE id = ?", [newHash, userId]);
    saveDB();
    res.json({ message: 'Password updated successfully' });
});

app.get('/api/admin/all-payouts', authenticateToken, requireAdmin, (req, res) => {
    const db = getDB();
    const result = db.exec(`
        SELECT p.*, u.username FROM payouts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    `);
    if (result.length === 0) return res.json([]);
    const cols = result[0].columns;
    const payouts = result[0].values.map(row => {
        const obj = {};
        cols.forEach((c, i) => obj[c] = row[i]);
        try { obj.snapshot_json = JSON.parse(obj.snapshot_json); } catch (e) { }
        return obj;
    });
    res.json(payouts);
});

// ─── START SERVER ────────────────────────────────────────
async function start() {
    await initDB();
    app.listen(PORT, () => {
        console.log(`\n🚀 1PAYOUT SHEET running at http://localhost:${PORT}`);
        console.log(`   Admin: Amandeep3583\n`);
    });
}

start();
