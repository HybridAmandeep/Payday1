/* ═══════════════════════════════════════════════════════════
   1PAYOUT SHEET — Client Application
   ═══════════════════════════════════════════════════════════ */

const API = '';
let token = null;
let currentUser = null;
let userAccounts = [];

// ─── HELPERS ──────────────────────────────────────────────
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

async function api(endpoint, options = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(API + endpoint, { ...options, headers });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
}

function toast(message, type = 'info') {
    const container = $('#toast-container');
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => el.remove(), 3000);
}

function formatCurrency(amount) {
    return '₹' + Number(amount || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function formatDate(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
}

function formatDateTime(dateStr) {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// ─── AUTH ─────────────────────────────────────────────────
function initAuth() {
    $$('.auth-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            $$('.auth-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            $$('.auth-form').forEach(f => f.classList.remove('active'));
            $(`#${tab.dataset.tab}-form`).classList.add('active');
        });
    });

    $$('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = $(`#${btn.dataset.target}`);
            input.type = input.type === 'password' ? 'text' : 'password';
            btn.textContent = input.type === 'password' ? '👁' : '👁‍🗨';
        });
    });

    $('#login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = $('#login-username').value.trim();
        const password = $('#login-password').value;
        $('#login-error').textContent = '';
        try {
            const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
            token = data.token;
            currentUser = data.user;
            sessionStorage.setItem('token', token);
            sessionStorage.setItem('user', JSON.stringify(currentUser));
            showDashboard();
        } catch (err) {
            $('#login-error').textContent = err.message;
        }
    });

    $('#register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = $('#reg-username').value.trim();
        const password = $('#reg-password').value;
        const confirm = $('#reg-confirm').value;
        $('#register-error').textContent = '';
        if (password !== confirm) { $('#register-error').textContent = 'Passwords do not match'; return; }
        try {
            const data = await api('/api/auth/register', { method: 'POST', body: JSON.stringify({ username, password }) });
            token = data.token;
            currentUser = data.user;
            sessionStorage.setItem('token', token);
            sessionStorage.setItem('user', JSON.stringify(currentUser));
            toast('Account created!', 'success');
            showDashboard();
        } catch (err) {
            $('#register-error').textContent = err.message;
        }
    });
}

// ─── SESSION ──────────────────────────────────────────────
function checkSession() {
    const savedToken = sessionStorage.getItem('token');
    const savedUser = sessionStorage.getItem('user');
    if (savedToken && savedUser) {
        token = savedToken;
        currentUser = JSON.parse(savedUser);
        showDashboard();
    }
}

function logout() {
    token = null;
    currentUser = null;
    userAccounts = [];
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('user');
    $$('.screen').forEach(s => s.classList.remove('active'));
    $('#auth-screen').classList.add('active');
    $('#login-username').value = '';
    $('#login-password').value = '';
    $('#login-error').textContent = '';
    $('#profile-panel').style.display = 'none';
}

// ─── DASHBOARD ────────────────────────────────────────────
function showDashboard() {
    $$('.screen').forEach(s => s.classList.remove('active'));
    $('#dashboard-screen').classList.add('active');

    $('#user-avatar').textContent = currentUser.username[0].toUpperCase();
    $('#user-name').textContent = currentUser.username;
    $('#role-tag').textContent = currentUser.role;

    if (currentUser.role === 'admin') {
        $$('.admin-only').forEach(el => el.style.display = '');
    } else {
        $$('.admin-only').forEach(el => el.style.display = 'none');
    }

    loadDashboardData();
}

async function loadDashboardData() {
    try {
        const [account, payout] = await Promise.all([
            api('/api/account'),
            api('/api/payout/calculate')
        ]);
        renderAccountInfo(account);
        renderPayout(payout);

        userAccounts = [account.primary_account, account.alt_account_1, account.alt_account_2, account.alt_account_3].filter(a => a && a.trim() !== '');
        populateAccountDropdown();
    } catch (err) {
        if (err.message.includes('token') || err.message.includes('Access')) {
            logout();
            toast('Session expired. Please login again.', 'error');
        } else {
            toast(err.message, 'error');
        }
    }
}

// ─── PROFILE PANEL ────────────────────────────────────────
function initProfilePanel() {
    const trigger = $('#profile-trigger');
    const panel = $('#profile-panel');
    const closeBtn = $('#close-profile-btn');

    trigger.addEventListener('click', () => {
        const isOpen = panel.style.display !== 'none';
        if (isOpen) {
            panel.style.display = 'none';
            trigger.classList.remove('open');
        } else {
            panel.style.display = 'block';
            trigger.classList.add('open');
        }
    });

    closeBtn.addEventListener('click', () => {
        panel.style.display = 'none';
        trigger.classList.remove('open');
    });
}

// ─── ACCOUNT ──────────────────────────────────────────────
function renderAccountInfo(account) {
    $('#primary-account').value = account.primary_account || '';
    $('#alt-1').value = account.alt_account_1 || '';
    $('#alt-2').value = account.alt_account_2 || '';
    $('#alt-3').value = account.alt_account_3 || '';
    $('#reddit-cqs').value = account.reddit_cqs || 'Moderate';

    const badge = $('#cqs-badge');
    badge.textContent = account.reddit_cqs || 'Moderate';
    badge.className = `cqs-badge ${account.reddit_cqs || 'Moderate'}`;
}

function initAccountSave() {
    $('#save-account-btn').addEventListener('click', async () => {
        try {
            await api('/api/account', {
                method: 'PUT',
                body: JSON.stringify({
                    primary_account: $('#primary-account').value,
                    alt_account_1: $('#alt-1').value,
                    alt_account_2: $('#alt-2').value,
                    alt_account_3: $('#alt-3').value,
                    reddit_cqs: $('#reddit-cqs').value
                })
            });
            toast('Account saved!', 'success');

            const cqs = $('#reddit-cqs').value;
            const badge = $('#cqs-badge');
            badge.textContent = cqs;
            badge.className = `cqs-badge ${cqs}`;

            userAccounts = [$('#primary-account').value, $('#alt-1').value, $('#alt-2').value, $('#alt-3').value].filter(a => a && a.trim() !== '');
            populateAccountDropdown();
        } catch (err) {
            toast(err.message, 'error');
        }
    });
}

// ─── TASK SUBMISSION ─────────────────────────────────────
function populateAccountDropdown() {
    const select = $('#task-account');
    select.innerHTML = '<option value="">Select account...</option>';
    userAccounts.forEach(acc => {
        const opt = document.createElement('option');
        opt.value = acc;
        opt.textContent = acc;
        select.appendChild(opt);
    });
}

function initTaskForm() {
    const today = new Date().toISOString().split('T')[0];
    $('#task-date').value = today;

    $('#task-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        $('#task-form-error').textContent = '';

        const task_date = $('#task-date').value;
        const task_url = $('#task-url').value.trim();
        const account_used = $('#task-account').value;
        const task_type = $('#task-type').value;

        if (!account_used) {
            $('#task-form-error').textContent = 'Please select an account. Set up your accounts in Profile first.';
            return;
        }

        try {
            await api('/api/tasks', {
                method: 'POST',
                body: JSON.stringify({ task_date, task_url, account_used, task_type })
            });
            toast('Task submitted for verification!', 'success');
            $('#task-url').value = '';
            $('#task-type').value = '';
            loadDashboardData();
        } catch (err) {
            $('#task-form-error').textContent = err.message;
        }
    });
}

// ─── MY TASKS ─────────────────────────────────────────────
async function loadMyTasks() {
    try {
        const tasks = await api('/api/tasks');
        const filter = $('#my-task-filter').value;
        const filtered = filter ? tasks.filter(t => t.status === filter) : tasks;
        renderMyTasks(filtered);
    } catch (err) {
        toast(err.message, 'error');
    }
}

function renderMyTasks(tasks) {
    const container = $('#my-tasks-list');
    if (!tasks || tasks.length === 0) {
        container.innerHTML = '<p class="empty-state">No tasks found. Submit your first task!</p>';
        return;
    }

    let html = `<div class="table-wrap"><table class="tasks-table">
    <thead><tr>
      <th>Date</th><th>URL</th><th>Account</th><th>Type</th><th>Post</th><th>Status</th><th>Actions</th>
    </tr></thead><tbody>`;

    tasks.forEach(t => {
        html += `<tr>
      <td>${formatDate(t.task_date)}</td>
      <td><a href="${t.task_url}" target="_blank" class="task-url-link" title="${t.task_url}">${t.task_url}</a></td>
      <td><strong>${t.account_used}</strong></td>
      <td>${t.task_type}</td>
      <td><span class="post-status-badge ${t.post_status}">${t.post_status}</span></td>
      <td><span class="status-badge ${t.status}">${t.status}</span></td>
      <td>${t.status === 'Pending' ? `<button class="btn btn-sm btn-danger" onclick="deleteTask(${t.id})">🗑</button>` : ''}</td>
    </tr>`;
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

function initMyTaskFilter() {
    $('#my-task-filter').addEventListener('change', loadMyTasks);
}

window.deleteTask = async function (taskId) {
    if (!confirm('Delete this pending task?')) return;
    try {
        await api(`/api/tasks/${taskId}`, { method: 'DELETE' });
        toast('Task deleted', 'success');
        loadMyTasks();
        loadDashboardData();
    } catch (err) {
        toast(err.message, 'error');
    }
};

// ─── PAYOUT RENDERING ────────────────────────────────────
function renderPayout(payout) {
    const breakdownEl = $('#payout-breakdown');
    const totalEl = $('#payout-total');
    const pendingNotice = $('#pending-notice');

    breakdownEl.innerHTML = '';

    (payout.breakdown || []).forEach(item => {
        const div = document.createElement('div');
        div.className = 'breakdown-item';
        div.innerHTML = `
      <div>
        <div class="breakdown-label">${item.category}</div>
        <div class="breakdown-calc">${item.verified} verified × ₹${item.rate} (${item.submitted} submitted)</div>
      </div>
      <div class="breakdown-value">${formatCurrency(item.amount)}</div>
    `;
        breakdownEl.appendChild(div);
    });

    totalEl.textContent = formatCurrency(payout.total);

    if (payout.pendingCount > 0) {
        pendingNotice.style.display = 'block';
        $('#pending-count').textContent = payout.pendingCount;
    } else {
        pendingNotice.style.display = 'none';
    }
}

// ─── PAYOUT ACTIONS (ADMIN ONLY) ─────────────────────────
function initPayoutActions() {
    ['pending', 'due', 'paid'].forEach(status => {
        $(`#record-${status}-btn`).addEventListener('click', async () => {
            const statusMap = { pending: 'Pending', due: 'Due', paid: 'Paid' };
            const s = statusMap[status];
            if (s === 'Paid' && !confirm('Mark as PAID? This will lock the payout and clear verified tasks.')) return;
            try {
                const result = await api('/api/payouts', { method: 'POST', body: JSON.stringify({ status: s }) });
                toast(`Payout recorded as ${s}: ${formatCurrency(result.total)}`, 'success');
                loadDashboardData();
            } catch (err) {
                toast(err.message, 'error');
            }
        });
    });
}

// ─── HISTORY ──────────────────────────────────────────────
async function loadHistory() {
    try {
        const payouts = await api('/api/payouts');
        renderHistory(payouts, '#history-list', false);
    } catch (err) {
        toast(err.message, 'error');
    }
}

function renderHistory(payouts, containerSel, showUser = false, adminEdit = false) {
    const container = $(containerSel);
    if (!payouts || payouts.length === 0) {
        container.innerHTML = '<p class="empty-state">No payout records yet.</p>';
        return;
    }

    container.innerHTML = '';
    payouts.forEach(p => {
        const item = document.createElement('div');
        item.className = 'history-item';

        let rightContent = '';
        if (p.status === 'Paid') {
            // Paid = locked, just show status with lock icon
            rightContent = `<span class="history-status Paid">✅ Paid</span> 🔒`;
        } else if (adminEdit) {
            // Admin can change status
            rightContent = `
                <span class="history-status ${p.status}">${p.status}</span>
                <button class="btn btn-sm btn-primary" onclick="updatePayoutStatus(${p.id}, 'Paid')">✅ Mark Paid</button>
                <button class="btn btn-sm btn-warning" onclick="updatePayoutStatus(${p.id}, 'Due')">📋 Due</button>
            `;
        } else {
            rightContent = `<span class="history-status ${p.status}">${p.status}</span>`;
        }

        item.innerHTML = `
      <div class="history-left">
        <div class="history-amount">${formatCurrency(p.gross_amount)}</div>
        <div class="history-date">${formatDateTime(p.created_at)}${p.paid_at ? ' | Paid: ' + formatDateTime(p.paid_at) : ''}</div>
        ${showUser ? `<div class="history-user">@${p.username || 'unknown'}</div>` : ''}
      </div>
      <div class="history-right">${rightContent}</div>
    `;
        container.appendChild(item);
    });
}

window.updatePayoutStatus = async function (id, status) {
    if (!confirm(`Mark payout #${id} as ${status}?`)) return;
    try {
        await api(`/api/payouts/${id}/status`, { method: 'PUT', body: JSON.stringify({ status }) });
        toast(`Payout marked as ${status}`, 'success');
        loadHistory();
        if (currentUser.role === 'admin') loadAdminPayouts();
    } catch (err) {
        toast(err.message, 'error');
    }
};

// ─── NAVIGATION ───────────────────────────────────────────
function initNav() {
    $$('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const view = btn.dataset.view;
            $$('.nav-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            $$('.view').forEach(v => v.classList.remove('active'));
            $(`#view-${view}`).classList.add('active');

            // Close profile panel when navigating
            $('#profile-panel').style.display = 'none';
            $('#profile-trigger').classList.remove('open');

            if (view === 'history') loadHistory();
            if (view === 'admin') loadAdminData();
            if (view === 'dashboard') loadDashboardData();
            if (view === 'my-tasks') loadMyTasks();
            if (view === 'submit-task') {
                populateAccountDropdown();
                $('#task-date').value = new Date().toISOString().split('T')[0];
            }
        });
    });
}

// ─── ADMIN ────────────────────────────────────────────────
async function loadAdminData() {
    if (currentUser.role !== 'admin') return;
    try {
        const [rates, users, payouts] = await Promise.all([
            api('/api/rates'),
            api('/api/admin/users'),
            api('/api/admin/all-payouts')
        ]);
        renderRateCards(rates);
        renderUsersTable(users);
        renderHistory(payouts, '#admin-all-payouts', true, true);
        loadAdminTasks();
    } catch (err) {
        toast(err.message, 'error');
    }
}

async function loadAdminTasks() {
    const filter = $('#admin-task-filter').value;
    try {
        const url = filter ? `/api/admin/tasks?status=${filter}` : '/api/admin/tasks';
        const tasks = await api(url);
        renderAdminTasks(tasks);
    } catch (err) {
        toast(err.message, 'error');
    }
}

function renderAdminTasks(tasks) {
    const container = $('#admin-tasks-list');
    if (!tasks || tasks.length === 0) {
        container.innerHTML = '<p class="empty-state">No tasks found.</p>';
        return;
    }

    let html = `<table class="tasks-table">
    <thead><tr>
      <th>User</th><th>Date</th><th>URL</th><th>Account</th>
      <th>Type</th><th>Post</th><th>Status</th><th>Actions</th>
    </tr></thead><tbody>`;

    tasks.forEach(t => {
        // Type dropdown
        const typeOptions = ['Post', 'Comment', 'Support Comment'].map(opt =>
            `<option value="${opt}" ${t.task_type === opt ? 'selected' : ''}>${opt}</option>`
        ).join('');

        // Post status dropdown (Live/Deleted)
        const postOptions = ['Live', 'Deleted'].map(opt =>
            `<option value="${opt}" ${t.post_status === opt ? 'selected' : ''}>${opt}</option>`
        ).join('');

        // Status dropdown — only Verified/Rejected as actions, Pending shown as ghost default
        let statusOptions = '';
        if (t.status === 'Pending') {
            statusOptions = `<option value="Pending" selected disabled>Pending</option><option value="Verified">✅ Verify</option><option value="Rejected">❌ Reject</option>`;
        } else if (t.status === 'Verified') {
            statusOptions = `<option value="Verified" selected>Verified</option><option value="Rejected">❌ Reject</option>`;
        } else {
            statusOptions = `<option value="Rejected" selected>Rejected</option><option value="Verified">✅ Verify</option>`;
        }

        // Show verify button only for non-verified tasks
        const verifyBtn = t.status !== 'Verified'
            ? `<button class="btn btn-sm btn-primary" onclick="changeTaskStatus(${t.id}, 'Verified')" title="Verify">✅</button>`
            : '';

        html += `<tr>
      <td><strong>${t.username}</strong></td>
      <td>${formatDate(t.task_date)}</td>
      <td><a href="${t.task_url}" target="_blank" class="task-url-link" title="${t.task_url}">${t.task_url}</a></td>
      <td>${t.account_used}</td>
      <td><select class="inline-select" onchange="changeTaskType(${t.id}, this.value)">${typeOptions}</select></td>
      <td><select class="inline-select" onchange="changePostStatus(${t.id}, this.value)">${postOptions}</select></td>
      <td><select class="inline-select" onchange="changeTaskStatus(${t.id}, this.value)">${statusOptions}</select></td>
      <td style="display:flex;gap:4px">
        ${verifyBtn}
        <button class="btn btn-sm btn-danger" onclick="adminDeleteTask(${t.id})" title="Delete task">🗑</button>
      </td>
    </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

function getSelectedTaskIds() {
    return Array.from($$('.task-checkbox:checked')).map(cb => parseInt(cb.value));
}

function initAdminTaskActions() {
    $('#admin-task-filter').addEventListener('change', loadAdminTasks);
}

// Admin inline edit handlers
window.changeTaskType = async function (taskId, newType) {
    try {
        await api(`/api/admin/tasks/${taskId}/type`, { method: 'PUT', body: JSON.stringify({ task_type: newType }) });
        toast(`Type → ${newType}`, 'success');
    } catch (err) { toast(err.message, 'error'); loadAdminTasks(); }
};

window.changePostStatus = async function (taskId, newStatus) {
    try {
        await api(`/api/admin/tasks/${taskId}/post-status`, { method: 'PUT', body: JSON.stringify({ post_status: newStatus }) });
        toast(`Post → ${newStatus}${newStatus === 'Deleted' ? ' (₹0)' : ' (rewards)'}`, 'success');
    } catch (err) { toast(err.message, 'error'); loadAdminTasks(); }
};

window.changeTaskStatus = async function (taskId, newStatus) {
    try {
        await api(`/api/admin/tasks/${taskId}/status`, { method: 'PUT', body: JSON.stringify({ status: newStatus }) });
        toast(`Status → ${newStatus}`, 'success');
    } catch (err) { toast(err.message, 'error'); loadAdminTasks(); }
};

window.adminDeleteTask = async function (taskId) {
    if (!confirm('Delete this task permanently?')) return;
    try {
        await api(`/api/tasks/${taskId}`, { method: 'DELETE' });
        toast('Task deleted', 'success');
        loadAdminTasks();
    } catch (err) { toast(err.message, 'error'); }
};

async function loadAdminPayouts() {
    try {
        const payouts = await api('/api/admin/all-payouts');
        renderHistory(payouts, '#admin-all-payouts', true, true);
    } catch (err) { toast(err.message, 'error'); }
}

// ─── RATE CARDS ──────────────────────────────────────────
function renderRateCards(rates) {
    const container = $('#rate-cards');
    container.innerHTML = '';
    const icons = { 'Post': '📄', 'Comment': '💬', 'Support Comment': '🤝' };
    rates.forEach(r => {
        const card = document.createElement('div');
        card.className = 'glass-card rate-card';
        card.innerHTML = `
      <h4>${icons[r.category] || '📋'} ${r.category}</h4>
      <input type="number" min="0" step="0.5" value="${r.rate}" id="rate-${r.category.replace(/ /g, '_')}" data-category="${r.category}">
    `;
        container.appendChild(card);
    });
}

function initRateSave() {
    $('#save-rates-btn').addEventListener('click', async () => {
        const categories = ['Post', 'Comment', 'Support Comment'];
        const rates = categories.map(cat => ({
            category: cat,
            rate: parseFloat($(`#rate-${cat.replace(/ /g, '_')}`)?.value) || 0
        }));
        try {
            await api('/api/rates', { method: 'PUT', body: JSON.stringify({ rates }) });
            toast('Payout rates updated!', 'success');
        } catch (err) { toast(err.message, 'error'); }
    });
}

// ─── USERS TABLE ──────────────────────────────────────────
function renderUsersTable(users) {
    const container = $('#admin-users-list');
    if (!users || users.length === 0) {
        container.innerHTML = '<p class="empty-state">No users found.</p>';
        return;
    }

    let html = `<table class="users-table">
    <thead><tr>
      <th>Username</th><th>Role</th><th>CQS</th><th>Joined</th><th>Actions</th>
    </tr></thead><tbody>`;

    users.forEach(u => {
        html += `<tr>
      <td><strong>${u.username}</strong></td>
      <td><span class="role-tag">${u.role}</span></td>
      <td><span class="cqs-badge ${u.reddit_cqs || ''}">${u.reddit_cqs || '—'}</span></td>
      <td>${formatDate(u.created_at)}</td>
      <td>
        <button class="btn btn-sm btn-primary" onclick="viewUserDetail(${u.id})">🔍</button>
        <button class="btn btn-sm btn-warning" onclick="resetUserPassword(${u.id}, '${u.username}')">🔑</button>
        ${u.role !== 'admin' ? `<button class="btn btn-sm btn-danger" onclick="deleteUser(${u.id}, '${u.username}')">🗑</button>` : ''}
      </td>
    </tr>`;
    });

    html += '</tbody></table>';
    container.innerHTML = html;
}

window.viewUserDetail = async function (userId) {
    try {
        const data = await api(`/api/admin/user/${userId}`);
        const section = $('#admin-user-detail-section');
        section.style.display = 'block';
        $('#detail-username').textContent = data.user.username;

        let html = '<div class="detail-grid">';
        html += `<div class="detail-item"><div class="detail-label">Username</div><div class="detail-value">${data.user.username}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Role</div><div class="detail-value">${data.user.role}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Reddit CQS</div><div class="detail-value"><span class="cqs-badge ${data.account.reddit_cqs || ''}">${data.account.reddit_cqs || 'N/A'}</span></div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Primary Account</div><div class="detail-value">${data.account.primary_account || '—'}</div></div>`;
        html += `<div class="detail-item"><div class="detail-label">Current Payout</div><div class="detail-value" style="color:var(--success)">${formatCurrency(data.currentTotal)}</div></div>`;
        html += '</div>';

        if (data.taskStats.length > 0) {
            html += '<h4 style="margin:16px 0 8px;font-size:14px;color:var(--text-secondary)">TASK STATS</h4>';
            html += '<div class="detail-grid">';
            data.taskStats.forEach(s => {
                html += `<div class="detail-item">
          <div class="detail-label">${s.type} (${s.postStatus})</div>
          <div class="detail-value"><span class="status-badge ${s.status}">${s.status}</span> × ${s.count}</div>
        </div>`;
            });
            html += '</div>';
        }

        if (data.payouts.length > 0) {
            html += '<h4 style="margin:16px 0 8px;font-size:14px;color:var(--text-secondary)">PAYOUT HISTORY</h4>';
            data.payouts.forEach(p => {
                html += `<div class="history-item">
          <div class="history-left">
            <div class="history-amount">${formatCurrency(p.gross_amount)}</div>
            <div class="history-date">${formatDateTime(p.created_at)}</div>
          </div>
          <div class="history-right"><span class="history-status ${p.status}">${p.status}</span></div>
        </div>`;
            });
        }

        // Admin payout controls for this specific user
        html += `<div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap">
          <button class="btn btn-sm btn-ghost" onclick="adminCreatePayout(${userId}, 'Pending')">⏳ Create Pending</button>
          <button class="btn btn-sm btn-warning" onclick="adminCreatePayout(${userId}, 'Due')">📋 Create Due</button>
          <button class="btn btn-sm btn-primary" onclick="adminCreatePayout(${userId}, 'Paid')">✅ Create Paid</button>
        </div>`;

        $('#admin-user-detail').innerHTML = html;
        section.scrollIntoView({ behavior: 'smooth' });
    } catch (err) { toast(err.message, 'error'); }
};

window.adminCreatePayout = async function (userId, status) {
    if (!confirm(`Create ${status} payout for this user?`)) return;
    try {
        const result = await api('/api/payouts', { method: 'POST', body: JSON.stringify({ status, userId }) });
        toast(`Payout ${status}: ${formatCurrency(result.total)}`, 'success');
        viewUserDetail(userId);
        loadAdminPayouts();
    } catch (err) { toast(err.message, 'error'); }
};

window.deleteUser = async function (userId, username) {
    if (!confirm(`Delete user "${username}" and all their data? This cannot be undone.`)) return;
    try {
        await api(`/api/admin/user/${userId}`, { method: 'DELETE' });
        toast(`User ${username} deleted`, 'success');
        loadAdminData();
    } catch (err) { toast(err.message, 'error'); }
};

window.resetUserPassword = async function (userId, username) {
    const newPassword = prompt(`Enter new password for "${username}" (min 6 characters):`);
    if (!newPassword) return;
    if (newPassword.length < 6) { toast('Password must be at least 6 characters', 'error'); return; }
    try {
        await api(`/api/admin/user/${userId}/password`, { method: 'PUT', body: JSON.stringify({ newPassword }) });
        toast(`Password updated for ${username}`, 'success');
    } catch (err) { toast(err.message, 'error'); }
};

// ─── PASSWORD CHANGE ──────────────────────────────────────
function initPasswordChange() {
    $('#change-password-btn').addEventListener('click', () => {
        $('#password-modal').style.display = 'flex';
    });

    $('#cancel-password-btn').addEventListener('click', () => {
        $('#password-modal').style.display = 'none';
        $('#change-password-form').reset();
        $('#password-error').textContent = '';
    });

    $('#password-modal').addEventListener('click', (e) => {
        if (e.target === $('#password-modal')) {
            $('#password-modal').style.display = 'none';
            $('#change-password-form').reset();
        }
    });

    $('#change-password-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const newPassword = $('#new-pass').value;
        const confirm = $('#confirm-new-pass').value;
        $('#password-error').textContent = '';

        if (newPassword !== confirm) {
            $('#password-error').textContent = 'Passwords do not match';
            return;
        }

        try {
            await api('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ newPassword }) });
            toast('Password changed!', 'success');
            $('#password-modal').style.display = 'none';
            $('#change-password-form').reset();
        } catch (err) { $('#password-error').textContent = err.message; }
    });
}

// ─── CLOSE DETAIL ─────────────────────────────────────────
function initCloseDetail() {
    $('#close-detail-btn').addEventListener('click', () => {
        $('#admin-user-detail-section').style.display = 'none';
    });
}

// ─── LOGOUT ───────────────────────────────────────────────
function initLogout() {
    $('#logout-btn').addEventListener('click', () => {
        if (confirm('Are you sure you want to logout?')) {
            logout();
            toast('Logged out', 'info');
        }
    });
}

// ─── INITIALIZE ───────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initAuth();
    initNav();
    initProfilePanel();
    initAccountSave();
    initTaskForm();
    initMyTaskFilter();
    initPayoutActions();
    initPasswordChange();
    initLogout();
    initRateSave();
    initAdminTaskActions();
    initCloseDetail();
    checkSession();
});
