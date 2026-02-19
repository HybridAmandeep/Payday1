const http = require('http');

function req(method, path, body, token) {
    return new Promise((resolve, reject) => {
        const data = body ? JSON.stringify(body) : '';
        const headers = { 'Content-Type': 'application/json' };
        if (token) headers['Authorization'] = `Bearer ${token}`;
        const options = { hostname: 'localhost', port: 3000, path, method, headers };
        if (data) options.headers['Content-Length'] = Buffer.byteLength(data);
        const r = http.request(options, (res) => {
            let b = ''; res.on('data', c => b += c);
            res.on('end', () => { try { resolve({ status: res.statusCode, data: JSON.parse(b) }); } catch (e) { resolve({ status: res.statusCode, data: b }); } });
        });
        r.on('error', reject);
        if (data) r.write(data);
        r.end();
    });
}

async function test() {
    let pass = 0, fail = 0;
    function check(label, ok) {
        if (ok) { console.log(`  ✅ ${label}`); pass++; }
        else { console.log(`  ❌ ${label}`); fail++; }
    }

    console.log('\n=== 1PAYOUT SHEET — Redesign V2 Tests ===\n');

    // Auth
    const admin = await req('POST', '/api/auth/login', { username: 'Amandeep3583', password: 'Amandeep@3583' });
    check('1. Admin login', admin.status === 200);
    const aToken = admin.data.token;

    const reg = await req('POST', '/api/auth/register', { username: 'worker1', password: 'worker123' });
    check('2. User register', reg.status === 200);
    const uToken = reg.data.token;

    // Account + CQS
    await req('PUT', '/api/account', { primary_account: 'u/main', alt_account_1: 'u/alt1', reddit_cqs: 'High' }, uToken);
    const acc = await req('GET', '/api/account', null, uToken);
    check('3. CQS = High', acc.data.reddit_cqs === 'High');

    // Submit tasks
    const t1 = await req('POST', '/api/tasks', { task_date: '2026-02-20', task_url: 'https://reddit.com/p1', account_used: 'u/main', task_type: 'Post' }, uToken);
    const t2 = await req('POST', '/api/tasks', { task_date: '2026-02-20', task_url: 'https://reddit.com/c1', account_used: 'u/main', task_type: 'Comment' }, uToken);
    const t3 = await req('POST', '/api/tasks', { task_date: '2026-02-20', task_url: 'https://reddit.com/s1', account_used: 'u/alt1', task_type: 'Support Comment' }, uToken);
    const t4 = await req('POST', '/api/tasks', { task_date: '2026-02-20', task_url: 'https://reddit.com/p2', account_used: 'u/main', task_type: 'Post' }, uToken);
    check('4. Submit 4 tasks', [t1, t2, t3, t4].every(t => t.status === 200));

    // Payout before verify = 0
    const payBefore = await req('GET', '/api/payout/calculate', null, uToken);
    check('5. Payout before verify = ₹0', payBefore.data.total === 0);
    check('6. Pending count = 4', payBefore.data.pendingCount === 4);

    // USER cannot create payout (admin only now)
    const userPayout = await req('POST', '/api/payouts', { status: 'Pending' }, uToken);
    check('7. User blocked from creating payout', userPayout.status === 403);

    // Admin verifies all
    const pending = await req('GET', '/api/admin/tasks?status=Pending', null, aToken);
    const taskIds = pending.data.map(t => t.id);
    await req('POST', '/api/admin/tasks/bulk-verify', { taskIds, status: 'Verified' }, aToken);
    const payAfter = await req('GET', '/api/payout/calculate', null, uToken);
    check('8. Payout after verify = ₹180', payAfter.data.total === 180);

    // Admin changes task type (Post → Comment)
    const chType = await req('PUT', `/api/admin/tasks/${taskIds[0]}/type`, { task_type: 'Comment' }, aToken);
    check('9. Admin change task type', chType.status === 200);
    const payRecalc = await req('GET', '/api/payout/calculate', null, uToken);
    // Was 2×Post(75)+1×Comment(15)+1×Support(15)=180, now 1×Post(75)+2×Comment(15)+1×Support(15)=120
    check('10. Payout recalculated after type change = ₹120', payRecalc.data.total === 120);

    // Admin marks a task as Deleted → ₹0 for that task
    const chPost = await req('PUT', `/api/admin/tasks/${taskIds[1]}/post-status`, { post_status: 'Deleted' }, aToken);
    check('11. Admin mark post Deleted', chPost.status === 200);
    const payDel = await req('GET', '/api/payout/calculate', null, uToken);
    // Task 0 is now Comment (verified, Live) = 15
    // Task 1 is Comment (verified, Deleted) = 0
    // Task 2 is Support Comment (verified, Live) = 15
    // Task 3 is Post (verified, Live) = 75
    // Total = 15 + 0 + 15 + 75 = 105
    check('12. Deleted task = ₹0, total = ₹105', payDel.data.total === 105);

    // Restore to Live
    await req('PUT', `/api/admin/tasks/${taskIds[1]}/post-status`, { post_status: 'Live' }, aToken);
    const payLive = await req('GET', '/api/payout/calculate', null, uToken);
    check('13. Restored to Live, total = ₹120', payLive.data.total === 120);

    // Admin creates payout as Due (no duplication test)
    const userId = reg.data.user.id;
    const createDue = await req('POST', '/api/payouts', { status: 'Due', userId }, aToken);
    check('14. Admin create Due payout', createDue.status === 200);
    const payoutId = createDue.data.total > 0 ? true : false;
    check('15. Due payout amount = ₹120', createDue.data.total === 120);

    // Check user sees it in history
    const hist = await req('GET', '/api/payouts', null, uToken);
    check('16. User sees 1 payout in history', hist.data.length === 1 && hist.data[0].status === 'Due');

    // Admin marks Due → Paid (updates same record, no new record)
    const allPayouts = await req('GET', '/api/admin/all-payouts', null, aToken);
    const pid = allPayouts.data[0].id;
    const markPaid = await req('PUT', `/api/payouts/${pid}/status`, { status: 'Paid' }, aToken);
    check('17. Mark existing payout as Paid (no dup)', markPaid.status === 200);

    // Check history: should be 1 record as Paid, NOT 2 records
    const histAfter = await req('GET', '/api/payouts', null, uToken);
    check('18. History shows 1 record (no duplication)', histAfter.data.length === 1);
    check('19. Status is now Paid', histAfter.data[0].status === 'Paid');

    // Cannot modify paid payout
    const modPaid = await req('PUT', `/api/payouts/${pid}/status`, { status: 'Due' }, aToken);
    check('20. Cannot modify paid payout', modPaid.status === 400);

    console.log(`\n=== Results: ${pass} passed, ${fail} failed out of ${pass + fail} ===\n`);
}

test().catch(err => console.error(err));
