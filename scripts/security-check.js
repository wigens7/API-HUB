// End-to-end authorization and tenant-isolation checks. Run against a server started with ADMIN_EMAIL/ADMIN_PASSWORD:
//   BASE=http://localhost:8080 ADMIN_EMAIL=... ADMIN_PASSWORD=... DATABASE_URL=... node scripts/security-check.js
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const BASE = process.env.BASE || 'http://localhost:8080';
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
let failures = 0, passes = 0;
const check = (name, ok, extra = '') => { ok ? passes++ : failures++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  ' + extra}`); };
class Client {
 constructor() { this.cookie = ''; }
 async req(method, url, body, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (this.cookie) headers.cookie = this.cookie;
  if (opts.csrf !== false && method !== 'GET' && !opts.apiKey) headers['X-Zytrelix-Client'] = 'web';
  const res = await fetch(BASE + url, { method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
  const set = res.headers.get('set-cookie'); if (set && /zy_session=/.test(set)) { const m = set.match(/zy_session=([^;]*)/)[0]; this.cookie = m === 'zy_session=' ? '' : m; }
  let data = null; const text = await res.text(); try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data, location: res.headers.get('location') };
 }
 get(u, o) { return this.req('GET', u, null, o); } post(u, b, o) { return this.req('POST', u, b, o); } patch(u, b, o) { return this.req('PATCH', u, b, o); } del(u, o) { return this.req('DELETE', u, null, o); }
}
const tag = Math.random().toString(36).slice(2, 8);
const PW = 'Str0ng-Password-' + tag;
async function register(name) { const c = new Client(); const r = await c.post('/api/auth/register', { name: name + ' Owner', businessName: name + ' Ltd', email: `${name.toLowerCase()}-${tag}@example.com`, password: PW }); if (r.status !== 201) throw new Error('register failed ' + JSON.stringify(r)); return { c, email: `${name.toLowerCase()}-${tag}@example.com`, bizId: r.data.business.id, userId: r.data.user.id }; }

(async () => {
 const anon = new Client();
 console.log('--- anonymous');
 let r = await anon.get('/admin'); check('anonymous /admin redirects to /login', r.status === 302 && r.location === '/login', JSON.stringify(r));
 r = await anon.get('/admin/assets/admin.js'); check('anonymous admin.js blocked', r.status === 302);
 r = await anon.get('/dashboard'); check('anonymous /dashboard redirects', r.status === 302);
 for (const p of ['/api/admin/businesses', '/api/admin/kyc', '/api/admin/api-keys', '/api/admin/transactions', '/api/admin/subscriptions', '/api/admin/audit', '/api/admin/dashboard', '/api/keys', '/api/dashboard']) { r = await anon.get(p); check(`anonymous GET ${p} -> 401`, r.status === 401, r.status); }
 r = await anon.get('/api/health'); check('health does not leak provider/database config', r.status === 200 && Object.keys(r.data).sort().join() === 'ok,service', JSON.stringify(r.data));
 r = await anon.get('/admin.html'); check('admin.html not served statically', r.status === 404, r.status);
 r = await anon.get('/views/admin.js'); check('views/ not served statically', r.status === 404, r.status);
 r = await anon.get('/server.js'); check('server source not served', r.status === 404, r.status);

 console.log('--- admin login');
 const admin = new Client();
 r = await admin.post('/api/auth/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD }); check('admin login -> redirect /admin', r.status === 200 && r.data.redirect === '/admin', JSON.stringify(r));
 r = await admin.get('/admin'); check('admin can open /admin', r.status === 200 && /Admin overview/.test(r.data));
 r = await admin.get('/admin/assets/admin.js'); check('admin can load admin.js', r.status === 200);
 r = await admin.get('/dashboard'); check('admin visiting /dashboard is sent to /admin', r.status === 302 && r.location === '/admin');
 r = await admin.get('/api/keys'); check('admin blocked from business API /api/keys', r.status === 403);
 r = await admin.get('/api/dashboard'); check('admin blocked from business /api/dashboard', r.status === 403);
 r = await admin.get('/api/admin/dashboard'); check('admin dashboard API works', r.status === 200 && r.data.stats);

 console.log('--- business registration and login');
 const A = await register('Alpha'), B = await register('Bravo');
 r = await A.c.get('/dashboard'); check('business user can open /dashboard', r.status === 200 && /Zytrelix/.test(r.data) && !/page-businesses/.test(r.data));
 r = await A.c.get('/admin'); check('business user /admin -> 403', r.status === 403 && !/Admin overview/.test(r.data), r.status);
 r = await A.c.get('/admin/assets/admin.js'); check('business user cannot download admin.js', r.status === 403 && !/loadBusinesses/.test(String(r.data)));
 const login = new Client(); r = await login.post('/api/auth/login', { email: A.email, password: PW }); check('business login -> redirect /dashboard', r.data.redirect === '/dashboard');
 r = await login.post('/api/auth/login', { email: A.email, password: 'wrong-password-123' }); check('wrong password -> 401', r.status === 401);
 r = await new Client().post('/api/auth/login', { email: 'nobody@example.com', password: PW }); check('unknown user -> 401', r.status === 401);

 console.log('--- business user hitting admin APIs directly');
 for (const p of ['/api/admin/businesses', '/api/admin/kyc', '/api/admin/api-keys', '/api/admin/transactions', '/api/admin/subscriptions', '/api/admin/audit', '/api/admin/dashboard']) { r = await A.c.get(p); check(`business GET ${p} -> 403`, r.status === 403, r.status); }
 r = await A.c.patch(`/api/admin/businesses/${A.bizId}`, { status: 'active' }); check('business cannot self-approve', r.status === 403);
 r = await A.c.patch(`/api/admin/subscriptions/${A.bizId}`, { plan: 'enterprise' }); check('business cannot change own plan', r.status === 403);
 r = await A.c.patch(`/api/admin/kyc/${A.bizId}`, { decision: 'approved' }); check('business cannot review KYC', r.status === 403);
 const forged = jwt.sign({ sub: A.userId, role: 'admin' }, 'x'.repeat(48), { issuer: 'zytrelix' });
 r = await anon.get('/api/admin/businesses', { headers: { authorization: 'Bearer ' + forged } }); check('forged admin JWT -> 401', r.status === 401);
 const none = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url') + '.' + Buffer.from(JSON.stringify({ sub: A.userId, role: 'admin', iss: 'zytrelix' })).toString('base64url') + '.';
 r = await anon.get('/api/admin/businesses', { headers: { authorization: 'Bearer ' + none } }); check('alg=none JWT -> 401', r.status === 401);
 const privEsc = new Client(); r = await privEsc.post('/api/auth/register', { name: 'Eve', businessName: 'Eve', email: `eve-${tag}@example.com`, password: PW, role: 'admin' }); check('register ignores role=admin', r.status === 201 && r.data.user.role === 'business' && r.data.redirect === '/dashboard');
 r = await privEsc.get('/api/admin/businesses'); check('mass-assigned admin role gives no access', r.status === 403);
 r = await A.c.post('/api/keys', { label: 'x' }); check('pending business cannot create key', r.status === 403);

 console.log('--- CSRF');
 r = await admin.patch(`/api/admin/businesses/${A.bizId}`, { status: 'pending' }, { csrf: false }); check('cookie write without client header blocked', r.status === 403);
 r = await admin.patch(`/api/admin/businesses/${A.bizId}`, { status: 'pending' }, { headers: { origin: 'https://evil.example' } }); check('cross-origin write blocked', r.status === 403);

 console.log('--- admin approves businesses');
 for (const t of [A, B]) { r = await admin.patch(`/api/admin/businesses/${t.bizId}`, { status: 'active' }); check('admin approves business', r.status === 200 && r.data.business.status === 'active'); }
 r = await admin.patch('/api/admin/businesses/not-a-uuid', { status: 'active' }); check('bad business id -> 404', r.status === 404);
 r = await admin.patch(`/api/admin/businesses/${A.bizId}`, { status: 'hacked' }); check('invalid status rejected', r.status === 400);
 const keys = {};
 for (const [n, t] of [['A', A], ['B', B]]) { r = await t.c.post('/api/keys', { label: n + ' key' }); check(`${n} creates API key`, r.status === 201 && r.data.secret); keys[n] = { secret: r.data.secret, id: r.data.key.id }; }

 console.log('--- tenant isolation (seed data directly, then read through the API)');
 const seed = async (t, label) => {
  const k = await pool.query(`INSERT INTO kyc_submissions(business_id,customer_email,customer_name,country,status,provider_customer_id) VALUES($1,$2,$3,'HTI','submitted',$4) RETURNING id`, [t.bizId, `cust-${label}-${tag}@example.com`, 'Cust ' + label, 'cid-' + label + tag]);
  const c = await pool.query(`INSERT INTO cards(business_id,provider_card_id,cardholder_name,status) VALUES($1,$2,$3,'active') RETURNING id,provider_card_id`, [t.bizId, 'card-' + label + tag, 'Holder ' + label]);
  await pool.query(`INSERT INTO transactions(business_id,card_id,type,amount,status) VALUES($1,$2,'fund',10,'ok')`, [t.bizId, c.rows[0].id]);
  await pool.query(`INSERT INTO api_usage(business_id,method,path,status_code,duration_ms) VALUES($1,'GET','/seed-${label}',200,1)`, [t.bizId]);
  return { kyc: k.rows[0].id, card: c.rows[0].provider_card_id };
 };
 const dA = await seed(A, 'A'), dB = await seed(B, 'B');
 const seesOnly = (rows, field, mine, theirs) => rows.some(x => String(x[field]).includes(mine)) && !rows.some(x => String(x[field]).includes(theirs));
 r = await A.c.get('/api/kyc'); check('A sees only A KYC', seesOnly(r.data.submissions, 'customer_name', 'Cust A', 'Cust B'));
 r = await A.c.get('/api/cards'); check('A sees only A cards', seesOnly(r.data.cards, 'cardholder_name', 'Holder A', 'Holder B'));
 r = await A.c.get('/api/transactions'); check('A sees only own transactions', r.data.transactions.length === 1);
 r = await A.c.get('/api/activity'); check('A sees only A usage', seesOnly(r.data.activity, 'path', 'seed-A', 'seed-B'));
 r = await A.c.get('/api/keys'); check('A sees only A keys', r.data.keys.length === 1 && r.data.keys[0].id === keys.A.id);
 r = await A.c.get('/api/keys'); check('API key list never exposes key_hash', !JSON.stringify(r.data).includes('key_hash'));
 r = await A.c.del(`/api/keys/${keys.B.id}`); check("A cannot revoke B's key -> 404", r.status === 404);
 r = await B.c.get('/api/keys'); check("B's key still active after A's attempt", r.data.keys[0].revoked_at === null);
 r = await anon.get('/v1/cards', { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check('A partner API lists only A cards', r.status === 200 && r.data.cards.length === 1 && r.data.cards[0].provider_card_id === dA.card, JSON.stringify(r.data));
 r = await anon.get(`/v1/cards/${dB.card}`, { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check("A key cannot read B's card -> 404", r.status === 404, r.status);
 r = await anon.post(`/v1/cards/${dB.card}/funding`, { amount: 5 }, { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check("A key cannot fund B's card -> 404", r.status === 404, r.status);
 r = await anon.post(`/v1/cards/${dB.card}/status`, { status: 'frozen' }, { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check("A key cannot freeze B's card -> 404", r.status === 404, r.status);
 r = await anon.get(`/v1/kyc/status?email=cust-B-${tag}@example.com`, { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check("A key cannot query B's KYC -> 404", r.status === 404, r.status);
 r = await anon.post('/v1/cards', { name: 'x', customer_id: 'cid-B' + tag, amount: 5 }, { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check("A key cannot issue card for B's customer -> 403", r.status === 403, r.status);
 r = await anon.get('/v1/status', { apiKey: true, headers: { 'x-api-key': 'zy_test_nonsense' } }); check('invalid API key -> 401', r.status === 401);
 r = await anon.get('/v1/status'); check('missing API key -> 401', r.status === 401);
 r = await A.c.get('/v1/status'); check('session cookie is not accepted on partner API', r.status === 401);

 console.log('--- database-level isolation (row-level security)');
 const q = async (role, biz, sql, params = []) => { const c = await pool.connect(); try { await c.query('BEGIN'); await c.query(`SET LOCAL ROLE ${role}`); if (biz) await c.query(`SELECT set_config('app.business_id',$1,true)`, [biz]); const res = await c.query(sql, params); await c.query('ROLLBACK'); return { rows: res.rows, count: res.rowCount }; } catch (e) { await c.query('ROLLBACK').catch(() => {}); return { error: e.message }; } finally { c.release(); } };
 let x = await q('zytrelix_tenant', A.bizId, 'SELECT business_id FROM cards'); check('RLS: tenant A sees only its cards at DB level', !x.error && x.rows.length > 0 && x.rows.every(r => r.business_id === A.bizId), JSON.stringify(x));
 x = await q('zytrelix_tenant', null, 'SELECT * FROM cards'); check('RLS: no tenant context -> zero rows (fail closed)', !x.error && x.rows.length === 0, JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, 'SELECT * FROM kyc_submissions WHERE business_id=$1', [B.bizId]); check("RLS: tenant A cannot select B's KYC even by id", x.rows.length === 0);
 x = await q('zytrelix_tenant', A.bizId, 'UPDATE cards SET status=$1 WHERE business_id=$2', ['frozen', B.bizId]); check("RLS: tenant A cannot update B's cards", !x.error && x.count === 0, JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, `INSERT INTO cards(business_id,provider_card_id) VALUES($1,'evil')`, [B.bizId]); check("RLS: tenant A cannot insert rows into B's tenant", /row-level security/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, 'SELECT password_hash FROM users'); check('privileges: tenant cannot read password hashes', /permission denied/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, 'SELECT key_hash FROM api_keys'); check('privileges: tenant cannot read API key hashes', /permission denied/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, 'SELECT * FROM audit_logs'); check('privileges: tenant cannot read audit logs', /permission denied/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, 'UPDATE businesses SET status=$1', ['active']); check('privileges: tenant cannot modify businesses', /permission denied/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, 'UPDATE subscriptions SET plan=$1', ['enterprise']); check('privileges: tenant cannot modify subscription', /permission denied/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_tenant', A.bizId, 'SELECT id, email FROM businesses'); check('RLS: tenant sees only its own business row', x.rows.length === 1 && x.rows[0].id === A.bizId, JSON.stringify(x));
 x = await q('zytrelix_admin', null, 'SELECT password_hash FROM users'); check('privileges: admin role cannot read password hashes', /permission denied/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_admin', null, 'SELECT key_hash FROM api_keys'); check('privileges: admin role cannot read API key hashes', /permission denied/i.test(x.error || ''), JSON.stringify(x));
 x = await q('zytrelix_admin', null, 'DELETE FROM cards'); check('privileges: admin role cannot delete cards', /permission denied/i.test(x.error || ''), JSON.stringify(x));

 console.log('--- admin management features');
 r = await admin.get('/api/admin/businesses'); check('admin lists both businesses', [A.bizId, B.bizId].every(id => r.data.businesses.some(b => b.id === id)));
 r = await admin.get('/api/admin/kyc'); check('admin sees KYC from all businesses', r.data.submissions.some(s => s.id === dA.kyc) && r.data.submissions.some(s => s.id === dB.kyc));
 r = await admin.patch(`/api/admin/kyc/${dA.kyc}`, { decision: 'approved' }); check('admin approves KYC', r.status === 200 && r.data.submission.status === 'approved', JSON.stringify(r));
 r = await admin.patch(`/api/admin/kyc/${dB.kyc}`, { decision: 'rejected', note: 'blurry id' }); check('admin rejects KYC', r.status === 200 && r.data.submission.status === 'rejected');
 r = await A.c.get('/api/kyc'); check('business sees admin KYC decision', r.data.submissions[0].status === 'approved');
 r = await admin.patch(`/api/admin/kyc/${dA.kyc}`, { decision: 'maybe' }); check('invalid KYC decision rejected', r.status === 400);
 r = await admin.get('/api/admin/api-keys'); check('admin lists keys without hashes', r.data.keys.length >= 2 && !JSON.stringify(r.data).includes('key_hash'));
 r = await admin.get('/api/admin/transactions'); check('admin views transactions with business names', r.data.transactions.length >= 2 && r.data.transactions.every(t => t.business_name));
 r = await admin.patch(`/api/admin/subscriptions/${A.bizId}`, { plan: 'growth', status: 'paused' }); check('admin pauses subscription', r.status === 200 && r.data.subscription.status === 'paused');
 r = await anon.get('/v1/status', { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check('paused subscription blocks partner API', r.status === 403, r.status);
 r = await A.c.get('/api/subscription'); check('business reads its own subscription', r.data.subscription.plan === 'growth' && r.data.subscription.status === 'paused');
 r = await admin.patch(`/api/admin/subscriptions/${A.bizId}`, { plan: 'platinum' }); check('invalid plan rejected', r.status === 400);
 r = await admin.patch(`/api/admin/subscriptions/${A.bizId}`, { status: 'active' }); check('admin reactivates subscription', r.status === 200);
 r = await anon.get('/v1/status', { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check('partner API works again', r.status === 200);
 r = await admin.del(`/api/admin/api-keys/${keys.B.id}`); check("admin revokes B's key", r.status === 200);
 r = await anon.get('/v1/status', { apiKey: true, headers: { 'x-api-key': keys.B.secret } }); check('revoked key rejected', r.status === 401);
 r = await admin.patch(`/api/admin/businesses/${A.bizId}`, { status: 'suspended' }); check('admin suspends A', r.status === 200);
 r = await A.c.get('/api/dashboard'); check('suspended business session is cut off immediately', r.status === 403, r.status);
 r = await A.c.get('/dashboard'); check('suspended business cannot open /dashboard', r.status === 302 && r.location === '/login', r.status);
 r = await new Client().post('/api/auth/login', { email: A.email, password: PW }); check('suspended business cannot log in', r.status === 403);
 r = await anon.get('/v1/status', { apiKey: true, headers: { 'x-api-key': keys.A.secret } }); check('suspended business API key rejected', r.status === 403);
 r = await admin.get('/api/admin/audit'); check('audit log records admin actions', r.data.logs.some(l => l.action === 'business.status_changed') && r.data.logs.some(l => l.action === 'kyc.reviewed'));
 r = await A.c.post('/api/auth/logout'); check('logout clears cookie', A.c.cookie === '');
 console.log(`\n${passes} passed, ${failures} failed`);
 await pool.end(); process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
