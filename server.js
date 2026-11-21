require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const PROVIDER_BASE = (process.env.ZIIROPAY_BASE_URL || 'https://www.ziiropay.com/api').replace(/\/$/, '');
const PROVIDER_KEY = process.env.ZIIROPAY_PUBLIC_KEY;
const PROVIDER_MODE = process.env.ZIIROPAY_MODE || 'sandbox';
const COOKIE_NAME = 'zy_session';
const SESSION_HOURS = 12;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PLANS = ['free', 'starter', 'growth', 'enterprise'];
const SUBSCRIPTION_STATUSES = ['active', 'paused', 'cancelled'];
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined, max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 });

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], formAction: ["'self'"], upgradeInsecureRequests: [] } } }));
const origins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: (origin, cb) => !origin || origins.includes(origin) ? cb(null, true) : cb(null, false), methods: ['GET','POST','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization','X-API-Key','X-Idempotency-Key','X-Zytrelix-Client'] }));
app.use(express.json({ limit: '12mb' }));
app.use('/api/', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: true, legacyHeaders: false }));
app.use('/v1/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15 * 60_000, limit: Number(process.env.AUTH_RATE_LIMIT || 15), standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again later.' } });
// Only public, non-sensitive assets are served statically. Dashboard code lives in views/ behind role checks.
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

const schema = `
CREATE TABLE IF NOT EXISTS businesses (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID REFERENCES businesses(id) ON DELETE CASCADE,
 name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK (role IN ('admin','business')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 CHECK ((role = 'admin' AND business_id IS NULL) OR (role = 'business' AND business_id IS NOT NULL))
);
CREATE TABLE IF NOT EXISTS api_keys (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 label TEXT NOT NULL, key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE,
 environment TEXT NOT NULL DEFAULT 'sandbox' CHECK (environment IN ('sandbox','production')),
 last_used_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS kyc_submissions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 provider_customer_id TEXT, customer_email TEXT NOT NULL, customer_name TEXT NOT NULL,
 country TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'submitted', provider_reference TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE kyc_submissions ADD COLUMN IF NOT EXISTS admin_decision TEXT CHECK (admin_decision IN ('approved','rejected'));
ALTER TABLE kyc_submissions ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE kyc_submissions ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE kyc_submissions ADD COLUMN IF NOT EXISTS review_note TEXT;
CREATE INDEX IF NOT EXISTS kyc_business_idx ON kyc_submissions(business_id, created_at DESC);
CREATE TABLE IF NOT EXISTS cards (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 provider_card_id TEXT NOT NULL, provider_customer_id TEXT, cardholder_name TEXT,
 last_four TEXT, status TEXT, currency TEXT DEFAULT 'USD', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE (business_id, provider_card_id)
);
CREATE INDEX IF NOT EXISTS cards_business_idx ON cards(business_id, created_at DESC);
CREATE TABLE IF NOT EXISTS transactions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 card_id UUID REFERENCES cards(id) ON DELETE SET NULL, provider_reference TEXT, type TEXT NOT NULL,
 amount NUMERIC(18,2), currency TEXT DEFAULT 'USD', status TEXT NOT NULL DEFAULT 'submitted',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS webhook_endpoints (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 url TEXT NOT NULL, events TEXT[] NOT NULL DEFAULT ARRAY['*'], secret_hash TEXT NOT NULL,
 active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id BIGSERIAL PRIMARY KEY, business_id UUID REFERENCES businesses(id) ON DELETE SET NULL,
 actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL,
 details JSONB NOT NULL DEFAULT '{}'::jsonb, ip INET, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS api_usage (
 id BIGSERIAL PRIMARY KEY, business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL, method TEXT NOT NULL, path TEXT NOT NULL,
 status_code INTEGER NOT NULL, duration_ms INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS subscriptions (
 business_id UUID PRIMARY KEY REFERENCES businesses(id) ON DELETE CASCADE,
 plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free','starter','growth','enterprise')),
 status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','cancelled')),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO subscriptions (business_id) SELECT id FROM businesses ON CONFLICT DO NOTHING;
`;

// Database-level tenant isolation. Every tenant-scoped request runs inside a transaction that drops to a
// restricted, non-superuser role (SET LOCAL ROLE). PostgreSQL row-level security then limits that role to
// rows whose business_id equals app.business_id. The admin role has its own, narrower privilege set
// (no password hashes, no API key hashes). If the context is missing, the policies match no rows.
const tenantRows = ['kyc_submissions', 'cards', 'transactions', 'api_usage', 'api_keys', 'webhook_endpoints', 'subscriptions', 'audit_logs'];
const TENANT_PREDICATE = `business_id = NULLIF(current_setting('app.business_id', true), '')::uuid`;
const security = `
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='zytrelix_tenant') THEN CREATE ROLE zytrelix_tenant NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='zytrelix_admin') THEN CREATE ROLE zytrelix_admin NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
END $$;
GRANT zytrelix_tenant TO CURRENT_USER;
GRANT zytrelix_admin TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO zytrelix_tenant, zytrelix_admin;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM zytrelix_tenant, zytrelix_admin;
ALTER TABLE businesses ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
${tenantRows.map(t => `ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;`).join('\n')}
DROP POLICY IF EXISTS tenant_isolation ON businesses;
CREATE POLICY tenant_isolation ON businesses AS PERMISSIVE FOR ALL TO zytrelix_tenant USING (id = NULLIF(current_setting('app.business_id', true), '')::uuid) WITH CHECK (false);
DROP POLICY IF EXISTS admin_all ON businesses;
CREATE POLICY admin_all ON businesses FOR ALL TO zytrelix_admin USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS tenant_isolation ON users;
CREATE POLICY tenant_isolation ON users FOR SELECT TO zytrelix_tenant USING (${TENANT_PREDICATE} AND role = 'business');
DROP POLICY IF EXISTS admin_all ON users;
CREATE POLICY admin_all ON users FOR SELECT TO zytrelix_admin USING (true);
${tenantRows.map(t => `DROP POLICY IF EXISTS tenant_isolation ON ${t};
CREATE POLICY tenant_isolation ON ${t} FOR ALL TO zytrelix_tenant USING (${TENANT_PREDICATE}) WITH CHECK (${TENANT_PREDICATE});
DROP POLICY IF EXISTS admin_all ON ${t};
CREATE POLICY admin_all ON ${t} FOR ALL TO zytrelix_admin USING (true) WITH CHECK (true);`).join('\n')}
-- tenant privileges
GRANT SELECT ON businesses TO zytrelix_tenant;
GRANT SELECT (id, business_id, name, email, role, created_at) ON users TO zytrelix_tenant;
GRANT SELECT (id, business_id, label, key_prefix, environment, last_used_at, revoked_at, created_at), INSERT, UPDATE (revoked_at, last_used_at) ON api_keys TO zytrelix_tenant;
GRANT SELECT, INSERT, UPDATE (status, provider_customer_id, updated_at) ON kyc_submissions TO zytrelix_tenant;
GRANT SELECT, INSERT, UPDATE (status) ON cards TO zytrelix_tenant;
GRANT SELECT, INSERT ON transactions TO zytrelix_tenant;
GRANT SELECT, INSERT ON api_usage TO zytrelix_tenant;
GRANT INSERT ON audit_logs TO zytrelix_tenant;
GRANT SELECT ON subscriptions TO zytrelix_tenant;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO zytrelix_tenant, zytrelix_admin;
-- admin privileges
GRANT SELECT, UPDATE (status) ON businesses TO zytrelix_admin;
GRANT SELECT (id, business_id, name, email, role, created_at) ON users TO zytrelix_admin;
GRANT SELECT (id, business_id, label, key_prefix, environment, last_used_at, revoked_at, created_at), UPDATE (revoked_at) ON api_keys TO zytrelix_admin;
GRANT SELECT, UPDATE (status, admin_decision, reviewed_by, reviewed_at, review_note, updated_at) ON kyc_submissions TO zytrelix_admin;
GRANT SELECT ON cards, transactions, api_usage TO zytrelix_admin;
GRANT SELECT, INSERT ON audit_logs TO zytrelix_admin;
GRANT SELECT, INSERT, UPDATE ON subscriptions TO zytrelix_admin;
`;

/** Run fn inside a transaction bound to one tenant (ctx.businessId) or to the admin role (ctx.admin). */
async function scoped(ctx, fn) {
 if (!ctx.admin && !UUID_RE.test(String(ctx.businessId || ''))) { const e = new Error('Tenant context missing.'); e.status = 403; throw e; }
 const client = await pool.connect();
 try {
  await client.query('BEGIN');
  await client.query(`SET LOCAL ROLE ${ctx.admin ? 'zytrelix_admin' : 'zytrelix_tenant'}`);
  if (!ctx.admin) await client.query(`SELECT set_config('app.business_id', $1, true)`, [ctx.businessId]);
  const result = await fn(client);
  await client.query('COMMIT');
  return result;
 } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
 finally { client.release(); }
}

function safeEqual(a, b) { const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b)); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); }
function hashKey(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function createToken(user) { return jwt.sign({ sub: user.id }, JWT_SECRET, { algorithm: 'HS256', expiresIn: `${SESSION_HOURS}h`, issuer: 'zytrelix' }); }
function asyncRoute(fn) { return (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next); }
function httpError(status, message) { const e = new Error(message); e.status = status; return e; }
function parseCookies(header) { const out = {}; for (const part of String(header || '').split(';')) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } return out; }
function setSession(req, res, user) { res.cookie(COOKIE_NAME, createToken(user), { httpOnly: true, sameSite: 'strict', secure: req.secure, maxAge: SESSION_HOURS * 3600_000, path: '/' }); }
function clearSession(res) { res.clearCookie(COOKIE_NAME, { path: '/' }); }
function auditEvent(db, actor, action, details = {}, ip = null) { return db.query('INSERT INTO audit_logs (business_id, actor_user_id, action, details, ip) VALUES ($1,$2,$3,$4,$5)', [actor?.businessId || null, actor?.sub || null, action, JSON.stringify(details), ip]); }
function audit(req, action, details = {}) { return auditEvent(pool, req.auth, action, details, req.ip).catch(err => console.error('audit log failed:', err.message)); }

/** Resolve the session to a user. Role, business and business status always come from the database, never from the token. */
async function loadSession(req) {
 const cookieToken = parseCookies(req.get('cookie'))[COOKIE_NAME];
 const header = req.get('authorization') || '';
 const bearer = header.startsWith('Bearer ') ? header.slice(7) : '';
 const token = cookieToken || bearer;
 if (!token || !JWT_SECRET) return null;
 let claims; try { claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer: 'zytrelix' }); } catch { return null; }
 if (!UUID_RE.test(String(claims.sub))) return null;
 const q = await pool.query(`SELECT u.id,u.name,u.email,u.role,u.business_id,b.status AS business_status FROM users u LEFT JOIN businesses b ON b.id=u.business_id WHERE u.id=$1`, [claims.sub]);
 if (!q.rowCount) return null;
 const u = q.rows[0];
 return { sub: u.id, name: u.name, email: u.email, role: u.role, businessId: u.business_id, businessStatus: u.business_status, viaCookie: Boolean(cookieToken) };
}
function sameOrigin(req) { const origin = req.get('origin'); if (!origin) return true; try { return new URL(origin).host === req.get('host'); } catch { return false; } }
const requireAuth = asyncRoute(async (req, res, next) => {
 const session = await loadSession(req);
 if (!session) return res.status(401).json({ error: 'Authentication required.' });
 if (session.viaCookie && !['GET','HEAD','OPTIONS'].includes(req.method) && (req.get('x-zytrelix-client') !== 'web' || !sameOrigin(req))) return res.status(403).json({ error: 'Cross-site request blocked.' });
 if (session.role === 'business' && session.businessStatus === 'suspended') return res.status(403).json({ error: 'This business account is suspended. Contact support.' });
 req.auth = session; next();
});
function requireAdmin(req,res,next) { if (req.auth?.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' }); next(); }
function requireBusiness(req,res,next) { if (req.auth?.role !== 'business' || !req.auth.businessId) return res.status(403).json({ error: 'Business account required.' }); next(); }
const adminDb = (req, fn) => scoped({ admin: true }, fn);
const tenantDb = (req, fn) => scoped({ businessId: req.auth.businessId }, fn);

// Role-guarded pages. The anonymous and wrong-role cases never receive dashboard code.
const pageSession = asyncRoute(async (req, _res, next) => { req.auth = await loadSession(req).catch(() => null); next(); });
const homeFor = s => s.role === 'admin' ? '/admin' : '/dashboard';
function guardPage(role) {
 return (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  if (!req.auth) return res.redirect(302, '/login');
  if (req.auth.role === 'business' && req.auth.businessStatus === 'suspended') { clearSession(res); return res.redirect(302, '/login'); }
  if (req.auth.role !== role) return role === 'admin' ? res.status(403).type('html').send('<!doctype html><title>Forbidden</title><h1>403 Forbidden</h1><p>Administrator access is required.</p><p><a href="/dashboard">Back to your dashboard</a></p>') : res.redirect(302, homeFor(req.auth));
  next();
 };
}
async function requireApiKey(req,res,next) {
 const raw = req.get('x-api-key') || ''; if (!raw) return res.status(401).json({ error: 'X-API-Key header is required.' });
 try {
  const result = await pool.query(`SELECT k.id AS key_id,k.business_id,k.environment,b.status AS business_status,COALESCE(s.status,'active') AS subscription_status FROM api_keys k JOIN businesses b ON b.id=k.business_id LEFT JOIN subscriptions s ON s.business_id=k.business_id WHERE k.key_hash=$1 AND k.revoked_at IS NULL`, [hashKey(raw)]);
  if (!result.rowCount) return res.status(401).json({ error: 'Invalid API key.' });
  const row = result.rows[0]; if (row.business_status !== 'active') return res.status(403).json({ error: 'Business account is not active.' });
  if (row.subscription_status !== 'active') return res.status(403).json({ error: `Subscription is ${row.subscription_status}. Contact support.` });
  if (row.environment !== PROVIDER_MODE) return res.status(403).json({ error: `This API key is for ${row.environment}, but provider mode is ${PROVIDER_MODE}.` });
  req.partner = { businessId: row.business_id, apiKeyId: row.key_id, environment: row.environment };
  await scoped({ businessId: row.business_id }, c => c.query('UPDATE api_keys SET last_used_at=NOW() WHERE id=$1', [row.key_id])); next();
 } catch (e) { next(e); }
}
async function providerRequest(endpoint, method, fields = {}) {
 if (!PROVIDER_KEY) { const e = new Error('ZiiroPay credentials are not configured on the server.'); e.status = 503; throw e; }
 const params = new URLSearchParams({ public_key: PROVIDER_KEY });
 for (const [key,value] of Object.entries(fields)) if (value !== undefined && value !== null && value !== '') params.set(key, typeof value === 'object' ? JSON.stringify(value) : String(value));
 if (PROVIDER_MODE === 'sandbox') params.set('mode','sandbox');
 const url = `${PROVIDER_BASE}${endpoint}?${params.toString()}`;
 const response = await fetch(url, { method, headers: { accept: 'application/json', 'content-type': 'application/json' }, ...(method === 'POST' ? { body: '{}' } : {}), signal: AbortSignal.timeout(25000) });
 const raw = await response.text(); let data; try { data = raw ? JSON.parse(raw) : {}; } catch { data = { message: raw.slice(0,1000) }; }
 if (!response.ok || data.success === false) { const e = new Error(data.message || `ZiiroPay returned HTTP ${response.status}`); e.status = response.status >= 400 && response.status < 500 ? 422 : 502; e.providerStatus = response.status; throw e; }
 return data;
}
function redactProvider(data) { if (!data || typeof data !== 'object') return data; const copy = JSON.parse(JSON.stringify(data)); const scrub = obj => { if (!obj || typeof obj !== 'object') return; for (const key of Object.keys(obj)) { if (/card_number|cvv|id_front_image|id_back_image|selfie|secret|public_key|token/i.test(key)) obj[key] = '[REDACTED]'; else if (obj[key] && typeof obj[key] === 'object') scrub(obj[key]); } }; scrub(copy); return copy; }

async function initDb() {
 if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required. Add a PostgreSQL database and set DATABASE_URL.');
 if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters.');
 await pool.query(schema);
 await pool.query(security);
 const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
 if (adminEmail && process.env.ADMIN_PASSWORD) {
  if (process.env.ADMIN_PASSWORD.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters.');
  const exists = await pool.query('SELECT id, role FROM users WHERE email=$1', [adminEmail]);
  if (!exists.rowCount) {
   const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
   await pool.query(`INSERT INTO users (name,email,password_hash,role) VALUES ($1,$2,$3,'admin')`, [process.env.ADMIN_NAME || 'Platform Admin', adminEmail, passwordHash]);
   console.log('Initial admin account created:', adminEmail);
  } else if (exists.rows[0].role !== 'admin') console.warn('ADMIN_EMAIL belongs to a non-admin account; it was not promoted.');
 } else if (!(await pool.query(`SELECT 1 FROM users WHERE role='admin' LIMIT 1`)).rowCount) console.warn('No admin account exists. Set ADMIN_EMAIL and ADMIN_PASSWORD.');
}

// ---------- pages ----------
const sendView = name => (_req, res) => res.sendFile(path.join(__dirname, 'views', name));
app.get(['/', '/login'], pageSession, (req, res) => { res.set('Cache-Control', 'no-store'); if (req.auth && !(req.auth.role === 'business' && req.auth.businessStatus === 'suspended')) return res.redirect(302, homeFor(req.auth)); res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.get('/admin', pageSession, guardPage('admin'), sendView('admin.html'));
app.get('/admin/assets/:file', pageSession, guardPage('admin'), (req, res) => { const f = { 'admin.js': 'admin.js' }[req.params.file]; if (!f) return res.status(404).end(); res.sendFile(path.join(__dirname, 'views', f)); });
app.get('/dashboard', pageSession, guardPage('business'), sendView('dashboard.html'));
app.get('/dashboard/assets/:file', pageSession, guardPage('business'), (req, res) => { const f = { 'dashboard.js': 'dashboard.js' }[req.params.file]; if (!f) return res.status(404).end(); res.sendFile(path.join(__dirname, 'views', f)); });

// ---------- public / auth ----------
app.get('/api/health', (_req,res) => res.json({ ok: true, service: 'Zytrelix API Hub' }));
app.post('/api/auth/register', authLimiter, asyncRoute(async (req,res) => {
 const name = String(req.body.name || '').trim(), businessName = String(req.body.businessName || '').trim(), email = String(req.body.email || '').toLowerCase().trim(), password = String(req.body.password || '');
 if (!name || !businessName || !/^\S+@\S+\.\S+$/.test(email) || password.length < 12) return res.status(400).json({ error: 'Enter your name, business name, valid email and a password of at least 12 characters.' });
 const client = await pool.connect();
 try { await client.query('BEGIN'); const b = await client.query('INSERT INTO businesses(name,email) VALUES($1,$2) RETURNING id,status', [businessName,email]); const p = await bcrypt.hash(password,12); const u = await client.query(`INSERT INTO users(business_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,'business') RETURNING id,name,email,role,business_id`, [b.rows[0].id,name,email,p]); await client.query(`INSERT INTO subscriptions(business_id) VALUES($1)`, [b.rows[0].id]); await auditEvent(client, { businessId: b.rows[0].id, sub: u.rows[0].id }, 'business.registered', { businessName }, req.ip); await client.query('COMMIT'); setSession(req, res, u.rows[0]); res.status(201).json({ user:u.rows[0], business:{id:b.rows[0].id,status:b.rows[0].status}, redirect:'/dashboard' }); }
 catch(e) { await client.query('ROLLBACK').catch(()=>{}); if (e.code==='23505') return res.status(409).json({error:'An account with this email already exists.'}); throw e; } finally { client.release(); }
}));
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer', 12);
app.post('/api/auth/login', authLimiter, asyncRoute(async (req,res) => {
 const email = String(req.body.email || '').toLowerCase().trim(), password = String(req.body.password || '');
 const q = await pool.query(`SELECT u.id,u.name,u.email,u.password_hash,u.role,u.business_id,b.status AS business_status FROM users u LEFT JOIN businesses b ON b.id=u.business_id WHERE u.email=$1`, [email]);
 const u = q.rows[0]; const ok = await bcrypt.compare(password, u ? u.password_hash : DUMMY_HASH);
 if (!u || !ok) return res.status(401).json({error:'Email or password is incorrect.'});
 if (u.role === 'business' && u.business_status === 'suspended') return res.status(403).json({error:'This business account is suspended. Contact support.'});
 setSession(req, res, u); await auditEvent(pool, { businessId: u.business_id, sub: u.id }, 'auth.login', { role: u.role }, req.ip).catch(()=>{});
 res.json({ user:{id:u.id,name:u.name,email:u.email,role:u.role,business_id:u.business_id,business_status:u.business_status}, redirect: homeFor({ role: u.role }) });
}));
app.post('/api/auth/logout', (req,res) => { clearSession(res); res.json({ ok: true }); });
app.get('/api/auth/me', requireAuth, asyncRoute(async (req,res) => {
 if (req.auth.role === 'admin') return res.json({ user: { id: req.auth.sub, name: req.auth.name, email: req.auth.email, role: 'admin', business_id: null } });
 const q = await tenantDb(req, c => c.query(`SELECT id,name,status FROM businesses WHERE id=$1`, [req.auth.businessId]));
 res.json({ user: { id: req.auth.sub, name: req.auth.name, email: req.auth.email, role: 'business', business_id: req.auth.businessId, business_name: q.rows[0]?.name, business_status: q.rows[0]?.status } });
}));

// ---------- business dashboard API (own tenant only, enforced again by row-level security) ----------
const biz = [requireAuth, requireBusiness];
app.get('/api/dashboard', biz, asyncRoute(async (req,res) => {
 const id = req.auth.businessId;
 const r = await tenantDb(req, async c => { const [b,keys,kyc,cards,tx,usage,sub] = await Promise.all([c.query('SELECT name,status FROM businesses WHERE id=$1',[id]),c.query('SELECT COUNT(*)::int AS total FROM api_keys WHERE business_id=$1 AND revoked_at IS NULL',[id]),c.query('SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE status ILIKE $2)::int AS approved FROM kyc_submissions WHERE business_id=$1',[id,'%approved%']),c.query('SELECT COUNT(*)::int AS total FROM cards WHERE business_id=$1',[id]),c.query('SELECT COUNT(*)::int AS total FROM transactions WHERE business_id=$1',[id]),c.query("SELECT COUNT(*)::int AS total FROM api_usage WHERE business_id=$1 AND created_at > NOW()-INTERVAL '30 days'",[id]),c.query('SELECT plan,status FROM subscriptions WHERE business_id=$1',[id])]); return { b, keys, kyc, cards, tx, usage, sub }; });
 res.json({role:'business',business:r.b.rows[0],providerMode:PROVIDER_MODE,subscription:r.sub.rows[0]||null,stats:{keys:r.keys.rows[0].total,kyc:r.kyc.rows[0],cards:r.cards.rows[0].total,transactions:r.tx.rows[0].total,requests30d:r.usage.rows[0].total}});
}));
app.get('/api/keys', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query('SELECT id,label,key_prefix,environment,last_used_at,created_at,revoked_at FROM api_keys WHERE business_id=$1 ORDER BY created_at DESC',[req.auth.businessId]));res.json({keys:q.rows});}));
app.post('/api/keys', biz, asyncRoute(async(req,res)=>{const label=String(req.body.label||'').trim().slice(0,80);const environment= req.body.environment==='production'?'production':'sandbox';if(!label)return res.status(400).json({error:'API key name is required.'});
 const raw=`zy_${environment==='sandbox'?'test':'live'}_${crypto.randomBytes(24).toString('hex')}`;
 const out=await tenantDb(req,async c=>{const b=await c.query('SELECT status FROM businesses WHERE id=$1',[req.auth.businessId]);if(!b.rowCount||b.rows[0].status!=='active')return {error:'Your business must be approved before creating API keys.'};if(environment!==PROVIDER_MODE)return {error:`${environment} API keys are unavailable while provider mode is ${PROVIDER_MODE}.`};const q=await c.query('INSERT INTO api_keys(business_id,label,key_prefix,key_hash,environment) VALUES($1,$2,$3,$4,$5) RETURNING id,label,key_prefix,environment,created_at',[req.auth.businessId,label,raw.slice(0,15),hashKey(raw),environment]);await auditEvent(c,req.auth,'api_key.created',{keyId:q.rows[0].id,environment},req.ip);return {key:q.rows[0]};});
 if(out.error)return res.status(403).json({error:out.error});res.status(201).json({key:out.key,secret:raw,warning:'Copy this key now. It will not be shown again.'});}));
app.delete('/api/keys/:id', biz, asyncRoute(async(req,res)=>{if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'Active API key not found.'});const q=await tenantDb(req,async c=>{const r=await c.query('UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND business_id=$2 AND revoked_at IS NULL RETURNING id',[req.params.id,req.auth.businessId]);if(r.rowCount)await auditEvent(c,req.auth,'api_key.revoked',{keyId:req.params.id},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Active API key not found.'});res.json({ok:true});}));
app.get('/api/kyc', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query(`SELECT id,customer_email,customer_name,country,status,provider_customer_id,created_at,updated_at FROM kyc_submissions WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100`,[req.auth.businessId]));res.json({submissions:q.rows});}));
app.get('/api/cards', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query('SELECT id,provider_card_id,cardholder_name,last_four,status,currency,created_at FROM cards WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100',[req.auth.businessId]));res.json({cards:q.rows});}));
app.get('/api/transactions', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query('SELECT id,provider_reference,type,amount,currency,status,created_at FROM transactions WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100',[req.auth.businessId]));res.json({transactions:q.rows});}));
app.get('/api/activity', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query('SELECT method,path,status_code,duration_ms,created_at FROM api_usage WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100',[req.auth.businessId]));res.json({activity:q.rows});}));
app.get('/api/subscription', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query('SELECT plan,status,updated_at FROM subscriptions WHERE business_id=$1',[req.auth.businessId]));res.json({subscription:q.rows[0]||null});}));

// ---------- admin API (admin role only; every route passes requireAuth then requireAdmin) ----------
const admin = express.Router();
admin.use(requireAuth, requireAdmin);
admin.get('/dashboard', asyncRoute(async (req,res) => {
 const r = await adminDb(req, async c => { const [biz,kyc,cards,tx,usage,keys] = await Promise.all([c.query(`SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE status='active')::int AS active,COUNT(*) FILTER (WHERE status='pending')::int AS pending,COUNT(*) FILTER (WHERE status='suspended')::int AS suspended FROM businesses`),c.query(`SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE status NOT ILIKE '%approved%' AND status NOT ILIKE '%reject%')::int AS pending FROM kyc_submissions`),c.query('SELECT COUNT(*)::int AS total FROM cards'),c.query('SELECT COUNT(*)::int AS total FROM transactions'),c.query("SELECT COUNT(*)::int AS total FROM api_usage WHERE created_at > NOW()-INTERVAL '30 days'"),c.query('SELECT COUNT(*)::int AS total FROM api_keys WHERE revoked_at IS NULL')]); return { biz, kyc, cards, tx, usage, keys }; });
 res.json({ role:'admin', provider:{ configured:Boolean(PROVIDER_KEY), mode:PROVIDER_MODE }, stats:{ businesses:r.biz.rows[0], kyc:r.kyc.rows[0], cards:r.cards.rows[0].total, transactions:r.tx.rows[0].total, requests30d:r.usage.rows[0].total, activeKeys:r.keys.rows[0].total } });
}));
admin.get('/businesses', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT b.id,b.name,b.email,b.status,b.created_at,s.plan,s.status AS subscription_status,(SELECT COUNT(*)::int FROM api_keys k WHERE k.business_id=b.id AND k.revoked_at IS NULL) AS api_keys FROM businesses b LEFT JOIN subscriptions s ON s.business_id=b.id ORDER BY b.created_at DESC`));res.json({businesses:q.rows});}));
admin.patch('/businesses/:id', asyncRoute(async(req,res)=>{const status=req.body.status;if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'Business not found.'});if(!['pending','active','suspended'].includes(status))return res.status(400).json({error:'Invalid business status.'});const q=await adminDb(req,async c=>{const r=await c.query('UPDATE businesses SET status=$1 WHERE id=$2 RETURNING id,name,email,status',[status,req.params.id]);if(r.rowCount)await auditEvent(c,{sub:req.auth.sub,businessId:req.params.id},'business.status_changed',{businessId:req.params.id,status},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Business not found.'});res.json({business:q.rows[0]});}));
admin.get('/kyc', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT k.id,k.business_id,b.name AS business_name,k.customer_email,k.customer_name,k.country,k.status,k.admin_decision,k.review_note,k.provider_customer_id,k.created_at,k.reviewed_at FROM kyc_submissions k JOIN businesses b ON b.id=k.business_id ORDER BY k.created_at DESC LIMIT 300`));res.json({submissions:q.rows});}));
admin.patch('/kyc/:id', asyncRoute(async(req,res)=>{const decision=req.body.decision;const note=String(req.body.note||'').trim().slice(0,500)||null;if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'KYC submission not found.'});if(!['approved','rejected'].includes(decision))return res.status(400).json({error:'decision must be approved or rejected.'});const q=await adminDb(req,async c=>{const r=await c.query('UPDATE kyc_submissions SET status=$1,admin_decision=$1,reviewed_by=$2,reviewed_at=NOW(),review_note=$3,updated_at=NOW() WHERE id=$4 RETURNING id,business_id,status',[decision,req.auth.sub,note,req.params.id]);if(r.rowCount)await auditEvent(c,{sub:req.auth.sub,businessId:r.rows[0].business_id},'kyc.reviewed',{submissionId:req.params.id,decision},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'KYC submission not found.'});res.json({submission:q.rows[0]});}));
admin.get('/api-keys', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT k.id,k.business_id,b.name AS business_name,k.label,k.key_prefix,k.environment,k.last_used_at,k.created_at,k.revoked_at FROM api_keys k JOIN businesses b ON b.id=k.business_id ORDER BY k.created_at DESC LIMIT 300`));res.json({keys:q.rows});}));
admin.delete('/api-keys/:id', asyncRoute(async(req,res)=>{if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'Active API key not found.'});const q=await adminDb(req,async c=>{const r=await c.query('UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND revoked_at IS NULL RETURNING id,business_id',[req.params.id]);if(r.rowCount)await auditEvent(c,{sub:req.auth.sub,businessId:r.rows[0].business_id},'api_key.revoked_by_admin',{keyId:req.params.id},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Active API key not found.'});res.json({ok:true});}));
admin.get('/transactions', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT t.id,t.business_id,b.name AS business_name,t.provider_reference,t.type,t.amount,t.currency,t.status,t.created_at FROM transactions t JOIN businesses b ON b.id=t.business_id ORDER BY t.created_at DESC LIMIT 300`));res.json({transactions:q.rows});}));
admin.get('/subscriptions', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT b.id AS business_id,b.name AS business_name,b.status AS business_status,COALESCE(s.plan,'free') AS plan,COALESCE(s.status,'active') AS status,s.updated_at FROM businesses b LEFT JOIN subscriptions s ON s.business_id=b.id ORDER BY b.created_at DESC`));res.json({subscriptions:q.rows,plans:PLANS,statuses:SUBSCRIPTION_STATUSES});}));
admin.patch('/subscriptions/:businessId', asyncRoute(async(req,res)=>{const {plan,status}=req.body;if(!UUID_RE.test(req.params.businessId))return res.status(404).json({error:'Business not found.'});if(plan!==undefined&&!PLANS.includes(plan))return res.status(400).json({error:'Invalid plan.'});if(status!==undefined&&!SUBSCRIPTION_STATUSES.includes(status))return res.status(400).json({error:'Invalid subscription status.'});if(plan===undefined&&status===undefined)return res.status(400).json({error:'plan or status is required.'});const q=await adminDb(req,async c=>{const b=await c.query('SELECT id FROM businesses WHERE id=$1',[req.params.businessId]);if(!b.rowCount)return b;const r=await c.query(`INSERT INTO subscriptions(business_id,plan,status) VALUES($1,COALESCE($2,'free'),COALESCE($3,'active')) ON CONFLICT (business_id) DO UPDATE SET plan=COALESCE($2,subscriptions.plan),status=COALESCE($3,subscriptions.status),updated_at=NOW() RETURNING business_id,plan,status`,[req.params.businessId,plan??null,status??null]);await auditEvent(c,{sub:req.auth.sub,businessId:req.params.businessId},'subscription.updated',{plan,status},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Business not found.'});res.json({subscription:q.rows[0]});}));
admin.get('/audit', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query('SELECT id,business_id,actor_user_id,action,details,ip,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 150'));res.json({logs:q.rows});}));
app.use('/api/admin', admin);

// ---------- partner API: authenticated by API key, every query runs in that business's tenant context ----------
async function recordUsage(req,status,duration){ if(req.partner) scoped({businessId:req.partner.businessId},c=>c.query('INSERT INTO api_usage(business_id,api_key_id,method,path,status_code,duration_ms) VALUES($1,$2,$3,$4,$5,$6)',[req.partner.businessId,req.partner.apiKeyId,req.method,req.path,status,duration])).catch(e=>console.error('usage log failed:',e.message)); }
const partnerDb = (req, fn) => scoped({ businessId: req.partner.businessId }, fn);
app.use('/v1', requireApiKey, (req,res,next)=>{const start=Date.now();const original=res.json.bind(res);res.json=(body)=>{recordUsage(req,res.statusCode,Date.now()-start);return original(body);};next();});
app.get('/v1/status', (req,res)=>res.json({ok:true,businessId:req.partner.businessId,environment:req.partner.environment,providerMode:PROVIDER_MODE}));
app.post('/v1/kyc', asyncRoute(async(req,res)=>{
 const required=['first_name','last_name','id_number','email','phone_number','date_of_birth','dial_code','id_front_image','line1','state','postal_code','city','country','id_type','occupation','employment_status','account_purpose','annual_salary','expected_monthly_volume','place_of_birth'];
 const missing=required.filter(k=>!req.body[k]);if(missing.length)return res.status(400).json({error:'Missing required KYC fields.',missing});
 if(typeof req.body.id_front_image!=='string'||req.body.id_front_image.length>9_000_000)return res.status(400).json({error:'id_front_image must be Base64 and no larger than 6.5 MB decoded.'});
 const email=String(req.body.email).toLowerCase().trim();const name=`${req.body.first_name} ${req.body.last_name}`.trim();
 const existing=await partnerDb(req,c=>c.query('SELECT id FROM kyc_submissions WHERE business_id=$1 AND customer_email=$2 AND status IN ($3,$4) ORDER BY created_at DESC LIMIT 1',[req.partner.businessId,email,'submitted','pending']));if(existing.rowCount)return res.status(409).json({error:'A KYC request for this email is already pending.',submissionId:existing.rows[0].id});
 const payload={};for(const k of required)payload[k]=req.body[k];
 const result=await providerRequest('/bitvcard/cardkyc','POST',payload);const status=String(result?.data?.status||result?.status||'submitted').toLowerCase();const customerId=result?.data?.customer_id||result?.customer_id||null;
 const saved=await partnerDb(req,c=>c.query('INSERT INTO kyc_submissions(business_id,provider_customer_id,customer_email,customer_name,country,status,provider_reference) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,status,created_at',[req.partner.businessId,customerId,email,name,String(req.body.country),status,result?.reference||null]));
 res.status(201).json({submission:saved.rows[0],provider:redactProvider(result),notice:'Identity document was forwarded to ZiiroPay and is not stored by Zytrelix.'});
}));
app.get('/v1/kyc/status', asyncRoute(async(req,res)=>{const email=String(req.query.email||'').toLowerCase().trim();if(!email)return res.status(400).json({error:'email query parameter is required.'});const owned=await partnerDb(req,c=>c.query('SELECT id FROM kyc_submissions WHERE business_id=$1 AND customer_email=$2 LIMIT 1',[req.partner.businessId,email]));if(!owned.rowCount)return res.status(404).json({error:'No KYC submission for this email belongs to your business.'});const result=await providerRequest('/bitvcard/cardkycstatus','GET',{email});const status=String(result?.data?.status||result?.status||'unknown').toLowerCase();const customerId=result?.data?.customer_id||null;await partnerDb(req,c=>c.query('UPDATE kyc_submissions SET status=CASE WHEN admin_decision IS NOT NULL THEN status ELSE $1 END,provider_customer_id=COALESCE($2,provider_customer_id),updated_at=NOW() WHERE business_id=$3 AND customer_email=$4',[status,customerId,req.partner.businessId,email]));res.json({provider:redactProvider(result)});}));
app.post('/v1/cards', asyncRoute(async(req,res)=>{const {name,customer_id,amount}=req.body;if(!name||!customer_id||!amount||!Number.isFinite(Number(amount))||Number(amount)<=0)return res.status(400).json({error:'name, approved customer_id and positive amount are required.'});const approved=await partnerDb(req,c=>c.query("SELECT id FROM kyc_submissions WHERE business_id=$1 AND provider_customer_id=$2 AND status ILIKE '%approved%' AND admin_decision IS DISTINCT FROM 'rejected' LIMIT 1",[req.partner.businessId,String(customer_id)]));if(!approved.rowCount)return res.status(403).json({error:'No approved KYC record exists for this customer under your business.'});const result=await providerRequest('/bitvcard/create-nfc-card','POST',{name,customer_id,amount});const detail=result?.response?.card_detail||result?.data||result?.card||{};const providerCardId=detail.card_id||result.card_id||result.id;if(providerCardId){await partnerDb(req,c=>c.query('INSERT INTO cards(business_id,provider_card_id,provider_customer_id,cardholder_name,last_four,status) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (business_id,provider_card_id) DO UPDATE SET status=EXCLUDED.status',[req.partner.businessId,String(providerCardId),String(customer_id),name,detail.last4||detail.last_four||null,detail.card_status||detail.status||'created']));}res.status(201).json({provider:redactProvider(result)});}));
const ownedCard=asyncRoute(async(req,res,next)=>{const q=await partnerDb(req,c=>c.query('SELECT * FROM cards WHERE business_id=$1 AND provider_card_id=$2',[req.partner.businessId,req.params.cardId]));if(!q.rowCount)return res.status(404).json({error:'Card not found for this business.'});req.ownedCard=q.rows[0];next();});
app.get('/v1/cards',asyncRoute(async(req,res)=>{const q=await partnerDb(req,c=>c.query('SELECT id,provider_card_id,cardholder_name,last_four,status,currency,created_at FROM cards WHERE business_id=$1 ORDER BY created_at DESC',[req.partner.businessId]));res.json({cards:q.rows});}));
app.get('/v1/cards/:cardId',ownedCard,asyncRoute(async(req,res)=>{const result=await providerRequest('/bitvcard/fetch-nfccard-detail','GET',{card_id:req.params.cardId});res.json({provider:redactProvider(result)});}));
app.get('/v1/cards/:cardId/transactions',ownedCard,asyncRoute(async(req,res)=>{const result=await providerRequest('/bitvcard/nfc-card-transactions','GET',{card_id:req.params.cardId});res.json({provider:redactProvider(result)});}));
app.post('/v1/cards/:cardId/funding',ownedCard,asyncRoute(async(req,res)=>{const {amount,type='fund'}=req.body;if(!Number.isFinite(Number(amount))||Number(amount)<=0||!['fund','withdraw'].includes(type))return res.status(400).json({error:'A positive amount and type fund or withdraw are required.'});const result=await providerRequest('/bitvcard/fund-withdraw-nfccard','POST',{card_id:req.params.cardId,amount,type});await partnerDb(req,c=>c.query('INSERT INTO transactions(business_id,card_id,type,amount,status) VALUES($1,$2,$3,$4,$5)',[req.partner.businessId,req.ownedCard.id,type,amount,result?.status||'submitted']));res.json({provider:redactProvider(result)});}));
app.post('/v1/cards/:cardId/status',ownedCard,asyncRoute(async(req,res)=>{const {status}=req.body;if(!['active','frozen'].includes(status))return res.status(400).json({error:'status must be active or frozen.'});const result=await providerRequest('/bitvcard/nfc-cards/status','POST',{card_id:req.params.cardId,status});await partnerDb(req,c=>c.query('UPDATE cards SET status=$1 WHERE id=$2 AND business_id=$3',[status,req.ownedCard.id,req.partner.businessId]));res.json({provider:redactProvider(result)});}));

// Provider webhook: authenticated by shared secret; runs as the table owner because it is not a tenant request.
app.post('/api/webhooks/ziiropay', asyncRoute(async(req,res)=>{const secret=process.env.PROVIDER_WEBHOOK_SECRET;if(!secret)return res.status(503).json({error:'Provider webhook is disabled until a verification method is configured.'});const supplied=req.get('x-zytrelix-webhook-secret')||'';if(!safeEqual(supplied,secret))return res.status(401).json({error:'Invalid webhook secret.'});const event=String(req.body.event||'unknown');const cardId=req.body.cardId||req.body.card_id;const status=req.body.status||req.body.createdStatus;if(event.startsWith('virtualcard.')&&cardId){await pool.query('UPDATE cards SET status=COALESCE($1,status) WHERE provider_card_id=$2',[status||null,String(cardId)]);}if(event.toLowerCase().includes('kyc')&&req.body.email){await pool.query('UPDATE kyc_submissions SET status=$1,updated_at=NOW() WHERE customer_email=$2 AND admin_decision IS NULL AND ($3::text IS NULL OR provider_customer_id=$3)',[String(status||'updated'),String(req.body.email).toLowerCase(),req.body.customer_id?String(req.body.customer_id):null]);}res.json({received:true});}));

app.all(['/api/*', '/v1/*'], (_req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((req, res) => res.status(404).type('text').send('Not found'));
app.use((err,req,res,_next)=>{console.error('Request failed:',err.message);if(res.headersSent)return;res.status(err.status||500).json({error:err.status?err.message:'Internal server error.'});});

if (require.main === module) initDb().then(()=>app.listen(PORT,()=>console.log(`Zytrelix API Hub listening on ${PORT}; provider mode=${PROVIDER_MODE}`))).catch(err=>{console.error('Startup failed:',err);process.exit(1);});
module.exports = { app, initDb, pool };
