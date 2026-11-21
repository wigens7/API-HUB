require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, scoped, UUID_RE } = require('./lib/db');
const { providerRequest, redactProvider, P, configured: providerConfigured, PROVIDER_MODE: providerModeFn } = require('./lib/provider');
const F = require('./lib/finance');
const { financeSchema, financeTenantRows, financeSecurityGrants } = require('./lib/schema');
const registerWallet = require('./routes/wallet');
const partnerRouter = require('./routes/partner');
const webhookHandler = require('./routes/webhooks');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const PROVIDER_KEY = process.env.ZIIROPAY_PUBLIC_KEY; // read via lib/provider; kept for status display only
const PROVIDER_MODE = process.env.ZIIROPAY_MODE || 'sandbox';
const COOKIE_NAME = 'zy_session';
const SESSION_HOURS = 12;
const PLANS = ['free', 'starter', 'growth', 'enterprise'];
const SUBSCRIPTION_STATUSES = ['active', 'paused', 'cancelled'];

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], formAction: ["'self'"], upgradeInsecureRequests: [] } } }));
const origins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: (origin, cb) => !origin || origins.includes(origin) ? cb(null, true) : cb(null, false), methods: ['GET','POST','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization','X-API-Key','X-Idempotency-Key','X-Zytrelix-Client'] }));
app.use(express.json({ limit: '12mb' }));
app.use('/api/', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: true, legacyHeaders: false, skip: req => req.path.startsWith('/webhooks/') }));
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
// finance tables get RLS and grants from lib/schema.js
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
${financeSecurityGrants}
`;

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
async function initDb() {
 if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required. Add a PostgreSQL database and set DATABASE_URL.');
 if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be at least 32 characters.');
 await pool.query(schema + financeSchema);
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
 try { await client.query('BEGIN'); const b = await client.query('INSERT INTO businesses(name,email) VALUES($1,$2) RETURNING id,status', [businessName,email]); const p = await bcrypt.hash(password,12); const u = await client.query(`INSERT INTO users(business_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,'business') RETURNING id,name,email,role,business_id`, [b.rows[0].id,name,email,p]); await client.query(`INSERT INTO subscriptions(business_id) VALUES($1)`, [b.rows[0].id]); await client.query(`INSERT INTO wallets(business_id) VALUES($1)`, [b.rows[0].id]); await auditEvent(client, { businessId: b.rows[0].id, sub: u.rows[0].id }, 'business.registered', { businessName }, req.ip); await client.query('COMMIT'); setSession(req, res, u.rows[0]); res.status(201).json({ user:u.rows[0], business:{id:b.rows[0].id,status:b.rows[0].status}, redirect:'/dashboard' }); }
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
app.get('/api/kyc', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query(`SELECT k.id,k.customer_email,k.customer_name,k.country,k.status,e.public_id AS customer_id,k.created_at,k.updated_at FROM kyc_submissions k LEFT JOIN end_users e ON e.id=k.end_user_id WHERE k.business_id=$1 ORDER BY k.created_at DESC LIMIT 100`,[req.auth.businessId]));res.json({submissions:q.rows});}));
app.get('/api/customers', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query('SELECT * FROM end_users WHERE business_id=$1 ORDER BY created_at DESC LIMIT 200',[req.auth.businessId]));res.json({customers:q.rows.map(F.customerView)});}));
const walletRouter = express.Router(); registerWallet(walletRouter, req => req.auth.businessId, { auditEvent }, '');
app.use('/api/wallet', biz, walletRouter);
app.get('/api/cards', biz, asyncRoute(async(req,res)=>{const q=await tenantDb(req,c=>c.query('SELECT c.id,e.public_id AS customer_id,c.cardholder_name,c.last_four,c.brand,c.status,c.provider_balance AS balance,c.currency,c.created_at FROM cards c LEFT JOIN end_users e ON e.id=c.end_user_id WHERE c.business_id=$1 ORDER BY c.created_at DESC LIMIT 100',[req.auth.businessId]));res.json({cards:q.rows});}));
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
admin.get('/businesses', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT b.id,b.name,b.email,b.status,b.card_data_reveal,b.created_at,s.plan,s.status AS subscription_status,(SELECT COUNT(*)::int FROM api_keys k WHERE k.business_id=b.id AND k.revoked_at IS NULL) AS api_keys FROM businesses b LEFT JOIN subscriptions s ON s.business_id=b.id ORDER BY b.created_at DESC`));res.json({businesses:q.rows});}));
admin.patch('/businesses/:id', asyncRoute(async(req,res)=>{const status=req.body.status;if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'Business not found.'});if(!['pending','active','suspended'].includes(status))return res.status(400).json({error:'Invalid business status.'});const q=await adminDb(req,async c=>{const r=await c.query('UPDATE businesses SET status=$1 WHERE id=$2 RETURNING id,name,email,status',[status,req.params.id]);if(r.rowCount)await auditEvent(c,{sub:req.auth.sub,businessId:req.params.id},'business.status_changed',{businessId:req.params.id,status},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Business not found.'});res.json({business:q.rows[0]});}));
admin.get('/kyc', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT k.id,k.business_id,b.name AS business_name,k.customer_email,k.customer_name,k.country,k.status,k.admin_decision,k.review_note,k.provider_customer_id,k.created_at,k.reviewed_at FROM kyc_submissions k JOIN businesses b ON b.id=k.business_id ORDER BY k.created_at DESC LIMIT 300`));res.json({submissions:q.rows});}));
admin.patch('/kyc/:id', asyncRoute(async(req,res)=>{const decision=req.body.decision;const note=String(req.body.note||'').trim().slice(0,500)||null;if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'KYC submission not found.'});if(!['approved','rejected'].includes(decision))return res.status(400).json({error:'decision must be approved or rejected.'});const q=await adminDb(req,async c=>{const r=await c.query('UPDATE kyc_submissions SET status=$1,admin_decision=$1,reviewed_by=$2,reviewed_at=NOW(),review_note=$3,updated_at=NOW() WHERE id=$4 RETURNING id,business_id,status',[decision,req.auth.sub,note,req.params.id]);if(r.rowCount)await c.query('UPDATE end_users SET kyc_status=$1,kyc_updated_at=NOW() WHERE id=(SELECT end_user_id FROM kyc_submissions WHERE id=$2)',[decision,req.params.id]);if(r.rowCount)await auditEvent(c,{sub:req.auth.sub,businessId:r.rows[0].business_id},'kyc.reviewed',{submissionId:req.params.id,decision},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'KYC submission not found.'});res.json({submission:q.rows[0]});}));
admin.get('/api-keys', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT k.id,k.business_id,b.name AS business_name,k.label,k.key_prefix,k.environment,k.last_used_at,k.created_at,k.revoked_at FROM api_keys k JOIN businesses b ON b.id=k.business_id ORDER BY k.created_at DESC LIMIT 300`));res.json({keys:q.rows});}));
admin.delete('/api-keys/:id', asyncRoute(async(req,res)=>{if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'Active API key not found.'});const q=await adminDb(req,async c=>{const r=await c.query('UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND revoked_at IS NULL RETURNING id,business_id',[req.params.id]);if(r.rowCount)await auditEvent(c,{sub:req.auth.sub,businessId:r.rows[0].business_id},'api_key.revoked_by_admin',{keyId:req.params.id},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Active API key not found.'});res.json({ok:true});}));
admin.get('/transactions', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT t.id,t.business_id,b.name AS business_name,t.provider_reference,t.type,t.amount,t.currency,t.status,t.created_at FROM transactions t JOIN businesses b ON b.id=t.business_id ORDER BY t.created_at DESC LIMIT 300`));res.json({transactions:q.rows});}));
admin.get('/subscriptions', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query(`SELECT b.id AS business_id,b.name AS business_name,b.status AS business_status,COALESCE(s.plan,'free') AS plan,COALESCE(s.status,'active') AS status,s.updated_at FROM businesses b LEFT JOIN subscriptions s ON s.business_id=b.id ORDER BY b.created_at DESC`));res.json({subscriptions:q.rows,plans:PLANS,statuses:SUBSCRIPTION_STATUSES});}));
admin.patch('/subscriptions/:businessId', asyncRoute(async(req,res)=>{const {plan,status}=req.body;if(!UUID_RE.test(req.params.businessId))return res.status(404).json({error:'Business not found.'});if(plan!==undefined&&!PLANS.includes(plan))return res.status(400).json({error:'Invalid plan.'});if(status!==undefined&&!SUBSCRIPTION_STATUSES.includes(status))return res.status(400).json({error:'Invalid subscription status.'});if(plan===undefined&&status===undefined)return res.status(400).json({error:'plan or status is required.'});const q=await adminDb(req,async c=>{const b=await c.query('SELECT id FROM businesses WHERE id=$1',[req.params.businessId]);if(!b.rowCount)return b;const r=await c.query(`INSERT INTO subscriptions(business_id,plan,status) VALUES($1,COALESCE($2,'free'),COALESCE($3,'active')) ON CONFLICT (business_id) DO UPDATE SET plan=COALESCE($2,subscriptions.plan),status=COALESCE($3,subscriptions.status),updated_at=NOW() RETURNING business_id,plan,status`,[req.params.businessId,plan??null,status??null]);await auditEvent(c,{sub:req.auth.sub,businessId:req.params.businessId},'subscription.updated',{plan,status},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Business not found.'});res.json({subscription:q.rows[0]});}));
admin.get('/audit', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query('SELECT id,business_id,actor_user_id,action,details,ip,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 150'));res.json({logs:q.rows});}));
// ---- finance admin (admin role only) ----
admin.get('/finance', asyncRoute(async (req,res) => {
 const r = await adminDb(req, async c => ({
  total: (await c.query('SELECT COALESCE(SUM(amount),0)::text AS t FROM ledger_entries')).rows[0].t,
  perBusiness: (await c.query(`SELECT b.id AS business_id,b.name AS business_name,COALESCE(SUM(l.amount),0)::text AS balance FROM businesses b LEFT JOIN ledger_entries l ON l.business_id=b.id GROUP BY b.id,b.name ORDER BY b.name LIMIT 200`)).rows,
  unknownOps: (await c.query("SELECT COUNT(*)::int AS n FROM card_operations WHERE status IN ('unknown','pending')")).rows[0].n,
 }));
 let providerBalance = null; try { providerBalance = (await P.mainBalance())?.balance ?? null; } catch { providerBalance = null; }
 res.json({ providerBalance, ledgerTotal: r.total, businesses: r.perBusiness, unresolvedOperations: r.unknownOps, productionEnabled: (process.env.ZIIROPAY_MODE||'sandbox')!=='production'||process.env.PROVIDER_PRODUCTION_ENABLED==='true' });
}));
admin.get('/deposits', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query('SELECT d.id,d.business_id,b.name AS business_name,d.provider_trx,d.token,d.gross_amount,d.fee,d.credited_amount,d.created_at FROM deposits d JOIN businesses b ON b.id=d.business_id ORDER BY d.created_at DESC LIMIT 200'));res.json({deposits:q.rows});}));
admin.get('/card-operations', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query('SELECT o.id,o.business_id,b.name AS business_name,o.op_type,o.status,o.amount,o.card_id,o.error,o.created_at,o.updated_at FROM card_operations o JOIN businesses b ON b.id=o.business_id ORDER BY o.created_at DESC LIMIT 200'));res.json({operations:q.rows});}));
admin.patch('/card-operations/:id', asyncRoute(async(req,res)=>{
 if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'Operation not found.'});
 const status=req.body.status;if(!['succeeded','failed'].includes(status))return res.status(400).json({error:'status must be succeeded or failed.'});
 const q=await adminDb(req,c=>c.query('SELECT * FROM card_operations WHERE id=$1',[req.params.id]));const op=q.rows[0];
 if(!op)return res.status(404).json({error:'Operation not found.'});
 if(!['unknown','pending'].includes(op.status))return res.status(409).json({error:'Only unknown or pending operations can be resolved.'});
 let hook;
 if(op.op_type==='create'&&status==='succeeded'){
  const pid=String(req.body.provider_card_id||'').trim();if(!pid||pid.length>120)return res.status(400).json({error:'provider_card_id is required to resolve a card creation as succeeded.'});
  const eu=(await pool.query('SELECT * FROM end_users WHERE id=$1',[op.end_user_id])).rows[0];if(!eu)return res.status(409).json({error:'The customer for this operation no longer exists.'});
  hook=async c=>({cardId:await F.insertCard(c,{businessId:op.business_id,endUser:eu,providerCardId:pid,name:`${eu.first_name} ${eu.last_name}`})});
 }
 const done=await F.completeOperation(op.business_id,op.id,{status,error:'Resolved by an administrator.'},hook);
 await auditEvent(pool,{sub:req.auth.sub,businessId:op.business_id},'card_operation.resolved',{operation:op.id,status},req.ip);
 res.json({operation:F.opView(done)});
}));
admin.get('/webhook-events', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query('SELECT id,event,business_id,outcome,error,received_at FROM webhook_events ORDER BY id DESC LIMIT 200'));res.json({events:q.rows});}));
admin.get('/customers', asyncRoute(async(req,res)=>{const q=await adminDb(req,c=>c.query('SELECT e.public_id AS id,e.business_id,b.name AS business_name,e.email,e.first_name,e.last_name,e.kyc_status,e.created_at FROM end_users e JOIN businesses b ON b.id=e.business_id ORDER BY e.created_at DESC LIMIT 200'));res.json({customers:q.rows});}));
admin.post('/reconcile', asyncRoute(async(req,res)=>{const out=await F.reconcileAll();await auditEvent(pool,{sub:req.auth.sub},'finance.reconcile',out,req.ip);res.json(out);}));
admin.patch('/businesses/:id/card-data-reveal', asyncRoute(async(req,res)=>{if(!UUID_RE.test(req.params.id))return res.status(404).json({error:'Business not found.'});if(typeof req.body.enabled!=='boolean')return res.status(400).json({error:'enabled must be true or false.'});const q=await adminDb(req,async c=>{const r=await c.query('UPDATE businesses SET card_data_reveal=$1 WHERE id=$2 RETURNING id,card_data_reveal',[req.body.enabled,req.params.id]);if(r.rowCount)await auditEvent(c,{sub:req.auth.sub,businessId:req.params.id},'business.card_data_reveal',{enabled:req.body.enabled},req.ip);return r;});if(!q.rowCount)return res.status(404).json({error:'Business not found.'});res.json({business:q.rows[0]});}));
app.use('/api/admin', admin);

// ---------- partner API: authenticated by API key, every query runs in that business's tenant context ----------
async function recordUsage(req,status,duration){ if(req.partner) scoped({businessId:req.partner.businessId},c=>c.query('INSERT INTO api_usage(business_id,api_key_id,method,path,status_code,duration_ms) VALUES($1,$2,$3,$4,$5,$6)',[req.partner.businessId,req.partner.apiKeyId,req.method,String(req.originalUrl).split('?')[0].slice(0,200),status,duration])).catch(()=>{}); }
app.use('/v1', requireApiKey, (req,res,next)=>{const start=Date.now();const original=res.json.bind(res);res.json=(body)=>{recordUsage(req,res.statusCode,Date.now()-start);return original(body);};next();}, partnerRouter({ auditEvent, providerMode: providerModeFn }));

// Provider webhooks: authenticated by shared secret (path token or header); own rate limit, not the generic /api one.
const webhookLimiter = rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: true, legacyHeaders: false });
app.post('/api/webhooks/ziiropay/:token', webhookLimiter, webhookHandler());
app.post('/api/webhooks/ziiropay', webhookLimiter, webhookHandler());

app.all(['/api/*', '/v1/*'], (_req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((req, res) => res.status(404).type('text').send('Not found'));
app.use((err,req,res,_next)=>{console.error('Request failed:',err.message);if(res.headersSent)return;const extra={};if(err.status)for(const k of ['missing','balance','supported','operation_id'])if(err[k]!==undefined)extra[k]=err[k];res.status(err.status||500).json({error:err.status?err.message:'Internal server error.',...extra});});

if (require.main === module) initDb().then(()=>{F.startReconciler();return app.listen(PORT,()=>console.log(`Zytrelix API Hub listening on ${PORT}; provider mode=${PROVIDER_MODE}`))}).catch(err=>{console.error('Startup failed:',err);process.exit(1);});
module.exports = { app, initDb, pool };
