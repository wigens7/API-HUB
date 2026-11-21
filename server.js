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
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined, max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 });

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: [] } } }));
const origins = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({ origin: (origin, cb) => !origin || origins.length === 0 || origins.includes(origin) ? cb(null, true) : cb(new Error('Origin not allowed')), methods: ['GET','POST','PATCH','DELETE'], allowedHeaders: ['Content-Type','Authorization','X-API-Key','X-Idempotency-Key'] }));
app.use(express.json({ limit: '12mb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: true, legacyHeaders: false }));
app.use('/v1/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

const schema = `
CREATE TABLE IF NOT EXISTS businesses (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID REFERENCES businesses(id) ON DELETE CASCADE,
 name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK (role IN ('admin','business')), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
`;

function safeEqual(a, b) { const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b)); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); }
function hashKey(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function createToken(user) { return jwt.sign({ sub: user.id, role: user.role, businessId: user.business_id || null, email: user.email }, JWT_SECRET, { expiresIn: '12h', issuer: 'zytrelix' }); }
function asyncRoute(fn) { return (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next); }
function audit(req, action, details = {}) { return pool.query('INSERT INTO audit_logs (business_id, actor_user_id, action, details, ip) VALUES ($1,$2,$3,$4,$5)', [req.auth?.businessId || null, req.auth?.sub || null, action, JSON.stringify(details), req.ip]).catch(err => console.error('audit log failed:', err.message)); }
function requireAuth(req,res,next) {
 const header = req.get('authorization') || ''; const token = header.startsWith('Bearer ') ? header.slice(7) : '';
 if (!token || !JWT_SECRET) return res.status(401).json({ error: 'Authentication required.' });
 try { req.auth = jwt.verify(token, JWT_SECRET, { issuer: 'zytrelix' }); next(); } catch { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
}
function requireAdmin(req,res,next) { if (req.auth?.role !== 'admin') return res.status(403).json({ error: 'Admin access required.' }); next(); }
async function requireApiKey(req,res,next) {
 const raw = req.get('x-api-key') || ''; if (!raw) return res.status(401).json({ error: 'X-API-Key header is required.' });
 try {
  const result = await pool.query(`SELECT k.id AS key_id,k.business_id,k.environment,b.status AS business_status FROM api_keys k JOIN businesses b ON b.id=k.business_id WHERE k.key_hash=$1 AND k.revoked_at IS NULL`, [hashKey(raw)]);
  if (!result.rowCount) return res.status(401).json({ error: 'Invalid API key.' });
  const row = result.rows[0]; if (row.business_status !== 'active') return res.status(403).json({ error: 'Business account is not active.' });
  if (row.environment !== PROVIDER_MODE) return res.status(403).json({ error: `This API key is for ${row.environment}, but provider mode is ${PROVIDER_MODE}.` });
  req.partner = { businessId: row.business_id, apiKeyId: row.key_id, environment: row.environment };
  await pool.query('UPDATE api_keys SET last_used_at=NOW() WHERE id=$1', [row.key_id]); next();
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
 const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
 if (adminEmail && process.env.ADMIN_PASSWORD) {
  const exists = await pool.query('SELECT id FROM users WHERE email=$1', [adminEmail]);
  if (!exists.rowCount) {
   const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
   await pool.query(`INSERT INTO users (name,email,password_hash,role) VALUES ($1,$2,$3,'admin')`, [process.env.ADMIN_NAME || 'Platform Admin', adminEmail, passwordHash]);
   console.log('Initial admin account created:', adminEmail);
  }
 }
}

app.get('/api/health', (_req,res) => res.json({ ok: true, service: 'Zytrelix API Hub', databaseConfigured: Boolean(process.env.DATABASE_URL), providerConfigured: Boolean(PROVIDER_KEY), providerMode: PROVIDER_MODE, liveEnabled: PROVIDER_MODE === 'production' && Boolean(PROVIDER_KEY) }));
app.post('/api/auth/register', asyncRoute(async (req,res) => {
 const name = String(req.body.name || '').trim(), businessName = String(req.body.businessName || '').trim(), email = String(req.body.email || '').toLowerCase().trim(), password = String(req.body.password || '');
 if (!name || !businessName || !/^\S+@\S+\.\S+$/.test(email) || password.length < 12) return res.status(400).json({ error: 'Enter your name, business name, valid email and a password of at least 12 characters.' });
 const client = await pool.connect();
 try { await client.query('BEGIN'); const b = await client.query('INSERT INTO businesses(name,email) VALUES($1,$2) RETURNING id,status', [businessName,email]); const p = await bcrypt.hash(password,12); const u = await client.query(`INSERT INTO users(business_id,name,email,password_hash,role) VALUES($1,$2,$3,$4,'business') RETURNING id,name,email,role,business_id`, [b.rows[0].id,name,email,p]); await client.query('COMMIT'); await audit({auth:{businessId:b.rows[0].id,sub:u.rows[0].id},ip:req.ip},'business.registered',{businessName}); res.status(201).json({ token:createToken(u.rows[0]), user:u.rows[0], business:{id:b.rows[0].id,status:b.rows[0].status} }); }
 catch(e) { await client.query('ROLLBACK'); if (e.code==='23505') return res.status(409).json({error:'An account with this email already exists.'}); throw e; } finally { client.release(); }
}));
app.post('/api/auth/login', asyncRoute(async (req,res) => {
 const email = String(req.body.email || '').toLowerCase().trim(), password = String(req.body.password || '');
 const q = await pool.query(`SELECT u.id,u.name,u.email,u.password_hash,u.role,u.business_id,b.status AS business_status FROM users u LEFT JOIN businesses b ON b.id=u.business_id WHERE u.email=$1`, [email]);
 if (!q.rowCount || !(await bcrypt.compare(password,q.rows[0].password_hash))) return res.status(401).json({error:'Email or password is incorrect.'});
 const u=q.rows[0];
 res.json({token:createToken(u),user:{id:u.id,name:u.name,email:u.email,role:u.role,business_id:u.business_id,business_status:u.business_status}});
}));
app.get('/api/auth/me', requireAuth, asyncRoute(async (req,res) => { const q=await pool.query(`SELECT u.id,u.name,u.email,u.role,u.business_id,b.name AS business_name,b.status AS business_status FROM users u LEFT JOIN businesses b ON b.id=u.business_id WHERE u.id=$1`,[req.auth.sub]); if(!q.rowCount)return res.status(401).json({error:'User not found'}); res.json({user:q.rows[0]}); }));

app.get('/api/dashboard', requireAuth, asyncRoute(async (req,res) => {
 if(req.auth.role==='admin') { const [biz,kyc,cards,usage]=await Promise.all([pool.query('SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE status=$1)::int AS active FROM businesses',['active']),pool.query('SELECT COUNT(*)::int AS total FROM kyc_submissions'),pool.query('SELECT COUNT(*)::int AS total FROM cards'),pool.query("SELECT COUNT(*)::int AS total FROM api_usage WHERE created_at > NOW()-INTERVAL '30 days'")]); return res.json({role:'admin',stats:{businesses:biz.rows[0],kyc:kyc.rows[0].total,cards:cards.rows[0].total,requests30d:usage.rows[0].total}}); }
 const id=req.auth.businessId; const [keys,kyc,cards,tx,usage]=await Promise.all([pool.query('SELECT COUNT(*)::int AS total FROM api_keys WHERE business_id=$1 AND revoked_at IS NULL',[id]),pool.query('SELECT COUNT(*)::int AS total,COUNT(*) FILTER (WHERE status ILIKE $2)::int AS approved FROM kyc_submissions WHERE business_id=$1',[id,'%approved%']),pool.query('SELECT COUNT(*)::int AS total FROM cards WHERE business_id=$1',[id]),pool.query('SELECT COUNT(*)::int AS total FROM transactions WHERE business_id=$1',[id]),pool.query("SELECT COUNT(*)::int AS total FROM api_usage WHERE business_id=$1 AND created_at > NOW()-INTERVAL '30 days'",[id])]);
 res.json({role:'business',stats:{keys:keys.rows[0].total,kyc:kyc.rows[0],cards:cards.rows[0].total,transactions:tx.rows[0].total,requests30d:usage.rows[0].total}});
}));
app.get('/api/keys', requireAuth, asyncRoute(async(req,res)=>{if(req.auth.role==='admin')return res.status(403).json({error:'Admin cannot view partner API keys.'});const q=await pool.query('SELECT id,label,key_prefix,environment,last_used_at,created_at,revoked_at FROM api_keys WHERE business_id=$1 ORDER BY created_at DESC',[req.auth.businessId]);res.json({keys:q.rows});}));
app.post('/api/keys', requireAuth, asyncRoute(async(req,res)=>{if(req.auth.role!=='business')return res.status(403).json({error:'Business account required.'});const label=String(req.body.label||'').trim().slice(0,80);const environment= req.body.environment==='production'?'production':'sandbox';if(!label)return res.status(400).json({error:'API key name is required.'});const biz=await pool.query('SELECT status FROM businesses WHERE id=$1',[req.auth.businessId]);if(!biz.rowCount||biz.rows[0].status!=='active')return res.status(403).json({error:'Your business must be approved before creating API keys.'});if(environment!==PROVIDER_MODE)return res.status(403).json({error:`${environment} API keys are unavailable while provider mode is ${PROVIDER_MODE}.`});const raw=`zy_${environment==='sandbox'?'test':'live'}_${crypto.randomBytes(24).toString('hex')}`;const q=await pool.query('INSERT INTO api_keys(business_id,label,key_prefix,key_hash,environment) VALUES($1,$2,$3,$4,$5) RETURNING id,label,key_prefix,environment,created_at',[req.auth.businessId,label,raw.slice(0,15),hashKey(raw),environment]);await audit(req,'api_key.created',{keyId:q.rows[0].id,environment});res.status(201).json({key:q.rows[0],secret:raw,warning:'Copy this key now. It will not be shown again.'});}));
app.delete('/api/keys/:id', requireAuth, asyncRoute(async(req,res)=>{if(req.auth.role!=='business')return res.status(403).json({error:'Business account required.'});const q=await pool.query('UPDATE api_keys SET revoked_at=NOW() WHERE id=$1 AND business_id=$2 AND revoked_at IS NULL RETURNING id',[req.params.id,req.auth.businessId]);if(!q.rowCount)return res.status(404).json({error:'Active API key not found.'});await audit(req,'api_key.revoked',{keyId:req.params.id});res.json({ok:true});}));
app.get('/api/kyc', requireAuth, asyncRoute(async(req,res)=>{const q=await pool.query(`SELECT id,customer_email,customer_name,country,status,provider_customer_id,created_at,updated_at FROM kyc_submissions WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100`,[req.auth.businessId]);res.json({submissions:q.rows});}));
app.get('/api/cards', requireAuth, asyncRoute(async(req,res)=>{const q=await pool.query('SELECT id,provider_card_id,cardholder_name,last_four,status,currency,created_at FROM cards WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100',[req.auth.businessId]);res.json({cards:q.rows});}));
app.get('/api/transactions', requireAuth, asyncRoute(async(req,res)=>{const q=await pool.query('SELECT id,provider_reference,type,amount,currency,status,created_at FROM transactions WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100',[req.auth.businessId]);res.json({transactions:q.rows});}));
app.get('/api/activity', requireAuth, asyncRoute(async(req,res)=>{const q=await pool.query('SELECT method,path,status_code,duration_ms,created_at FROM api_usage WHERE business_id=$1 ORDER BY created_at DESC LIMIT 100',[req.auth.businessId]);res.json({activity:q.rows});}));
app.get('/api/admin/businesses', requireAuth, requireAdmin, asyncRoute(async(req,res)=>{const q=await pool.query(`SELECT b.id,b.name,b.email,b.status,b.created_at,COUNT(k.id)::int AS api_keys FROM businesses b LEFT JOIN api_keys k ON k.business_id=b.id AND k.revoked_at IS NULL GROUP BY b.id ORDER BY b.created_at DESC`);res.json({businesses:q.rows});}));
app.patch('/api/admin/businesses/:id', requireAuth, requireAdmin, asyncRoute(async(req,res)=>{const status=req.body.status;if(!['pending','active','suspended'].includes(status))return res.status(400).json({error:'Invalid business status.'});const q=await pool.query('UPDATE businesses SET status=$1 WHERE id=$2 RETURNING id,name,email,status',[status,req.params.id]);if(!q.rowCount)return res.status(404).json({error:'Business not found.'});await audit(req,'business.status_changed',{businessId:req.params.id,status});res.json({business:q.rows[0]});}));
app.get('/api/admin/audit', requireAuth, requireAdmin, asyncRoute(async(req,res)=>{const q=await pool.query('SELECT id,business_id,actor_user_id,action,details,ip,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 150');res.json({logs:q.rows});}));

// Partner-facing API. Each request is authenticated and isolated to one business.
async function recordUsage(req,status,duration){ if(req.partner) pool.query('INSERT INTO api_usage(business_id,api_key_id,method,path,status_code,duration_ms) VALUES($1,$2,$3,$4,$5,$6)',[req.partner.businessId,req.partner.apiKeyId,req.method,req.path,status,duration]).catch(e=>console.error('usage log failed:',e.message)); }
app.use('/v1', requireApiKey, (req,res,next)=>{const start=Date.now();const original=res.json.bind(res);res.json=(body)=>{recordUsage(req,res.statusCode,Date.now()-start);return original(body);};next();});
app.get('/v1/status', (req,res)=>res.json({ok:true,businessId:req.partner.businessId,environment:req.partner.environment,providerMode:PROVIDER_MODE}));
app.post('/v1/kyc', asyncRoute(async(req,res)=>{
 const required=['first_name','last_name','id_number','email','phone_number','date_of_birth','dial_code','id_front_image','line1','state','postal_code','city','country','id_type','occupation','employment_status','account_purpose','annual_salary','expected_monthly_volume','place_of_birth'];
 const missing=required.filter(k=>!req.body[k]);if(missing.length)return res.status(400).json({error:'Missing required KYC fields.',missing});
 if(typeof req.body.id_front_image!=='string'||req.body.id_front_image.length>9_000_000)return res.status(400).json({error:'id_front_image must be Base64 and no larger than 6.5 MB decoded.'});
 const email=String(req.body.email).toLowerCase().trim();const name=`${req.body.first_name} ${req.body.last_name}`.trim();
 const existing=await pool.query('SELECT id FROM kyc_submissions WHERE business_id=$1 AND customer_email=$2 AND status IN ($3,$4) ORDER BY created_at DESC LIMIT 1',[req.partner.businessId,email,'submitted','pending']);if(existing.rowCount)return res.status(409).json({error:'A KYC request for this email is already pending.',submissionId:existing.rows[0].id});
 const payload={};for(const k of required)payload[k]=req.body[k];
 const result=await providerRequest('/bitvcard/cardkyc','POST',payload);const status=String(result?.data?.status||result?.status||'submitted').toLowerCase();const customerId=result?.data?.customer_id||result?.customer_id||null;
 const saved=await pool.query('INSERT INTO kyc_submissions(business_id,provider_customer_id,customer_email,customer_name,country,status,provider_reference) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,status,created_at',[req.partner.businessId,customerId,email,name,String(req.body.country),status,result?.reference||null]);
 res.status(201).json({submission:saved.rows[0],provider:redactProvider(result),notice:'Identity document was forwarded to ZiiroPay and is not stored by Zytrelix.'});
}));
app.get('/v1/kyc/status', asyncRoute(async(req,res)=>{const email=String(req.query.email||'').toLowerCase().trim();if(!email)return res.status(400).json({error:'email query parameter is required.'});const owned=await pool.query('SELECT id FROM kyc_submissions WHERE business_id=$1 AND customer_email=$2 LIMIT 1',[req.partner.businessId,email]);if(!owned.rowCount)return res.status(404).json({error:'No KYC submission for this email belongs to your business.'});const result=await providerRequest('/bitvcard/cardkycstatus','GET',{email});const status=String(result?.data?.status||result?.status||'unknown').toLowerCase();const customerId=result?.data?.customer_id||null;await pool.query('UPDATE kyc_submissions SET status=$1,provider_customer_id=COALESCE($2,provider_customer_id),updated_at=NOW() WHERE business_id=$3 AND customer_email=$4',[status,customerId,req.partner.businessId,email]);res.json({provider:redactProvider(result)});}));
app.post('/v1/cards', asyncRoute(async(req,res)=>{const {name,customer_id,amount}=req.body;if(!name||!customer_id||!amount||!Number.isFinite(Number(amount))||Number(amount)<=0)return res.status(400).json({error:'name, approved customer_id and positive amount are required.'});const approved=await pool.query("SELECT id FROM kyc_submissions WHERE business_id=$1 AND provider_customer_id=$2 AND status ILIKE '%approved%' LIMIT 1",[req.partner.businessId,String(customer_id)]);if(!approved.rowCount)return res.status(403).json({error:'No approved KYC record exists for this customer under your business.'});const result=await providerRequest('/bitvcard/create-nfc-card','POST',{name,customer_id,amount});const detail=result?.response?.card_detail||result?.data||result?.card||{};const providerCardId=detail.card_id||result.card_id||result.id;if(providerCardId){await pool.query('INSERT INTO cards(business_id,provider_card_id,provider_customer_id,cardholder_name,last_four,status) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT (business_id,provider_card_id) DO UPDATE SET status=EXCLUDED.status',[req.partner.businessId,String(providerCardId),String(customer_id),name,detail.last4||detail.last_four||null,detail.card_status||detail.status||'created']);}res.status(201).json({provider:redactProvider(result)});}));
const ownedCard=asyncRoute(async(req,res,next)=>{const q=await pool.query('SELECT * FROM cards WHERE business_id=$1 AND provider_card_id=$2',[req.partner.businessId,req.params.cardId]);if(!q.rowCount)return res.status(404).json({error:'Card not found for this business.'});req.ownedCard=q.rows[0];next();});
app.get('/v1/cards',asyncRoute(async(req,res)=>{const q=await pool.query('SELECT id,provider_card_id,cardholder_name,last_four,status,currency,created_at FROM cards WHERE business_id=$1 ORDER BY created_at DESC',[req.partner.businessId]);res.json({cards:q.rows});}));
app.get('/v1/cards/:cardId',ownedCard,asyncRoute(async(req,res)=>{const result=await providerRequest('/bitvcard/fetch-nfccard-detail','GET',{card_id:req.params.cardId});res.json({provider:redactProvider(result)});}));
app.get('/v1/cards/:cardId/transactions',ownedCard,asyncRoute(async(req,res)=>{const result=await providerRequest('/bitvcard/nfc-card-transactions','GET',{card_id:req.params.cardId});res.json({provider:redactProvider(result)});}));
app.post('/v1/cards/:cardId/funding',ownedCard,asyncRoute(async(req,res)=>{const {amount,type='fund'}=req.body;if(!Number.isFinite(Number(amount))||Number(amount)<=0||!['fund','withdraw'].includes(type))return res.status(400).json({error:'A positive amount and type fund or withdraw are required.'});const result=await providerRequest('/bitvcard/fund-withdraw-nfccard','POST',{card_id:req.params.cardId,amount,type});await pool.query('INSERT INTO transactions(business_id,card_id,type,amount,status) VALUES($1,$2,$3,$4,$5)',[req.partner.businessId,req.ownedCard.id,type,amount,result?.status||'submitted']);res.json({provider:redactProvider(result)});}));
app.post('/v1/cards/:cardId/status',ownedCard,asyncRoute(async(req,res)=>{const {status}=req.body;if(!['active','frozen'].includes(status))return res.status(400).json({error:'status must be active or frozen.'});const result=await providerRequest('/bitvcard/nfc-cards/status','POST',{card_id:req.params.cardId,status});await pool.query('UPDATE cards SET status=$1 WHERE id=$2',[status,req.ownedCard.id]);res.json({provider:redactProvider(result)});}));

app.post('/api/webhooks/ziiropay', asyncRoute(async(req,res)=>{const secret=process.env.PROVIDER_WEBHOOK_SECRET;if(!secret)return res.status(503).json({error:'Provider webhook is disabled until a verification method is configured.'});const supplied=req.get('x-zytrelix-webhook-secret')||'';if(!safeEqual(supplied,secret))return res.status(401).json({error:'Invalid webhook secret.'});const event=String(req.body.event||'unknown');const cardId=req.body.cardId||req.body.card_id;const customerId=req.body.customer_id;const status=req.body.status||req.body.createdStatus;if(event.startsWith('virtualcard.')&&cardId){await pool.query('UPDATE cards SET status=COALESCE($1,status) WHERE provider_card_id=$2',[status||null,String(cardId)]);}if(event.toLowerCase().includes('kyc')&&req.body.email){await pool.query('UPDATE kyc_submissions SET status=$1,updated_at=NOW() WHERE customer_email=$2',[String(status||'updated'),String(req.body.email).toLowerCase()]);}res.json({received:true});}));

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,_next)=>{console.error('Request failed:',err.message);if(res.headersSent)return;res.status(err.status||500).json({error:err.status?err.message:'Internal server error.'});});

initDb().then(()=>app.listen(PORT,()=>console.log(`Zytrelix API Hub listening on ${PORT}; provider mode=${PROVIDER_MODE}`))).catch(err=>{console.error('Startup failed:',err);process.exit(1);});
