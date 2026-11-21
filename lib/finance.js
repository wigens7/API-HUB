// Ledger, idempotent financial operations, deposit reconciliation and KYC sync.
const crypto = require('crypto');
const { pool, scoped } = require('./db');
const { P, configured, extractCardId, maskedCard, mapKycStatus } = require('./provider');

const AMOUNT_RE = /^\d{1,7}(\.\d{1,2})?$/;
const MAX_OPERATION_AMOUNT = () => Number(process.env.MAX_OPERATION_AMOUNT || 10000);
const httpError = (status, message, extra = {}) => Object.assign(new Error(message), { status }, extra);
const round2 = n => Math.round((Number(n) + Number.EPSILON) * 100) / 100;

function parseAmount(v) {
 const s = typeof v === 'number' ? String(v) : v;
 if (typeof s !== 'string' || !AMOUNT_RE.test(s)) return null;
 const n = Number(s);
 if (!(n > 0) || n > MAX_OPERATION_AMOUNT()) return null;
 return n.toFixed(2);
}
function idempotencyKey(req) {
 const k = req.get('Idempotency-Key') || req.get('X-Idempotency-Key');
 if (!k || k.length < 8 || k.length > 128 || !/^[\w.:-]+$/.test(k)) throw httpError(400, 'An Idempotency-Key header (8-128 characters: letters, digits, . _ : -) is required for this operation.');
 return k;
}
const hashOf = obj => crypto.createHash('sha256').update(JSON.stringify(obj)).digest('hex');

/** Production gate: nothing financial runs against live mode until the provider has confirmed the open questions. */
function assertFinancialEnabled() {
 if ((process.env.ZIIROPAY_MODE || 'sandbox') === 'production' && process.env.PROVIDER_PRODUCTION_ENABLED !== 'true') throw httpError(403, 'Financial operations are disabled pending provider approval.');
}

async function ensureWallet(c, businessId) { await c.query('INSERT INTO wallets (business_id) VALUES ($1) ON CONFLICT DO NOTHING', [businessId]); }
async function balanceOf(c, businessId) { const r = await c.query('SELECT COALESCE(SUM(amount),0)::text AS b FROM ledger_entries WHERE business_id=$1', [businessId]); return r.rows[0].b; }

async function insertCard(c, { businessId, endUser, providerCardId, name, masked = {} }) {
 const r = await c.query(`INSERT INTO cards(business_id,provider_card_id,provider_customer_id,end_user_id,cardholder_name,last_four,status,brand,provider_balance,synced_at)
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW()) RETURNING id`, [businessId, providerCardId, endUser.provider_customer_id, endUser.id, name, masked.last_four || null, masked.status || 'created', masked.brand || null, masked.balance ?? null]);
 return r.rows[0].id;
}

/** Start an operation. Locks the wallet so balance checks and holds are serialized per business. */
async function beginOperation(o) {
 return scoped({ businessId: o.businessId }, async c => {
  await ensureWallet(c, o.businessId);
  await c.query('SELECT 1 FROM wallets WHERE business_id=$1 FOR UPDATE', [o.businessId]);
  const ins = await c.query(`INSERT INTO card_operations(business_id,op_type,idempotency_key,request_hash,amount,end_user_id,card_id) VALUES($1,$2,$3,$4,$5,$6,$7)
   ON CONFLICT (business_id, idempotency_key) DO NOTHING RETURNING *`, [o.businessId, o.opType, o.key, o.hash, o.amount, o.endUserId || null, o.cardId || null]);
  if (!ins.rowCount) { const ex = await c.query('SELECT * FROM card_operations WHERE business_id=$1 AND idempotency_key=$2', [o.businessId, o.key]); return { op: ex.rows[0], existing: true }; }
  const op = ins.rows[0];
  if (o.hold) {
   const bal = Number(await balanceOf(c, o.businessId));
   if (bal < Number(o.amount)) throw httpError(402, 'Insufficient wallet balance.', { balance: bal.toFixed(2) });
   await c.query(`INSERT INTO ledger_entries(business_id,entry_type,amount,ref_type,ref_id) VALUES($1,'card_fund',$2,'card_operation',$3)`, [o.businessId, (-Number(o.amount)).toFixed(2), op.id]);
  }
  return { op, existing: false };
 });
}

/** Finish an operation exactly once (pending/unknown -> final). Ledger effects happen here and only here. */
async function completeOperation(businessId, opId, outcome, hook) {
 return scoped({ businessId }, async c => {
  await ensureWallet(c, businessId);
  await c.query('SELECT 1 FROM wallets WHERE business_id=$1 FOR UPDATE', [businessId]);
  const cur = await c.query('SELECT * FROM card_operations WHERE id=$1 AND business_id=$2 FOR UPDATE', [opId, businessId]);
  const op = cur.rows[0];
  if (!op) throw httpError(404, 'Operation not found.');
  if (!['pending', 'unknown'].includes(op.status)) return op;
  let cardId = op.card_id; let response = outcome.response || null;
  if (outcome.status === 'succeeded') {
   if (hook) { const h = await hook(c); if (h?.cardId) cardId = h.cardId; if (h?.response) response = h.response; }
   if (op.op_type === 'withdraw') await c.query(`INSERT INTO ledger_entries(business_id,entry_type,amount,ref_type,ref_id) VALUES($1,'card_withdraw',$2,'card_operation',$3) ON CONFLICT DO NOTHING`, [businessId, op.amount, op.id]);
   await c.query(`INSERT INTO transactions(business_id,card_id,provider_reference,type,amount,status) VALUES($1,$2,$3,$4,$5,'succeeded') ON CONFLICT DO NOTHING`, [businessId, cardId, `op:${op.id}`, op.op_type, op.amount]);
  } else if (outcome.status === 'failed' && op.op_type !== 'withdraw') {
   await c.query(`INSERT INTO ledger_entries(business_id,entry_type,amount,ref_type,ref_id) VALUES($1,'refund',$2,'card_operation',$3) ON CONFLICT DO NOTHING`, [businessId, op.amount, op.id]);
  }
  const up = await c.query(`UPDATE card_operations SET status=$1, card_id=$2, provider_reference=$3, error=$4, response=$5, updated_at=NOW() WHERE id=$6 RETURNING *`,
   [outcome.status, cardId, outcome.reference || null, outcome.error || null, response ? JSON.stringify(response) : null, op.id]);
  return up.rows[0];
 });
}

const opView = op => ({ operation_id: op.id, type: op.op_type, status: op.status, amount: Number(op.amount).toFixed(2), card_id: op.card_id || undefined, ...(op.status === 'unknown' ? { outcome_unknown: true, message: 'The outcome is being verified. Do not retry with a new Idempotency-Key.' } : {}), ...(op.status === 'failed' && op.error ? { error: op.error } : {}) });

/**
 * Idempotent provider operation. spec: businessId, opType, key, hash, amount, hold, endUserId, cardId,
 * call() -> provider result, interpret(result) -> {reference, hook?} (may throw to mark unknown).
 * Returns { status: http status, body, replay }.
 */
async function runOperation(spec) {
 const { op, existing } = await beginOperation(spec);
 if (existing) {
  if (op.request_hash !== spec.hash) throw httpError(422, 'This Idempotency-Key was already used with a different request.');
  if (['pending', 'unknown'].includes(op.status)) throw httpError(409, 'An operation with this Idempotency-Key is still being processed.', { operation_id: op.id });
  return { status: op.status === 'succeeded' ? 200 : 422, body: op.response || opView(op), replay: true };
 }
 let result;
 try { result = await spec.call(); }
 catch (e) {
  if (e.outcomeUnknown) { const u = await completeOperation(spec.businessId, op.id, { status: 'unknown', error: 'Provider did not confirm.' }); return { status: 502, body: opView(u) }; }
  const f = await completeOperation(spec.businessId, op.id, { status: 'failed', error: e.notConfigured ? 'Card services are not available.' : e.message });
  return { status: e.status === 503 ? 503 : 422, body: opView(f) };
 }
 let interp;
 try { interp = spec.interpret(result); } catch (e) { interp = null; }
 if (!interp) { const u = await completeOperation(spec.businessId, op.id, { status: 'unknown', error: 'Provider response could not be verified.' }); return { status: 502, body: opView(u) }; }
 try {
  const done = await completeOperation(spec.businessId, op.id, { status: 'succeeded', reference: interp.reference }, interp.hook);
  const body = { ...opView(done), ...(interp.extra || {}) };
  await scoped({ businessId: spec.businessId }, c => c.query('UPDATE card_operations SET response=$1 WHERE id=$2', [JSON.stringify(body), op.id]));
  return { status: spec.opType === 'create' ? 201 : 200, body };
 } catch (e) {
  const u = await completeOperation(spec.businessId, op.id, { status: 'unknown', error: 'Provider accepted the request but local completion failed.' }).catch(() => op);
  return { status: 502, body: opView(u) };
 }
}

// ---------- end users / KYC ----------
async function createEndUser(businessId, f) {
 const publicId = 'cus_' + crypto.randomBytes(12).toString('hex');
 try {
  const r = await scoped({ businessId }, c => c.query('INSERT INTO end_users(public_id,business_id,external_ref,email,first_name,last_name) VALUES($1,$2,$3,$4,$5,$6) RETURNING *', [publicId, businessId, f.external_ref || null, f.email, f.first_name, f.last_name]));
  return r.rows[0];
 } catch (e) { if (e.code === '23505') throw httpError(409, 'A customer with this email or external_ref already exists.'); throw e; }
}
const customerView = u => ({ id: u.public_id, external_ref: u.external_ref, email: u.email, first_name: u.first_name, last_name: u.last_name, kyc_status: u.kyc_status, created_at: u.created_at });

const KYC_REQUIRED = ['id_number', 'phone_number', 'date_of_birth', 'dial_code', 'id_front_image', 'line1', 'state', 'postal_code', 'city', 'country', 'id_type', 'occupation', 'employment_status', 'account_purpose', 'annual_salary', 'expected_monthly_volume', 'place_of_birth'];

async function submitKyc(businessId, endUser, body, ip) {
 const missing = KYC_REQUIRED.filter(k => !body[k]);
 if (missing.length) throw httpError(400, 'Missing required KYC fields.', { missing });
 if (typeof body.id_front_image !== 'string' || body.id_front_image.length > 9_000_000) throw httpError(400, 'id_front_image must be Base64 and no larger than 6.5 MB decoded.');
 if (['pending', 'approved'].includes(endUser.kyc_status)) throw httpError(409, `KYC for this customer is already ${endUser.kyc_status}.`);
 // The provider identifies customers by email only. Never let two tenants share one email for KYC.
 const clash = await pool.query('SELECT 1 FROM end_users WHERE lower(email)=lower($1) AND business_id<>$2 AND kyc_status<>$3 LIMIT 1', [endUser.email, businessId, 'not_submitted']);
 if (clash.rowCount) throw httpError(409, 'KYC cannot be submitted for this email address.');
 assertFinancialEnabled();
 const payload = { first_name: endUser.first_name, last_name: endUser.last_name, email: endUser.email };
 for (const k of KYC_REQUIRED) payload[k] = body[k];
 const result = await P.submitKyc(payload);
 const d = result?.data || result || {};
 const status = mapKycStatus(d.status || result?.status || 'pending');
 let customerId = d.customer_id || result?.customer_id || null;
 if (customerId) { const taken = await pool.query('SELECT 1 FROM end_users WHERE provider_customer_id=$1 AND id<>$2', [String(customerId), endUser.id]); if (taken.rowCount) customerId = null; }
 const name = `${endUser.first_name} ${endUser.last_name}`;
 await scoped({ businessId }, async c => {
  await c.query('UPDATE end_users SET kyc_status=$1, provider_customer_id=COALESCE($2,provider_customer_id), kyc_submitted_at=NOW(), kyc_updated_at=NOW() WHERE id=$3 AND business_id=$4', [status, customerId ? String(customerId) : null, endUser.id, businessId]);
  await c.query('INSERT INTO kyc_submissions(business_id,end_user_id,provider_customer_id,customer_email,customer_name,country,status,provider_reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [businessId, endUser.id, customerId ? String(customerId) : null, endUser.email, name, String(body.country), status, null]);
 });
 return status;
}

/** Pull KYC status from the provider and sync it. Admin decisions are never overwritten. */
async function syncKyc(businessId, endUser) {
 const result = await P.kycStatus(endUser.email);
 const d = result?.data || {};
 if (d.email && String(d.email).toLowerCase() !== endUser.email.toLowerCase()) throw httpError(502, 'Verification response did not match this customer.');
 const status = mapKycStatus(d.status);
 let customerId = d.customer_id ? String(d.customer_id) : null;
 if (customerId) { const taken = await pool.query('SELECT 1 FROM end_users WHERE provider_customer_id=$1 AND id<>$2', [customerId, endUser.id]); if (taken.rowCount) customerId = null; }
 return scoped({ businessId }, async c => {
  const lock = await c.query("SELECT 1 FROM kyc_submissions WHERE end_user_id=$1 AND admin_decision IS NOT NULL LIMIT 1", [endUser.id]);
  if (!lock.rowCount) {
   await c.query('UPDATE end_users SET kyc_status=$1, kyc_updated_at=NOW() WHERE id=$2 AND business_id=$3', [status, endUser.id, businessId]);
   await c.query("UPDATE kyc_submissions SET status=$1, updated_at=NOW() WHERE end_user_id=$2 AND admin_decision IS NULL", [status, endUser.id]);
  }
  if (customerId && !endUser.provider_customer_id) await c.query('UPDATE end_users SET provider_customer_id=$1 WHERE id=$2 AND business_id=$3', [customerId, endUser.id, businessId]);
  return (await c.query('SELECT * FROM end_users WHERE id=$1', [endUser.id])).rows[0];
 });
}

// ---------- deposits ----------
async function ensureSubAccount(businessId, profile) {
 const have = await pool.query('SELECT provider_sub_id FROM provider_accounts WHERE business_id=$1', [businessId]);
 if (have.rowCount) return have.rows[0].provider_sub_id;
 const biz = await pool.query('SELECT b.name, b.email FROM businesses b WHERE b.id=$1', [businessId]);
 const client = await pool.connect();
 try {
  await client.query('SELECT pg_advisory_lock(hashtext($1))', ['subacct:' + businessId]);
  const again = await client.query('SELECT provider_sub_id FROM provider_accounts WHERE business_id=$1', [businessId]);
  if (again.rowCount) return again.rows[0].provider_sub_id;
  const missing = ['phone', 'country', 'state', 'city'].filter(k => !profile?.[k]);
  if (missing.length) throw httpError(400, 'phone, country, state and city are required to create the deposit account.', { missing });
  const parts = String(biz.rows[0].name).trim().split(/\s+/);
  const r = await P.createSubAccount({ firstname: parts[0], lastname: parts.slice(1).join(' ') || parts[0], email: biz.rows[0].email, phone: profile.phone, country: profile.country, state: profile.state, city: profile.city, address: profile.address });
  const subId = r?.data?.sub_id; if (!subId) throw httpError(502, 'Deposit account could not be created.', { outcomeUnknown: true });
  await client.query('INSERT INTO provider_accounts(business_id,provider_sub_id,phone,country,state,city,address) VALUES($1,$2,$3,$4,$5,$6,$7)', [businessId, String(subId), profile.phone, profile.country, profile.state, profile.city, profile.address || null]);
  return String(subId);
 } finally { await client.query('SELECT pg_advisory_unlock(hashtext($1))', ['subacct:' + businessId]).catch(() => {}); client.release(); }
}

async function getDepositAddress(businessId, { token = 'USDT', chain = 'tron', profile }) {
 token = String(token).toUpperCase(); chain = String(chain).toLowerCase();
 const have = await scoped({ businessId }, c => c.query('SELECT token,chain,address,memo FROM deposit_addresses WHERE business_id=$1 AND token=$2 AND chain=$3', [businessId, token, chain]));
 if (have.rowCount) return have.rows[0];
 assertFinancialEnabled();
 if (token !== 'USDT') throw httpError(400, 'Only USDT deposits are supported.');
 const coins = await P.availCoins();
 const list = coins?.data?.[token] || coins?.data?.[token.toLowerCase()] || coins?.[token] || [];
 const names = (Array.isArray(list) ? list : Object.keys(list)).map(x => String(x?.chain || x?.name || x).toLowerCase());
 if (!names.includes(chain)) throw httpError(400, 'Unsupported chain for this token.', { supported: names });
 const subId = await ensureSubAccount(businessId, profile);
 const r = await P.generateCoin(subId, token, chain);
 const address = r?.data?.address; if (!address) throw httpError(502, 'Deposit address could not be generated.');
 return scoped({ businessId }, async c => {
  await c.query('INSERT INTO deposit_addresses(business_id,token,chain,address,memo) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING', [businessId, token, chain, String(address), r?.data?.memo || null]);
  return (await c.query('SELECT token,chain,address,memo FROM deposit_addresses WHERE business_id=$1 AND token=$2 AND chain=$3', [businessId, token, chain])).rows[0];
 });
}

/** Credits only deposits the provider reports as completed credits for this business's sub account. Idempotent per provider transaction id. */
async function reconcileDeposits(businessId) {
 const pa = await pool.query('SELECT provider_sub_id FROM provider_accounts WHERE business_id=$1', [businessId]);
 if (!pa.rowCount) return { credited: 0 };
 const subId = pa.rows[0].provider_sub_id;
 const hist = await P.subHistory(subId);
 const rows = Array.isArray(hist?.data) ? hist.data : [];
 let credited = 0;
 for (const r of rows) {
  if (String(r.trx_type).toLowerCase() !== 'credit' || String(r.status).toLowerCase() !== 'completed') continue;
  if (!/^RCV_/.test(String(r.trx || ''))) continue;
  if (r.sub_id && String(r.sub_id) !== subId) continue;
  const gross = Number(r.amount), fee = Number(r.fee || 0);
  const net = round2(gross - fee);
  if (!Number.isFinite(gross) || !(net > 0)) continue;
  const added = await scoped({ businessId }, async c => {
   const ins = await c.query(`INSERT INTO deposits(business_id,provider_trx,gross_amount,fee,credited_amount,details,provider_created_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (provider_trx) DO NOTHING RETURNING id`,
    [businessId, String(r.trx), gross, Number.isFinite(fee) ? fee : 0, net.toFixed(2), String(r.details || '').slice(0, 300), r.created_at ? new Date(r.created_at) : null]);
   if (!ins.rowCount) return false;
   await ensureWallet(c, businessId);
   await c.query(`INSERT INTO ledger_entries(business_id,entry_type,amount,ref_type,ref_id) VALUES($1,'deposit',$2,'deposit',$3) ON CONFLICT DO NOTHING`, [businessId, net.toFixed(2), ins.rows[0].id]);
   return true;
  });
  if (added) credited++;
 }
 return { credited };
}

// ---------- background reconciler ----------
async function reconcileAll() {
 if (!configured()) return { skipped: true };
 const lockClient = await pool.connect();
 try {
  const got = await lockClient.query('SELECT pg_try_advisory_lock(727001) AS ok');
  if (!got.rows[0].ok) return { skipped: true };
  const out = { deposits: 0, kyc: 0, stale: 0 };
  const accts = await pool.query('SELECT business_id FROM provider_accounts');
  for (const a of accts.rows) { try { out.deposits += (await reconcileDeposits(a.business_id)).credited; } catch (e) { console.error('deposit reconcile failed:', e.message); } }
  const pend = await pool.query("SELECT * FROM end_users WHERE kyc_status='pending' ORDER BY COALESCE(kyc_updated_at, created_at) LIMIT 25");
  for (const u of pend.rows) { try { await syncKyc(u.business_id, u); out.kyc++; } catch (e) { console.error('kyc sync failed:', e.message); } }
  const stale = await pool.query("UPDATE card_operations SET status='unknown', error='Marked unknown by reconciler.', updated_at=NOW() WHERE status='pending' AND updated_at < NOW() - INTERVAL '5 minutes'");
  out.stale = stale.rowCount;
  return out;
 } finally { await lockClient.query('SELECT pg_advisory_unlock(727001)').catch(() => {}); lockClient.release(); }
}
function startReconciler() {
 const secs = Math.max(30, Number(process.env.RECONCILE_INTERVAL_SECONDS || 120));
 const t = setInterval(() => reconcileAll().catch(e => console.error('reconciler failed:', e.message)), secs * 1000);
 t.unref();
 return t;
}
module.exports = { httpError, parseAmount, idempotencyKey, hashOf, assertFinancialEnabled, ensureWallet, balanceOf, insertCard, runOperation, completeOperation, opView, createEndUser, customerView, submitKyc, syncKyc, getDepositAddress, reconcileDeposits, reconcileAll, startReconciler, extractCardId, maskedCard, round2 };
