// Partner API (/v1). Mounted after API-key authentication; req.partner.businessId is the only tenant identity used.
const express = require('express');
const { scoped, pool, UUID_RE } = require('../lib/db');
const F = require('../lib/finance');
const { P, redactProvider, mapKycStatus } = require('../lib/provider');
const registerWallet = require('./wallet');

const CUS_RE = /^cus_[0-9a-f]{24}$/;
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
const str = (v, max = 100) => typeof v === 'string' && v.trim() && v.trim().length <= max ? v.trim() : null;

module.exports = function partnerRouter({ auditEvent, providerMode }) {
 const r = express.Router();
 const bid = req => req.partner.businessId;
 const pdb = (req, fn) => scoped({ businessId: bid(req) }, fn);

 const cardView = row => ({ id: row.id, customer_id: row.customer_public_id || null, cardholder_name: row.cardholder_name, last_four: row.last_four, brand: row.brand, status: row.status, balance: row.provider_balance === null || row.provider_balance === undefined ? null : Number(row.provider_balance), currency: row.currency, created_at: row.created_at });
 const CARD_SQL = 'SELECT c.*, e.public_id AS customer_public_id FROM cards c LEFT JOIN end_users e ON e.id=c.end_user_id WHERE c.business_id=$1';
 async function loadCustomer(req, id) {
  if (!CUS_RE.test(String(id))) throw F.httpError(404, 'Customer not found.');
  const q = await pdb(req, c => c.query('SELECT * FROM end_users WHERE business_id=$1 AND public_id=$2', [bid(req), id]));
  if (!q.rowCount) throw F.httpError(404, 'Customer not found.');
  return q.rows[0];
 }
 async function loadCard(req, id) {
  if (!UUID_RE.test(String(id))) throw F.httpError(404, 'Card not found.');
  const q = await pdb(req, c => c.query(`${CARD_SQL} AND c.id=$2`, [bid(req), id]));
  if (!q.rowCount) throw F.httpError(404, 'Card not found.');
  return q.rows[0];
 }

 r.get('/status', (req, res) => res.json({ ok: true, businessId: bid(req), environment: req.partner.environment, providerMode: providerMode() }));

 // ----- customers (end users) -----
 r.post('/customers', asyncRoute(async (req, res) => {
  const email = str(req.body.email, 320)?.toLowerCase(), first = str(req.body.first_name), last = str(req.body.last_name);
  if (!email || !EMAIL_RE.test(email) || !first || !last) return res.status(400).json({ error: 'email, first_name and last_name are required.' });
  const ext = req.body.external_ref === undefined ? null : str(req.body.external_ref, 128);
  if (req.body.external_ref !== undefined && !ext) return res.status(400).json({ error: 'external_ref must be a non-empty string up to 128 characters.' });
  const u = await F.createEndUser(bid(req), { email, first_name: first, last_name: last, external_ref: ext });
  await auditEvent(pool, { businessId: bid(req) }, 'customer.create', { customer: u.public_id }, req.ip).catch(() => {});
  res.status(201).json({ customer: F.customerView(u) });
 }));
 r.get('/customers', asyncRoute(async (req, res) => {
  const q = await pdb(req, c => c.query('SELECT * FROM end_users WHERE business_id=$1 ORDER BY created_at DESC LIMIT 200', [bid(req)]));
  res.json({ customers: q.rows.map(F.customerView) });
 }));
 r.get('/customers/:id', asyncRoute(async (req, res) => res.json({ customer: F.customerView(await loadCustomer(req, req.params.id)) })));
 r.post('/customers/:id/kyc', asyncRoute(async (req, res) => {
  const u = await loadCustomer(req, req.params.id);
  await F.submitKyc(bid(req), u, req.body || {}, req.ip);
  await auditEvent(pool, { businessId: bid(req) }, 'kyc.submit', { customer: u.public_id }, req.ip).catch(() => {});
  const fresh = await loadCustomer(req, req.params.id);
  res.status(201).json({ customer: F.customerView(fresh), notice: 'Identity document was forwarded for verification and is not stored by Zytrelix.' });
 }));
 r.get('/customers/:id/kyc', asyncRoute(async (req, res) => {
  let u = await loadCustomer(req, req.params.id);
  if (u.kyc_status === 'pending' || u.kyc_status === 'rejected') { try { u = await F.syncKyc(bid(req), u); } catch (e) { if (!e.status) throw e; } }
  res.json({ customer_id: u.public_id, kyc_status: u.kyc_status });
 }));
 // legacy endpoints, kept: identify the customer by email, return the internal customer id
 r.post('/kyc', asyncRoute(async (req, res) => {
  const email = str(req.body.email, 320)?.toLowerCase(), first = str(req.body.first_name), last = str(req.body.last_name);
  if (!email || !EMAIL_RE.test(email) || !first || !last) return res.status(400).json({ error: 'Missing required KYC fields.', missing: ['first_name', 'last_name', 'email'].filter(k => !str(req.body[k], 320)) });
  let u = (await pdb(req, c => c.query('SELECT * FROM end_users WHERE business_id=$1 AND email=$2', [bid(req), email]))).rows[0];
  if (!u) u = await F.createEndUser(bid(req), { email, first_name: first, last_name: last });
  await F.submitKyc(bid(req), u, req.body, req.ip);
  await auditEvent(pool, { businessId: bid(req) }, 'kyc.submit', { customer: u.public_id }, req.ip).catch(() => {});
  const fresh = await loadCustomer(req, u.public_id);
  res.status(201).json({ customer_id: fresh.public_id, kyc_status: fresh.kyc_status, notice: 'Identity document was forwarded for verification and is not stored by Zytrelix.' });
 }));
 r.get('/kyc/status', asyncRoute(async (req, res) => {
  const email = String(req.query.email || '').toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'email query parameter is required.' });
  let u = (await pdb(req, c => c.query('SELECT * FROM end_users WHERE business_id=$1 AND email=$2', [bid(req), email]))).rows[0];
  if (!u) return res.status(404).json({ error: 'No KYC submission for this email belongs to your business.' });
  if (u.kyc_status !== 'not_submitted') { try { u = await F.syncKyc(bid(req), u); } catch (e) { if (!e.status) throw e; } }
  res.json({ customer_id: u.public_id, kyc_status: u.kyc_status });
 }));

 // ----- cards -----
 r.post('/cards', asyncRoute(async (req, res) => {
  const key = F.idempotencyKey(req);
  const name = str(req.body.name, 60), amount = F.parseAmount(req.body.amount);
  if (!name || !CUS_RE.test(String(req.body.customer_id || '')) || !amount) return res.status(400).json({ error: 'name, customer_id and a positive amount (max 2 decimals) are required.' });
  const u = await loadCustomer(req, req.body.customer_id);
  if (u.kyc_status !== 'approved' || !u.provider_customer_id) return res.status(403).json({ error: 'Cards can only be created for customers with approved KYC.' });
  F.assertFinancialEnabled();
  const out = await F.runOperation({
   businessId: bid(req), opType: 'create', key, hash: F.hashOf({ t: 'create', name, customer: u.public_id, amount }), amount, hold: true, endUserId: u.id,
   call: () => P.createCard({ name, customer_id: u.provider_customer_id, amount }),
   interpret: result => {
    const pid = F.extractCardId(result); if (!pid) return null;
    return { hook: async c => ({ cardId: await F.insertCard(c, { businessId: bid(req), endUser: u, providerCardId: pid, name, masked: F.maskedCard(result) }) }) };
   },
  });
  if (!out.replay && out.status === 201) await auditEvent(pool, { businessId: bid(req) }, 'card.create', { operation: out.body.operation_id, card: out.body.card_id, customer: u.public_id }, req.ip).catch(() => {});
  if (out.replay) res.set('Idempotent-Replay', 'true');
  res.status(out.status).json(out.body);
 }));
 r.get('/cards', asyncRoute(async (req, res) => {
  const q = await pdb(req, c => c.query(`${CARD_SQL} ORDER BY c.created_at DESC LIMIT 200`, [bid(req)]));
  res.json({ cards: q.rows.map(cardView) });
 }));
 const cardDetails = asyncRoute(async (req, res) => {
  const card = await loadCard(req, req.params.id);
  try {
   const m = F.maskedCard(await P.cardDetail(card.provider_card_id));
   await pdb(req, c => c.query('UPDATE cards SET status=COALESCE($1,status), last_four=COALESCE($2,last_four), brand=COALESCE($3,brand), provider_balance=COALESCE($4,provider_balance), synced_at=NOW() WHERE id=$5 AND business_id=$6', [m.status, m.last_four, m.brand, m.balance, card.id, bid(req)]));
   const fresh = await loadCard(req, req.params.id);
   res.json({ card: { ...cardView(fresh), expiry: m.expiry }, stale: false });
  } catch (e) { res.json({ card: cardView(card), stale: true }); }
 });
 r.get('/cards/:id', cardDetails);
 r.get('/cards/:id/details', cardDetails);
 r.post('/cards/:id/reveal', asyncRoute(async (req, res) => {
  const card = await loadCard(req, req.params.id);
  const b = await pdb(req, c => c.query('SELECT card_data_reveal FROM businesses WHERE id=$1', [bid(req)]));
  if (!b.rows[0]?.card_data_reveal) return res.status(403).json({ error: 'Full card data is not enabled for this business.' });
  const d = (await P.cardDetail(card.provider_card_id))?.response?.card_detail || {};
  await auditEvent(pool, { businessId: bid(req) }, 'card.reveal', { card: card.id }, req.ip).catch(() => {});
  res.set('Cache-Control', 'no-store, private').json({ card_number: d.card_number || null, cvv: d.cvv || null, expiry: d.expiry || null });
 }));
 const history = asyncRoute(async (req, res) => {
  const card = await loadCard(req, req.params.id);
  const ledger = await pdb(req, c => c.query('SELECT id,type,amount,currency,status,created_at FROM transactions WHERE business_id=$1 AND card_id=$2 ORDER BY created_at DESC LIMIT 200', [bid(req), card.id]));
  let hist = null;
  try { const raw = await P.cardTransactions(card.provider_card_id); hist = redactProvider(raw?.data ?? raw?.response ?? raw?.transactions ?? raw); } catch (e) { hist = null; }
  res.json({ card_id: card.id, history: hist, history_available: hist !== null, ledger: ledger.rows });
 });
 r.get('/cards/:id/transactions', history);
 r.get('/cards/:id/history', history);

 async function moneyOp(req, res, type, amountIn) {
  const key = F.idempotencyKey(req);
  const amount = F.parseAmount(amountIn);
  if (!amount) return res.status(400).json({ error: 'A positive amount (max 2 decimals) is required.' });
  const card = await loadCard(req, req.params.id);
  F.assertFinancialEnabled();
  const out = await F.runOperation({
   businessId: bid(req), opType: type, key, hash: F.hashOf({ t: type, card: card.id, amount }), amount, hold: type === 'fund', endUserId: card.end_user_id, cardId: card.id,
   call: () => P.fundWithdraw(card.provider_card_id, amount, type),
   interpret: result => ({ reference: String(result?.data?.reference || result?.reference || '').slice(0, 120) || null }),
  });
  if (!out.replay && out.status === 200) await auditEvent(pool, { businessId: bid(req) }, `card.${type}`, { operation: out.body.operation_id, card: card.id, amount }, req.ip).catch(() => {});
  if (out.replay) res.set('Idempotent-Replay', 'true');
  res.status(out.status).json(out.body);
 }
 r.post('/cards/:id/fund', asyncRoute((req, res) => moneyOp(req, res, 'fund', req.body.amount)));
 r.post('/cards/:id/withdraw', asyncRoute((req, res) => moneyOp(req, res, 'withdraw', req.body.amount)));
 r.post('/cards/:id/funding', asyncRoute((req, res) => { const t = req.body.type === undefined ? 'fund' : req.body.type; if (!['fund', 'withdraw'].includes(t)) return res.status(400).json({ error: 'type must be fund or withdraw.' }); return moneyOp(req, res, t, req.body.amount); }));
 async function setStatus(req, res, status) {
  const card = await loadCard(req, req.params.id);
  F.assertFinancialEnabled();
  try { await P.setCardStatus(card.provider_card_id, status); }
  catch (e) { if (e.outcomeUnknown) return res.status(502).json({ error: e.message, outcome_unknown: true }); return res.status(e.status === 503 ? 503 : 422).json({ error: e.message }); }
  await pdb(req, c => c.query('UPDATE cards SET status=$1 WHERE id=$2 AND business_id=$3', [status, card.id, bid(req)]));
  await auditEvent(pool, { businessId: bid(req) }, `card.${status === 'frozen' ? 'freeze' : 'activate'}`, { card: card.id }, req.ip).catch(() => {});
  res.json({ card_id: card.id, status });
 }
 r.post('/cards/:id/freeze', asyncRoute((req, res) => setStatus(req, res, 'frozen')));
 r.post('/cards/:id/activate', asyncRoute((req, res) => setStatus(req, res, 'active')));
 r.post('/cards/:id/status', asyncRoute((req, res) => { if (!['active', 'frozen'].includes(req.body.status)) return res.status(400).json({ error: 'status must be active or frozen.' }); return setStatus(req, res, req.body.status); }));

 registerWallet(r, bid, { auditEvent });
 return r;
};
