// Wallet routes shared by the partner API (/v1/wallet/*) and the dashboard API (/api/wallet/*).
const { scoped, pool } = require('../lib/db');
const F = require('../lib/finance');
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clean = v => (typeof v === 'string' && v.trim() && v.trim().length <= 120 ? v.trim() : undefined);

module.exports = function registerWallet(router, bizOf, { auditEvent }, prefix = '/wallet') {
 const db = (req, fn) => scoped({ businessId: bizOf(req) }, fn);
 router.get(prefix + '/balance', asyncRoute(async (req, res) => {
  const b = await db(req, async c => { await F.ensureWallet(c, bizOf(req)); return F.balanceOf(c, bizOf(req)); });
  res.json({ currency: 'USD', balance: Number(b).toFixed(2) });
 }));
 router.get(prefix + '/ledger', asyncRoute(async (req, res) => {
  const q = await db(req, c => c.query('SELECT id,entry_type,amount,currency,created_at FROM ledger_entries WHERE business_id=$1 ORDER BY id DESC LIMIT 200', [bizOf(req)]));
  res.json({ ledger: q.rows });
 }));
 router.get(prefix + '/deposits', asyncRoute(async (req, res) => {
  const q = await db(req, c => c.query('SELECT id,token,gross_amount,fee,credited_amount,created_at FROM deposits WHERE business_id=$1 ORDER BY created_at DESC LIMIT 200', [bizOf(req)]));
  const a = await db(req, c => c.query('SELECT token,chain,address,memo FROM deposit_addresses WHERE business_id=$1', [bizOf(req)]));
  res.json({ deposits: q.rows, addresses: a.rows });
 }));
 router.post(prefix + '/deposit-address', asyncRoute(async (req, res) => {
  const out = await F.getDepositAddress(bizOf(req), { token: req.body.token || 'USDT', chain: req.body.chain || 'tron', profile: { phone: clean(req.body.phone), country: clean(req.body.country), state: clean(req.body.state), city: clean(req.body.city), address: clean(req.body.address) } });
  await auditEvent(pool, { businessId: bizOf(req) }, 'wallet.deposit_address', { token: out.token, chain: out.chain }, req.ip).catch(() => {});
  res.json({ deposit_address: out, notice: 'Send only the specified token on the specified network. Deposits are credited after network confirmation.' });
 }));
 router.post(prefix + '/sync', asyncRoute(async (req, res) => {
  try { res.json(await F.reconcileDeposits(bizOf(req))); }
  catch (e) { if (e.status) throw e; throw e; }
 }));
};
