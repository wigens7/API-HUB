// Provider webhooks. The provider documents no signature, so authenticity rests on a secret in the URL path (or header),
// and nothing in a payload is trusted: deposits are re-verified against provider history, cards are re-fetched.
const crypto = require('crypto');
const { pool } = require('../lib/db');
const F = require('../lib/finance');
const { P, maskedCard } = require('../lib/provider');
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const safeEqual = (a, b) => { const aa = Buffer.from(String(a)); const bb = Buffer.from(String(b)); return aa.length === bb.length && crypto.timingSafeEqual(aa, bb); };
const SENSITIVE = /card_number|cvv|\bpan\b|number_url|cvv_url/i;
function sanitize(v, depth = 0) {
 if (depth > 6 || v === null || typeof v !== 'object') return v;
 const out = Array.isArray(v) ? [] : {};
 for (const k of Object.keys(v)) out[k] = SENSITIVE.test(k) ? '[REDACTED]' : sanitize(v[k], depth + 1);
 return out;
}

module.exports = function webhookHandler() {
 return asyncRoute(async (req, res) => {
  const secret = process.env.PROVIDER_WEBHOOK_SECRET;
  if (!secret) return res.status(503).json({ error: 'Webhook is not configured.' });
  const given = req.params.token || req.get('x-zytrelix-webhook-secret') || '';
  if (!safeEqual(given, secret)) return res.status(401).json({ error: 'Unauthorized.' });
  const p = req.body && typeof req.body === 'object' ? req.body : {};
  const data = p.data && typeof p.data === 'object' ? { ...p.data, event: p.event || p.data.event } : p;
  const event = String(p.event || data.event || p.type || 'unknown').slice(0, 80);
  const eventKey = `${event}:${data.id || data.reference || data.hash || crypto.createHash('sha256').update(JSON.stringify(p)).digest('hex').slice(0, 32)}`.slice(0, 200);
  const ins = await pool.query('INSERT INTO webhook_events(provider_event_id,event,payload) VALUES($1,$2,$3) ON CONFLICT (provider_event_id) DO NOTHING RETURNING id', [eventKey, event, JSON.stringify(sanitize(p))]);
  if (!ins.rowCount) return res.json({ ok: true, duplicate: true });
  const evId = ins.rows[0].id;
  let outcome = 'ignored', businessId = null, error = null;
  try {
   if (event.startsWith('coin.received')) {
    const addr = data.address ? String(data.address) : null;
    const q = addr ? await pool.query('SELECT business_id FROM deposit_addresses WHERE address=$1', [addr]) : { rowCount: 0 };
    if (q.rowCount) { businessId = q.rows[0].business_id; const r = await F.reconcileDeposits(businessId); outcome = `reconciled:${r.credited}`; } else outcome = 'unmatched';
   } else if (event.startsWith('virtualcard.')) {
    const cardId = data.cardId || data.card_id;
    const q = cardId ? await pool.query('SELECT id,business_id,provider_card_id FROM cards WHERE provider_card_id=$1', [String(cardId)]) : { rowCount: 0 };
    if (!q.rowCount) outcome = 'unmatched';
    else {
     const card = q.rows[0]; businessId = card.business_id;
     try { const m = maskedCard(await P.cardDetail(card.provider_card_id)); await pool.query('UPDATE cards SET status=COALESCE($1,status), last_four=COALESCE($2,last_four), brand=COALESCE($3,brand), provider_balance=COALESCE($4,provider_balance), synced_at=NOW() WHERE id=$5', [m.status, m.last_four, m.brand, m.balance, card.id]); } catch (e) { error = 'card refresh failed'; }
     if (!/created|withdrawal|fund/.test(event)) {
      const amt = Number(data.amount); const ref = String(data.reference || data.transactionReference || data.id || '').slice(0, 120) || null;
      await pool.query("INSERT INTO transactions(business_id,card_id,provider_reference,type,amount,status) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING", [businessId, card.id, ref, event.slice(0, 60), Number.isFinite(amt) && amt < 1e9 ? amt.toFixed(2) : null, String(data.status || 'received').slice(0, 40)]);
     }
     outcome = 'card_synced';
    }
   }
  } catch (e) { outcome = 'error'; error = String(e.message).slice(0, 200); console.error('webhook processing failed:', event, e.message); }
  await pool.query('UPDATE webhook_events SET outcome=$1, error=$2, business_id=$3 WHERE id=$4', [outcome, error, businessId, evId]).catch(() => {});
  res.json({ ok: true });
 });
};
