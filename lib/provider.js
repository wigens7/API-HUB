// Backend card-issuing provider client. Only endpoints documented by the provider are used.
// Nothing here is ever sent to browsers or tenants: callers map results into our own response shapes.
const PROVIDER_BASE = () => (process.env.ZIIROPAY_BASE_URL || 'https://www.ziiropay.com/api').replace(/\/$/, '');
const PROVIDER_KEY = () => process.env.ZIIROPAY_PUBLIC_KEY;
const PROVIDER_MODE = () => process.env.ZIIROPAY_MODE || 'sandbox';
const configured = () => Boolean(PROVIDER_KEY());

/** Calls the provider. Errors carry: status (HTTP status for our caller), outcomeUnknown (request may have been applied). The URL is never logged: it contains the key. */
async function providerRequest(endpoint, method, fields = {}, opts = {}) {
 if (!PROVIDER_KEY()) { const e = new Error('Card services are not configured on the server.'); e.status = 503; e.notConfigured = true; throw e; }
 const params = new URLSearchParams({ public_key: PROVIDER_KEY() });
 for (const [key, value] of Object.entries(fields)) if (value !== undefined && value !== null && value !== '') params.set(key, typeof value === 'object' ? JSON.stringify(value) : String(value));
 if (PROVIDER_MODE() === 'sandbox' && !opts.noMode) params.set('mode', 'sandbox');
 const url = `${PROVIDER_BASE()}${endpoint}?${params.toString()}`;
 let response, raw;
 try {
  response = await fetch(url, { method, headers: { accept: 'application/json', 'content-type': 'application/json' }, ...(method === 'POST' ? { body: '{}' } : {}), signal: AbortSignal.timeout(Number(process.env.PROVIDER_TIMEOUT_MS || 25000)) });
  raw = await response.text();
 } catch {
  const e = new Error('Card service did not respond. The outcome of this request is unknown.'); e.status = 502; e.outcomeUnknown = true; throw e;
 }
 let data; try { data = raw ? JSON.parse(raw) : {}; } catch { data = { message: raw.slice(0, 300) }; }
 if (response.status >= 500) { const e = new Error('Card service is temporarily unavailable. The outcome of this request is unknown.'); e.status = 502; e.outcomeUnknown = true; throw e; }
 if (!response.ok || data.success === false) {
  const e = new Error(typeof data.message === 'string' && data.message.length < 200 ? data.message : `Upstream service returned HTTP ${response.status}`);
  e.status = 422; e.definitiveFailure = true; throw e;
 }
 return data;
}
function redactProvider(data) { if (!data || typeof data !== 'object') return data; const copy = JSON.parse(JSON.stringify(data)); const scrub = obj => { if (!obj || typeof obj !== 'object') return; for (const key of Object.keys(obj)) { if (/card_number|cvv|\bpan\b|id_front_image|id_back_image|selfie|secret|public_key|token|customer_id|sub_id|provider/i.test(key)) obj[key] = '[REDACTED]'; else if (obj[key] && typeof obj[key] === 'object') scrub(obj[key]); } }; scrub(copy); return copy; }

const P = {
 submitKyc: fields => providerRequest('/bitvcard/cardkyc', 'POST', fields),
 kycStatus: email => providerRequest('/bitvcard/cardkycstatus', 'GET', { email }),
 createCard: f => providerRequest('/bitvcard/create-nfc-card', 'POST', { name: f.name, customer_id: f.customer_id, amount: f.amount }),
 cardDetail: cardId => providerRequest('/bitvcard/fetch-nfccard-detail', 'GET', { card_id: cardId }),
 cardTransactions: cardId => providerRequest('/bitvcard/nfc-card-transactions', 'GET', { card_id: cardId }),
 fundWithdraw: (cardId, amount, type) => providerRequest('/bitvcard/fund-withdraw-nfccard', 'POST', { card_id: cardId, amount, type }),
 setCardStatus: (cardId, status) => providerRequest('/bitvcard/nfc-cards/status', 'POST', { card_id: cardId, status }),
 createSubAccount: f => providerRequest('/CreateSubAcct', 'POST', f),
 subHistory: subId => providerRequest('/GetSubHistory', 'GET', { sub_id: subId }),
 availCoins: () => providerRequest('/GetAvailCoins', 'GET', {}, { noMode: true }),
 generateCoin: (subId, token, chain) => providerRequest('/GenerateCoins', 'POST', { sub_id: subId, token, chain }),
 mainBalance: () => providerRequest('/wallet/balance/USD', 'GET', {}, { noMode: true }),
};

/** Extract a card id from the (undocumented) create-card response. */
function extractCardId(result) {
 const c = result?.response?.card_detail || result?.data?.card_detail || result?.card_detail || result?.data || result?.card || result?.response || {};
 const id = c.card_id || c.id || c.cardId;
 return id ? String(id) : null;
}
/** Map the provider's card detail into our own masked shape. PAN/CVV are never included. */
function maskedCard(detail) {
 const d = detail?.response?.card_detail || detail?.data?.card_detail || detail?.card_detail || {};
 const bal = d.balance !== undefined && d.balance !== null ? Number(d.balance) : null;
 return { status: d.card_status ? String(d.card_status).toLowerCase() : null, brand: d.card_brand || null, last_four: d.last4 ? String(d.last4).slice(-4) : (d.card_number ? String(d.card_number).slice(-4) : null), balance: Number.isFinite(bal) ? bal : null, expiry: d.expiry || null, holder_name: d.card_holder_name || null };
}
function mapKycStatus(s) { const v = String(s || '').toLowerCase(); if (v.includes('approv')) return 'approved'; if (v.includes('reject') || v.includes('declin') || v.includes('fail')) return 'rejected'; return 'pending'; }
module.exports = { providerRequest, redactProvider, P, configured, extractCardId, maskedCard, mapKycStatus, PROVIDER_MODE };
