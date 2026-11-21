require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ZIIRO_BASE = 'https://www.ziiropay.com/api';
const ZIIRO_KEY = process.env.ZIIROPAY_PUBLIC_KEY;
const MODE = process.env.ZIIROPAY_MODE || 'sandbox';

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '12mb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

function requireConfigured(req, res, next) {
  if (!ZIIRO_KEY) return res.status(503).json({ error: 'ZiiroPay is not configured. Add ZIIROPAY_PUBLIC_KEY on the server.' });
  const expected = process.env.HUB_ADMIN_TOKEN;
  if (!expected) return res.status(503).json({ error: 'Set HUB_ADMIN_TOKEN on the server before using provider proxy routes.' });
  if (req.get('x-hub-admin-token') !== expected) {
    return res.status(401).json({ error: 'Unauthorized hub request.' });
  }
  next();
}

function clean(value) {
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

async function ziiroRequest(endpoint, method, fields = {}) {
  const params = new URLSearchParams();
  params.set('public_key', ZIIRO_KEY);
  for (const [key, value] of Object.entries(fields)) {
    if (value !== undefined && value !== null && value !== '') params.set(key, String(value));
  }
  if (MODE === 'sandbox') params.set('mode', 'sandbox');
  const url = `${ZIIRO_BASE}${endpoint}?${params.toString()}`;
  const response = await fetch(url, {
    method,
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    ...(method === 'POST' ? { body: '{}' } : {})
  });
  const raw = await response.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = { raw }; }
  if (!response.ok) {
    const error = new Error(data.message || `ZiiroPay returned HTTP ${response.status}`);
    error.status = response.status;
    error.details = data;
    throw error;
  }
  return data;
}

app.get('/api/health', (_req, res) => res.json({
  ok: true,
  service: 'Zytrelix API Hub',
  providerConfigured: Boolean(ZIIRO_KEY),
  mode: MODE
}));

// Submit end-user KYC. The document image must be Base64 as required by the provider docs.
app.post('/api/ziiro/kyc', requireConfigured, async (req, res, next) => {
  try {
    const required = ['first_name','last_name','id_number','email','phone_number','date_of_birth','dial_code','id_front_image','line1','state','postal_code','city','country','id_type','occupation','employment_status','account_purpose','annual_salary','expected_monthly_volume','place_of_birth'];
    const missing = required.filter(k => !clean(req.body[k]));
    if (missing.length) return res.status(400).json({ error: 'Missing required KYC fields.', missing });
    const payload = {};
    for (const key of required) payload[key] = req.body[key];
    const result = await ziiroRequest('/bitvcard/cardkyc', 'POST', payload);
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.get('/api/ziiro/kyc/status', requireConfigured, async (req, res, next) => {
  try {
    if (!clean(req.query.email)) return res.status(400).json({ error: 'email is required' });
    const result = await ziiroRequest('/bitvcard/cardkycstatus', 'GET', { email: req.query.email });
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.post('/api/ziiro/cards', requireConfigured, async (req, res, next) => {
  try {
    const { name, customer_id, amount } = req.body;
    if (!clean(name) || !clean(customer_id) || !clean(amount)) return res.status(400).json({ error: 'name, customer_id and amount are required' });
    const result = await ziiroRequest('/bitvcard/create-nfc-card', 'POST', { name, customer_id, amount });
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.get('/api/ziiro/cards/:cardId', requireConfigured, async (req, res, next) => {
  try {
    const result = await ziiroRequest('/bitvcard/fetch-nfccard-detail', 'GET', { card_id: req.params.cardId });
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.get('/api/ziiro/cards/:cardId/transactions', requireConfigured, async (req, res, next) => {
  try {
    const result = await ziiroRequest('/bitvcard/nfc-card-transactions', 'GET', { card_id: req.params.cardId });
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.post('/api/ziiro/cards/:cardId/funding', requireConfigured, async (req, res, next) => {
  try {
    const { amount, type = 'fund' } = req.body;
    if (!clean(amount) || !['fund','withdraw'].includes(type)) return res.status(400).json({ error: 'Valid amount and type (fund or withdraw) are required' });
    const result = await ziiroRequest('/bitvcard/fund-withdraw-nfccard', 'POST', { card_id: req.params.cardId, amount, type });
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.post('/api/ziiro/cards/:cardId/status', requireConfigured, async (req, res, next) => {
  try {
    const { status } = req.body;
    if (!['active','frozen'].includes(status)) return res.status(400).json({ error: 'status must be active or frozen' });
    const result = await ziiroRequest('/bitvcard/nfc-cards/status', 'POST', { card_id: req.params.cardId, status });
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.post('/api/ziiro/subaccounts', requireConfigured, async (req, res, next) => {
  try {
    const required = ['firstname','lastname','email','phone','country','state','city'];
    const missing = required.filter(k => !clean(req.body[k]));
    if (missing.length) return res.status(400).json({ error: 'Missing subaccount fields', missing });
    const result = await ziiroRequest('/CreateSubAcct', 'POST', req.body);
    res.json({ provider: 'ziiropay', result });
  } catch (err) { next(err); }
});

app.use((err, _req, res, _next) => {
  console.error('API error:', err.message);
  res.status(err.status || 502).json({ error: err.message || 'Provider request failed', details: err.details || undefined });
});

app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Zytrelix API Hub running on port ${PORT} (${MODE})`));
