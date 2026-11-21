// Local stand-in for the card provider's documented API shapes. FOR TESTS ONLY: it is never used by the app unless ZIIROPAY_BASE_URL points at it.
const http = require('http');
const KEY = 'stub-public-key';
const RUN = Date.now().toString(36);
const state = { kyc: {}, cards: {}, behavior: {}, history: [], seq: 0, calls: [] };
const json = (res, code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
http.createServer((req, res) => {
 const u = new URL(req.url, 'http://x'); const q = u.searchParams; const p = u.pathname;
 let body = ''; req.on('data', d => body += d); req.on('end', () => {
  if (p === '/__ctl') { const c = JSON.parse(body || '{}'); if (c.kycStatus) state.kyc[c.email] = c.kycStatus; if (c.behavior) Object.assign(state.behavior, c.behavior); if (c.history) state.history = c.history; if (c.reset) { state.behavior = {}; state.calls = []; } if (c.calls) return json(res, 200, { calls: state.calls }); return json(res, 200, { ok: true }); }
  if (q.get('public_key') !== KEY) return json(res, 401, { success: false, message: 'Invalid public key' });
  state.calls.push(`${req.method} ${p}`);
  const beh = state.behavior[p];
  if (beh === 'hang') return; // simulate timeout
  if (beh === '500') return json(res, 500, { message: 'boom' });
  if (beh === 'fail') return json(res, 400, { success: false, message: 'Declined by stub' });
  if (p === '/bitvcard/cardkyc') { state.kyc[q.get('email')] = state.kyc[q.get('email')] || 'pending'; return json(res, 200, { success: true, message: 'KYC submitted', data: { status: 'pending' } }); }
  if (p === '/bitvcard/cardkycstatus') { const e = q.get('email'); if (!state.kyc[e]) return json(res, 404, { success: false, message: 'not found' }); return json(res, 200, { success: true, data: { email: e, status: state.kyc[e], customer_id: 'zp_cust_' + Buffer.from(e).toString('hex') } }); }
  if (p === '/bitvcard/create-nfc-card') { const id = 'zp_card_' + RUN + (++state.seq); state.cards[id] = { balance: Number(q.get('amount')), status: 'active' }; return json(res, 200, { success: true, response: { card_detail: { card_id: id, last4: '4242', card_status: 'active', card_brand: 'visa' } } }); }
  if (p === '/bitvcard/fetch-nfccard-detail') { const c = state.cards[q.get('card_id')]; if (!c) return json(res, 404, { success: false, message: 'no card' }); return json(res, 200, { success: true, response: { card_detail: { card_id: q.get('card_id'), card_number: '4111111111114242', cvv: '123', last4: '4242', expiry: '12/29', card_brand: 'visa', card_status: c.status, balance: c.balance, customer_id: 'zp_x' } } }); }
  if (p === '/bitvcard/nfc-card-transactions') return json(res, 200, { success: true, data: [{ id: 't1', amount: 5, type: 'fund', card_number: '4111111111114242' }] });
  if (p === '/bitvcard/fund-withdraw-nfccard') { const c = state.cards[q.get('card_id')]; const a = Number(q.get('amount')); if (q.get('type') === 'fund') c.balance += a; else c.balance -= a; return json(res, 200, { success: true, message: 'ok', data: { reference: 'ref_' + (++state.seq) } }); }
  if (p === '/bitvcard/nfc-cards/status') { state.cards[q.get('card_id')].status = q.get('status'); return json(res, 200, { success: true }); }
  if (p === '/CreateSubAcct') return json(res, 200, { success: true, data: { sub_id: 'sub_stub_' + RUN + (++state.seq), usdt_balance: '0' } });
  if (p === '/GetAvailCoins') return json(res, 200, { success: true, data: { USDT: ['tron', 'solana', 'ethereum'], USDC: ['solana'] } });
  if (p === '/GenerateCoins') return json(res, 200, { success: true, data: { address: 'T' + require('crypto').createHash('sha256').update(q.get('sub_id')).digest('hex').slice(0, 33), memo: null } });
  if (p === '/GetSubHistory') return json(res, 200, { success: true, data: state.history.filter(h => h.sub_id === q.get('sub_id')) });
  if (p === '/wallet/balance/USD') return json(res, 200, { balance: '1468.29' });
  json(res, 404, { success: false, message: 'unknown endpoint' });
 });
}).listen(Number(process.env.STUB_PORT || 9099), '127.0.0.1', () => console.log('stub provider on', process.env.STUB_PORT || 9099));
