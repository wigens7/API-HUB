// End-to-end checks for the white-label finance flows against a running server and the local stub provider.
// Usage: STUB on :9099 (scripts/stub-provider.js), server started with ZIIROPAY_BASE_URL=http://127.0.0.1:9099 ZIIROPAY_PUBLIC_KEY=stub-public-key
//        PROVIDER_WEBHOOK_SECRET=whsec_test_0123456789abcdef PROVIDER_TIMEOUT_MS=1500; then: node scripts/finance-check.js
const { Client } = require('pg');
const BASE = process.env.BASE || 'http://localhost:8080', STUB = 'http://127.0.0.1:9099', WH = process.env.PROVIDER_WEBHOOK_SECRET || 'whsec_test_0123456789abcdef';
let pass = 0, fail = 0;
const ok = (c, name, extra = '') => { if (c) { pass++; console.log('  ok  ', name); } else { fail++; console.log('  FAIL', name, extra); } };
const sfx = Date.now().toString(36);
async function call(method, url, { body, headers = {}, cookie } = {}) {
 const r = await fetch(url, { method, headers: { 'content-type': 'application/json', ...(cookie ? { cookie, 'x-zytrelix-client': 'web' } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
 const text = await r.text(); let json; try { json = JSON.parse(text); } catch { json = {}; }
 return { status: r.status, json, text, headers: r.headers };
}
const ctl = b => call('POST', STUB + '/__ctl', { body: b });
async function mkBusiness(tag) {
 const r = await fetch(BASE + '/api/auth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'Owner ' + tag, businessName: 'Biz ' + tag + sfx, email: `${tag}${sfx}@example.com`, password: 'Test-Password-12345' }) });
 const j = await r.json(); const cookie = r.headers.get('set-cookie').split(';')[0];
 return { cookie, id: j.business.id, email: `${tag}${sfx}@example.com` };
}
const KYC = { id_number: 'A1234567', phone_number: '50930000000', date_of_birth: '1990-01-01', dial_code: '+509', id_front_image: 'aGVsbG8=', line1: '1 Rue Test', state: 'Ouest', postal_code: 'HT6110', city: 'Port-au-Prince', country: 'HTI', id_type: 'passport', occupation: 'engineer', employment_status: 'employed', account_purpose: 'spending', annual_salary: '20000', expected_monthly_volume: '1000', place_of_birth: 'Port-au-Prince' };
let n = 0; const idem = () => `test-key-${sfx}-${++n}-abcdef`;

(async () => {
 const db = new Client({ connectionString: process.env.DATABASE_URL }); await db.connect();
 await ctl({ reset: true });
 const admin = await call('POST', BASE + '/api/auth/login', { body: { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD } });
 const adminCookie = admin.headers.get('set-cookie').split(';')[0];
 const A = await mkBusiness('a'), B = await mkBusiness('b');
 for (const b of [A, B]) {
  await call('PATCH', `${BASE}/api/admin/businesses/${b.id}`, { body: { status: 'active' }, cookie: adminCookie });
  const k = await call('POST', BASE + '/api/keys', { body: { label: 'k', environment: 'sandbox' }, cookie: b.cookie }); b.key = k.json.secret;
 }
 const v1 = (b, method, path, body, headers = {}) => call(method, BASE + '/v1' + path, { body, headers: { 'x-api-key': b.key, ...headers } });

 console.log('customers and KYC');
 const cu = await v1(A, 'POST', '/customers', { email: `cust${sfx}@example.com`, first_name: 'Ann', last_name: 'Lee', external_ref: 'u1' });
 ok(cu.status === 201 && /^cus_[0-9a-f]{24}$/.test(cu.json.customer?.id), 'customer created with internal id', cu.text);
 const cid = cu.json.customer.id;
 ok((await v1(A, 'POST', '/customers', { email: `cust${sfx}@example.com`, first_name: 'x', last_name: 'y' })).status === 409, 'duplicate email rejected');
 let r = await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '10' }, { 'idempotency-key': idem() });
 ok(r.status === 403, 'card creation blocked before KYC', r.text);
 ok((await v1(A, 'POST', `/customers/${cid}/kyc`, { id_number: '1' })).status === 400, 'KYC with missing fields rejected');
 r = await v1(A, 'POST', `/customers/${cid}/kyc`, KYC);
 ok(r.status === 201 && r.json.customer.kyc_status === 'pending', 'KYC submitted to provider, status pending', r.text);
 ok(!/zp_cust|customer_id":"zp/.test(r.text), 'no provider customer id in KYC response');
 r = await v1(A, 'GET', `/customers/${cid}/kyc`);
 ok(r.json.kyc_status === 'pending', 'status still pending before provider approval');
 r = await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '10' }, { 'idempotency-key': idem() });
 ok(r.status === 403, 'card still blocked while pending');
 await ctl({ email: `cust${sfx}@example.com`, kycStatus: 'approved' });
 r = await v1(A, 'GET', `/customers/${cid}/kyc`);
 ok(r.json.kyc_status === 'approved', 'KYC status synced from provider');
 const mapped = await db.query('SELECT provider_customer_id, business_id FROM end_users WHERE public_id=$1', [cid]);
 ok(mapped.rows[0]?.provider_customer_id?.startsWith('zp_cust_') && mapped.rows[0].business_id === A.id, 'provider customer id stored and mapped to tenant');
 ok((await v1(B, 'GET', `/customers/${cid}`)).status === 404, 'other tenant cannot read customer');
 ok((await v1(B, 'POST', `/customers/${cid}/kyc`, KYC)).status === 404, 'other tenant cannot submit KYC for it');
 const bc = await v1(B, 'POST', '/customers', { email: `cust${sfx}@example.com`, first_name: 'Ann', last_name: 'Lee' });
 r = await v1(B, 'POST', `/customers/${bc.json.customer.id}/kyc`, KYC);
 ok(r.status === 409, 'same email cannot be KYC-submitted by a second tenant', r.text);
 ok((await v1(B, 'GET', '/customers')).json.customers.every(c => c.id !== cid), 'customer list is tenant scoped');

 console.log('wallet and deposits');
 r = await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '10' });
 ok(r.status === 400, 'Idempotency-Key required');
 r = await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '10' }, { 'idempotency-key': idem() });
 ok(r.status === 402, 'insufficient wallet balance blocks card creation', r.text);
 ok((await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '-5' }, { 'idempotency-key': idem() })).status === 400, 'negative amount rejected');
 r = await v1(A, 'POST', '/wallet/deposit-address', {});
 ok(r.status === 400, 'deposit address needs profile on first use', r.text);
 r = await v1(A, 'POST', '/wallet/deposit-address', { phone: '50930000000', country: 'Haiti', state: 'Ouest', city: 'Port-au-Prince' });
 const addr = r.json.deposit_address?.address; ok(r.status === 200 && addr, 'deposit address generated', r.text);
 ok(!/sub_stub/.test(r.text), 'no provider account id in response');
 const sub = (await db.query('SELECT provider_sub_id FROM provider_accounts WHERE business_id=$1', [A.id])).rows[0].provider_sub_id;
 r = await v1(A, 'POST', '/wallet/deposit-address', {});
 ok(r.json.deposit_address?.address === addr, 'same address returned on repeat');
 const hook = (token, body, headers = {}) => call('POST', `${BASE}/api/webhooks/ziiropay${token ? '/' + token : ''}`, { body, headers });
 ok((await hook('wrong-token', { event: 'coin.received.success', data: { id: 'w0' + sfx, address: addr, amount: '999' } })).status === 401, 'webhook with wrong token rejected');
 ok((await hook(null, { event: 'x' })).status === 401, 'webhook without secret rejected');
 r = await hook(WH, { event: 'coin.received.success', data: { id: 'w1' + sfx, address: addr, amount: '999', status: 'success' } });
 ok(r.status === 200, 'authenticated webhook accepted');
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '0.00', 'webhook claim alone credits nothing');
 await ctl({ history: [{ sub_id: sub, amount: '50', fee: '1', trx_type: 'credit', status: 'pending', trx: 'RCV_USDT_p1_' + sfx, details: 'pending' }, { sub_id: 'other', amount: '70', fee: '0', trx_type: 'credit', status: 'completed', trx: 'RCV_USDT_o1_' + sfx, details: 'other sub' }] });
 await hook(WH, { event: 'coin.received.success', data: { id: 'w2' + sfx, address: addr, amount: '50' } });
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '0.00', 'pending or foreign provider history is not credited');
 await ctl({ history: [{ sub_id: sub, amount: '50', fee: '1', trx_type: 'credit', status: 'completed', trx: 'RCV_USDT_c1_' + sfx, details: 'Received USDT on TRON. Hash: abc' }] });
 await hook(WH, { event: 'coin.received.success', data: { id: 'w3' + sfx, address: addr, amount: '1' } });
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '49.00', 'confirmed deposit credited (net of fee) after provider confirmation');
 await hook(WH, { event: 'coin.received.success', data: { id: 'w3' + sfx, address: addr, amount: '1' } });
 await v1(A, 'POST', '/wallet/sync', {}); await v1(A, 'POST', '/wallet/sync', {});
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '49.00', 'duplicate webhook and repeated sync do not double credit');
 ok((await db.query('SELECT COUNT(*)::int n FROM deposits WHERE provider_trx=$1', ['RCV_USDT_c1_' + sfx])).rows[0].n === 1, 'one deposit row per provider transaction');
 ok((await v1(B, 'GET', '/wallet/balance')).json.balance === '0.00', 'other tenant balance unaffected');

 console.log('cards and idempotency');
 const ck = idem();
 r = await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '20' }, { 'idempotency-key': ck });
 ok(r.status === 201 && /^[0-9a-f-]{36}$/.test(r.json.card_id), 'card created through provider', r.text);
 const card = r.json.card_id, opId = r.json.operation_id;
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '29.00', 'card creation debited wallet');
 const r2 = await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '20' }, { 'idempotency-key': ck });
 ok(r2.status === 200 && r2.headers.get('idempotent-replay') === 'true' && r2.json.card_id === card, 'same key replays stored result', r2.text);
 ok((await db.query('SELECT COUNT(*)::int n FROM cards WHERE business_id=$1', [A.id])).rows[0].n === 1, 'replay created no second card');
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '29.00', 'replay did not debit again');
 r = await v1(A, 'POST', '/cards', { name: 'ANN LEE', customer_id: cid, amount: '21' }, { 'idempotency-key': ck });
 ok(r.status === 422, 'same key with different body rejected');
 ok((await v1(B, 'GET', `/cards/${card}`)).status === 404 && (await v1(B, 'POST', `/cards/${card}/freeze`, {})).status === 404, 'other tenant cannot see or freeze card');
 r = await v1(A, 'GET', `/cards/${card}`);
 ok(r.status === 200 && r.json.card.last_four === '4242' && r.json.card.balance === 20 && r.json.stale === false, 'card details masked and refreshed', r.text);
 ok(!/4111|cvv|"123"|zp_card|zp_x/.test(r.text), 'details contain no PAN, CVV or provider ids');
 ok((await v1(A, 'POST', `/cards/${card}/fund`, { amount: '5' }, { 'idempotency-key': idem() })).status === 200, 'card funded');
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '24.00', 'funding debited wallet');
 ok((await v1(A, 'POST', `/cards/${card}/withdraw`, { amount: '3' }, { 'idempotency-key': idem() })).status === 200, 'card withdraw');
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '27.00', 'withdraw credited wallet');
 r = await v1(A, 'GET', `/cards/${card}/history`);
 ok(r.status === 200 && Array.isArray(r.json.ledger) && r.json.ledger.length >= 3 && !/4111/.test(r.text), 'history returns ledger and redacted provider history', r.text.slice(0, 300));
 ok((await v1(A, 'POST', `/cards/${card}/freeze`, {})).json.status === 'frozen' && (await v1(A, 'POST', `/cards/${card}/activate`, {})).json.status === 'active', 'freeze and activate');
 await ctl({ behavior: { '/bitvcard/fund-withdraw-nfccard': 'fail' } });
 r = await v1(A, 'POST', `/cards/${card}/fund`, { amount: '4' }, { 'idempotency-key': idem() });
 ok(r.status === 422 && r.json.status === 'failed', 'definitive provider failure marks operation failed', r.text);
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '27.00', 'failed funding refunded the hold');
 await ctl({ behavior: { '/bitvcard/fund-withdraw-nfccard': 'hang' } });
 const tk = idem();
 r = await v1(A, 'POST', `/cards/${card}/fund`, { amount: '6' }, { 'idempotency-key': tk });
 ok(r.status === 502 && r.json.outcome_unknown === true && r.json.status === 'unknown', 'provider timeout leaves operation unknown', r.text);
 ok((await v1(A, 'GET', '/wallet/balance')).json.balance === '21.00', 'funds stay held while outcome unknown');
 r = await v1(A, 'POST', `/cards/${card}/fund`, { amount: '6' }, { 'idempotency-key': tk });
 ok(r.status === 409, 'retry with same key while unknown is refused (no blind double send)');
 await ctl({ behavior: { '/bitvcard/fund-withdraw-nfccard': null } });
 const unk = (await db.query("SELECT id FROM card_operations WHERE business_id=$1 AND status='unknown'", [A.id])).rows[0].id;
 ok((await call('PATCH', `${BASE}/api/admin/card-operations/${unk}`, { body: { status: 'failed' }, cookie: A.cookie })).status === 403, 'business cannot resolve operations');
 r = await call('PATCH', `${BASE}/api/admin/card-operations/${unk}`, { body: { status: 'failed' }, cookie: adminCookie });
 ok(r.status === 200 && (await v1(A, 'GET', '/wallet/balance')).json.balance === '27.00', 'admin resolution releases the hold');

 console.log('card data reveal and logs');
 ok((await v1(A, 'POST', `/cards/${card}/reveal`, {})).status === 403, 'reveal disabled by default');
 await call('PATCH', `${BASE}/api/admin/businesses/${A.id}/card-data-reveal`, { body: { enabled: true }, cookie: adminCookie });
 r = await v1(A, 'POST', `/cards/${card}/reveal`, {});
 ok(r.status === 200 && r.json.cvv === '123' && /no-store/.test(r.headers.get('cache-control') || ''), 'reveal returns data uncached once enabled');
 await hook(WH, { event: 'virtualcard.transaction.declined.terminated', data: { id: 'vc1' + sfx, cardId: (await db.query('SELECT provider_card_id FROM cards WHERE id=$1', [card])).rows[0].provider_card_id, amount: '2', status: 'declined', reference: 'dref1' + sfx, card_number: '4111111111114242', cvv: '123' } });
 await hook(WH, { event: 'virtualcard.transaction.declined.terminated', data: { id: 'vc1' + sfx, cardId: 'x', amount: '2' } });
 const leak = await db.query(`SELECT (SELECT COUNT(*) FROM webhook_events WHERE payload::text ~ '4111111111114242|"123"') + (SELECT COUNT(*) FROM audit_logs WHERE details::text ~ '4111111111114242|"123"') + (SELECT COUNT(*) FROM card_operations WHERE response::text ~ '4111111111114242|"123"') AS n`);
 ok(Number(leak.rows[0].n) === 0, 'no PAN or CVV in webhook, audit or operation tables');
 ok((await db.query("SELECT COUNT(*)::int n FROM webhook_events WHERE provider_event_id = $1", ['virtualcard.transaction.declined.terminated:vc1' + sfx])).rows[0].n === 1, 'webhook events deduplicated');
 ok((await db.query("SELECT COUNT(*)::int n FROM transactions WHERE business_id=$1 AND provider_reference=$2", [A.id, 'dref1' + sfx])).rows[0].n === 1, 'card event recorded as transaction once');
 ok((await db.query("SELECT COUNT(*)::int n FROM audit_logs WHERE business_id=$1 AND action IN ('card.create','card.fund','card.reveal','kyc.submit','wallet.deposit_address')", [A.id])).rows[0].n >= 5, 'audit events written');

 console.log('RBAC and database isolation');
 ok((await call('GET', BASE + '/api/admin/finance', { cookie: A.cookie })).status === 403, 'business cannot call admin finance');
 r = await call('GET', BASE + '/api/admin/finance', { cookie: adminCookie });
 ok(r.status === 200 && r.json.providerBalance === '1468.29' && r.json.businesses.length >= 2, 'admin finance overview', r.text.slice(0, 200));
 for (const p of ['/api/admin/deposits', '/api/admin/card-operations', '/api/admin/webhook-events', '/api/admin/customers']) { const x = await call('GET', BASE + p, { cookie: adminCookie }); ok(x.status === 200, 'admin ' + p); ok(!/zp_cust|zp_card|sub_stub/.test(x.text), 'no provider ids in ' + p); }
 const w = await call('GET', BASE + '/api/wallet/balance', { cookie: A.cookie });
 ok(w.status === 200 && w.json.balance === '27.00', 'dashboard wallet API returns own balance');
 const cs = await call('GET', BASE + '/api/customers', { cookie: B.cookie }); ok(cs.json.customers.every(c => c.id !== cid), 'dashboard customers tenant scoped');
 ok(!/zp_|provider_card_id|provider_customer_id/.test((await call('GET', BASE + '/api/cards', { cookie: A.cookie })).text + (await call('GET', BASE + '/api/kyc', { cookie: A.cookie })).text), 'dashboard cards and KYC expose no provider ids');
 const asTenant = async (biz, sql, params = []) => { await db.query('BEGIN'); try { await db.query('SET LOCAL ROLE zytrelix_tenant'); await db.query("SELECT set_config('app.business_id',$1,true)", [biz]); const x = await db.query(sql, params); await db.query('ROLLBACK'); return x; } catch (e) { await db.query('ROLLBACK'); return { error: e.message }; } };
 for (const t of ['end_users', 'card_operations', 'ledger_entries', 'deposits', 'deposit_addresses', 'provider_accounts', 'wallets', 'cards']) {
  const own = await asTenant(B.id, `SELECT COUNT(*)::int n FROM ${t} WHERE business_id=$1`, [A.id]);
  ok(own.rows?.[0].n === 0, `RLS hides ${t} of another business`, JSON.stringify(own));
 }
 ok((await asTenant(B.id, 'SELECT 1 FROM webhook_events')).error?.includes('permission denied'), 'tenant role cannot read webhook_events');
 ok((await asTenant(B.id, "INSERT INTO ledger_entries(business_id,entry_type,amount,ref_type,ref_id) VALUES ($1,'deposit',100,'x','y')", [A.id])).error?.includes('row-level security'), 'tenant cannot write ledger rows for another business');
 ok((await asTenant(A.id, 'UPDATE ledger_entries SET amount=amount+1')).error?.includes('permission denied'), 'ledger is append-only for tenants');
 ok((await asTenant(A.id, 'DELETE FROM ledger_entries')).error?.includes('permission denied'), 'tenant cannot delete ledger rows');
 process.env.ZIIROPAY_MODE = 'production'; delete process.env.PROVIDER_PRODUCTION_ENABLED;
 let blocked = false; try { require('../lib/finance').assertFinancialEnabled(); } catch (e) { blocked = e.status === 403; }
 ok(blocked, 'production mode refuses financial operations until explicitly enabled');
 await db.end();
 console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
