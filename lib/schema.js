// Finance / white-label schema. Appended to the base schema; grants are appended to the security script.
const financeTenantRows = ['end_users', 'card_operations', 'wallets', 'ledger_entries', 'deposits', 'deposit_addresses', 'provider_accounts'];

const financeSchema = `
ALTER TABLE businesses ADD COLUMN IF NOT EXISTS card_data_reveal BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS end_users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), public_id TEXT NOT NULL UNIQUE,
 business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 external_ref TEXT, email TEXT NOT NULL, first_name TEXT NOT NULL, last_name TEXT NOT NULL,
 kyc_status TEXT NOT NULL DEFAULT 'not_submitted' CHECK (kyc_status IN ('not_submitted','pending','approved','rejected')),
 provider_customer_id TEXT UNIQUE, kyc_submitted_at TIMESTAMPTZ, kyc_updated_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE (business_id, email), UNIQUE (business_id, external_ref)
);
ALTER TABLE kyc_submissions ADD COLUMN IF NOT EXISTS end_user_id UUID REFERENCES end_users(id) ON DELETE SET NULL;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS end_user_id UUID REFERENCES end_users(id) ON DELETE SET NULL;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS brand TEXT;
ALTER TABLE cards ADD COLUMN IF NOT EXISTS provider_balance NUMERIC(18,2);
ALTER TABLE cards ADD COLUMN IF NOT EXISTS synced_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS cards_provider_card_uidx ON cards(provider_card_id);
CREATE UNIQUE INDEX IF NOT EXISTS transactions_provider_ref_uidx ON transactions(business_id, type, provider_reference) WHERE provider_reference IS NOT NULL;
CREATE TABLE IF NOT EXISTS wallets (
 business_id UUID PRIMARY KEY REFERENCES businesses(id) ON DELETE CASCADE, currency TEXT NOT NULL DEFAULT 'USD', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO wallets (business_id) SELECT id FROM businesses ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS ledger_entries (
 id BIGSERIAL PRIMARY KEY, business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 entry_type TEXT NOT NULL CHECK (entry_type IN ('deposit','card_fund','card_withdraw','refund')),
 amount NUMERIC(18,2) NOT NULL, currency TEXT NOT NULL DEFAULT 'USD',
 ref_type TEXT NOT NULL, ref_id TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE (entry_type, ref_type, ref_id)
);
CREATE INDEX IF NOT EXISTS ledger_business_idx ON ledger_entries(business_id, created_at DESC);
CREATE TABLE IF NOT EXISTS card_operations (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 op_type TEXT NOT NULL CHECK (op_type IN ('create','fund','withdraw')),
 idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','succeeded','failed','unknown')),
 card_id UUID REFERENCES cards(id) ON DELETE SET NULL, end_user_id UUID REFERENCES end_users(id) ON DELETE SET NULL,
 amount NUMERIC(18,2) NOT NULL, provider_reference TEXT, error TEXT, response JSONB,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE (business_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS provider_accounts (
 business_id UUID PRIMARY KEY REFERENCES businesses(id) ON DELETE CASCADE, provider_sub_id TEXT NOT NULL UNIQUE,
 phone TEXT, country TEXT, state TEXT, city TEXT, address TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS deposit_addresses (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 token TEXT NOT NULL, chain TEXT NOT NULL, address TEXT NOT NULL UNIQUE, memo TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE (business_id, token, chain)
);
CREATE TABLE IF NOT EXISTS deposits (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), business_id UUID NOT NULL REFERENCES businesses(id) ON DELETE CASCADE,
 provider_trx TEXT NOT NULL UNIQUE, token TEXT NOT NULL DEFAULT 'USDT', gross_amount NUMERIC(18,6) NOT NULL, fee NUMERIC(18,6) NOT NULL DEFAULT 0,
 credited_amount NUMERIC(18,2) NOT NULL, details TEXT, provider_created_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS webhook_events (
 id BIGSERIAL PRIMARY KEY, provider_event_id TEXT NOT NULL UNIQUE, event TEXT, business_id UUID REFERENCES businesses(id) ON DELETE SET NULL,
 payload JSONB NOT NULL DEFAULT '{}'::jsonb, outcome TEXT, error TEXT, received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`;

const financeSecurityGrants = `
${financeTenantRows.map(t => `ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ${t};
CREATE POLICY tenant_isolation ON ${t} FOR ALL TO zytrelix_tenant USING (${"business_id = NULLIF(current_setting('app.business_id', true), '')::uuid"}) WITH CHECK (${"business_id = NULLIF(current_setting('app.business_id', true), '')::uuid"});
DROP POLICY IF EXISTS admin_all ON ${t};
CREATE POLICY admin_all ON ${t} FOR ALL TO zytrelix_admin USING (true) WITH CHECK (true);`).join('\n')}
ALTER TABLE webhook_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS admin_all ON webhook_events;
CREATE POLICY admin_all ON webhook_events FOR SELECT TO zytrelix_admin USING (true);
GRANT SELECT, INSERT, UPDATE (kyc_status, provider_customer_id, kyc_submitted_at, kyc_updated_at) ON end_users TO zytrelix_tenant;
GRANT UPDATE (status, last_four, brand, provider_balance, synced_at) ON cards TO zytrelix_tenant;
GRANT SELECT, INSERT, UPDATE (status, card_id, provider_reference, error, response, updated_at) ON card_operations TO zytrelix_tenant;
GRANT SELECT, INSERT ON ledger_entries, deposits, deposit_addresses, provider_accounts TO zytrelix_tenant;
GRANT SELECT, INSERT, UPDATE (currency) ON wallets TO zytrelix_tenant;
GRANT SELECT ON end_users, card_operations, ledger_entries, deposits, deposit_addresses, wallets, webhook_events TO zytrelix_admin;
GRANT UPDATE (kyc_status, kyc_updated_at) ON end_users TO zytrelix_admin;
GRANT UPDATE (card_data_reveal) ON businesses TO zytrelix_admin;
GRANT SELECT (business_id, created_at) ON provider_accounts TO zytrelix_admin;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO zytrelix_tenant, zytrelix_admin;
`;
module.exports = { financeSchema, financeTenantRows, financeSecurityGrants };
