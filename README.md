# Zytrelix API Hub

A starter project for a multi-business API hub that proxies approved card/KYC operations to ZiiroPay. The included dashboard is a front-end prototype with sample records. It is not a production multi-tenant platform yet.

## What's included

- HTML, CSS and browser JavaScript dashboard.
- Express.js server that keeps the ZiiroPay provider key off the browser.
- Provider adapter routes for card KYC, KYC status, card creation, card details, card history, funding/withdrawal, freeze/activate and subaccount creation.
- Sandbox-first configuration.

## Run locally

1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env`.
3. Add the ZiiroPay public key supplied for your account. Keep it private.
4. Keep `ZIIROPAY_MODE=sandbox` while testing.
5. Set a long random `HUB_ADMIN_TOKEN`.
6. Run:

```bash
npm install
npm start
```

Open `http://localhost:3000`.

## Important current limitations

- The dashboard uses sample/demo data. API-key generation in the browser is a visual demo only. It does not persist keys or authenticate real partner businesses.
- The provider proxy routes are protected by the optional `HUB_ADMIN_TOKEN`, but they are not yet connected to a real multi-tenant identity/database layer. Do not expose these routes to client businesses as-is.
- Do not collect real KYC documents until encrypted storage, access controls, retention/deletion rules, audit logs and the required privacy/compliance arrangements are implemented.
- ZiiroPay's public card reference documents legacy endpoints that pass `public_key` and fields as query parameters. Its current marketing/API page also shows Bearer secret-key authentication and a different `/api/cards` example. Confirm which API version and request format are enabled for your account before production use.
- ZiiroPay documentation marks `mode=sandbox` for testing and says to omit it for live mode. This project defaults to sandbox.
- The KYC endpoint requires `id_front_image` as Base64. The public reference lists a set of required fields, including `country` (Haiti code: `HTI`).
- Card creation requires the provider's `customer_id` after KYC approval.
- Confirm subaccount behaviour and reseller/third-party KYC permissions with ZiiroPay in writing. The existence of a Create Subaccount endpoint does not prove each subaccount can issue cards or submit KYC.
- Webhook signature header/algorithm is not implemented. Do not trust or process production webhooks until ZiiroPay supplies signing instructions.

## Environment variables

- `PORT`: HTTP port, default 3000.
- `ZIIROPAY_PUBLIC_KEY`: provider key for the documented legacy card endpoints.
- `ZIIROPAY_MODE`: `sandbox` or empty for production only after provider approval.
- `HUB_ADMIN_TOKEN`: optional shared secret for internal proxy routes.

## Provider references reviewed

- Submit Card KYC: https://ziiropay.readme.io/reference/submit-card-kyc
- Get KYC Status: https://ziiropay.readme.io/reference/get-kyc-status
- Create Dollar Card: https://ziiropay.readme.io/reference/create-dollar-card
- Get Card Details: https://ziiropay.readme.io/reference/get-card-details
- Get Card History: https://ziiropay.readme.io/reference/get-card-history
- Fund / Withdraw Card: https://ziiropay.readme.io/reference/fund-withdraw-card
- Freeze / Activate Card: https://ziiropay.readme.io/reference/freezeactivate-card
- Create Subaccount: https://ziiropay.readme.io/reference/create-subaccount
- Webhooks: https://ziiropay.readme.io/reference/webhook

## Before production

1. Get written permission from ZiiroPay for third-party/reseller use and multi-tenant processing.
2. Confirm the exact API version, credentials, endpoint payload format, KYC flow, subaccount model, pricing and webhook signature verification.
3. Add PostgreSQL persistence, business accounts, secure login, tenant isolation, scoped API keys (hash at rest), usage metering, billing, audit logging and admin roles.
4. Add encrypted document storage and a compliant KYC data retention/deletion policy.
5. Add idempotency, request signing, retries, provider error mapping, alerting and rate limits per client.
6. Complete provider business verification and production approval.
