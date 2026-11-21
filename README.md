# ZYTRELIX API Infrastructure

A multi-tenant Node.js + Express + PostgreSQL API Hub for businesses integrating with ZiiroPay card/KYC services. The frontend is plain HTML, CSS and JavaScript under `public/`.

## Features implemented

- Business registration and login with bcrypt password hashing and 12-hour JWT sessions.
- Admin account bootstrap from environment variables.
- Business approval/suspension workflow in the admin dashboard.
- Tenant-scoped API key creation and revocation. Raw keys are shown once and only SHA-256 hashes are stored.
- Partner API authentication with `X-API-Key`, tenant isolation and usage metering.
- KYC submission proxy and KYC status lookup through ZiiroPay's documented legacy card endpoints.
- Card creation restricted to a customer with an approved KYC record for that business.
- Card listing, details, transaction history, funding/withdrawal and freeze/activate routes.
- Admin business management and audit log.
- No KYC document images are stored in Zytrelix. The Base64 ID image is forwarded directly to ZiiroPay.
- Sandbox-first provider configuration.

## Project structure

```text
zytrelix-api-hub/
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── server.js
├── package.json
├── .env.example
├── .gitignore
└── README.md
```

## Deploy on Railway

1. Push this folder to a GitHub repository.
2. In Railway, create a project from that GitHub repository.
3. Add a Railway PostgreSQL service to the same project.
4. Add the variables below to the Node.js service. Set `DATABASE_URL` to Railway's PostgreSQL connection variable, usually `${{Postgres.DATABASE_URL}}` (select the actual database service name in Railway's variable picker).
5. Deploy. The app creates its tables automatically on first start.
6. Open the generated domain and sign in using `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
7. Review the deployment logs and `/api/health` endpoint.

## Required Railway variables

```env
NODE_ENV=production
DATABASE_URL=${{Postgres.DATABASE_URL}}
DATABASE_SSL=true
JWT_SECRET=<at-least-32-random-characters>
ADMIN_NAME=Platform Admin
ADMIN_EMAIL=<your-admin-email>
ADMIN_PASSWORD=<long-unique-password>
ZIIROPAY_PUBLIC_KEY=<server-side-provider-key>
ZIIROPAY_MODE=sandbox
ZIIROPAY_BASE_URL=https://www.ziiropay.com/api
```

Do not commit `.env`. Do not put ZiiroPay credentials in `public/`, browser JavaScript, GitHub source, or screenshots. Use Railway Variables.

## Local development

Requires Node.js 20+ and a PostgreSQL database.

```bash
cp .env.example .env
npm install
npm start
```

Open `http://localhost:3000`.

## Partner API

Every approved business can create a Sandbox API key from the dashboard. Send it using:

```http
X-API-Key: zy_test_...
Content-Type: application/json
```

Base URL: `https://YOUR-DOMAIN/v1`

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/v1/status` | Check key and workspace |
| POST | `/v1/kyc` | Submit end-user KYC |
| GET | `/v1/kyc/status?email=...` | Retrieve KYC status for an email owned by that business |
| POST | `/v1/cards` | Create a card for an approved KYC customer |
| GET | `/v1/cards` | List this business's cards |
| GET | `/v1/cards/:cardId` | Get card details |
| GET | `/v1/cards/:cardId/transactions` | Get card transaction history |
| POST | `/v1/cards/:cardId/funding` | Fund or withdraw |
| POST | `/v1/cards/:cardId/status` | Freeze or activate |

### KYC required fields

`first_name`, `last_name`, `id_number`, `email`, `phone_number`, `date_of_birth`, `dial_code`, `id_front_image` (Base64), `line1`, `state`, `postal_code`, `city`, `country`, `id_type`, `occupation`, `employment_status`, `account_purpose`, `annual_salary`, `expected_monthly_volume`, `place_of_birth`.

ZiiroPay's public reference specifies the three-letter country code and uses `HTI` for Haiti. Its public card endpoints document `public_key` and query parameters, including `mode=sandbox` for test requests. This project implements that legacy reference format. ZiiroPay also presents newer API authentication examples elsewhere. Confirm the exact API version and credentials enabled for your merchant account before live use.

## Important provider/compliance dependencies

This application is deployable, but actual ZiiroPay processing requires valid merchant credentials and account permissions. Before accepting real customer data or issuing cards, obtain written confirmation from ZiiroPay covering:

- Permission to resell or provide API access to multiple third-party businesses.
- Whether one master account can submit KYC and issue cards for multiple businesses, or whether each business requires a provider subaccount.
- KYC/customer ownership, country eligibility, production limits and fees.
- The exact API version, authentication method, request fields and response formats for your account.
- Webhook signing/verification method and supported custom headers.

The current webhook receiver is disabled unless `PROVIDER_WEBHOOK_SECRET` is set. It only supports a shared `X-Zytrelix-Webhook-Secret` header if ZiiroPay can be configured to send it. The public webhook reference does not specify a signature algorithm, so do not assume this is ZiiroPay's native signing mechanism.

## Security notes and remaining production hardening

- KYC image content is not stored by this app. It is passed to the provider in the request. Ensure TLS is enabled and obtain the required privacy/legal approvals before collecting identity documents.
- Add encrypted object storage only if there is a documented business need and a retention/deletion policy.
- Add MFA, password reset/email verification, stronger admin role separation and account recovery before broad customer onboarding.
- Add billing, plan limits and partner webhook delivery/retry handling before charging customers for usage.
- Provider card-detail responses may contain PAN/CVV. The app redacts these values from API responses returned through the dashboard logs, but cardholder data display/storage and PCI DSS scope require a separate compliant design. Do not log or persist full card numbers or CVV.
- Funding and withdrawal routes call the provider directly. Add business-level balance/limits, idempotency and explicit transaction confirmation before allowing external partners to use them in production.
- API key creation is limited to the configured provider environment. Sandbox keys cannot call production and vice versa.
- This code is a deployable foundation, not a certification of regulatory compliance, PCI compliance or provider approval.

## Official provider references reviewed

- https://ziiropay.readme.io/reference/submit-card-kyc
- https://ziiropay.readme.io/reference/get-kyc-status
- https://ziiropay.readme.io/reference/create-dollar-card
- https://ziiropay.readme.io/reference/get-card-details
- https://ziiropay.readme.io/reference/get-card-history
- https://ziiropay.readme.io/reference/fund-withdraw-card
- https://ziiropay.readme.io/reference/freezeactivate-card
- https://ziiropay.readme.io/reference/create-subaccount
- https://ziiropay.readme.io/reference/webhook


## Access control (admin vs business)

- Pages: `/login` (public), `/dashboard` (business role only), `/admin` (admin role only). Dashboard code for each role is served only to that role; anonymous users are redirected to `/login`, wrong-role users get 403 or are sent to their own dashboard.
- Sessions are httpOnly, SameSite=Strict cookies. Role, business and business status are re-read from the database on every request, so a suspended business loses access immediately. State-changing cookie requests require the `X-Zytrelix-Client` header and a same-origin `Origin`.
- `/api/admin/*` requires the admin role. `/api/keys`, `/api/kyc`, `/api/cards`, `/api/transactions`, `/api/activity`, `/api/dashboard` and `/api/subscription` require a business user and only touch that business.
- Database isolation: tenant requests run as the non-superuser role `zytrelix_tenant` with PostgreSQL row-level security on `business_id = app.business_id`; admin requests run as `zytrelix_admin`. Neither role can read `users.password_hash` or `api_keys.key_hash`. Roles, grants and policies are created at startup.
- Admin features: approve/suspend businesses, approve/reject KYC (admin decisions are not overwritten by provider sync), revoke any API key, view all transactions, change plan or pause/cancel subscriptions (paused or cancelled subscriptions block the partner API), audit log.
- Create the first admin with `ADMIN_EMAIL` and `ADMIN_PASSWORD` (12+ characters).
- Verify: `BASE=... ADMIN_EMAIL=... ADMIN_PASSWORD=... DATABASE_URL=... node scripts/security-check.js`.
