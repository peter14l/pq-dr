# PQ-Aura — Payment & Monetization Setup Guide

This document covers every step needed to take the payment infrastructure from zero to fully live: Razorpay credentials, Resend email, webhook registration, server deployment, and end-to-end testing.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [Step 1 — Razorpay Account & Live Keys](#4-step-1--razorpay-account--live-keys)
5. [Step 2 — Resend Email Account & Domain Verification](#5-step-2--resend-email-account--domain-verification)
6. [Step 3 — Configure Environment Variables](#6-step-3--configure-environment-variables)
7. [Step 4 — Register the Webhook in Razorpay](#7-step-4--register-the-webhook-in-razorpay)
8. [Step 5 — Deploy the Server](#8-step-5--deploy-the-server)
9. [Step 6 — End-to-End Test](#9-step-6--end-to-end-test)
10. [How the Payment Flow Works (Internals)](#10-how-the-payment-flow-works-internals)
11. [The License Email](#11-the-license-email)
12. [Pricing Tiers](#12-pricing-tiers)
13. [Security Model](#13-security-model)
14. [Troubleshooting](#14-troubleshooting)
15. [Next Steps & Roadmap](#15-next-steps--roadmap)

---

## 1. Overview

PQ-Aura uses a **dual-licensing model**:

| Tier | Price | Who |
|------|-------|-----|
| **Open Source** | Free | Projects that are GPL-3.0 compliant (source must stay open) |
| **Commercial SDK** | ₹16,500 / month ($199) | Proprietary / closed-source applications |
| **Enterprise** | Custom | Large teams, self-hosted, multi-seat, SLA |

When a customer pays for the Commercial SDK:

1. Razorpay processes the payment
2. Razorpay sends a signed `payment.captured` webhook to the server
3. The server verifies the HMAC-SHA256 signature using your `RAZORPAY_KEY_SECRET`
4. A unique `PQAURA-XXXX-...` license key is generated
5. A branded HTML invoice + license email is sent instantly via Resend
6. The order and license are stored in-memory (with idempotency protection)

---

## 2. Architecture

```
Customer browser
      │
      │  clicks "Buy with Razorpay"
      ▼
website/app.js  ──── GET /config ────▶  Axum server (main.rs)
      │                                       │
      │  opens Razorpay checkout modal         │  returns RAZORPAY_KEY_ID
      │                                       │
      │  customer completes payment            │
      ▼                                       │
Razorpay servers                              │
      │                                       │
      │  POST /webhook/razorpay               │
      │  (HMAC-SHA256 signed)                 │
      └───────────────────────────────────────▶
                                              │
                              verify signature (RAZORPAY_KEY_SECRET)
                                              │
                              generate PQAURA-XXXX license key
                                              │
                              store Order + License (in-memory)
                                              │
                              POST https://api.resend.com/emails
                                              │
                                              ▼
                                    Customer inbox ✅
                                    (license key + invoice)
```

---

## 3. Prerequisites

- **Razorpay account** — [razorpay.com](https://razorpay.com) (Indian business or individual with PAN/GST)
- **Resend account** — [resend.com](https://resend.com) (free tier: 3,000 emails/month)
- **A verified sending domain** — `pqaura.dev` must be verified in Resend via DNS TXT record
- **Hugging Face account** — server is deployed at `peter14l-pq-aura-server.hf.space`
- **Rust toolchain** — for local `cargo check` (or use GitHub Actions CI)

---

## 4. Step 1 — Razorpay Account & Live Keys

### 4.1 Get your Live API Keys

1. Log in to [Razorpay Dashboard](https://dashboard.razorpay.com)
2. Navigate to **Settings → API Keys**
3. Switch the toggle from **Test Mode** to **Live Mode**
4. Click **Generate Key** (or **Regenerate Key** if you already have one)
5. Copy both values:
   - **Key ID** — starts with `rzp_live_`
   - **Key Secret** — shown only once; save it immediately

> [!CAUTION]
> Never commit live API keys to git. They must only be stored in `.env` (which is in `.gitignore`) and in the Hugging Face Space secrets.

### 4.2 Current Keys (already configured)

The following keys are already set in [`.env`](.env) and the server code:

```ini
RAZORPAY_KEY_ID=rzp_live_T4lf7Dnej3RrDS
RAZORPAY_KEY_SECRET=TWvboB7lrlIH5NlUqfbhLVcZ
```

---

## 5. Step 2 — Resend Email Account & Domain Verification

Resend is used to send the license key + invoice email to customers automatically after payment.

### 5.1 Create a Resend Account

1. Go to [resend.com](https://resend.com) and sign up (free)
2. Navigate to **Domains → Add Domain**
3. Enter `pqaura.dev`
4. Resend will give you DNS records to add:

| Type | Name | Value |
|------|------|-------|
| `TXT` | `resend._domainkey.pqaura.dev` | `p=MII...` (DKIM key) |
| `TXT` | `pqaura.dev` | `v=spf1 include:_spf.resend.com ~all` |
| `MX` | `bounce.pqaura.dev` | `feedback-smtp.resend.com` |

5. Add these records at your DNS provider (e.g., Cloudflare, Namecheap)
6. Click **Verify** in Resend dashboard — turns green within 10–30 minutes

### 5.2 Create an API Key

1. In Resend dashboard, go to **API Keys → Create API Key**
2. Name it `pq-aura-production`
3. Set permission: **Sending access**
4. Copy the key — it starts with `re_`

---

## 6. Step 3 — Configure Environment Variables

### 6.1 Local `.env` file

Edit [`.env`](.env) at the project root:

```ini
# ─────────────────────────────────────────────
# PQ-Aura Payment & Email Credentials
# ─────────────────────────────────────────────

# Razorpay Live Keys
RAZORPAY_KEY_ID=rzp_live_T4lf7Dnej3RrDS
RAZORPAY_KEY_SECRET=TWvboB7lrlIH5NlUqfbhLVcZ

# Resend API Key (get from https://resend.com)
RESEND_API_KEY=re_YOUR_ACTUAL_KEY_HERE

# Sending email address (must be verified in Resend)
FROM_EMAIL=support@pqaura.dev

# Server port
PORT=8080
```

> [!IMPORTANT]
> The `.env` file is listed in `.gitignore` and will never be committed to the repository. It is only used for local development.

### 6.2 Hugging Face Space Secrets (Production)

For the deployed server at `peter14l-pq-aura-server.hf.space`:

1. Go to [huggingface.co/spaces/peter14l/pq-aura-server](https://huggingface.co/spaces/peter14l/pq-aura-server)
2. Click **Settings → Variables and secrets**
3. Add the following as **Secrets** (not Variables):

| Secret Name | Value |
|-------------|-------|
| `RAZORPAY_KEY_ID` | `rzp_live_T4lf7Dnej3RrDS` |
| `RAZORPAY_KEY_SECRET` | `TWvboB7lrlIH5NlUqfbhLVcZ` |
| `RESEND_API_KEY` | `re_your_actual_key` |
| `FROM_EMAIL` | `support@pqaura.dev` |

4. Click **Save** — the Space will restart automatically

---

## 7. Step 4 — Register the Webhook in Razorpay

This is the most critical step. Without a registered webhook, Razorpay will never notify your server of payments.

1. Go to **Razorpay Dashboard → Settings → Webhooks**
2. Click **Add New Webhook**
3. Fill in:

| Field | Value |
|-------|-------|
| **Webhook URL** | `https://peter14l-pq-aura-server.hf.space/webhook/razorpay` |
| **Secret** | `TWvboB7lrlIH5NlUqfbhLVcZ` |
| **Alert Email** | `support@pqaura.dev` |
| **Active Events** | ✅ `payment.captured` |

4. Click **Save**

> [!NOTE]
> Razorpay will show a green checkmark next to the webhook URL after the first successful delivery. Until then, it shows as "Pending."

---

## 8. Step 5 — Deploy the Server

The server is a Docker container deployed to Hugging Face Spaces using the [`Dockerfile`](Dockerfile) at the project root.

### 8.1 Automatic Deployment (Recommended)

Every `git push` to the `main` branch automatically triggers a rebuild on Hugging Face Spaces:

```bash
git add server/src/main.rs server/Cargo.toml .env
git commit -m "feat: add Razorpay webhook + license email delivery"
git push origin main
```

> The Space rebuild takes ~3–5 minutes. Monitor progress at the Space's **Logs** tab.

### 8.2 Local Development

```bash
# From the project root
cd server
cargo run
```

Server starts at `http://0.0.0.0:8080`. The `.env` file is auto-loaded by `dotenvy`.

### 8.3 Available Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/config` | Returns `{"razorpay_key_id": "rzp_live_..."}` to the frontend |
| `POST` | `/webhook/razorpay` | Razorpay webhook receiver (HMAC-verified) |
| `POST` | `/prekey/upload` | Upload a user's Pre-Key Bundle |
| `GET` | `/prekey/fetch/:username` | Fetch a user's Pre-Key Bundle |
| `POST` | `/message/send` | Enqueue an encrypted message |
| `GET` | `/message/fetch/:username` | Fetch and flush pending messages |

---

## 9. Step 6 — End-to-End Test

### 9.1 Test with Razorpay Test Mode

Before going fully live, verify the entire flow using Razorpay test cards:

1. Temporarily swap your `.env` back to test keys:
   ```ini
   RAZORPAY_KEY_ID=rzp_test_...
   RAZORPAY_KEY_SECRET=...
   ```
2. Use Razorpay's [test card numbers](https://razorpay.com/docs/payments/payments/test-card-upi-details/):
   - Card: `4111 1111 1111 1111`
   - Expiry: Any future date
   - CVV: Any 3 digits
3. Complete a payment on the website
4. Check server logs for:
   ```
   [webhook] ✅ Captured — order=... payment=pay_... email=...
   [email] ✅ License + invoice sent to customer@email.com
   ```
5. Check that the license email arrived in the customer's inbox

### 9.2 Manually Trigger a Webhook (for debugging)

Use Razorpay's **Webhook Test** feature:
1. Dashboard → Settings → Webhooks → (your webhook) → **Send Test Event**
2. Select event: `payment.captured`
3. Check your server logs

### 9.3 Verify Signature Locally with curl

```bash
# Compute expected signature
BODY='{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_test","amount":1650000,"currency":"INR","email":"test@example.com","notes":{"product":"Commercial SDK License","customer_name":"Test User"}}}}}'
SECRET="TWvboB7lrlIH5NlUqfbhLVcZ"
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')

# Send to local server
curl -X POST http://localhost:8080/webhook/razorpay \
  -H "Content-Type: application/json" \
  -H "x-razorpay-signature: $SIG" \
  -d "$BODY"
```

Expected response: `200 OK`

---

## 10. How the Payment Flow Works (Internals)

### `website/app.js` — Frontend

- On page load, fetches `GET /config` to get the Razorpay public key
- When "Buy with Razorpay" is clicked, opens the Razorpay checkout modal for ₹16,500
- Customer's name and product type are passed in Razorpay `notes` so the webhook can include them in the email
- After Razorpay confirms the payment client-side, shows a success modal telling the customer to check their inbox

### `server/src/main.rs` — Backend

The `razorpay_webhook` handler does the following in order:

```
1. Read RAZORPAY_KEY_SECRET from environment
2. Compute HMAC-SHA256(request_body, secret)
3. Compare with x-razorpay-signature header → reject (401) if mismatch
4. Parse JSON body → extract payment entity fields
5. Check event == "payment.captured" → ignore anything else (200 OK)
6. Extract: payment_id, amount, currency, email, customer_name, plan
7. Check idempotency: if payment_id already in orders → skip (200 OK)
8. Generate: order_id (UUID v4), license_key ("PQAURA-" + UUID v4)
9. Store Order + License in in-memory Db (with 30-day valid_until)
10. Spawn background task → send_license_email() via Resend API
11. Return 200 OK to Razorpay immediately (webhook must respond fast)
```

### Idempotency

Razorpay may deliver a webhook multiple times (retries on timeout). The server checks if the `payment_id` already exists in `db.orders` before processing — duplicate deliveries are silently acknowledged with `200 OK` without creating a second license.

---

## 11. The License Email

The customer receives a single branded HTML email containing:

- ✅ **Payment confirmation banner**
- 🔑 **License key box** — `PQAURA-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
- 📋 **Invoice table** — Order ID, Razorpay Payment ID, product, dates, amount paid
- 📖 **Usage instructions** — how to set `PQ_AURA_LICENSE_KEY` env var
- ⚖️ **Refund policy notice** — 7-day refund, email support@pqaura.dev with Order ID

**Subject line:** `Your PQ-Aura Commercial License — Order {order_id}`

**From:** `PQ-Aura <support@pqaura.dev>`

---

## 12. Pricing Tiers

As configured in [`website/index.html`](website/index.html):

| Tier | Monthly Price | Button Action | Contact |
|------|--------------|---------------|---------|
| **Open Source** | Free | Link to GitHub | — |
| **Commercial SDK** | ₹16,500 / $199 | Razorpay checkout | Auto-email on payment |
| **Enterprise** | Custom | Email CTA | support@pqaura.dev |

To change the price, update **both**:
1. `website/app.js` — the `"amount"` field (in paise, so ₹16,500 = `"1650000"`)
2. `website/index.html` — the displayed price text in the pricing card

---

## 13. Security Model

| Threat | Mitigation |
|--------|-----------|
| **Spoofed webhook** (fake payment_id) | HMAC-SHA256 verification rejects any request without a valid signature → `401 Unauthorized` |
| **Credential exposure** | Keys are in `.env` (gitignored locally) and Hugging Face Space Secrets (encrypted at rest) |
| **Replay attacks** (same webhook delivered twice) | Idempotency guard checks `payment_id` uniqueness before any processing |
| **Key leakage** | `RAZORPAY_KEY_SECRET` is never exposed to the frontend; only `RAZORPAY_KEY_ID` is served via `/config` |
| **Email interception** | License key is sent over TLS via Resend's SMTP infrastructure |

> [!WARNING]
> The current storage is **in-memory only**. All order and license records are lost if the server restarts. For production, replace the `Vec<Order>` / `Vec<License>` fields in `Db` with a SQLite database using `sqlx` or `rusqlite`.

---

## 14. Troubleshooting

### Webhook returns 401 Unauthorized
- The `x-razorpay-signature` header doesn't match → wrong `RAZORPAY_KEY_SECRET` in `.env` or Hugging Face Secrets
- Make sure the **Secret** field in Razorpay's webhook settings exactly matches `RAZORPAY_KEY_SECRET`

### Webhook returns 500 Internal Server Error
- `RAZORPAY_KEY_SECRET` is not set in the environment
- Check Hugging Face Space Secrets → ensure `RAZORPAY_KEY_SECRET` is defined

### Email not received
- `RESEND_API_KEY` is not set or is wrong → check server logs for `[email] ❌`
- Domain `pqaura.dev` not verified in Resend → Resend will reject the send
- Check spam/junk folder

### "Payment Successful" modal shows but no email arrives
- The Razorpay client-side `handler` callback fires on client-side confirmation, **not** webhook delivery
- The webhook may have failed — check server logs at the Hugging Face Space Logs tab
- Razorpay retries webhooks up to 3 times; check Dashboard → Settings → Webhooks → (webhook) → **Deliveries**

### `/config` returns test key ID despite live keys being set
- Server is still running with old environment — restart the Hugging Face Space or restart local server
- Ensure the Space Secret name is exactly `RAZORPAY_KEY_ID` (case-sensitive)

---

## 15. Next Steps & Roadmap

| Priority | Task | Effort |
|----------|------|--------|
| 🔴 High | Add SQLite persistence (`sqlx`) so orders survive restarts | ~1 day |
| 🔴 High | Integrate Razorpay Subscriptions API for auto-renewal billing | ~2 days |
| 🟠 Medium | Build a simple `/admin` dashboard to view/revoke licenses | ~1 day |
| 🟠 Medium | Add Stripe for USD-denominated international payments | ~1 day |
| 🟡 Low | Add analytics (Plausible/Fathom) to track pricing page conversions | ~2 hrs |
| 🟡 Low | Add invoice PDF generation (attach PDF to the email) | ~1 day |

---

*Last updated: 2026-06-23 | Maintainer: Shreyas Sengupta (support@pqaura.dev)*
