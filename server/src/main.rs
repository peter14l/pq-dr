use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use hmac::{Hmac, Mac};
use pq_aura::handshake::PreKeyBundle;
use pq_aura::ratchet::Message;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

// ─────────────────────────────────────────────
// In-memory database (messaging + orders + licenses)
// ─────────────────────────────────────────────
struct Db {
    bundles: HashMap<String, PreKeyBundle>,
    mailbox: HashMap<String, VecDeque<Message>>,
    orders: Vec<Order>,
    licenses: Vec<License>,
}

#[derive(Debug, Clone, Serialize)]
struct Order {
    order_id: String,
    payment_id: String,
    customer_email: String,
    customer_name: String,
    plan: String,
    amount_paise: u64,
    currency: String,
    created_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct License {
    license_key: String,
    order_id: String,
    customer_email: String,
    plan: String,
    issued_at: String,
    valid_until: String,
}

type SharedState = Arc<Mutex<Db>>;

// ─────────────────────────────────────────────
// Request / Response types
// ─────────────────────────────────────────────
#[derive(Deserialize)]
struct UploadBundleRequest {
    username: String,
    bundle: PreKeyBundle,
}

#[derive(Deserialize)]
struct SendMessageRequest {
    recipient: String,
    message: Message,
}

#[derive(Serialize)]
struct FetchMessagesResponse {
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct ConfigResponse {
    razorpay_key_id: String,
}

// Razorpay webhook body shape for payment.captured
#[derive(Debug, Deserialize)]
struct RazorpayWebhookPayload {
    event: String,
    payload: RazorpayPayloadWrapper,
}

#[derive(Debug, Deserialize)]
struct RazorpayPayloadWrapper {
    payment: RazorpayPaymentItem,
}

#[derive(Debug, Deserialize)]
struct RazorpayPaymentItem {
    entity: RazorpayPaymentEntity,
}

#[derive(Debug, Deserialize)]
struct RazorpayPaymentEntity {
    id: String,
    amount: u64,
    currency: String,
    email: Option<String>,
    #[allow(dead_code)]
    contact: Option<String>,
    #[allow(dead_code)]
    description: Option<String>,
    notes: Option<RazorpayNotes>,
}

#[derive(Debug, Deserialize)]
struct RazorpayNotes {
    product: Option<String>,
    customer_name: Option<String>,
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let state: SharedState = Arc::new(Mutex::new(Db {
        bundles: HashMap::new(),
        mailbox: HashMap::new(),
        orders: Vec::new(),
        licenses: Vec::new(),
    }));

    let cors = CorsLayer::permissive();

    let app = Router::new()
        // Messaging protocol routes
        .route("/prekey/upload", post(upload_prekey))
        .route("/prekey/fetch/:username", get(fetch_prekey))
        .route("/message/send", post(send_message))
        .route("/message/fetch/:username", get(fetch_messages))
        // Config + payment routes
        .route("/config", get(get_config))
        .route("/webhook/razorpay", post(razorpay_webhook))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("PQ-Aura Cloud Key Server listening on {}...", addr);
    axum::serve(listener, app).await.unwrap();
}

// ─────────────────────────────────────────────
// Messaging handlers
// ─────────────────────────────────────────────
async fn upload_prekey(
    State(state): State<SharedState>,
    Json(payload): Json<UploadBundleRequest>,
) -> StatusCode {
    let mut db = state.lock().unwrap();
    db.bundles.insert(payload.username, payload.bundle);
    StatusCode::OK
}

async fn fetch_prekey(
    Path(username): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<PreKeyBundle>, StatusCode> {
    let db = state.lock().unwrap();
    if let Some(bundle) = db.bundles.get(&username) {
        Ok(Json(bundle.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn send_message(
    State(state): State<SharedState>,
    Json(payload): Json<SendMessageRequest>,
) -> StatusCode {
    let mut db = state.lock().unwrap();
    db.mailbox
        .entry(payload.recipient)
        .or_insert_with(VecDeque::new)
        .push_back(payload.message);
    StatusCode::OK
}

async fn fetch_messages(
    Path(username): Path<String>,
    State(state): State<SharedState>,
) -> Json<FetchMessagesResponse> {
    let mut db = state.lock().unwrap();
    let mut messages = Vec::new();
    if let Some(queue) = db.mailbox.get_mut(&username) {
        while let Some(msg) = queue.pop_front() {
            messages.push(msg);
        }
    }
    Json(FetchMessagesResponse { messages })
}

// ─────────────────────────────────────────────
// /config — serves Razorpay public key to frontend
// ─────────────────────────────────────────────
async fn get_config() -> Json<ConfigResponse> {
    let razorpay_key_id =
        std::env::var("RAZORPAY_KEY_ID").unwrap_or_else(|_| "rzp_test_placeholder".to_string());
    Json(ConfigResponse { razorpay_key_id })
}

// ─────────────────────────────────────────────
// /webhook/razorpay — HMAC-verified payment handler
// ─────────────────────────────────────────────
async fn razorpay_webhook(
    headers: HeaderMap,
    State(state): State<SharedState>,
    body: Bytes,
) -> StatusCode {
    // ── Step 1: Verify HMAC-SHA256 signature ─────────────────────────────
    let secret = match std::env::var("RAZORPAY_KEY_SECRET") {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[webhook] RAZORPAY_KEY_SECRET not set");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let signature = headers
        .get("x-razorpay-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_razorpay_signature(&body, &secret, signature) {
        eprintln!("[webhook] Signature verification FAILED — rejecting");
        return StatusCode::UNAUTHORIZED;
    }

    // ── Step 2: Parse the webhook payload ────────────────────────────────
    let webhook: RazorpayWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[webhook] Failed to parse payload: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Only handle payment.captured; silently acknowledge everything else
    if webhook.event != "payment.captured" {
        return StatusCode::OK;
    }

    // ── Step 3: Extract all fields as owned Strings before payload is dropped
    // (tokio::spawn requires 'static captures)
    let entity = &webhook.payload.payment.entity;

    let payment_id = entity.id.clone();
    let amount_paise = entity.amount;
    let currency = entity.currency.clone();
    let customer_email = entity
        .email
        .clone()
        .unwrap_or_else(|| "unknown@example.com".to_string());
    let customer_name = entity
        .notes
        .as_ref()
        .and_then(|n| n.customer_name.clone())
        .unwrap_or_else(|| "Valued Customer".to_string());
    let plan = entity
        .notes
        .as_ref()
        .and_then(|n| n.product.clone())
        .unwrap_or_else(|| "Commercial SDK License".to_string());

    // ── Step 4: Generate order + license records ──────────────────────────
    let now = Utc::now();
    let valid_until = now + chrono::Duration::days(30);
    let order_id = Uuid::new_v4().to_string();
    let license_key = format!("PQAURA-{}", Uuid::new_v4().to_string().to_uppercase());

    {
        let mut db = state.lock().unwrap();

        // Idempotency guard — ignore replayed webhook deliveries
        if db.orders.iter().any(|o| o.payment_id == payment_id) {
            eprintln!("[webhook] Duplicate payment_id {} — skipping", payment_id);
            return StatusCode::OK;
        }

        db.orders.push(Order {
            order_id: order_id.clone(),
            payment_id: payment_id.clone(),
            customer_email: customer_email.clone(),
            customer_name: customer_name.clone(),
            plan: plan.clone(),
            amount_paise,
            currency: currency.clone(),
            created_at: now.to_rfc3339(),
        });

        db.licenses.push(License {
            license_key: license_key.clone(),
            order_id: order_id.clone(),
            customer_email: customer_email.clone(),
            plan: plan.clone(),
            issued_at: now.to_rfc3339(),
            valid_until: valid_until.to_rfc3339(),
        });
    }

    println!(
        "[webhook] ✅ Captured — order={} payment={} email={}",
        order_id, payment_id, customer_email
    );

    // ── Step 5: Send invoice + license email (non-blocking) ───────────────
    let amount_inr = amount_paise / 100;
    let issued_date_str = now.format("%d %B %Y").to_string();
    let valid_until_str = valid_until.format("%d %B %Y").to_string();

    tokio::spawn(async move {
        match send_license_email(
            &customer_email,
            &customer_name,
            &license_key,
            &order_id,
            &payment_id,
            amount_inr,
            &currency,
            &plan,
            &issued_date_str,
            &valid_until_str,
        )
        .await
        {
            Ok(()) => println!("[email] ✅ License + invoice sent to {}", customer_email),
            Err(e) => eprintln!("[email] ❌ Failed to send to {}: {}", customer_email, e),
        }
    });

    StatusCode::OK
}

// ─────────────────────────────────────────────
// HMAC-SHA256 signature verification
// ─────────────────────────────────────────────
fn verify_razorpay_signature(body: &[u8], secret: &str, received_sig: &str) -> bool {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    let computed = hex::encode(mac.finalize().into_bytes());
    computed == received_sig
}

// ─────────────────────────────────────────────
// Email: License Key + Invoice via Resend API
// ─────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
async fn send_license_email(
    to_email: &str,
    customer_name: &str,
    license_key: &str,
    order_id: &str,
    payment_id: &str,
    amount_inr: u64,
    currency: &str,
    plan: &str,
    issued_date: &str,
    valid_until: &str,
) -> Result<(), String> {
    let resend_api_key =
        std::env::var("RESEND_API_KEY").map_err(|_| "RESEND_API_KEY not set".to_string())?;

    let from_email =
        std::env::var("FROM_EMAIL").unwrap_or_else(|_| "support@pqaura.dev".to_string());

    let html_body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PQ-Aura Commercial License</title>
</head>
<body style="margin:0;padding:0;background:#0f0f12;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f0f12;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#1a1a2e;border-radius:16px;overflow:hidden;border:1px solid rgba(99,102,241,0.3);">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#6366f1,#8b5cf6);padding:32px 40px;text-align:center;">
          <h1 style="margin:0;color:#fff;font-size:28px;font-weight:700;letter-spacing:-0.5px;">PQ-Aura</h1>
          <p style="margin:8px 0 0;color:rgba(255,255,255,0.85);font-size:14px;">Post-Quantum Secure Messaging SDK</p>
        </td></tr>

        <!-- Success Banner -->
        <tr><td style="padding:32px 40px 0;">
          <div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.3);border-radius:12px;padding:20px;text-align:center;">
            <div style="font-size:32px;margin-bottom:8px;">&#x2705;</div>
            <h2 style="margin:0;color:#10b981;font-size:20px;">Payment Confirmed!</h2>
            <p style="margin:8px 0 0;color:#94a3b8;font-size:14px;">Your commercial license has been issued.</p>
          </div>
        </td></tr>

        <!-- Greeting -->
        <tr><td style="padding:28px 40px 0;">
          <p style="margin:0;font-size:16px;color:#e2e8f0;">Hi <strong style="color:#a5b4fc;">{customer_name}</strong>,</p>
          <p style="margin:12px 0 0;font-size:15px;color:#94a3b8;line-height:1.6;">
            Thank you for purchasing the <strong style="color:#e2e8f0;">PQ-Aura {plan}</strong>.
            Your license key is below — keep it safe and do not share it publicly.
          </p>
        </td></tr>

        <!-- License Key Box -->
        <tr><td style="padding:24px 40px 0;">
          <div style="background:#0f0f12;border:2px solid #6366f1;border-radius:12px;padding:24px;text-align:center;">
            <p style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1.5px;color:#6366f1;font-weight:600;">Your License Key</p>
            <code style="font-size:18px;font-weight:700;color:#a5b4fc;letter-spacing:1px;word-break:break-all;">{license_key}</code>
            <p style="margin:12px 0 0;font-size:12px;color:#64748b;">Valid from {issued_date} to {valid_until}</p>
          </div>
        </td></tr>

        <!-- Invoice Table -->
        <tr><td style="padding:28px 40px 0;">
          <h3 style="margin:0 0 16px;font-size:14px;text-transform:uppercase;letter-spacing:1.5px;color:#6366f1;font-weight:600;">Invoice Details</h3>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Invoice / Order ID</td>
              <td style="padding:12px 0;font-size:14px;color:#e2e8f0;text-align:right;font-family:monospace;">{order_id}</td>
            </tr>
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Razorpay Payment ID</td>
              <td style="padding:12px 0;font-size:14px;color:#e2e8f0;text-align:right;font-family:monospace;">{payment_id}</td>
            </tr>
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Product</td>
              <td style="padding:12px 0;font-size:14px;color:#e2e8f0;text-align:right;">{plan}</td>
            </tr>
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Billing Period</td>
              <td style="padding:12px 0;font-size:14px;color:#e2e8f0;text-align:right;">Monthly</td>
            </tr>
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Issue Date</td>
              <td style="padding:12px 0;font-size:14px;color:#e2e8f0;text-align:right;">{issued_date}</td>
            </tr>
            <tr style="border-bottom:1px solid rgba(255,255,255,0.06);">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Valid Until</td>
              <td style="padding:12px 0;font-size:14px;color:#e2e8f0;text-align:right;">{valid_until}</td>
            </tr>
            <tr>
              <td style="padding:16px 0 0;font-size:16px;font-weight:700;color:#e2e8f0;">Amount Paid</td>
              <td style="padding:16px 0 0;font-size:18px;font-weight:700;color:#a5b4fc;text-align:right;">&#x20B9;{amount_inr} {currency}</td>
            </tr>
          </table>
        </td></tr>

        <!-- Usage Instructions -->
        <tr><td style="padding:28px 40px 0;">
          <div style="background:#0f0f12;border-radius:12px;padding:20px;border:1px solid rgba(255,255,255,0.06);">
            <h3 style="margin:0 0 14px;font-size:14px;text-transform:uppercase;letter-spacing:1.5px;color:#6366f1;font-weight:600;">How to Use Your License</h3>
            <ol style="margin:0;padding-left:20px;color:#94a3b8;font-size:14px;line-height:2;">
              <li>Add <code style="color:#a5b4fc;background:rgba(99,102,241,0.1);padding:1px 6px;border-radius:4px;">pq-aura</code> to your <code style="color:#a5b4fc;background:rgba(99,102,241,0.1);padding:1px 6px;border-radius:4px;">Cargo.toml</code> dependencies.</li>
              <li>Store your license key as an environment variable: <code style="color:#a5b4fc;background:rgba(99,102,241,0.1);padding:1px 6px;border-radius:4px;">PQ_AURA_LICENSE_KEY</code>.</li>
              <li>You may use this license in <strong style="color:#e2e8f0;">one commercial product</strong>. Contact us for multi-seat/enterprise.</li>
              <li>Renew before <strong style="color:#e2e8f0;">{valid_until}</strong> to avoid service interruption.</li>
            </ol>
          </div>
        </td></tr>

        <!-- Refund Policy -->
        <tr><td style="padding:20px 40px 0;">
          <p style="margin:0;font-size:13px;color:#475569;line-height:1.6;">
            <strong style="color:#64748b;">Refund Policy:</strong> You are entitled to a full refund within 7 days of purchase.
            Email <a href="mailto:support@pqaura.dev" style="color:#6366f1;text-decoration:none;">support@pqaura.dev</a> with your Order ID.
          </p>
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding:32px 40px;text-align:center;border-top:1px solid rgba(255,255,255,0.06);margin-top:28px;">
          <p style="margin:0;font-size:13px;color:#334155;">
            Questions? <a href="mailto:support@pqaura.dev" style="color:#6366f1;text-decoration:none;">support@pqaura.dev</a>
          </p>
          <p style="margin:8px 0 0;font-size:12px;color:#1e293b;">
            PQ-Aura &middot; Post-Quantum Secure Messaging SDK &middot; India
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"#,
        customer_name = customer_name,
        license_key = license_key,
        order_id = order_id,
        payment_id = payment_id,
        plan = plan,
        amount_inr = amount_inr,
        currency = currency,
        issued_date = issued_date,
        valid_until = valid_until,
    );

    let client = reqwest::Client::new();
    let req_body = serde_json::json!({
        "from": format!("PQ-Aura <{}>", from_email),
        "to": [to_email],
        "subject": format!("Your PQ-Aura Commercial License — Order {}", order_id),
        "html": html_body,
    });

    let response = client
        .post("https://api.resend.com/emails")
        .header("Authorization", format!("Bearer {}", resend_api_key))
        .header("Content-Type", "application/json")
        .json(&req_body)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if response.status().is_success() {
        Ok(())
    } else {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        Err(format!("Resend API error {status}: {text}"))
    }
}
