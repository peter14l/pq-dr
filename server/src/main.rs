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
// Database State & Schemas (Ephemeral Messaging + SQLite Orders/Licenses)
// ─────────────────────────────────────────────
struct Db {
    bundles: HashMap<String, PreKeyBundle>,
    mailbox: HashMap<String, VecDeque<Message>>,
    conn: rusqlite::Connection,
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
    revoked: bool,
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

// License verification request/response
#[derive(Deserialize)]
struct VerifyLicenseRequest {
    license_key: String,
}

#[derive(Serialize)]
struct VerifyLicenseResponse {
    status: String, // "Active", "Expired", "Revoked", "Not Found"
    customer_email: Option<String>,
    plan: Option<String>,
    valid_until: Option<String>,
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

    // Open connection to SQLite
    let db_path = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite.db".to_string());
    let conn = rusqlite::Connection::open(&db_path).expect("Failed to open SQLite database");

    // Enable foreign key support
    conn.execute_batch("PRAGMA foreign_keys = ON;").ok();

    // Run table migrations
    conn.execute(
        "CREATE TABLE IF NOT EXISTS orders (
            order_id TEXT PRIMARY KEY,
            payment_id TEXT UNIQUE,
            customer_email TEXT,
            customer_name TEXT,
            plan TEXT,
            amount_paise INTEGER,
            currency TEXT,
            created_at TEXT
        )",
        [],
    ).expect("Failed to create orders table");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            order_id TEXT,
            customer_email TEXT,
            plan TEXT,
            issued_at TEXT,
            valid_until TEXT,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY(order_id) REFERENCES orders(order_id)
        )",
        [],
    ).expect("Failed to create licenses table");

    let state: SharedState = Arc::new(Mutex::new(Db {
        bundles: HashMap::new(),
        mailbox: HashMap::new(),
        conn,
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
        .route("/license/verify", post(verify_license))
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
// /license/verify — returns validation status for a license key
// ─────────────────────────────────────────────
async fn verify_license(
    State(state): State<SharedState>,
    Json(payload): Json<VerifyLicenseRequest>,
) -> Json<VerifyLicenseResponse> {
    let db = state.lock().unwrap();

    let query_result = db.conn.query_row(
        "SELECT customer_email, plan, valid_until, revoked FROM licenses WHERE license_key = ?",
        [&payload.license_key],
        |row| {
            let revoked_int: i32 = row.get(3)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                revoked_int != 0,
            ))
        },
    );

    match query_result {
        Ok((customer_email, plan, valid_until_str, revoked)) => {
            if revoked {
                return Json(VerifyLicenseResponse {
                    status: "Revoked".to_string(),
                    customer_email: Some(customer_email),
                    plan: Some(plan),
                    valid_until: Some(valid_until_str),
                });
            }

            if let Ok(valid_until) = chrono::DateTime::parse_from_rfc3339(&valid_until_str) {
                if Utc::now() > valid_until {
                    return Json(VerifyLicenseResponse {
                        status: "Expired".to_string(),
                        customer_email: Some(customer_email),
                        plan: Some(plan),
                        valid_until: Some(valid_until_str),
                    });
                }

                Json(VerifyLicenseResponse {
                    status: "Active".to_string(),
                    customer_email: Some(customer_email),
                    plan: Some(plan),
                    valid_until: Some(valid_until_str),
                })
            } else {
                Json(VerifyLicenseResponse {
                    status: "Expired".to_string(),
                    customer_email: Some(customer_email),
                    plan: Some(plan),
                    valid_until: Some(valid_until_str),
                })
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Json(VerifyLicenseResponse {
            status: "Not Found".to_string(),
            customer_email: None,
            plan: None,
            valid_until: None,
        }),
        Err(e) => {
            eprintln!("[verify] Database error: {e}");
            Json(VerifyLicenseResponse {
                status: "Error".to_string(),
                customer_email: None,
                plan: None,
                valid_until: None,
            })
        }
    }
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
        let exists: bool = db.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM orders WHERE payment_id = ?)",
            [&payment_id],
            |row| row.get(0),
        ).unwrap_or(false);

        if exists {
            eprintln!("[webhook] Duplicate payment_id {} — skipping", payment_id);
            return StatusCode::OK;
        }

        // Insert order & license inside a transaction for atomicity and data safety
        let tx = match db.conn.transaction() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[webhook] Failed to start database transaction: {e}");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        };

        if let Err(e) = tx.execute(
            "INSERT INTO orders (order_id, payment_id, customer_email, customer_name, plan, amount_paise, currency, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                &order_id,
                &payment_id,
                &customer_email,
                &customer_name,
                &plan,
                amount_paise,
                &currency,
                now.to_rfc3339(),
            ),
        ) {
            eprintln!("[webhook] Failed to insert order: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }

        if let Err(e) = tx.execute(
            "INSERT INTO licenses (license_key, order_id, customer_email, plan, issued_at, valid_until, revoked)
             VALUES (?, ?, ?, ?, ?, ?, 0)",
            (
                &license_key,
                &order_id,
                &customer_email,
                &plan,
                now.to_rfc3339(),
                valid_until.to_rfc3339(),
            ),
        ) {
            eprintln!("[webhook] Failed to insert license: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }

        if let Err(e) = tx.commit() {
            eprintln!("[webhook] Failed to commit database transaction: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
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
        std::env::var("FROM_EMAIL").unwrap_or_else(|_| "onboarding@resend.dev".to_string());

    let html_body = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PQ-Aura Commercial License</title>
</head>
<body style="margin:0;padding:0;background-color:#f8fafc;font-family:'Segoe UI',Arial,sans-serif;color:#0f172a;-webkit-font-smoothing:antialiased;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f8fafc;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 10px 25px -5px rgba(0,0,0,0.05),0 8px 10px -6px rgba(0,0,0,0.05);border:1px solid #e2e8f0;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:32px 40px;text-align:center;">
          <h1 style="margin:0;color:#ffffff;font-size:28px;font-weight:700;letter-spacing:-0.5px;">PQ-Aura</h1>
          <p style="margin:8px 0 0;color:rgba(255,255,255,0.9);font-size:14px;">Post-Quantum Secure Messaging SDK</p>
        </td></tr>

        <!-- Success Banner -->
        <tr><td style="padding:32px 40px 0;">
          <div style="background-color:#ecfdf5;border:1px solid #a7f3d0;border-radius:12px;padding:20px;text-align:center;">
            <div style="font-size:32px;margin-bottom:8px;">✅</div>
            <h2 style="margin:0;color:#047857;font-size:20px;">Payment Confirmed!</h2>
            <p style="margin:8px 0 0;color:#065f46;font-size:14px;">Your commercial license has been successfully issued.</p>
          </div>
        </td></tr>

        <!-- Greeting -->
        <tr><td style="padding:28px 40px 0;">
          <p style="margin:0;font-size:16px;color:#0f172a;">Hi <strong>{customer_name}</strong>,</p>
          <p style="margin:12px 0 0;font-size:15px;color:#475569;line-height:1.6;">
            Thank you for purchasing the <strong>PQ-Aura {plan}</strong>.
            Your license key is below. Please store it securely and do not share it publicly.
          </p>
        </td></tr>

        <!-- License Key Box -->
        <tr><td style="padding:24px 40px 0;">
          <div style="background-color:#f1f5f9;border:2px solid #e2e8f0;border-radius:12px;padding:24px;text-align:center;">
            <p style="margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:1.5px;color:#4f46e5;font-weight:600;">Your License Key</p>
            <code style="font-size:18px;font-weight:700;color:#4f46e5;letter-spacing:1px;word-break:break-all;font-family:monospace;">{license_key}</code>
            <p style="margin:12px 0 0;font-size:12px;color:#64748b;">Valid from {issued_date} to {valid_until}</p>
          </div>
        </td></tr>

        <!-- Invoice Table -->
        <tr><td style="padding:28px 40px 0;">
          <h3 style="margin:0 0 16px;font-size:14px;text-transform:uppercase;letter-spacing:1.5px;color:#4f46e5;font-weight:600;">Invoice Details</h3>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
            <tr style="border-bottom:1px solid #f1f5f9;">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Invoice / Order ID</td>
              <td style="padding:12px 0;font-size:14px;color:#0f172a;text-align:right;font-family:monospace;">{order_id}</td>
            </tr>
            <tr style="border-bottom:1px solid #f1f5f9;">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Razorpay Payment ID</td>
              <td style="padding:12px 0;font-size:14px;color:#0f172a;text-align:right;font-family:monospace;">{payment_id}</td>
            </tr>
            <tr style="border-bottom:1px solid #f1f5f9;">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Product</td>
              <td style="padding:12px 0;font-size:14px;color:#0f172a;text-align:right;">{plan}</td>
            </tr>
            <tr style="border-bottom:1px solid #f1f5f9;">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Billing Period</td>
              <td style="padding:12px 0;font-size:14px;color:#0f172a;text-align:right;">Monthly</td>
            </tr>
            <tr style="border-bottom:1px solid #f1f5f9;">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Issue Date</td>
              <td style="padding:12px 0;font-size:14px;color:#0f172a;text-align:right;">{issued_date}</td>
            </tr>
            <tr style="border-bottom:1px solid #f1f5f9;">
              <td style="padding:12px 0;font-size:14px;color:#64748b;">Valid Until</td>
              <td style="padding:12px 0;font-size:14px;color:#0f172a;text-align:right;">{valid_until}</td>
            </tr>
            <tr>
              <td style="padding:16px 0 0;font-size:16px;font-weight:700;color:#0f172a;">Amount Paid</td>
              <td style="padding:16px 0 0;font-size:18px;font-weight:700;color:#4f46e5;text-align:right;">&#x20B9;{amount_inr} {currency}</td>
            </tr>
          </table>
        </td></tr>

        <!-- Usage Instructions -->
        <tr><td style="padding:28px 40px 0;">
          <div style="background-color:#f8fafc;border-radius:12px;padding:20px;border:1px solid #e2e8f0;">
            <h3 style="margin:0 0 14px;font-size:14px;text-transform:uppercase;letter-spacing:1.5px;color:#4f46e5;font-weight:600;">How to Use Your License</h3>
            <ol style="margin:0;padding-left:20px;color:#475569;font-size:14px;line-height:2;">
              <li>Add <code style="color:#4f46e5;background-color:#eff6ff;padding:2px 6px;border-radius:4px;font-family:monospace;">pq-aura</code> to your <code style="color:#4f46e5;background-color:#eff6ff;padding:2px 6px;border-radius:4px;font-family:monospace;">Cargo.toml</code> dependencies.</li>
              <li>Store your license key as an environment variable: <code style="color:#4f46e5;background-color:#eff6ff;padding:2px 6px;border-radius:4px;font-family:monospace;">PQ_AURA_LICENSE_KEY</code>.</li>
              <li>You may use this license in <strong style="color:#0f172a;">one commercial product</strong>. Contact us for multi-seat/enterprise support.</li>
              <li>Renew before <strong style="color:#0f172a;">{valid_until}</strong> to avoid service interruption.</li>
            </ol>
          </div>
        </td></tr>

        <!-- Refund Policy -->
        <tr><td style="padding:20px 40px 0;">
          <p style="margin:0;font-size:13px;color:#475569;line-height:1.6;">
            <strong style="color:#64748b;">Refund Policy:</strong> You are entitled to a full refund within 7 days of purchase.
            Email <a href="mailto:peter_parker_2008@outlook.com" style="color:#6366f1;text-decoration:none;">peter_parker_2008@outlook.com</a> with your Order ID.
          </p>
        </td></tr>

        <!-- Footer -->
        <tr><td style="padding:32px 40px;text-align:center;border-top:1px solid rgba(255,255,255,0.06);margin-top:28px;">
          <p style="margin:0;font-size:13px;color:#334155;">
            Questions? <a href="mailto:peter_parker_2008@outlook.com" style="color:#6366f1;text-decoration:none;">peter_parker_2008@outlook.com</a>
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
