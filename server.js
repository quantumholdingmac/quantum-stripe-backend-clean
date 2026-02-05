// server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const fs = require("fs-extra");
const path = require("path");
const Stripe = require("stripe");
const crypto = require("crypto");
const { Resend } = require("resend");
const docusign = require("docusign-esign");

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// -------------------- RESEND --------------------
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

async function sendMailSafe({ to, subject, text, html }) {
  try {
    if (!resend) {
      console.log("MAIL: RESEND_API_KEY not configured -> skip");
      return;
    }

    const from = process.env.MAIL_FROM || "Quantum ITech <info@quantumitech.hu>";

    await resend.emails.send({
      from,
      to,
      subject,
      text,
      html,
    });

    console.log("MAIL: sent via Resend to", to);
  } catch (e) {
    console.error("MAIL: failed:", e?.message || e);
  }
}

// -------------------- CORS --------------------
const corsOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, cb) {
      // origin nélküli requestek (Stripe webhook, curl) -> ok
      if (!origin) return cb(null, true);

      if (!corsOrigins.length) return cb(null, true);
      if (corsOrigins.includes(origin)) return cb(null, true);

      return cb(new Error("Not allowed by CORS: " + origin));
    },
    methods: ["POST", "GET"],
    credentials: true,
  })
);

// ======================================================================
// ========================== DOCUSIGN HELPERS ===========================
// ======================================================================

function stripQuotes(s) {
  s = String(s || "").trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1);
  }
  return s.trim();
}

function normalizePemNewlines(pem) {
  pem = String(pem || "");
  // Render néha \\n-ként tárolja
  if (pem.includes("\\n")) pem = pem.replace(/\\n/g, "\n");
  // CRLF -> LF
  pem = pem.replace(/\r\n/g, "\n");
  return pem.trim();
}

/**
 * A lényeg: DOCUSIGN_PRIVATE_KEY_B64 (ajánlott) -> PEM string
 * Fallback: DOCUSIGN_PRIVATE_KEY vagy DOCUSIGN_PRIVATE_KEY_PEM -> PEM string
 */
function getDocuSignPrivateKeyPem() {
  // 1) Ajánlott: base64 env
  const b64raw = stripQuotes(process.env.DOCUSIGN_PRIVATE_KEY_B64 || "");
  if (b64raw) {
    // base64 lehet több soros / whitespace-es -> takarítsuk
    const b64 = b64raw.replace(/\s+/g, "");
    const decoded = Buffer.from(b64, "base64").toString("utf8");
    const pem = normalizePemNewlines(decoded);

    const looksLikePem =
      pem.includes("BEGIN RSA PRIVATE KEY") || pem.includes("BEGIN PRIVATE KEY");

    if (!looksLikePem) {
      throw new Error(
        "DOCUSIGN_PRIVATE_KEY_B64 decoded, but it does not look like a PEM private key (BEGIN ... PRIVATE KEY)"
      );
    }
    return pem;
  }

  // 2) Fallback: sima PEM env
  const pemRaw =
    stripQuotes(process.env.DOCUSIGN_PRIVATE_KEY_PEM) ||
    stripQuotes(process.env.DOCUSIGN_PRIVATE_KEY) ||
    "";

  const pem = normalizePemNewlines(pemRaw);

  const looksLikePem =
    pem.includes("BEGIN RSA PRIVATE KEY") || pem.includes("BEGIN PRIVATE KEY");

  if (!pem) return "";
  if (!looksLikePem) {
    throw new Error(
      "DOCUSIGN_PRIVATE_KEY(_PEM) is set, but it does not look like a PEM private key (BEGIN ... PRIVATE KEY)"
    );
  }

  return pem;
}

function getDocuSignConfig() {
  const integrationKey = stripQuotes(process.env.DOCUSIGN_INTEGRATION_KEY);
  const userId = stripQuotes(process.env.DOCUSIGN_USER_ID);
  const accountId = stripQuotes(process.env.DOCUSIGN_ACCOUNT_ID);
  const basePath =
    stripQuotes(process.env.DOCUSIGN_BASE_PATH) || "https://demo.docusign.net/restapi";
  const oAuthBasePath =
    stripQuotes(process.env.DOCUSIGN_OAUTH_BASE_PATH) || "account-d.docusign.com";
  const templateId = stripQuotes(process.env.DOCUSIGN_TEMPLATE_ID);

  const b64 = stripQuotes(process.env.DOCUSIGN_PRIVATE_KEY_B64);
  if (!b64) {
    throw new Error("Missing DOCUSIGN_PRIVATE_KEY_B64");
  }

  const pem = Buffer.from(b64, "base64")
    .toString("utf8")
    .replace(/\r\n/g, "\n")
    .trim();

  const looksLikePem = pem.includes("BEGIN PRIVATE KEY") || pem.includes("BEGIN RSA PRIVATE KEY");
  if (!looksLikePem) {
    throw new Error("Decoded key is not PEM private key");
  }

  if (!integrationKey || !userId || !accountId || !templateId) {
    throw new Error("Missing DOCUSIGN env vars (INTEGRATION_KEY, USER_ID, ACCOUNT_ID, TEMPLATE_ID)");
  }

  return { integrationKey, userId, accountId, basePath, oAuthBasePath, templateId, privateKey: pem };
}


async function getDocusignApiClient() {
  const cfg = getDocuSignConfig();

  const apiClient = new docusign.ApiClient();
  apiClient.setBasePath(cfg.basePath);
  apiClient.setOAuthBasePath(cfg.oAuthBasePath);

  // ✅ A LÉNYEG: PEM -> KeyObject (így RS256 biztosan "asymmetric key"-nek látja)
  let keyObject;
  try {
    keyObject = crypto.createPrivateKey({
      key: cfg.privateKeyPem,
      format: "pem",
    });
  } catch (e) {
    throw new Error("Invalid DOCUSIGN private key PEM (crypto.createPrivateKey failed): " + (e?.message || e));
  }

  const results = await apiClient.requestJWTUserToken(
  cfg.integrationKey,
  cfg.userId,
  ["signature", "impersonation"],
  cfg.privateKey, // STRING PEM
  3600
);


  const accessToken = results.body.access_token;
  apiClient.addDefaultHeader("Authorization", "Bearer " + accessToken);

  return { apiClient, cfg };
}


// -------------------- BODY PARSER --------------------
// Webhook RAW kell, ezért JSON parserből kivesszük:
app.use((req, res, next) => {
  if (req.originalUrl === "/api/stripe/webhook") return next();
  return express.json()(req, res, next);
});

// -------------------- DATA DIR (Render-safe) --------------------
function pickWritableDataDir() {
  // 1) explicit env
  if (process.env.DATA_DIR) return process.env.DATA_DIR;

  // 2) Render disk default hely (csak ha tényleg van mount)
  const candidate = "/var/data";
  try {
    fs.ensureDirSync(candidate);
    fs.accessSync(candidate, fs.constants.W_OK);
    return candidate;
  } catch (_) {
    // 3) fallback: /tmp mindig írható konténerben
    return "/tmp/quantum-data";
  }
}

const DATA_DIR = pickWritableDataDir();
const CONTRACTS_FILE = path.join(DATA_DIR, "contracts.json");

async function loadContracts() {
  await fs.ensureDir(DATA_DIR);

  if (!(await fs.pathExists(CONTRACTS_FILE))) {
    await fs.writeJson(
      CONTRACTS_FILE,
      { byContractId: {}, bySubscriptionId: {} },
      { spaces: 2 }
    );
  }
  return fs.readJson(CONTRACTS_FILE);
}

async function saveContracts(db) {
  await fs.ensureDir(DATA_DIR);
  await fs.writeJson(CONTRACTS_FILE, db, { spaces: 2 });
}

// -------------------- HELPERS --------------------
function isValidPlan(plan) {
  return plan === "basic" || plan === "premium";
}
function isValidTerm(term) {
  return term === 12 || term === 36;
}
function clampInt(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, Math.floor(x)));
}

function getMonthlyPriceId(plan) {
  if (plan === "basic") return process.env.PRICE_BASIC_MONTHLY;
  if (plan === "premium") return process.env.PRICE_PREMIUM_MONTHLY;
  return null;
}
function getDevicePriceId(plan) {
  if (plan === "basic") return process.env.PRICE_BASIC_DEVICE;
  if (plan === "premium") return process.env.PRICE_PREMIUM_DEVICE;
  return null;
}
function getSetupFeePriceId(plan) {
  if (plan === "basic") return process.env.PRICE_SETUP_BASIC_1Y;
  if (plan === "premium") return process.env.PRICE_SETUP_PREMIUM_1Y;
  return null;
}

function calcCommitmentEndsAt(termMonths) {
  const nowSec = Math.floor(Date.now() / 1000);
  return nowSec + termMonths * 30 * 24 * 60 * 60;
}

function planLabel(plan) {
  if (plan === "basic") return "Alapcsomag";
  if (plan === "premium") return "Prémiumcsomag";
  return plan || "";
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function b64urlEncode(bufOrStr) {
  const buf = Buffer.isBuffer(bufOrStr)
    ? bufOrStr
    : Buffer.from(String(bufOrStr), "utf8");
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecode(str) {
  str = String(str || "").replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

// token payload: email|exp|nonce
function signMagicToken(email, ttlSeconds = 600) {
  const secret = process.env.MAGIC_LINK_SECRET;
  if (!secret) throw new Error("MAGIC_LINK_SECRET missing");

  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const nonce = crypto.randomBytes(12).toString("hex");
  const payload = `${email}|${exp}|${nonce}`;
  const sig = crypto.createHmac("sha256", secret).update(payload).digest();
  return b64urlEncode(payload) + "." + b64urlEncode(sig);
}

function verifyMagicToken(token) {
  const secret = process.env.MAGIC_LINK_SECRET;
  if (!secret) throw new Error("MAGIC_LINK_SECRET missing");

  const parts = String(token || "").split(".");
  if (parts.length !== 2) throw new Error("Bad token format");

  const payload = b64urlDecode(parts[0]).toString("utf8");
  const sig = b64urlDecode(parts[1]);

  const expected = crypto.createHmac("sha256", secret).update(payload).digest();

  if (sig.length !== expected.length || !crypto.timingSafeEqual(sig, expected)) {
    throw new Error("Bad token signature");
  }

  const [email, expStr] = payload.split("|");
  const exp = Number(expStr || 0);
  if (!email || !exp) throw new Error("Bad token payload");

  const now = Math.floor(Date.now() / 1000);
  if (exp < now) throw new Error("Token expired");

  return { email: normalizeEmail(email), exp };
}

// Stripe: find customer by email (returns first)
async function findCustomerByEmail(email) {
  if (!email) return null;
  const res = await stripe.customers.list({ email: normalizeEmail(email), limit: 1 });
  return res.data && res.data.length ? res.data[0] : null;
}

// -------------------- ADMIN AUTH --------------------
function requireAdmin(req, res, next) {
  const token =
    (req.headers["x-admin-token"] ? String(req.headers["x-admin-token"]) : "") ||
    (req.query.token ? String(req.query.token) : "");

  if (!process.env.ADMIN_TOKEN) {
    return res.status(500).json({ error: "ADMIN_TOKEN not set on server" });
  }
  if (token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  return next();
}

// -------------------- HEALTH --------------------
app.get("/", (req, res) => {
  res.json({ ok: true, service: "quantum-stripe-backend", dataDir: DATA_DIR });
});

// ======================================================================
// ============================ DOCUSIGN API =============================
// ======================================================================

app.get("/api/docusign/ping", (req, res) => {
  return res.json({ ok: true, service: "docusign", time: new Date().toISOString() });
});

// DEBUG: nézd meg mit lát a backend kulcsnak (nem logoljuk ki a kulcsot!)
app.get("/api/docusign/debug-key", (req, res) => {
  try {
    const cfg = getDocuSignConfig();
    const pem = cfg.privateKeyPem;
    const firstLine = (pem.split("\n")[0] || "").trim();

    let keyInfo = {};
    try {
      const keyObj = crypto.createPrivateKey({ key: pem, format: "pem" });
      keyInfo = {
        isKeyObject: !!keyObj,
        type: keyObj.type, // "private"
        asymmetricKeyType: keyObj.asymmetricKeyType, // "rsa"
      };
    } catch (e) {
      keyInfo = { keyObjectError: e?.message || String(e) };
    }

    return res.json({
      ok: true,
      firstLine,
      length: pem.length,
      hasBegin: pem.includes("BEGIN"),
      hasPrivateKey: pem.includes("PRIVATE KEY"),
      hasRSA: pem.includes("RSA PRIVATE KEY"),
      keyInfo,
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});


// Egyszerű “start” endpoint (ahogy eddig használtad curl-lel)
app.post("/api/docusign/start", async (req, res) => {
  try {
    const {
      customer_name,
      customer_email,

      company_name,
      customer_phone,
      billing_address,
      tax_number,

      plan_name,
      term_months,
      devices_total,
      extra_devices,
      monthly_base_price,
      extra_device_price,
      setup_fee,
      monthly_total,

      contractId,
    } = req.body || {};

    if (!customer_name || !customer_email) {
      return res.status(400).json({ error: "Missing customer_name / customer_email" });
    }

    const { apiClient, cfg } = await getDocusignApiClient();
    docusign.Configuration.default.setDefaultApiClient(apiClient);

    const envelopesApi = new docusign.EnvelopesApi(apiClient);

    const clientUserId = String(contractId || "customer-" + Date.now());

    const textTabs = [
      { tabLabel: "customer_name", value: String(customer_name) },
      { tabLabel: "customer_email", value: String(customer_email) },
      { tabLabel: "company_name", value: String(company_name || "") },
      { tabLabel: "customer_phone", value: String(customer_phone || "") },
      { tabLabel: "billing_address", value: String(billing_address || "") },
      { tabLabel: "tax_number", value: String(tax_number || "") },

      { tabLabel: "plan_name", value: String(plan_name || "") },
      { tabLabel: "term_months", value: String(term_months || "") },
      { tabLabel: "devices_total", value: String(devices_total || "") },
      { tabLabel: "extra_devices", value: String(extra_devices || "") },

      { tabLabel: "monthly_base_price", value: String(monthly_base_price || "") },
      { tabLabel: "extra_device_price", value: String(extra_device_price || "") },
      { tabLabel: "setup_fee", value: String(setup_fee || "") },
      { tabLabel: "monthly_total", value: String(monthly_total || "") },
    ];

    const envelopeDefinition = new docusign.EnvelopeDefinition();
    envelopeDefinition.templateId = cfg.templateId;
    envelopeDefinition.status = "sent";

    envelopeDefinition.templateRoles = [
      {
        roleName: "Customer",
        name: String(customer_name),
        email: String(customer_email),
        clientUserId,
        tabs: { textTabs },
      },
    ];

    const envelopeSummary = await envelopesApi.createEnvelope(cfg.accountId, {
      envelopeDefinition,
    });

    const envelopeId = envelopeSummary.envelopeId;

    const baseReturn = process.env.DOCUSIGN_RETURN_URL || "https://quantumitech.hu/ugyfel";
    const returnUrl =
      baseReturn +
      `?docusign=return&envelopeId=${encodeURIComponent(envelopeId)}&contractId=${encodeURIComponent(
        clientUserId
      )}`;

    const viewRequest = new docusign.RecipientViewRequest();
    viewRequest.returnUrl = returnUrl;
    viewRequest.authenticationMethod = "none";
    viewRequest.email = String(customer_email);
    viewRequest.userName = String(customer_name);
    viewRequest.clientUserId = clientUserId;
    viewRequest.recipientId = "1";

    const viewResult = await envelopesApi.createRecipientView(cfg.accountId, envelopeId, {
      recipientViewRequest: viewRequest,
    });

    return res.json({
      ok: true,
      envelopeId,
      contractId: clientUserId,
      signingUrl: viewResult.url,
    });
  } catch (err) {
    console.error("DOCUSIGN start error:", err?.response?.body || err?.message || err);
    return res.status(500).json({
      error: "DocuSign start failed",
      details: err?.response?.body || err?.message || String(err),
    });
  }
});

// Kompatibilis “embedded-sign” endpoint (ha ezt akarod használni a frontendről)
app.post("/api/docusign/embedded-sign", async (req, res) => {
  try {
    const customer = req.body?.customer || {};
    const order = req.body?.order || {};

    const customerName = String(customer.name || "").trim();
    const customerEmail = String(customer.email || "").trim().toLowerCase();

    if (!customerName) return res.status(400).json({ error: "Missing customer.name" });
    if (!customerEmail || !customerEmail.includes("@")) {
      return res.status(400).json({ error: "Missing/invalid customer.email" });
    }

    const { apiClient, cfg } = await getDocusignApiClient();
    docusign.Configuration.default.setDefaultApiClient(apiClient);

    const envDef = new docusign.EnvelopeDefinition();
    envDef.templateId = cfg.templateId;
    envDef.status = "sent";

    const clientUserId = "customer-1";

    const signer = docusign.TemplateRole.constructFromObject({
      roleName: "Customer",
      name: customerName,
      email: customerEmail,
      clientUserId,
      tabs: docusign.Tabs.constructFromObject({
        textTabs: [
          { tabLabel: "customer_name", value: customerName },
          { tabLabel: "company_name", value: String(customer.company || "") },
          { tabLabel: "customer_email", value: customerEmail },
          { tabLabel: "customer_phone", value: String(customer.phone || "") },
          { tabLabel: "billing_address", value: String(customer.billingAddress || "") },
          { tabLabel: "tax_number", value: String(customer.taxNumber || "") },

          { tabLabel: "plan_name", value: String(order.planName || "") },
          { tabLabel: "term_months", value: String(order.termMonths || "") },
          { tabLabel: "devices_total", value: String(order.devicesTotal || "") },
          { tabLabel: "extra_devices", value: String(order.extraDevices || "") },

          { tabLabel: "monthly_base_price", value: String(order.monthlyBasePrice || "") },
          { tabLabel: "extra_device_price", value: String(order.extraDevicePrice || "") },
          { tabLabel: "setup_fee", value: String(order.setupFee || "") },
          { tabLabel: "monthly_total", value: String(order.monthlyTotal || "") },

          { tabLabel: "sum_period", value: order.termMonths ? `${order.termMonths} hónap` : "" },
        ],
      }),
    });

    envDef.templateRoles = [signer];

    const envelopesApi = new docusign.EnvelopesApi(apiClient);
    const createRes = await envelopesApi.createEnvelope(cfg.accountId, { envelopeDefinition: envDef });
    const envelopeId = createRes.envelopeId;

    const returnUrl = process.env.DOCUSIGN_RETURN_URL;
    if (!returnUrl) return res.status(500).json({ error: "Missing DOCUSIGN_RETURN_URL" });

    const viewReq = new docusign.RecipientViewRequest();
    viewReq.returnUrl = returnUrl;
    viewReq.authenticationMethod = "none";
    viewReq.email = customerEmail;
    viewReq.userName = customerName;
    viewReq.clientUserId = clientUserId;
    viewReq.recipientId = "1";

    const viewRes = await envelopesApi.createRecipientView(cfg.accountId, envelopeId, {
      recipientViewRequest: viewReq,
    });

    return res.json({ ok: true, envelopeId, url: viewRes.url });
  } catch (e) {
    console.error("docusign embedded-sign error:", e?.response?.body || e?.message || e);
    return res.status(500).json({
      error: "DocuSign error",
      details: e?.response?.body || e?.message || String(e),
    });
  }
});

app.get("/api/docusign/envelope-status", async (req, res) => {
  try {
    const envelopeId = String(req.query.envelopeId || "").trim();
    if (!envelopeId) return res.status(400).json({ error: "Missing envelopeId" });

    const { apiClient, cfg } = await getDocusignApiClient();
    docusign.Configuration.default.setDefaultApiClient(apiClient);

    const envelopesApi = new docusign.EnvelopesApi(apiClient);
    const envelope = await envelopesApi.getEnvelope(cfg.accountId, envelopeId);

    return res.json({
      ok: true,
      envelopeId,
      status: envelope.status,
      completedDateTime: envelope.completedDateTime || null,
    });
  } catch (err) {
    console.error("DOCUSIGN status error:", err?.response?.body || err?.message || err);
    return res.status(500).json({
      error: "DocuSign status failed",
      details: err?.response?.body || err?.message || String(err),
    });
  }
});

app.get("/api/docusign/test-sign", (req, res) => {
  return res.json({ ok: true, next: "implement embedded signing flow here" });
});

// ======================================================================
// ============================== STRIPE API =============================
// ======================================================================

app.post("/api/create-checkout-session", async (req, res) => {
  try {
    const { email, plan, termMonths, devicesTotal, contractId } = req.body;

    if (!email || typeof email !== "string") {
      return res.status(400).json({ error: "Missing/invalid email" });
    }
    if (!isValidPlan(plan)) {
      return res.status(400).json({ error: "Invalid plan (basic/premium)" });
    }

    const term = Number(termMonths);
    if (!isValidTerm(term)) {
      return res.status(400).json({ error: "Invalid termMonths (12 or 36)" });
    }

    const totalDevices = clampInt(devicesTotal, 1, 1000);
    const included = 25;
    const extraDevices = Math.max(0, totalDevices - included);

    const monthlyPrice = getMonthlyPriceId(plan);
    const devicePrice = getDevicePriceId(plan);
    if (!monthlyPrice || !devicePrice) {
      return res.status(500).json({ error: "Missing PRICE env vars for plan" });
    }

    const commitmentEndsAt = calcCommitmentEndsAt(term);

    const lineItems = [{ price: monthlyPrice, quantity: 1 }];
    if (extraDevices > 0) lineItems.push({ price: devicePrice, quantity: extraDevices });

    if (term === 12) {
      const setupFee = getSetupFeePriceId(plan);
      if (!setupFee) return res.status(500).json({ error: "Missing setup fee price env var" });
      lineItems.push({ price: setupFee, quantity: 1 });
    }

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: email,
      line_items: lineItems,
      success_url: `${process.env.WP_SUCCESS_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: process.env.WP_CANCEL_URL,

      subscription_data: {
        metadata: {
          contractId: contractId ? String(contractId) : "",
          plan: String(plan),
          termMonths: String(term),
          devicesTotal: String(totalDevices),
          extraDevices: String(extraDevices),
          commitmentEndsAt: String(commitmentEndsAt),
        },
      },

      metadata: {
        contractId: contractId ? String(contractId) : "",
        plan: String(plan),
        termMonths: String(term),
        devicesTotal: String(totalDevices),
        extraDevices: String(extraDevices),
        commitmentEndsAt: String(commitmentEndsAt),
      },
    });

    return res.json({ url: session.url });
  } catch (err) {
    console.error("create-checkout-session error:", err);
    return res.status(500).json({
      error: "Server error creating checkout session",
      details: err?.message || String(err),
    });
  }
});

// -------------------- WEBHOOK (RAW) --------------------
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature verify failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  let db;
  try {
    db = await loadContracts();
  } catch (e) {
    console.error("DB load failed (non-fatal):", e?.message || e);
    db = { byContractId: {}, bySubscriptionId: {} };
  }

  const upsertBySubscription = async (subscriptionId, patch) => {
    if (!subscriptionId) return;

    const existing = db.bySubscriptionId[subscriptionId] || {};
    const merged = { ...existing, ...patch, subscriptionId };
    db.bySubscriptionId[subscriptionId] = merged;

    if (merged.contractId) {
      db.byContractId[merged.contractId] = {
        ...(db.byContractId[merged.contractId] || {}),
        ...merged,
      };
    }

    try {
      await saveContracts(db);
    } catch (e) {
      console.error("DB save failed (non-fatal):", e?.message || e);
    }
  };

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const subscriptionId = session.subscription;
        const customerId = session.customer;

        await upsertBySubscription(subscriptionId, {
          contractId: session.metadata?.contractId || "",
          customerId: customerId || "",
          email: session.customer_email || "",
          plan: session.metadata?.plan || "",
          termMonths: Number(session.metadata?.termMonths || 0),
          devicesTotal: Number(session.metadata?.devicesTotal || 0),
          extraDevices: Number(session.metadata?.extraDevices || 0),
          commitmentEndsAt: Number(session.metadata?.commitmentEndsAt || 0),
          status: "active",
          lastEvent: "checkout.session.completed",
          updatedAt: Date.now(),
        });

        if (session.customer_email) {
          await sendMailSafe({
            to: session.customer_email,
            subject: "Quantum ITech - Sikeres előfizetés",
            text:
              "Sikeres fizetés és előfizetés létrejött.\n\n" +
              "Csomag: " + planLabel(session.metadata?.plan || "") + "\n" +
              "Szerződés hossza (hó): " + (session.metadata?.termMonths || "") + "\n" +
              "Eszközök száma: " + (session.metadata?.devicesTotal || "") + "\n" +
              "Előfizetés azonosító: " + (subscriptionId || "") + "\n\n" +
              "Köszönjük,\nQuantum ITech",
          });
        }
        break;
      }

      case "invoice.payment_succeeded": {
        const invoice = event.data.object;
        const subscriptionId =
          invoice.subscription || invoice.lines?.data?.[0]?.subscription || null;

        await upsertBySubscription(subscriptionId, {
          status: "active",
          lastPaymentAt: Date.now(),
          lastInvoiceId: invoice.id,
          lastEvent: "invoice.payment_succeeded",
          updatedAt: Date.now(),
        });

        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object;
        const subscriptionId =
          invoice.subscription || invoice.lines?.data?.[0]?.subscription || null;

        await upsertBySubscription(subscriptionId, {
          status: "past_due",
          lastEvent: "invoice.payment_failed",
          updatedAt: Date.now(),
        });

        break;
      }

      case "customer.subscription.deleted": {
        const sub = event.data.object;

        await upsertBySubscription(sub.id, {
          status: "canceled",
          lastEvent: "customer.subscription.deleted",
          updatedAt: Date.now(),
        });

        break;
      }

      default:
        break;
    }

    return res.json({ received: true });
  } catch (err) {
    console.error("Webhook handler error:", err);
    return res.json({ received: true, warning: "handler error (logged)" });
  }
});

// -------------------- ADMIN API (JSON + Stripe fallback) --------------------
app.get("/api/admin/contracts", requireAdmin, async (req, res) => {
  try {
    let local = [];
    try {
      const db = await loadContracts();
      local = Object.values(db.bySubscriptionId || {}).sort(
        (a, b) => (b.updatedAt || 0) - (a.updatedAt || 0)
      );
    } catch (_) {
      local = [];
    }

    const source = String(req.query.source || "").toLowerCase();
    if (source === "stripe") {
      const subs = await stripe.subscriptions.list({ limit: 100 });
      const stripeRows = subs.data.map((s) => ({
        subscriptionId: s.id,
        status: s.status,
        cancel_at_period_end: !!s.cancel_at_period_end,
        current_period_end: s.current_period_end,
        customer: s.customer,
        metadata: s.metadata || {},
        plan: s.metadata?.plan || "",
        termMonths: s.metadata?.termMonths ? Number(s.metadata.termMonths) : null,
        devicesTotal: s.metadata?.devicesTotal ? Number(s.metadata.devicesTotal) : null,
        extraDevices: s.metadata?.extraDevices ? Number(s.metadata.extraDevices) : null,
        commitmentEndsAt: s.metadata?.commitmentEndsAt ? Number(s.metadata.commitmentEndsAt) : null,
      }));
      return res.json({ ok: true, source: "stripe", count: stripeRows.length, items: stripeRows });
    }

    return res.json({ ok: true, source: "local", count: local.length, items: local });
  } catch (e) {
    return res.status(500).json({ error: "Server error", details: e?.message || String(e) });
  }
});

app.get("/api/admin/contract", requireAdmin, async (req, res) => {
  try {
    const subscriptionId = String(req.query.subscriptionId || "").trim();
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    try {
      const db = await loadContracts();
      const row = db.bySubscriptionId?.[subscriptionId];
      if (row) return res.json({ ok: true, source: "local", item: row });
    } catch (_) {}

    const sub = await stripe.subscriptions.retrieve(subscriptionId);
    return res.json({
      ok: true,
      source: "stripe",
      item: {
        subscriptionId: sub.id,
        status: sub.status,
        cancelAtPeriodEnd: !!sub.cancel_at_period_end,
        currentPeriodEnd: sub.current_period_end,
        customer: sub.customer,
        email: null,
        plan: sub.metadata?.plan || "",
        planLabel: planLabel(sub.metadata?.plan || ""),
        termMonths: sub.metadata?.termMonths ? Number(sub.metadata.termMonths) : null,
        devicesTotal: sub.metadata?.devicesTotal ? Number(sub.metadata?.devicesTotal) : null,
        extraDevices: sub.metadata?.extraDevices ? Number(sub.metadata?.extraDevices) : null,
        commitmentEndsAt: sub.metadata?.commitmentEndsAt ? Number(sub.metadata?.commitmentEndsAt) : null,
      },
    });
  } catch (e) {
    return res.status(500).json({ error: "Server error", details: e?.message || String(e) });
  }
});

// -------------------- SUCCESS PAGE: session-status --------------------
app.get("/api/session-status", async (req, res) => {
  try {
    const sessionId = String(req.query.session_id || "").trim();
    if (!sessionId) return res.status(400).json({ error: "Missing session_id" });

    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ["subscription", "line_items.data.price.product"],
    });

    const paid = session.payment_status === "paid" || session.status === "complete";

    const metadata = session.metadata || {};
    const sub = session.subscription && typeof session.subscription === "object" ? session.subscription : null;

    const items = (session.line_items?.data || []).map((li) => ({
      description: li.description || li.price?.nickname || li.price?.id || "",
      quantity: li.quantity || 0,
      amount_total: li.amount_total || 0,
      currency: li.currency || "",
    }));

    return res.json({
      ok: true,
      paid,
      customer_email: session.customer_details?.email || session.customer_email || "",
      session_id: session.id,
      subscription_id: sub?.id || session.subscription || null,
      subscription_status: sub?.status || null,
      plan: metadata.plan || null,
      planLabel: planLabel(metadata.plan || ""),
      termMonths: metadata.termMonths ? Number(metadata.termMonths) : null,
      devicesTotal: metadata.devicesTotal ? Number(metadata.devicesTotal) : null,
      extraDevices: metadata.extraDevices ? Number(metadata.extraDevices) : null,
      commitmentEndsAt: metadata.commitmentEndsAt ? Number(metadata.commitmentEndsAt) : null,
      items,
    });
  } catch (err) {
    console.error("session-status error:", err);
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// -------------------- CANCEL REQUEST (LOCAL + STRIPE FALLBACK) --------------------
app.post("/api/request-cancel", async (req, res) => {
  try {
    const { subscriptionId, email } = req.body || {};
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    let row = null;
    let db = null;

    try {
      db = await loadContracts();
      row = db.bySubscriptionId?.[subscriptionId] || null;
    } catch (_) {
      db = null;
      row = null;
    }

    let stripeSub = null;
    try {
      stripeSub = await stripe.subscriptions.retrieve(subscriptionId);
    } catch (e) {
      return res.status(404).json({ error: "Unknown subscriptionId (Stripe)" });
    }

    if (row?.email && email) {
      if (String(email).toLowerCase() !== String(row.email).toLowerCase()) {
        return res.status(403).json({ error: "Email mismatch" });
      }
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const commitmentEndsAt =
      (row && Number(row.commitmentEndsAt || 0)) ||
      (stripeSub?.metadata?.commitmentEndsAt ? Number(stripeSub.metadata.commitmentEndsAt) : 0);

    if (commitmentEndsAt && nowSec < commitmentEndsAt) {
      return res.status(400).json({
        error: "Commitment active - cannot cancel yet",
        commitmentEndsAt,
      });
    }

    const updated = await stripe.subscriptions.update(subscriptionId, { cancel_at_period_end: true });

    if (db) {
      const safeRow = row || {
        subscriptionId,
        email: row?.email || "",
        plan: row?.plan || stripeSub?.metadata?.plan || "",
        termMonths:
          row?.termMonths ||
          (stripeSub?.metadata?.termMonths ? Number(stripeSub.metadata.termMonths) : null),
        devicesTotal:
          row?.devicesTotal ||
          (stripeSub?.metadata?.devicesTotal ? Number(stripeSub.metadata.devicesTotal) : null),
        extraDevices:
          row?.extraDevices ||
          (stripeSub?.metadata?.extraDevices ? Number(stripeSub.metadata.extraDevices) : null),
        commitmentEndsAt: commitmentEndsAt || null,
        status: updated.status,
      };

      safeRow.cancelAtPeriodEnd = true;
      safeRow.cancelRequestedAt = Date.now();
      safeRow.updatedAt = Date.now();

      db.bySubscriptionId = db.bySubscriptionId || {};
      db.bySubscriptionId[subscriptionId] = safeRow;

      try {
        await saveContracts(db);
      } catch (e) {
        console.error("DB save failed (non-fatal):", e?.message || e);
      }

      if (safeRow.email) {
        await sendMailSafe({
          to: safeRow.email,
          subject: "Quantum ITech - Lemondás rögzítve",
          text:
            "A lemondási kérésedet rögzítettük.\n\n" +
            "Előfizetés azonosító: " + subscriptionId + "\n" +
            "Lemondás a periódus végén: " + String(updated.cancel_at_period_end) + "\n\n" +
            "Köszönjük,\nQuantum ITech",
        });
      }
    }

    return res.json({
      ok: true,
      subscriptionId,
      cancel_at_period_end: updated.cancel_at_period_end,
      status: updated.status,
      source: db ? "local+stripe" : "stripe-only",
    });
  } catch (err) {
    console.error("request-cancel error:", err);
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// ---------- Customer Portal session (Stripe Customer Portal) ----------
app.post("/api/create-portal-session", async (req, res) => {
  try {
    const { session_id, subscriptionId, email } = req.body || {};

    let customerId = null;

    if (session_id) {
      const session = await stripe.checkout.sessions.retrieve(String(session_id), {
        expand: ["subscription"],
      });

      customerId =
        (typeof session.customer === "string" && session.customer) ||
        (session.customer && session.customer.id) ||
        null;

      if (!customerId && session.subscription) {
        const subId =
          typeof session.subscription === "string"
            ? session.subscription
            : session.subscription.id;

        const sub = await stripe.subscriptions.retrieve(subId);
        customerId = typeof sub.customer === "string" ? sub.customer : sub.customer?.id || null;
      }
    }

    if (!customerId && subscriptionId) {
      try {
        const db = await loadContracts();
        const row = db.bySubscriptionId?.[String(subscriptionId)];
        if (row && row.customerId) customerId = String(row.customerId);
        if (row && email && row.email && String(email).toLowerCase() !== String(row.email).toLowerCase()) {
          return res.status(403).json({ error: "Email mismatch" });
        }
      } catch (_) {}

      if (!customerId) {
        const sub = await stripe.subscriptions.retrieve(String(subscriptionId));
        customerId = typeof sub.customer === "string" ? sub.customer : sub.customer?.id || null;
      }
    }

    if (!customerId) {
      return res.status(400).json({
        error: "Missing customer",
        details: "Adj meg session_id-t vagy subscriptionId-t.",
      });
    }

    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: process.env.PORTAL_RETURN_URL || process.env.WP_SUCCESS_URL || "https://quantumitech.hu/",
    });

    return res.json({ url: portalSession.url });
  } catch (err) {
    console.error("create-portal-session error:", err);
    return res.status(500).json({
      error: "Server error",
      details: err?.message || String(err),
    });
  }
});

// -------------------- MAGIC-LINK PORTAL FLOW --------------------
app.post("/api/portal/magic-request", async (req, res) => {
  try {
    const emailRaw = req.body && req.body.email;
    const email = normalizeEmail(emailRaw);
    if (!email || !email.includes("@")) {
      return res.status(400).json({ ok: false, error: "Invalid email" });
    }

    const customer = await findCustomerByEmail(email);

    // mindig ugyanazt válaszoljuk (ne lehessen emailt "kitalálni")
    if (customer) {
      const token = signMagicToken(email, 10 * 60);

      const fallbackBase = `${req.protocol}://${req.get("host")}`;
      const base = (process.env.FRONTEND_BASE || fallbackBase).replace(/\/+$/g, "");

      const magicUrl = `${base}/api/portal/magic?token=${encodeURIComponent(token)}`;

      const subject = "Quantum ITech - Belépő link az ügyfélportálhoz";
      const text =
`Szia!

Kattints a lenti linkre az ügyfélportál megnyitásához (a link 10 percig érvényes):
${magicUrl}

Ha nem te kérted, hagyd figyelmen kívül ezt az üzenetet.

Üdv,
Quantum ITech`;

      const html =
`<p>Szia!</p>
<p>Kattints a belépéshez (a link 10 percig érvényes):</p>
<p><a href="${magicUrl}">Belépés</a></p>
<p>Ha nem te kérted, hagyd figyelmen kívül.</p>
<p>Üdv,<br/>Quantum ITech</p>`;

      await sendMailSafe({ to: email, subject, text, html });
    }

    return res.json({
      ok: true,
      message: "Ha létezik előfizetés ehhez az emailhez, elküldtük a belépő linket."
    });
  } catch (e) {
    console.error("magic-request error:", e);
    return res.status(500).json({ ok: false, error: "Server error", details: e?.message || String(e) });
  }
});

app.get("/api/portal/magic", async (req, res) => {
  try {
    const token = String(req.query.token || "");
    if (!token) return res.status(400).send("Missing token");

    const { email } = verifyMagicToken(token);

    const customer = await findCustomerByEmail(email);
    if (!customer) {
      const returnUrl = process.env.PORTAL_RETURN_URL || process.env.WP_SUCCESS_URL || "/";
      return res.redirect(`${returnUrl}?portal_error=no_customer`);
    }

    const returnUrl = process.env.PORTAL_RETURN_URL || process.env.WP_SUCCESS_URL || "https://quantumitech.hu/";

    const session = await stripe.billingPortal.sessions.create({
      customer: customer.id,
      return_url: returnUrl,
    });

    return res.redirect(302, session.url);
  } catch (e) {
    console.error("magic consume error:", e?.message || e);
    const returnUrl = process.env.PORTAL_RETURN_URL || process.env.WP_SUCCESS_URL || "/";
    return res.redirect(`${returnUrl}?portal_error=invalid_token`);
  }
});

// -------------------- START --------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on :${port}, DATA_DIR=${DATA_DIR}`));
