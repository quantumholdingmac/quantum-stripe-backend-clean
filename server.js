// server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const fs = require("fs-extra");
const path = require("path");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

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
  const buf = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(String(bufOrStr), "utf8");
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

// -------------------- EMAIL (SMTP optional) --------------------
function getMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || "587");
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) return null;

  return nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass },
  });
}

async function sendMailSafe({ to, subject, text }) {
  try {
    const transporter = getMailer();
    if (!transporter) {
      console.log("MAIL: SMTP not configured -> skip");
      return;
    }
    await transporter.sendMail({
      from: process.env.MAIL_FROM || "no-reply@example.com",
      to,
      subject,
      text,
    });
    console.log("MAIL: sent to", to);
  } catch (e) {
    console.error("MAIL: failed:", e?.message || e);
  }
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

// -------------------- CHECKOUT SESSION --------------------
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

  // fontos: sose 500-azzunk fájlírás miatt -> külön try/catch
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
      // nem dobunk tovább -> Stripe kapjon 200-at
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
    // még itt is inkább 200, hogy Stripe ne pörgesse végtelen újraküldéssel
    return res.json({ received: true, warning: "handler error (logged)" });
  }
});

// -------------------- ADMIN API (JSON + Stripe fallback) --------------------
app.get("/api/admin/contracts", requireAdmin, async (req, res) => {
  try {
    // 1) próbáljuk helyi DB-ből
    let local = [];
    try {
      const db = await loadContracts();
      local = Object.values(db.bySubscriptionId || {}).sort(
        (a, b) => (b.updatedAt || 0) - (a.updatedAt || 0)
      );
    } catch (_) {
      local = [];
    }

    // 2) ha üres, kérhetünk Stripe listát is (opcionális)
    // query: ?source=stripe
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

    // local
    try {
      const db = await loadContracts();
      const row = db.bySubscriptionId?.[subscriptionId];
      if (row) return res.json({ ok: true, source: "local", item: row });
    } catch (_) {}

    // stripe fallback
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

// -------------------- subscription-status (LOCAL + STRIPE FALLBACK) --------------------
app.get("/api/subscription-status", async (req, res) => {
  try {
    const subscriptionId = String(req.query.subscriptionId || "").trim();
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    // 1) local
    try {
      const db = await loadContracts();
      const row = db.bySubscriptionId?.[subscriptionId];
      if (row) {
        return res.json({
          ok: true,
          source: "local",
          subscriptionId,
          email: row.email || "",
          plan: row.plan || "",
          planLabel: planLabel(row.plan || ""),
          termMonths: row.termMonths || null,
          devicesTotal: row.devicesTotal || null,
          extraDevices: row.extraDevices || null,
          commitmentEndsAt: row.commitmentEndsAt || null,
          cancelAtPeriodEnd: !!row.cancelAtPeriodEnd,
          status: row.status || "",
          updatedAt: row.updatedAt || null,
        });
      }
    } catch (_) {}

    // 2) stripe fallback
    const sub = await stripe.subscriptions.retrieve(subscriptionId);
    return res.json({
      ok: true,
      source: "stripe",
      subscriptionId: sub.id,
      email: null,
      plan: sub.metadata?.plan || "",
      planLabel: planLabel(sub.metadata?.plan || ""),
      termMonths: sub.metadata?.termMonths ? Number(sub.metadata.termMonths) : null,
      devicesTotal: sub.metadata?.devicesTotal ? Number(sub.metadata.devicesTotal) : null,
      extraDevices: sub.metadata?.extraDevices ? Number(sub.metadata.extraDevices) : null,
      commitmentEndsAt: sub.metadata?.commitmentEndsAt ? Number(sub.metadata.commitmentEndsAt) : null,
      cancelAtPeriodEnd: !!sub.cancel_at_period_end,
      status: sub.status,
      updatedAt: null,
    });
  } catch (err) {
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// -------------------- CANCEL REQUEST (LOCAL + STRIPE FALLBACK) --------------------
app.post("/api/request-cancel", async (req, res) => {
  try {
    const { subscriptionId, email } = req.body || {};
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    // 1) próbáljuk localból
    let row = null;
    let db = null;

    try {
      db = await loadContracts();
      row = db.bySubscriptionId?.[subscriptionId] || null;
    } catch (_) {
      db = null;
      row = null;
    }

    // 2) ha local nincs: Stripe fallback retrieve
    let stripeSub = null;
    try {
      stripeSub = await stripe.subscriptions.retrieve(subscriptionId);
    } catch (e) {
      return res.status(404).json({ error: "Unknown subscriptionId (Stripe)" });
    }

    // Email check: ha localban van email, ellenőrizzük; stripe fallbacknél ezt nem tudjuk biztosan
    if (row?.email && email) {
      if (String(email).toLowerCase() !== String(row.email).toLowerCase()) {
        return res.status(403).json({ error: "Email mismatch" });
      }
    }

    // Commitment ellenőrzés: local -> row.commitmentEndsAt, stripe -> metadata.commitmentEndsAt
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

    // Lemondás a periódus végére
    const updated = await stripe.subscriptions.update(subscriptionId, { cancel_at_period_end: true });

    // Local DB frissítés, ha van
    if (db) {
      const safeRow = row || {
        subscriptionId,
        email: row?.email || "",
        plan: row?.plan || stripeSub?.metadata?.plan || "",
        termMonths: row?.termMonths || (stripeSub?.metadata?.termMonths ? Number(stripeSub.metadata.termMonths) : null),
        devicesTotal: row?.devicesTotal || (stripeSub?.metadata?.devicesTotal ? Number(stripeSub.metadata.devicesTotal) : null),
        extraDevices: row?.extraDevices || (stripeSub?.metadata?.extraDevices ? Number(stripeSub.metadata.extraDevices) : null),
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

    // A) Ha van session_id (success oldalról a legjobb)
    if (session_id) {
      const session = await stripe.checkout.sessions.retrieve(String(session_id), {
        expand: ["subscription"],
      });

      customerId =
        (typeof session.customer === "string" && session.customer) ||
        (session.customer && session.customer.id) ||
        null;

      // fallback: ha customerId még sincs
      if (!customerId && session.subscription) {
        const subId =
          typeof session.subscription === "string"
            ? session.subscription
            : session.subscription.id;

        const sub = await stripe.subscriptions.retrieve(subId);
        customerId = typeof sub.customer === "string" ? sub.customer : sub.customer?.id || null;
      }
    }

    // B) Ha nincs session_id, de van subscriptionId (és/vagy email)
    if (!customerId && subscriptionId) {
      // 1) próbáljuk a helyi JSON-ból (ha van nálad db)
      try {
        const db = await loadContracts();
        const row = db.bySubscriptionId?.[String(subscriptionId)];
        if (row && row.customerId) customerId = String(row.customerId);
        // ha email megadva, ellenőrizheted (opcionális)
        if (row && email && row.email && String(email).toLowerCase() !== String(row.email).toLowerCase()) {
          return res.status(403).json({ error: "Email mismatch" });
        }
      } catch (_) {}

      // 2) Stripe fallback: subscription-ből kinyerjük a customer-t
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
    }); // :contentReference[oaicite:1]{index=1}

    return res.json({ url: portalSession.url });
  } catch (err) {
    console.error("create-portal-session error:", err);
    return res.status(500).json({
      error: "Server error",
      details: err?.message || String(err),
    });
  }
});

// -------------------- NEW: MAGIC-LINK PORTAL FLOW --------------------
// POST /api/portal/magic-request  { email }
// GET  /api/portal/magic?token=...  -> redirect to portal
// --------------------

app.post("/api/portal/magic-request", async (req, res) => {
  try {
    const emailRaw = req.body && req.body.email;
    const email = normalizeEmail(emailRaw);
    if (!email || !email.includes("@")) {
      return res.status(400).json({ ok: false, error: "Invalid email" });
    }

    // Find Stripe customer
    const customer = await findCustomerByEmail(email);

    // Always return generic ok to avoid email enumeration,
    // but only send email if customer exists.
    if (customer) {
      // sign token (10 minutes)
      const token = signMagicToken(email, 10 * 60);
      // Build magic URL - use request host + protocol so Render path works.
      // If you prefer absolute external URL, set FRONTEND_BASE env and use it.
      const host = req.get("host");
      const proto = req.protocol || "https";
      const magicUrl = `${proto}://${host}/api/portal/magic?token=${encodeURIComponent(token)}`;

      const subject = "Quantum ITech - Belépő link az ügyfélportálhoz";
      const text =
`Szia!

Kattints a lenti linkre az ügyfélportál megnyitásához (a link 10 percig érvényes):
${magicUrl}

Ha nem te kérted, hagyd figyelmen kívül ezt az üzenetet.

Üdv,
Quantum ITech`;

      // send via configured SMTP (if available)
      await sendMailSafe({ to: email, subject, text });
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

    // Find Stripe customer
    const customer = await findCustomerByEmail(email);
    if (!customer) {
      // Redirect to frontend portal page with error query (or show text)
      const returnUrl = process.env.PORTAL_RETURN_URL || process.env.WP_SUCCESS_URL || "/";
      // Optionally attach error query
      return res.redirect(`${returnUrl}?portal_error=no_customer`);
    }

    const returnUrl = process.env.PORTAL_RETURN_URL || process.env.WP_SUCCESS_URL || "https://quantumitech.hu/";

    const session = await stripe.billingPortal.sessions.create({
      customer: customer.id,
      return_url: returnUrl
    });

    return res.redirect(302, session.url);
  } catch (e) {
    console.error("magic consume error:", e?.message || e);
    // Redirect back to portal page with error param to show message
    const returnUrl = process.env.PORTAL_RETURN_URL || process.env.WP_SUCCESS_URL || "/";
    return res.redirect(`${returnUrl}?portal_error=invalid_token`);
  }
});

// -------------------- START --------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on :${port}, DATA_DIR=${DATA_DIR}`));
