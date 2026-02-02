require("dotenv").config();

const express = require("express");
const cors = require("cors");
const fs = require("fs-extra");
const path = require("path");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

const app = express();

// 1) Stripe init
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ---------- CORS ----------
const corsOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, cb) {
      // origin nélküli requestek (pl. curl, stripe webhook) -> engedjük
      if (!origin) return cb(null, true);

      if (!corsOrigins.length) return cb(null, true);

      if (corsOrigins.includes(origin)) return cb(null, true);

      return cb(new Error("Not allowed by CORS: " + origin));
    },
    methods: ["POST", "GET"],
    credentials: true,
  })
);

// ---------- JSON body (NEM webhookhoz!) ----------
// Webhook RAW kell -> azt külön route kezeli.
// Itt kivesszük a webhook útvonalat a JSON parserből.
app.use((req, res, next) => {
  if (req.originalUrl === "/api/stripe/webhook") return next();
  return express.json()(req, res, next);
});

// ---------- “DB” (JSON fájl) ----------
const DATA_DIR = path.join(__dirname, "data");
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
  await fs.writeJson(CONTRACTS_FILE, db, { spaces: 2 });
}

// ---------- Helpers ----------
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

// commitment vége unix timestamp (másodperc)
// (Egyszerű közelítés 30 napos hónapokkal)
function calcCommitmentEndsAt(termMonths) {
  const nowSec = Math.floor(Date.now() / 1000);
  return nowSec + termMonths * 30 * 24 * 60 * 60;
}

function planLabel(plan) {
  if (plan === "basic") return "Alapcsomag";
  if (plan === "premium") return "Prémiumcsomag";
  return plan || "";
}

// ---------- Email (SMTP) ----------
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
      console.log("MAIL: SMTP not configured, skipping email send.");
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
    console.error("MAIL: send failed:", e?.message || e);
  }
}

// ---------- Admin auth ----------
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

// ---------- Health ----------
app.get("/", (req, res) => {
  res.json({ ok: true, service: "quantum-stripe-backend" });
});

// ---------- Admin: contracts list ----------
app.get("/admin/contracts", requireAdmin, async (req, res) => {
  try {
    const db = await loadContracts();
    const rows = Object.values(db.bySubscriptionId || {}).sort(
      (a, b) => (b.updatedAt || 0) - (a.updatedAt || 0)
    );
    return res.json({ ok: true, count: rows.length, rows });
  } catch (e) {
    return res.status(500).json({ error: "Server error", details: e?.message || String(e) });
  }
});

app.get("/admin/contracts/:subscriptionId", requireAdmin, async (req, res) => {
  try {
    const subscriptionId = String(req.params.subscriptionId || "").trim();
    const db = await loadContracts();
    const row = db.bySubscriptionId[subscriptionId];
    if (!row) return res.status(404).json({ error: "Not found" });
    return res.json({ ok: true, row });
  } catch (e) {
    return res.status(500).json({ error: "Server error", details: e?.message || String(e) });
  }
});

// ---------- Create Checkout Session ----------
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

    // eszközök: minimum 1, maximum 1000
    const totalDevices = clampInt(devicesTotal, 1, 1000);

    // 25 benne van, afölött extra
    const included = 25;
    const extraDevices = Math.max(0, totalDevices - included);

    const monthlyPrice = getMonthlyPriceId(plan);
    const devicePrice = getDevicePriceId(plan);

    if (!monthlyPrice || !devicePrice) {
      return res.status(500).json({ error: "Missing PRICE env vars for plan" });
    }

    const commitmentEndsAt = calcCommitmentEndsAt(term);

    const lineItems = [{ price: monthlyPrice, quantity: 1 }];

    if (extraDevices > 0) {
      lineItems.push({ price: devicePrice, quantity: extraDevices });
    }

    // Setup fee csak 12 hónapnál (one-time price!)
    if (term === 12) {
      const setupFee = getSetupFeePriceId(plan);
      if (!setupFee) {
        return res.status(500).json({ error: "Missing setup fee price env var" });
      }
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

// ---------- Stripe Webhook (RAW BODY!) ----------
app.post(
  "/api/stripe/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        sig,
        process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      console.error("Webhook signature verify failed:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      const db = await loadContracts();

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

        await saveContracts(db);
      };

      switch (event.type) {
        case "checkout.session.completed": {
          const session = event.data.object;

          const subscriptionId = session.subscription;
          const customerId = session.customer;

          console.log("checkout.session.completed", {
            email: session.customer_email,
            subscription: subscriptionId,
            metadata: session.metadata,
          });

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

          // Email: megrendelés visszaigazolás
          const to = session.customer_email || "";
          if (to) {
            const p = session.metadata?.plan || "";
            const tm = session.metadata?.termMonths || "";
            const dv = session.metadata?.devicesTotal || "";
            const ce = session.metadata?.commitmentEndsAt || "";

            await sendMailSafe({
              to,
              subject: "Quantum ITech - Sikeres előfizetés",
              text:
                "Sikeres fizetés és előfizetés létrejött.\n\n" +
                "Csomag: " + planLabel(p) + "\n" +
                "Szerződés hossza (hó): " + tm + "\n" +
                "Eszközök száma: " + dv + "\n" +
                "Előfizetés azonosító: " + subscriptionId + "\n" +
                "Minimum szerződés vége (unix sec): " + ce + "\n\n" +
                "Köszönjük,\nQuantum ITech",
            });
          }

          break;
        }

        case "invoice.payment_succeeded": {
          const invoice = event.data.object;

          const subscriptionId =
            invoice.subscription ||
            invoice.lines?.data?.[0]?.subscription ||
            null;

          console.log("invoice.payment_succeeded", {
            customer: invoice.customer,
            subscription: subscriptionId,
            amount_paid: invoice.amount_paid,
          });

          await upsertBySubscription(subscriptionId, {
            status: "active",
            lastPaymentAt: Date.now(),
            lastInvoiceId: invoice.id,
            lastEvent: "invoice.payment_succeeded",
            updatedAt: Date.now(),
          });

          // Email: sikeres számla (opcionális, nem spam-eljük túl)
          // Ha akarod, bekapcsoljuk külön flaggel.
          break;
        }

        case "invoice.payment_failed": {
          const invoice = event.data.object;

          const subscriptionId =
            invoice.subscription ||
            invoice.lines?.data?.[0]?.subscription ||
            null;

          console.log("invoice.payment_failed", {
            customer: invoice.customer,
            subscription: subscriptionId,
          });

          await upsertBySubscription(subscriptionId, {
            status: "past_due",
            lastEvent: "invoice.payment_failed",
            updatedAt: Date.now(),
          });

          break;
        }

        case "customer.subscription.deleted": {
          const sub = event.data.object;

          console.log("customer.subscription.deleted", {
            id: sub.id,
            status: sub.status,
          });

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
      return res.status(500).send("Webhook handler error");
    }
  }
);

// ---------- Success page helper: session status ----------
app.get("/api/session-status", async (req, res) => {
  try {
    const sessionId = String(req.query.session_id || "").trim();
    if (!sessionId) return res.status(400).json({ error: "Missing session_id" });

    const session = await stripe.checkout.sessions.retrieve(sessionId, {
      expand: ["subscription", "line_items.data.price.product"],
    });

    const paid = session.payment_status === "paid" || session.status === "complete";

    const metadata = session.metadata || {};
    const sub =
      session.subscription && typeof session.subscription === "object"
        ? session.subscription
        : null;

    const commitmentEndsAt = Number(metadata.commitmentEndsAt || 0);

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
      commitmentEndsAt: commitmentEndsAt || null,
      items,
    });
  } catch (err) {
    console.error("session-status error:", err);
    return res.status(500).json({
      error: "Server error",
      details: err?.message || String(err),
    });
  }
});

// ---------- Subscription status from local DB ----------
app.get("/api/subscription-status", async (req, res) => {
  try {
    const subscriptionId = String(req.query.subscriptionId || "").trim();
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    const db = await loadContracts();
    const row = db.bySubscriptionId[subscriptionId];

    if (!row) return res.status(404).json({ error: "Unknown subscriptionId" });

    return res.json({
      ok: true,
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
  } catch (err) {
    return res.status(500).json({
      error: "Server error",
      details: err?.message || String(err),
    });
  }
});

// ---------- Cancel request (commitment után) ----------
app.post("/api/request-cancel", async (req, res) => {
  try {
    const { subscriptionId, email } = req.body || {};
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    const db = await loadContracts();
    const row = db.bySubscriptionId[subscriptionId];

    if (!row) return res.status(404).json({ error: "Unknown subscriptionId" });

    if (email && row.email && String(email).toLowerCase() !== String(row.email).toLowerCase()) {
      return res.status(403).json({ error: "Email mismatch" });
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const commitmentEndsAt = Number(row.commitmentEndsAt || 0);

    if (commitmentEndsAt && nowSec < commitmentEndsAt) {
      return res.status(400).json({
        error: "Commitment active - cannot cancel yet",
        commitmentEndsAt,
      });
    }

    // Lemondás a következő periódus végére
    const updated = await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true,
    });

    row.cancelAtPeriodEnd = true;
    row.cancelRequestedAt = Date.now();
    row.updatedAt = Date.now();

    db.bySubscriptionId[subscriptionId] = row;
    if (row.contractId) db.byContractId[row.contractId] = row;

    await saveContracts(db);

    // Email: lemondási visszaigazolás
    if (row.email) {
      await sendMailSafe({
        to: row.email,
        subject: "Quantum ITech - Lemondás rögzítve",
        text:
          "A lemondási kérésedet rögzítettük.\n\n" +
          "Előfizetés azonosító: " + subscriptionId + "\n" +
          "Lemondás a periódus végén: " + String(updated.cancel_at_period_end) + "\n\n" +
          "Köszönjük,\nQuantum ITech",
      });
    }

    return res.json({
      ok: true,
      subscriptionId,
      cancel_at_period_end: updated.cancel_at_period_end,
    });
  } catch (err) {
    console.error("request-cancel error:", err);
    return res.status(500).json({
      error: "Server error",
      details: err?.message || String(err),
    });
  }
});

// ---------- Start ----------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on :${port}`));
