require("dotenv").config();

const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");
const nodemailer = require("nodemailer");

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ---------- CORS ----------
const corsOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: function (origin, cb) {
      // origin nélküli requestek (Stripe webhook, curl) -> engedjük
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
app.use((req, res, next) => {
  if (req.originalUrl === "/api/stripe/webhook") return next();
  return express.json()(req, res, next);
});

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

// commitment vége unix timestamp (másodperc) - egyszerű 30 napos hónap közelítés
function calcCommitmentEndsAt(termMonths) {
  const nowSec = Math.floor(Date.now() / 1000);
  return nowSec + termMonths * 30 * 24 * 60 * 60;
}

function planLabel(plan) {
  if (plan === "basic") return "Alapcsomag";
  if (plan === "premium") return "Prémiumcsomag";
  return plan || "";
}

// ---------- Email (SMTP) - opcionális ----------
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
    if (!transporter) return; // nincs SMTP beállítva

    await transporter.sendMail({
      from: process.env.MAIL_FROM || "no-reply@example.com",
      to,
      subject,
      text,
    });
  } catch (e) {
    console.error("MAIL send failed:", e?.message || e);
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
  res.json({ ok: true, service: "quantum-stripe-backend (stripe-only)" });
});

// ---------- Admin: Stripe subscription list ----------
app.get("/api/admin/subscriptions", requireAdmin, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 1, 100);
    const status = String(req.query.status || "all"); // all | active | canceled | etc.

    const params = { limit };
    if (status !== "all") params.status = status;

    // expand: customer, hogy email is legyen
    const list = await stripe.subscriptions.list({
      ...params,
      expand: ["data.customer"],
    });

    const items = (list.data || []).map((s) => {
      const customer = s.customer && typeof s.customer === "object" ? s.customer : null;
      return {
        id: s.id,
        status: s.status,
        cancel_at_period_end: !!s.cancel_at_period_end,
        current_period_end: s.current_period_end,
        created: s.created,
        customerId: customer?.id || (typeof s.customer === "string" ? s.customer : null),
        email: customer?.email || null,
        metadata: s.metadata || {},
      };
    });

    return res.json({ ok: true, count: items.length, items });
  } catch (e) {
    console.error("admin/subscriptions error:", e);
    return res.status(500).json({ error: "Server error", details: e?.message || String(e) });
  }
});

// ---------- Admin: Stripe subscription detail ----------
app.get("/api/admin/subscription/:id", requireAdmin, async (req, res) => {
  try {
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ error: "Missing id" });

    const sub = await stripe.subscriptions.retrieve(id, {
      expand: ["customer", "items.data.price.product"],
    });

    const customer = sub.customer && typeof sub.customer === "object" ? sub.customer : null;

    return res.json({
      ok: true,
      subscription: {
        id: sub.id,
        status: sub.status,
        cancel_at_period_end: !!sub.cancel_at_period_end,
        current_period_end: sub.current_period_end,
        created: sub.created,
        customerId: customer?.id || (typeof sub.customer === "string" ? sub.customer : null),
        email: customer?.email || null,
        metadata: sub.metadata || {},
        items: (sub.items?.data || []).map((it) => ({
          priceId: it.price?.id,
          nickname: it.price?.nickname || null,
          product: it.price?.product || null,
          quantity: it.quantity || 0,
        })),
      },
    });
  } catch (e) {
    console.error("admin/subscription/:id error:", e);
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
    if (extraDevices > 0) {
      lineItems.push({ price: devicePrice, quantity: extraDevices });
    }

    if (term === 12) {
      const setupFee = getSetupFeePriceId(plan);
      if (!setupFee) {
        return res.status(500).json({ error: "Missing setup fee price env var" });
      }
      lineItems.push({ price: setupFee, quantity: 1 });
    }

    const meta = {
      contractId: contractId ? String(contractId) : "",
      plan: String(plan),
      termMonths: String(term),
      devicesTotal: String(totalDevices),
      extraDevices: String(extraDevices),
      commitmentEndsAt: String(commitmentEndsAt),
    };

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer_email: email,
      line_items: lineItems,
      success_url: `${process.env.WP_SUCCESS_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: process.env.WP_CANCEL_URL,

      // FONTOS: a subscription metadata ide kerül -> később Stripe-only lemondásnál ebből dolgozunk
      subscription_data: { metadata: meta },
      metadata: meta,
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
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error("Webhook signature verify failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const subscriptionId = session.subscription;

        console.log("✅ checkout.session.completed", {
          email: session.customer_email,
          subscription: subscriptionId,
          metadata: session.metadata,
        });

        // opcionális email
        if (session.customer_email) {
          await sendMailSafe({
            to: session.customer_email,
            subject: "Quantum ITech - Sikeres előfizetés",
            text:
              "Sikeres fizetés és előfizetés létrejött.\n\n" +
              "Csomag: " + planLabel(session.metadata?.plan || "") + "\n" +
              "Szerződés hossza (hó): " + (session.metadata?.termMonths || "") + "\n" +
              "Eszközök száma: " + (session.metadata?.devicesTotal || "") + "\n" +
              "Előfizetés azonosító: " + subscriptionId + "\n\n" +
              "Köszönjük,\nQuantum ITech",
          });
        }
        break;
      }

      case "invoice.payment_succeeded":
      case "invoice.payment_failed":
      case "customer.subscription.deleted":
      default:
        break;
    }

    return res.json({ received: true });
  } catch (err) {
    console.error("Webhook handler error:", err);
    return res.status(500).send("Webhook handler error");
  }
});

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
      session.subscription && typeof session.subscription === "object" ? session.subscription : null;

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
      items: (session.line_items?.data || []).map((li) => ({
        description: li.description || li.price?.nickname || li.price?.id || "",
        quantity: li.quantity || 0,
        amount_total: li.amount_total || 0,
        currency: li.currency || "",
      })),
    });
  } catch (err) {
    console.error("session-status error:", err);
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// ---------- Subscription status (Stripe-only) ----------
app.get("/api/subscription-status", async (req, res) => {
  try {
    const subscriptionId = String(req.query.subscriptionId || "").trim();
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    const sub = await stripe.subscriptions.retrieve(subscriptionId, { expand: ["customer"] });
    const customer = sub.customer && typeof sub.customer === "object" ? sub.customer : null;

    return res.json({
      ok: true,
      subscriptionId: sub.id,
      email: customer?.email || null,
      status: sub.status,
      cancelAtPeriodEnd: !!sub.cancel_at_period_end,
      currentPeriodEnd: sub.current_period_end,
      metadata: sub.metadata || {},
    });
  } catch (err) {
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// ---------- Cancel request (Stripe-only + commitment metadata alapján) ----------
app.post("/api/request-cancel", async (req, res) => {
  try {
    const { subscriptionId, email } = req.body || {};
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    const sub = await stripe.subscriptions.retrieve(subscriptionId, { expand: ["customer"] });
    const customer = sub.customer && typeof sub.customer === "object" ? sub.customer : null;

    // email ellenőrzés (ha küldesz emailt)
    if (email && customer?.email) {
      if (String(email).toLowerCase() !== String(customer.email).toLowerCase()) {
        return res.status(403).json({ error: "Email mismatch" });
      }
    }

    // commitment ellenőrzés a subscription metadata alapján
    const nowSec = Math.floor(Date.now() / 1000);
    const commitmentEndsAt = Number(sub.metadata?.commitmentEndsAt || 0);

    if (commitmentEndsAt && nowSec < commitmentEndsAt) {
      return res.status(400).json({
        error: "Commitment active - cannot cancel yet",
        commitmentEndsAt,
      });
    }

    const updated = await stripe.subscriptions.update(subscriptionId, {
      cancel_at_period_end: true,
    });

    // opcionális email a lemondásról
    if (customer?.email) {
      await sendMailSafe({
        to: customer.email,
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
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// ---------- Start ----------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on :${port}`));
