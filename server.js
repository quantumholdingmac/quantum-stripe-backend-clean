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
      // origin nélküli requestek (pl. curl, stripe webhook) -> engedjük
      if (!origin) return cb(null, true);

      if (!corsOrigins.length) return cb(null, true;

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

function planLabel(plan) {
  if (plan === "basic") return "Alapcsomag";
  if (plan === "premium") return "Prémiumcsomag";
  return plan || "";
}

// commitment vége unix timestamp (másodperc) - egyszerű 30 nap/hó közelítés
function calcCommitmentEndsAt(termMonths) {
  const nowSec = Math.floor(Date.now() / 1000);
  return nowSec + termMonths * 30 * 24 * 60 * 60;
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

// ---------- Stripe helpers ----------
async function getSubscriptionWithCustomer(subscriptionId) {
  return stripe.subscriptions.retrieve(subscriptionId, {
    expand: ["customer", "latest_invoice", "latest_invoice.payment_intent"],
  });
}

function normalizeSubscription(sub) {
  const md = sub.metadata || {};
  const customer = sub.customer && typeof sub.customer === "object" ? sub.customer : null;

  const commitmentEndsAt = Number(md.commitmentEndsAt || 0) || 0;

  return {
    subscriptionId: sub.id,
    status: sub.status,
    cancelAtPeriodEnd: !!sub.cancel_at_period_end,
    currentPeriodEnd: sub.current_period_end ? Number(sub.current_period_end) : null,
    currentPeriodStart: sub.current_period_start ? Number(sub.current_period_start) : null,

    customerId: customer?.id || (typeof sub.customer === "string" ? sub.customer : null),
    email: customer?.email || md.email || "",

    plan: md.plan || "",
    planLabel: planLabel(md.plan || ""),
    termMonths: md.termMonths ? Number(md.termMonths) : null,
    devicesTotal: md.devicesTotal ? Number(md.devicesTotal) : null,
    extraDevices: md.extraDevices ? Number(md.extraDevices) : null,
    commitmentEndsAt: commitmentEndsAt || null,

    created: sub.created ? Number(sub.created) : null,
  };
}

// ---------- Health ----------
app.get("/", (req, res) => {
  res.json({ ok: true, service: "quantum-stripe-backend", storage: "stripe-only" });
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
    if (extraDevices > 0) lineItems.push({ price: devicePrice, quantity: extraDevices });

    // Setup fee csak 12 hónapnál
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

      // MINDENT metadata-ba, mert Stripe-ONLY lesz
      subscription_data: {
        metadata: {
          contractId: contractId ? String(contractId) : "",
          email: String(email),
          plan: String(plan),
          termMonths: String(term),
          devicesTotal: String(totalDevices),
          extraDevices: String(extraDevices),
          commitmentEndsAt: String(commitmentEndsAt),
        },
      },

      metadata: {
        contractId: contractId ? String(contractId) : "",
        email: String(email),
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

          console.log("checkout.session.completed", {
            email: session.customer_email,
            subscription: subscriptionId,
          });

          // Email: visszaigazolás (ha van SMTP)
          const to = session.customer_email || "";
          if (to && subscriptionId) {
            // Itt már kérhetjük a subscription-t metadata miatt (Stripe-ONLY)
            let sub = null;
            try {
              sub = await getSubscriptionWithCustomer(subscriptionId);
            } catch (e) {
              console.log("Webhook: cannot retrieve sub for email, continuing:", e?.message || e);
            }

            const md = sub?.metadata || session.metadata || {};

            await sendMailSafe({
              to,
              subject: "Quantum ITech - Sikeres előfizetés",
              text:
                "Sikeres fizetés és előfizetés létrejött.\n\n" +
                "Csomag: " + planLabel(md.plan || "") + "\n" +
                "Szerződés hossza (hó): " + (md.termMonths || "") + "\n" +
                "Eszközök száma: " + (md.devicesTotal || "") + "\n" +
                "Előfizetés azonosító: " + subscriptionId + "\n\n" +
                "Köszönjük,\nQuantum ITech",
            });
          }

          break;
        }

        case "invoice.payment_succeeded": {
          const invoice = event.data.object;
          console.log("invoice.payment_succeeded", { invoiceId: invoice.id, sub: invoice.subscription });
          break;
        }

        case "invoice.payment_failed": {
          const invoice = event.data.object;
          console.log("invoice.payment_failed", { invoiceId: invoice.id, sub: invoice.subscription });
          break;
        }

        case "customer.subscription.deleted": {
          const sub = event.data.object;
          console.log("customer.subscription.deleted", { id: sub.id, status: sub.status });
          break;
        }

        default:
          break;
      }

      // fontos: mindig 200-at adjunk, különben Stripe újraküld
      return res.json({ received: true });
    } catch (err) {
      console.error("Webhook handler error:", err);
      // még itt is jobb 200-at adni, hogy ne floodoljon
      return res.json({ received: true, warning: "handler_error_logged" });
    }
  }
);

// ---------- Admin: Stripe-ONLY lista ----------
app.get("/api/admin/subscriptions", requireAdmin, async (req, res) => {
  try {
    const limit = clampInt(req.query.limit, 1, 100);
    const startingAfter = req.query.starting_after ? String(req.query.starting_after) : undefined;

    const resp = await stripe.subscriptions.list({
      limit,
      ...(startingAfter ? { starting_after: startingAfter } : {}),
      // Stripe list nem expand-eli tömegesen jól a customer-t, ezért az emailt metadata-ból is adjuk
    });

    const items = resp.data.map((sub) => ({
      subscriptionId: sub.id,
      status: sub.status,
      cancelAtPeriodEnd: !!sub.cancel_at_period_end,
      currentPeriodEnd: sub.current_period_end ? Number(sub.current_period_end) : null,
      customerId: typeof sub.customer === "string" ? sub.customer : (sub.customer?.id || null),
      email: sub.metadata?.email || "",
      plan: sub.metadata?.plan || "",
      planLabel: planLabel(sub.metadata?.plan || ""),
      termMonths: sub.metadata?.termMonths ? Number(sub.metadata.termMonths) : null,
      devicesTotal: sub.metadata?.devicesTotal ? Number(sub.metadata.devicesTotal) : null,
      extraDevices: sub.metadata?.extraDevices ? Number(sub.metadata.extraDevices) : null,
      commitmentEndsAt: sub.metadata?.commitmentEndsAt ? Number(sub.metadata.commitmentEndsAt) : null,
      created: sub.created ? Number(sub.created) : null,
    }));

    return res.json({
      ok: true,
      count: items.length,
      has_more: !!resp.has_more,
      items,
    });
  } catch (err) {
    console.error("admin/subscriptions error:", err);
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// ---------- Admin: egy subscription részletesen ----------
app.get("/api/admin/subscriptions/:subscriptionId", requireAdmin, async (req, res) => {
  try {
    const subscriptionId = String(req.params.subscriptionId || "").trim();
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    const sub = await getSubscriptionWithCustomer(subscriptionId);
    return res.json({ ok: true, item: normalizeSubscription(sub) });
  } catch (err) {
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
  }
});

// ---------- Public: subscription status (Stripe-ONLY) ----------
app.get("/api/subscription-status", async (req, res) => {
  try {
    const subscriptionId = String(req.query.subscriptionId || "").trim();
    if (!subscriptionId) return res.status(400).json({ error: "Missing subscriptionId" });

    const sub = await getSubscriptionWithCustomer(subscriptionId);
    return res.json({ ok: true, ...normalizeSubscription(sub) });
  } catch (err) {
    return res.status(500).json({ error: "Server error", details: err?.message || String(err) });
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
      session.subscription && typeof session.subscription === "object"
        ? session.subscription
        : null;

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
    return res.status(500).json({
      error: "Server error",
      details: err?.message || String(err),
    });
  }
});

// ---------- Cancel request (Stripe-ONLY + fallback) ----------
app.post("/api/request-cancel", async (req, res) => {
  try {
    const { subscriptionId, email } = req.body || {};
    const subId = String(subscriptionId || "").trim();
    if (!subId) return res.status(400).json({ error: "Missing subscriptionId" });

    const sub = await getSubscriptionWithCustomer(subId);
    const customer = sub.customer && typeof sub.customer === "object" ? sub.customer : null;

    // email ellenőrzés: ha megadta a user, próbáljuk validálni customer.email alapján
    // fallback: ha a customer.email üres, akkor nem tiltunk (Stripe-ONLY világban ez előfordulhat)
    if (email) {
      const given = String(email).toLowerCase().trim();
      const real = String(customer?.email || sub.metadata?.email || "").toLowerCase().trim();

      if (real && given !== real) {
        return res.status(403).json({ error: "Email mismatch" });
      }
    }

    // Commitment ellenőrzés: Stripe fallback
    // Ha nincs commitmentEndsAt metadata-ban -> ENGEDJÜK a lemondást (ez a fallback lényege)
    const nowSec = Math.floor(Date.now() / 1000);
    const commitmentEndsAt = Number(sub.metadata?.commitmentEndsAt || 0) || 0;

    if (commitmentEndsAt && nowSec < commitmentEndsAt) {
      return res.status(400).json({
        error: "Commitment active - cannot cancel yet",
        commitmentEndsAt,
      });
    }

    const updated = await stripe.subscriptions.update(subId, {
      cancel_at_period_end: true,
    });

    // Email: lemondás visszaigazolás
    const to = customer?.email || sub.metadata?.email || "";
    if (to) {
      await sendMailSafe({
        to,
        subject: "Quantum ITech - Lemondás rögzítve",
        text:
          "A lemondási kérésedet rögzítettük.\n\n" +
          "Előfizetés azonosító: " + subId + "\n" +
          "Lemondás a periódus végén: " + String(updated.cancel_at_period_end) + "\n\n" +
          "Köszönjük,\nQuantum ITech",
      });
    }

    return res.json({
      ok: true,
      subscriptionId: subId,
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
