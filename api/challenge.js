module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ ok: false, error: "method-not-allowed" });
    return;
  }

  const base = (process.env.ORACLE_LIVE_URL || "http://158.101.2.37:9797").trim();

  try {
    const headers = { "Content-Type": "application/json" };
    // Forward client IP so the oracle can bind the challenge
    const clientIp = req.headers["x-forwarded-for"] || req.headers["x-real-ip"] || "";
    if (clientIp) headers["X-Forwarded-For"] = clientIp;

    const upstream = await fetch(`${base}/challenge`, {
      method: "POST",
      headers,
      body: JSON.stringify(req.body || {})
    });

    const text = await upstream.text();
    const payload = text ? JSON.parse(text) : { ok: false, error: "empty-upstream-response" };
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.status(upstream.status).json(payload);
  } catch (error) {
    res.status(502).json({ ok: false, error: "oracle-challenge-unreachable", details: String(error.message || error) });
  }
};
