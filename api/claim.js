module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ ok: false, error: "method-not-allowed" });
    return;
  }

  const base = (process.env.ORACLE_LIVE_URL || "http://158.101.2.37:8787").trim();

  try {
    const upstream = await fetch(`${base}/claim`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body || {})
    });

    const text = await upstream.text();
    const payload = text ? JSON.parse(text) : { ok: false, error: "empty-upstream-response" };
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.status(upstream.status).json(payload);
  } catch (error) {
    res.status(502).json({ ok: false, error: "oracle-claim-unreachable", details: String(error.message || error) });
  }
};
