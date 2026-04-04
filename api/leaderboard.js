module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).json({ ok: false, error: "method-not-allowed" });
    return;
  }

  const base = (process.env.ORACLE_LIVE_URL || "http://158.101.2.37:9797").trim();

  try {
    const upstream = await fetch(`${base}/leaderboard`);
    const text = await upstream.text();
    const payload = text ? JSON.parse(text) : { ok: false, error: "empty-upstream-response" };
    res.setHeader("Cache-Control", "s-maxage=10, stale-while-revalidate=5");
    res.status(upstream.status).json(payload);
  } catch (error) {
    res.status(502).json({ ok: false, error: "oracle-leaderboard-unreachable", details: String(error.message || error) });
  }
};
