module.exports = async function handler(req, res) {
  const base = (process.env.ORACLE_LIVE_URL || "http://158.101.2.37:8787").trim();

  try {
    const upstream = await fetch(`${base}/state`, {
      method: "GET",
      headers: { "Accept": "application/json" },
      cache: "no-store"
    });

    const text = await upstream.text();
    res.setHeader("Cache-Control", "no-store, max-age=0");

    if (!upstream.ok) {
      res.status(upstream.status).json({ error: "oracle-state-failed", details: text.slice(0, 400) });
      return;
    }

    const data = JSON.parse(text);
    res.status(200).json(data);
  } catch (error) {
    res.status(502).json({ error: "oracle-state-unreachable", details: String(error.message || error) });
  }
};
