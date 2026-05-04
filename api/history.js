const http = require("http");
const { getOracleLiveBase } = require("./_oracle");

module.exports = async (req, res) => {
  const count = req.query.count || "20";
  const url = `${getOracleLiveBase()}/history?count=${encodeURIComponent(count)}`;
  return new Promise((resolve) => {
    http.get(url, { timeout: 8000 }, (upstream) => {
      let data = "";
      upstream.on("data", (c) => (data += c));
      upstream.on("end", () => {
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Cache-Control", "s-maxage=15");
        res.status(upstream.statusCode).send(data);
        resolve();
      });
    }).on("error", (e) => {
      res.status(502).json({ error: "Oracle unreachable", detail: e.message });
      resolve();
    });
  });
};
