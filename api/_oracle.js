const DEFAULT_ORACLE_LIVE_URL = "http://158.101.2.37:9797";

function normalizeBase(rawValue) {
  const raw = String(rawValue || "").trim();
  if (!raw) return null;

  try {
    const parsed = new URL(raw);
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    return parsed.toString().replace(/\/$/, "");
  } catch (_err) {
    return null;
  }
}

function getOracleLiveBase() {
  return (
    normalizeBase(process.env.ORACLE_LIVE_URL) ||
    normalizeBase(process.env.NEXT_PUBLIC_ORACLE_LIVE_URL) ||
    DEFAULT_ORACLE_LIVE_URL
  );
}

module.exports = {
  getOracleLiveBase
};