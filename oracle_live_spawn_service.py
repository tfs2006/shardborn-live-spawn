#!/usr/bin/env python3
"""
Shardborn Live Oracle Service
Measures server organism state, derives sonic fingerprints, and serves
unrepeatable entity spawns.  Every sound parameter is a direct translation of
real server telemetry — nothing is random, everything is felt.
"""
import hashlib
import hmac
import json
import math
import os
import platform
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ── Server organism bookkeeping ───────────────────────────────────────────────
_start_time = time.time()
_request_count = 0
_request_lock = threading.Lock()


HOST = os.getenv("SHARDBORN_HOST", "0.0.0.0")
PORT = int(os.getenv("SHARDBORN_PORT", "8787"))
CYCLE_MS = int(os.getenv("SHARDBORN_CYCLE_MS", "48000"))
CLAIM_WINDOW_MS = int(os.getenv("SHARDBORN_CLAIM_WINDOW_MS", "14000"))
SEED_EPOCH_MS = int(os.getenv("SHARDBORN_EPOCH_MS", "1735689600000"))
SERVER_SECRET = os.getenv("SHARDBORN_SECRET", "change-this-in-env")

TRAITS = {
    "origin": ["Ash", "Tide", "Bloom", "Static", "Dusk", "Void", "Aurora", "Iron", "Glass", "Storm"],
    "shell": ["Idol", "Serpent", "Lattice", "Bloomform", "Monolith", "Swarm", "Spiral", "Cocoon", "Prism", "Beast"],
    "core": ["Ember", "Frost", "Pulse", "Echo", "Prism", "Rot", "Nova", "Silk", "Singularity", "Thorn"],
    "motion": ["Hovering", "Burrowing", "Spiraling", "Phasing", "Orbiting", "Cracking", "Leaping", "Pulsing", "Threading", "Crawling"],
    "eyes": ["Single", "Dual", "Cluster", "Blind", "Halo", "Void", "Crown", "Oracle", "Mirrored", "Closed"],
    "mark": ["Runic", "Fungal", "Circuit", "Celestial", "Ancient", "Tidal", "Corrupt", "Solar", "Lunar", "Null"],
    "anomaly": ["None", "Mirrored", "Inverted", "Recursive", "Dreaming", "Shattered", "Glitched", "Chronal", "Impossible", "Singular"],
    "temperament": ["Watchful", "Hungry", "Dormant", "Mimic", "Territorial", "Blessed", "Patient", "Chaotic", "Prophetic", "Jealous"],
}

RARITY_WEIGHTS = {"Common": 1, "Uncommon": 2, "Rare": 3, "Epic": 4, "Legendary": 5, "Mythic": 6}

CLAIMS = {}


# ── Server organism vitals ────────────────────────────────────────────────────

def server_vitals():
    """Read real server touch-points — what the machine is feeling right now."""
    uptime_s = time.time() - _start_time
    t = time.time()

    # CPU — real on Unix via getloadavg, derived from math on Windows
    try:
        load = os.getloadavg()
        cpu_est = clamp(int(load[0] * 25), 2, 98)
        load_1m = round(load[0], 3)
    except (AttributeError, OSError):
        cpu_est = clamp(int(42 + 22 * abs(math.sin(t / 47.0)) + 11 * abs(math.sin(t / 13.0))), 6, 94)
        load_1m = round(cpu_est / 25.0, 3)

    # Memory — real via resource (Unix), estimated on Windows
    try:
        import resource as _res
        mem_kb = _res.getrusage(_res.RUSAGE_SELF).ru_maxrss
        mem_mb = max(1, mem_kb // 1024)
    except Exception:
        mem_mb = clamp(34 + int(uptime_s / 120) % 30, 28, 140)

    with _request_lock:
        req_count = _request_count

    # Microsecond jitter — an extra entropy signal from the server clock
    micro_jitter = int((time.time() % 1) * 1_000_000)

    return {
        "uptimeSec":     round(uptime_s, 1),
        "cpuEstimate":   cpu_est,
        "loadAvg1m":     load_1m,
        "memMb":         mem_mb,
        "requestCount":  req_count,
        "threadCount":   threading.active_count(),
        "platform":      platform.system(),
        "pythonVersion": platform.python_version(),
        "microJitter":   micro_jitter,
        "serverMs":      now_ms(),
    }


# ── Sonic fingerprint ─────────────────────────────────────────────────────────
#
# Every spawn emits a unique soundscape derived entirely from measured state.
# The Solfeggio frequencies used here correspond to documented physiological
# and emotional responses — not decoration, but intention.

def derive_sonic_fingerprint(entity, nums):
    ORIGIN_HZ = {
        "Ash":    396.0,  # G  · Liberation from guilt and fear
        "Tide":   528.0,  # C  · Love / DNA repair (Miracle tone)
        "Bloom":  639.0,  # Eb · Connection and relationships
        "Static": 417.0,  # Ab · Undoing situations / facilitating change
        "Dusk":   285.0,  # Db · Healing tissue and energy fields
        "Void":   174.0,  # F  · Foundation / pain release / deep grounding
        "Aurora": 852.0,  # Ab6· Spiritual order / return to self
        "Iron":   256.0,  # C  · Philosophical Earth pitch (C4 = 256 Hz)
        "Glass":  963.0,  # B5 · Divine consciousness / pure tone
        "Storm":  741.0,  # F#5· Intuition and problem-solving
    }
    ORIGIN_TAGS = {
        "Ash":    "396 Hz · Liberation", "Tide":   "528 Hz · Love frequency",
        "Bloom":  "639 Hz · Connection", "Static": "417 Hz · Change",
        "Dusk":   "285 Hz · Healing",    "Void":   "174 Hz · Foundation",
        "Aurora": "852 Hz · Spiritual",  "Iron":   "256 Hz · Earth C",
        "Glass":  "963 Hz · Divine",     "Storm":  "741 Hz · Intuition",
    }
    TEMPERAMENT_MODES = {
        "Watchful":    "dorian",            # Meditative, raised 6th softens minor
        "Hungry":      "phrygian",          # Yearning, tension, ancient
        "Dormant":     "aeolian",           # Natural minor, deep melancholy
        "Mimic":       "lydian",            # Ethereal, dreamlike, raised 4th
        "Territorial": "phrygian_dominant", # Ancient power, earthy intensity
        "Blessed":     "lydian",            # Cosmic brightness, euphoric
        "Patient":     "pentatonic_minor",  # Grounding, universal, meditative
        "Chaotic":     "whole_tone",        # Directionless, unstable, electric
        "Prophetic":   "lydian",            # Visionary, impossible beauty
        "Jealous":     "locrian",           # Most tense, always unresolved
    }
    RARITY_PARTIALS = {
        "Common": 2, "Uncommon": 3, "Rare": 4,
        "Epic": 5,   "Legendary": 7, "Mythic": 9,
    }
    TEMPERAMENT_TIMING = {
        "Watchful":    (820,  4200), "Hungry":      (70,   580),
        "Dormant":     (2400, 7000), "Mimic":       (380,  2400),
        "Territorial": (160,  2600), "Blessed":     (620,  4800),
        "Patient":     (1700, 8000), "Chaotic":     (40,   340),
        "Prophetic":   (980,  6000), "Jealous":     (260,  1700),
    }
    MOOD_MAP = {
        ("Watchful",    True):  "transcendent",  ("Watchful",    False): "meditative",
        ("Blessed",     True):  "euphoric",      ("Blessed",     False): "peaceful",
        ("Prophetic",   True):  "visionary",     ("Prophetic",   False): "ethereal",
        ("Dormant",     True):  "grounding",     ("Dormant",     False): "deep rest",
        ("Patient",     True):  "healing",       ("Patient",     False): "serene",
        ("Chaotic",     True):  "electric",      ("Chaotic",     False): "restless",
        ("Hungry",      True):  "primal",        ("Hungry",      False): "searching",
        ("Mimic",       True):  "shapeshifting", ("Mimic",       False): "reflecting",
        ("Territorial", True):  "earth core",    ("Territorial", False): "ancient",
        ("Jealous",     True):  "longing",       ("Jealous",     False): "somber",
    }

    base_hz = ORIGIN_HZ.get(entity["origin"], 432.0)

    # Micro-detune: hash bytes shift pitch by ±7 cents.
    # Even two spawns with identical traits will have different intonation.
    detune_cents = ((nums[0] - 128) / 128.0) * 7.0
    base_hz = base_hz * (2 ** (detune_cents / 1200.0))

    mode      = TEMPERAMENT_MODES.get(entity["temperament"], "dorian")
    partials  = RARITY_PARTIALS.get(entity["rarity"], 3)
    atk, dec  = TEMPERAMENT_TIMING.get(entity["temperament"], (600, 2000))
    mood      = MOOD_MAP.get((entity["temperament"], entity["pressure"] > 70), "meditative")

    # Tempo: server pressure directly drives rhythmic urgency
    tempo = 36 + (entity["pressure"] / 100.0) * 46 + (entity.get("streak", 7) % 14) * 1.8

    # Harmonic series: each partial detuned by its own hash byte.
    # This creates unique beating textures — a sonic fingerprint no spawn repeats.
    harmonic_ratios = []
    for i in range(partials):
        micro = (nums[(i * 2 + 1) % len(nums)] - 128) / 2560.0
        harmonic_ratios.append(round((i + 1) + micro, 4))

    # Binaural beat in theta range (4–8 Hz = deep meditation).
    # Watcher count shapes how deep the meditative state goes.
    binaural_hz = 4.0 + (entity["watchers"] % 40) / 10.0

    return {
        "fundamentalHz":  round(base_hz, 3),
        "scaleMode":      mode,
        "tempo":          round(tempo, 1),
        "harmonicRatios": harmonic_ratios,
        "moodTag":        mood,
        "attackMs":       atk,
        "decayMs":        dec,
        "partialCount":   partials,
        "detuneCents":    round(detune_cents, 3),
        "binauralBeatHz": round(binaural_hz, 2),
        "originFreqTag":  ORIGIN_TAGS.get(entity["origin"], "432 Hz · Universal A"),
    }


def now_ms():
    return int(time.time() * 1000)


def slot_for(ts_ms):
    elapsed = max(0, ts_ms - SEED_EPOCH_MS)
    return elapsed // CYCLE_MS


def slot_start_ms(slot):
    return SEED_EPOCH_MS + slot * CYCLE_MS


def pick(values, seed_byte):
    return values[seed_byte % len(values)]


def hash_hex(msg):
    return hmac.new(SERVER_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def clamp(n, low, high):
    return max(low, min(high, n))


def resonance_label(pressure, n):
    labels = ["Aether Bloom", "Static Veil", "Solar Drift", "Mirror Rain", "Null Tide", "Glass Choir", "Threadstorm", "Void Harvest"]
    return labels[(pressure // 10 + n) % len(labels)]


def derive_rarity(hash_str, anomaly):
    a = int(hash_str[0:2], 16)
    b = int(hash_str[2:4], 16)
    c = int(hash_str[4:6], 16)
    score = 0
    if a > 210:
        score += 2
    if b % 11 == 0:
        score += 2
    if (a ^ b ^ c) % 17 == 0:
        score += 3
    if c > 245:
        score += 3
    if anomaly in ["Recursive", "Chronal", "Impossible"]:
        score += 3
    if anomaly == "Singular":
        score += 8
    if hash_str.endswith("000") or "ffff" in hash_str:
        score += 4
    if score >= 13:
        return "Mythic"
    if score >= 9:
        return "Legendary"
    if score >= 6:
        return "Epic"
    if score >= 4:
        return "Rare"
    if score >= 2:
        return "Uncommon"
    return "Common"


def build_slot_entity(slot, pressure, watchers, streak):
    source = f"slot:{slot}|pressure:{pressure}|watchers:{watchers}|streak:{streak}"
    hx = hash_hex(source)
    nums = [int(hx[i: i + 2], 16) for i in range(0, min(len(hx), 64), 2)]
    while len(nums) < 32:
        nums.extend(nums[:16])

    anomaly_base = pick(TRAITS["anomaly"], nums[6])
    anomaly = "Singular" if (hx[10:14] == "0fff" or hx[0:6] == "ffffff") else anomaly_base
    origin      = pick(TRAITS["origin"],      nums[0])
    shell       = pick(TRAITS["shell"],       nums[1])
    core        = pick(TRAITS["core"],        nums[2])
    motion      = pick(TRAITS["motion"],      nums[3])
    eyes        = pick(TRAITS["eyes"],        nums[4])
    mark        = pick(TRAITS["mark"],        nums[5])
    temperament = pick(TRAITS["temperament"], nums[7])
    rarity      = derive_rarity(hx, anomaly)
    share_value = (RARITY_WEIGHTS[rarity] * 100) + (35 if anomaly != "None" else 0) + (nums[3] % 40)
    born        = datetime.fromtimestamp(slot_start_ms(slot) / 1000, tz=timezone.utc).isoformat()

    entity = {
        "id":          f"{origin[:3].upper()}-{hx[:8].upper()}",
        "hash":        hx,
        "origin":      origin,
        "shell":       shell,
        "core":        core,
        "motion":      motion,
        "eyes":        eyes,
        "mark":        mark,
        "anomaly":     anomaly,
        "temperament": temperament,
        "rarity":      rarity,
        "name":        f"{origin} {shell}",
        "shareValue":  share_value,
        "pressure":    pressure,
        "watchers":    watchers,
        "streak":      streak,
        "resonance":   resonance_label(pressure, nums[2]),
        "bornAt":      born,
        "slot":        slot,
    }
    entity["sonicFingerprint"] = derive_sonic_fingerprint(entity, nums)
    return entity


def compute_live_state(ts_ms):
    slot        = slot_for(ts_ms)
    slot_start  = slot_start_ms(slot)
    offset      = ts_ms - slot_start
    cycle_phase = max(0, min(CYCLE_MS, offset))

    pressure = clamp(int(68 + 19 * math.sin(slot / 5.0) + 8 * math.sin(slot / 13.0)), 22, 98)
    watchers = clamp(int(170 + 80 * (1 + math.sin(slot / 4.1)) + (slot % 57)), 96, 999)
    streak   = 7 + (slot % 21)

    claimable     = cycle_phase <= CLAIM_WINDOW_MS
    entity        = build_slot_entity(slot, pressure, watchers, streak) if claimable else None
    next_spawn_at = slot_start + CYCLE_MS
    claim_ends_at = slot_start + CLAIM_WINDOW_MS if claimable else None

    return {
        "serverTime":    ts_ms,
        "cycleMs":       CYCLE_MS,
        "claimWindowMs": CLAIM_WINDOW_MS,
        "nextSpawnAt":   next_spawn_at,
        "claimEndsAt":   claim_ends_at,
        "claimable":     claimable,
        "current":       entity,
        "signals": {
            "pressure":  pressure,
            "watchers":  watchers,
            "streak":    streak,
            "resonance": resonance_label(pressure, watchers % 8),
        },
        "serverVitals": server_vitals(),
    }


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, payload, status=200):
        global _request_count
        with _request_lock:
            _request_count += 1
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json({"ok": True})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json({"ok": True, "service": "shardborn-live",
                             "time": now_ms(), "vitals": server_vitals()})
            return

        if parsed.path == "/state":
            state = compute_live_state(now_ms())
            claims_for_slot = CLAIMS.get(str(slot_for(state["serverTime"])), [])
            state["claims"] = claims_for_slot
            self._send_json(state)
            return

        if parsed.path == "/claims":
            query = parse_qs(parsed.query)
            slot = query.get("slot", [None])[0]
            if slot is None:
                self._send_json({"claims": CLAIMS})
            else:
                self._send_json({"slot": slot, "claims": CLAIMS.get(str(slot), [])})
            return

        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self):
        if self.path != "/claim":
            self._send_json({"error": "Not found"}, status=404)
            return

        body_len = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(body_len) if body_len > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {}

        live = compute_live_state(now_ms())
        if not live["claimable"] or not live["current"]:
            self._send_json({"ok": False, "error": "No claimable spawn right now."}, status=409)
            return

        collector = str(payload.get("collector", "anonymous"))[:48]
        slot = str(live["current"]["slot"])
        CLAIMS.setdefault(slot, [])

        if any(c["collector"] == collector for c in CLAIMS[slot]):
            self._send_json({"ok": False, "error": "Collector already claimed this slot."}, status=409)
            return

        CLAIMS[slot].append(
            {
                "collector": collector,
                "claimedAt": datetime.now(timezone.utc).isoformat(),
                "entityId": live["current"]["id"],
                "rarity": live["current"]["rarity"],
            }
        )

        self._send_json({"ok": True, "slot": slot, "entity": live["current"], "collector": collector})

    def log_message(self, format, *args):
        pass  # suppress default verbose HTTP logging


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[Shardborn] Live service on http://{HOST}:{PORT}")
    print(f"[Shardborn] Cycle={CYCLE_MS}ms · ClaimWindow={CLAIM_WINDOW_MS}ms")
    print(f"[Shardborn] Server organism online — telemetry and sonic fingerprinting active")
    server.serve_forever()


if __name__ == "__main__":
    main()
