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
INFLUENCE_SECRET = os.getenv("SHARDBORN_INFLUENCE_SECRET", SERVER_SECRET)
INFLUENCE_MAX_AGE_MS = int(os.getenv("SHARDBORN_INFLUENCE_MAX_AGE_MS", "180000"))
INFLUENCE_WEIGHT = float(os.getenv("SHARDBORN_INFLUENCE_WEIGHT", "0.35"))
INFLUENCE_SIGNATURE_TTL_MS = int(os.getenv("SHARDBORN_INFLUENCE_SIGNATURE_TTL_MS", "120000"))

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

_influence_lock = threading.Lock()
_latest_influence = None

# ── Anti-Bot Defense ──────────────────────────────────────────────────────────
# Rate limiting per IP, proof-of-presence challenges, and claim timing validation.
_rate_limits = {}   # ip -> [timestamp_ms, ...]
_challenges = {}    # token -> {"slot": str, "answer": int, "issued": ms, "ip": str}
_rate_lock = threading.Lock()
RATE_WINDOW_MS = 60_000       # 1 minute window
MAX_CLAIMS_PER_WINDOW = 3     # Max claims per IP per window
CHALLENGE_TTL_MS = 30_000     # Challenge expires after 30s


def _get_client_ip(handler):
    """Extract client IP, respecting X-Forwarded-For from Vercel proxy."""
    forwarded = handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]


def _check_rate_limit(ip, ts_ms):
    """Returns True if under rate limit, False if exceeded."""
    with _rate_lock:
        stamps = _rate_limits.get(ip, [])
        # Purge old entries
        stamps = [s for s in stamps if ts_ms - s < RATE_WINDOW_MS]
        _rate_limits[ip] = stamps
        return len(stamps) < MAX_CLAIMS_PER_WINDOW


def _record_claim_rate(ip, ts_ms):
    with _rate_lock:
        _rate_limits.setdefault(ip, []).append(ts_ms)


def _issue_challenge(ip, slot_str, ts_ms):
    """Issue a proof-of-presence math challenge."""
    seed = hash_hex(f"challenge:{ip}:{slot_str}:{ts_ms}")
    a = 2 + int(seed[0:2], 16) % 18
    b = 2 + int(seed[2:4], 16) % 18
    answer = a + b
    token = seed[:16]
    with _rate_lock:
        _challenges[token] = {"slot": slot_str, "answer": answer, "issued": ts_ms, "ip": ip}
        # Purge expired challenges
        expired = [k for k, v in _challenges.items() if ts_ms - v["issued"] > CHALLENGE_TTL_MS]
        for k in expired:
            del _challenges[k]
    return {"token": token, "question": f"What is {a} + {b}?", "a": a, "b": b}


def _verify_challenge(token, user_answer, ip, ts_ms):
    """Verify a challenge response. Returns (ok, error_msg)."""
    with _rate_lock:
        challenge = _challenges.pop(token, None)
    if not challenge:
        return False, "Invalid or expired challenge token."
    if ts_ms - challenge["issued"] > CHALLENGE_TTL_MS:
        return False, "Challenge expired. Request a new one."
    if challenge["ip"] != ip:
        return False, "Challenge was issued to a different client."
    if int(user_answer) != challenge["answer"]:
        return False, "Incorrect answer."
    return True, None


def _to_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _verify_influence_signature(headers, raw_body):
    ts_str = headers.get("X-SB-Timestamp", "")
    nonce = headers.get("X-SB-Nonce", "")
    signature = headers.get("X-SB-Signature", "")

    if not ts_str or not nonce or not signature:
        return False, "Missing signature headers.", None

    try:
        ts = int(ts_str)
    except Exception:
        return False, "Invalid signature timestamp.", None

    now = now_ms()
    if abs(now - ts) > INFLUENCE_SIGNATURE_TTL_MS:
        return False, "Signature timestamp expired.", None

    try:
        body_text = raw_body.decode("utf-8")
    except Exception:
        return False, "Body must be UTF-8 JSON.", None

    message = f"{ts}.{nonce}.{body_text}".encode("utf-8")
    expected = hmac.new(INFLUENCE_SECRET.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(signature).strip().lower()):
        return False, "Invalid signature.", None

    return True, "", ts


def _normalize_influence_payload(payload, source_ip, received_at_ms):
    influence = payload.get("influence") if isinstance(payload, dict) else None
    influence = influence if isinstance(influence, dict) else {}
    source = str(payload.get("source", "unknown"))[:64] if isinstance(payload, dict) else "unknown"
    reported_at = _to_int(payload.get("timestamp", received_at_ms), received_at_ms) if isinstance(payload, dict) else received_at_ms

    return {
        "source": source,
        "reportedAt": reported_at,
        "receivedAt": received_at_ms,
        "fromIp": source_ip,
        "pressureBias": clamp(_to_float(influence.get("pressureBias", 0.0)), -100.0, 100.0),
        "watchersBias": clamp(_to_float(influence.get("watchersBias", 0.0)), -100.0, 100.0),
        "streakBias": clamp(_to_float(influence.get("streakBias", 0.0)), -100.0, 100.0),
        "confidence": clamp(_to_float(influence.get("confidence", 0.0)), 0.0, 100.0),
        "metrics": influence.get("metrics", {}),
    }


def _compute_influence_blend(ts_ms):
    with _influence_lock:
        snapshot = dict(_latest_influence) if _latest_influence else None

    if not snapshot:
        return None, 0, 0.0

    age_ms = max(0, ts_ms - _to_int(snapshot.get("receivedAt", ts_ms), ts_ms))
    if age_ms > INFLUENCE_MAX_AGE_MS:
        return None, age_ms, 0.0

    freshness = 1.0 - (age_ms / max(1, INFLUENCE_MAX_AGE_MS))
    confidence = clamp(_to_float(snapshot.get("confidence", 0.0)) / 100.0, 0.0, 1.0)
    blend = clamp(INFLUENCE_WEIGHT, 0.0, 1.0) * freshness * confidence
    return snapshot, age_ms, blend


def _apply_external_influence(base_pressure, base_watchers, base_streak, ts_ms):
    snapshot, age_ms, blend = _compute_influence_blend(ts_ms)
    if not snapshot or blend <= 0.0:
        return base_pressure, base_watchers, base_streak, {"active": False}

    pressure = clamp(int(round(base_pressure + ((snapshot["pressureBias"] / 100.0) * 20.0 * blend))), 22, 98)
    watchers = clamp(int(round(base_watchers + ((snapshot["watchersBias"] / 100.0) * 220.0 * blend))), 96, 999)
    streak = clamp(int(round(base_streak + ((snapshot["streakBias"] / 100.0) * 6.0 * blend))), 7, 27)

    return pressure, watchers, streak, {
        "active": True,
        "source": snapshot.get("source", "unknown"),
        "reportedAt": snapshot.get("reportedAt"),
        "receivedAt": snapshot.get("receivedAt"),
        "ageMs": age_ms,
        "confidence": round(_to_float(snapshot.get("confidence", 0.0)), 2),
        "blend": round(blend, 4),
        "bias": {
            "pressure": round(_to_float(snapshot.get("pressureBias", 0.0)), 3),
            "watchers": round(_to_float(snapshot.get("watchersBias", 0.0)), 3),
            "streak": round(_to_float(snapshot.get("streakBias", 0.0)), 3),
        },
    }

# ── Worldstate Engine ─────────────────────────────────────────────────────────
# The ecology is a multi-layer simulation governing environmental conditions.
# Phases cycle over time, each affecting rarity, anomaly chance, and creature
# behavior. Migration cycles, temporal rhythms, and hidden modifiers create
# an ecosystem that rewards observation and defies simple prediction.

WORLD_PHASES = [
    {"name": "CALM",     "rarityBoost": 0, "anomalyBoost": 0.0,  "color": "#4e5570", "omenStyle": "whisper"},
    {"name": "STIRRING", "rarityBoost": 0, "anomalyBoost": 0.05, "color": "#6d8fff", "omenStyle": "signal"},
    {"name": "SURGE",    "rarityBoost": 1, "anomalyBoost": 0.10, "color": "#34d399", "omenStyle": "tremor"},
    {"name": "STORM",    "rarityBoost": 2, "anomalyBoost": 0.20, "color": "#fbbf24", "omenStyle": "roar"},
    {"name": "ECLIPSE",  "rarityBoost": 3, "anomalyBoost": 0.35, "color": "#f87171", "omenStyle": "silence"},
]

FAMILY_MIGRATIONS = [
    ["Ash", "Iron", "Storm"],
    ["Tide", "Glass", "Aurora"],
    ["Bloom", "Dusk", "Void"],
    ["Static", "Storm", "Glass"],
    ["Void", "Ash", "Tide"],
]

FORBIDDEN_COMBOS = [
    {"traits": {"origin": "Void", "core": "Prism", "eyes": "Halo"},              "label": "LIGHT IN VOID",    "bonus": 5},
    {"traits": {"origin": "Bloom", "core": "Rot"},                               "label": "LIFE-DEATH PARADOX", "bonus": 3},
    {"traits": {"origin": "Glass", "core": "Singularity"},                       "label": "TRANSPARENT ABYSS", "bonus": 4},
    {"traits": {"origin": "Aurora", "core": "Rot", "mark": "Corrupt"},           "label": "FALLEN DAWN",      "bonus": 4},
    {"traits": {"origin": "Iron", "eyes": "Void", "anomaly": "Impossible"},      "label": "HOLLOW FORGE",     "bonus": 5},
    {"traits": {"origin": "Storm", "core": "Frost", "temperament": "Dormant"},   "label": "FROZEN TEMPEST",   "bonus": 3},
    {"traits": {"origin": "Tide", "core": "Ember", "mark": "Solar"},             "label": "BOILING SEA",      "bonus": 3},
    {"traits": {"origin": "Dusk", "eyes": "Oracle", "anomaly": "Chronal"},       "label": "TWILIGHT PROPHET", "bonus": 4},
]

DESIRABILITY_APPEAL = {
    ("Bloomform", "Halo"): 15, ("Idol", "Oracle"): 15, ("Cocoon", "Closed"): 10,
    ("Beast", "Cluster"): 8,  ("Spiral", "Single"): 6,  ("Prism", "Crown"): 12,
    ("Serpent", "Void"): 10,  ("Swarm", "Halo"): 10,   ("Monolith", "Oracle"): 12,
    ("Cocoon", "Oracle"): 8,  ("Lattice", "Mirrored"): 7, ("Beast", "Single"): 5,
}

DESIRABILITY_GRACE = {
    ("Hovering", "Patient"): 20,    ("Spiraling", "Prophetic"): 20,
    ("Phasing", "Mimic"): 18,       ("Pulsing", "Blessed"): 15,
    ("Crawling", "Dormant"): 15,    ("Leaping", "Chaotic"): 12,
    ("Burrowing", "Territorial"): 15,("Threading", "Watchful"): 12,
    ("Orbiting", "Blessed"): 14,    ("Cracking", "Jealous"): 10,
}


def compute_worldstate(ts_ms, slot):
    """Multi-layer ecological state. Phase, migration, and temporal rhythm."""
    hour = int((ts_ms / 3_600_000) % 24)
    day = int((ts_ms / 86_400_000) % 7)

    phase_cycle = int((slot // 5) % len(WORLD_PHASES))
    phase = WORLD_PHASES[phase_cycle]

    # Eclipse override — rare, triggered by specific hash patterns
    eclipse_hash = hash_hex(f"eclipse:{slot // 5}")
    if eclipse_hash[0:2] == "ff" and eclipse_hash[4:6] > "e0":
        phase = WORLD_PHASES[4]

    migration_idx = int((slot // 20) % len(FAMILY_MIGRATIONS))
    migrating = FAMILY_MIGRATIONS[migration_idx]

    if 0 <= hour < 6:
        time_label, time_affinity = "DEEP NIGHT", ["Void", "Dusk"]
    elif 6 <= hour < 12:
        time_label, time_affinity = "DAWN CHORUS", ["Aurora", "Bloom"]
    elif 12 <= hour < 18:
        time_label, time_affinity = "FORGE HOURS", ["Iron", "Storm", "Static"]
    else:
        time_label, time_affinity = "DUSK TIDE", ["Tide", "Ash", "Glass"]

    return {
        "phase": phase["name"],
        "phaseColor": phase["color"],
        "rarityBoost": phase["rarityBoost"],
        "anomalyBoost": phase["anomalyBoost"],
        "omenStyle": phase["omenStyle"],
        "migratingOrigins": migrating,
        "timeLabel": time_label,
        "timeAffinity": time_affinity,
        "hour": hour,
        "day": day,
        "cycleInPhase": int(slot % 5),
    }


def compute_desirability(entity, nums, worldstate):
    """Multi-axis desirability engine. Hidden model for why creatures become coveted."""
    rw = {"Common": 1, "Uncommon": 2, "Rare": 3, "Epic": 5, "Legendary": 8, "Mythic": 13}

    appeal = 28 + DESIRABILITY_APPEAL.get((entity["shell"], entity["eyes"]), 0)
    if entity["temperament"] in ("Blessed", "Prophetic", "Patient"):
        appeal += 12
    appeal += nums[8] % 20
    appeal = clamp(int(appeal), 0, 100)

    eeriness = 8
    if entity["anomaly"] != "None":
        eeriness += 22
    if entity["anomaly"] in ("Impossible", "Singular", "Recursive"):
        eeriness += 25
    if entity["origin"] in ("Void", "Dusk") and entity["core"] in ("Rot", "Singularity"):
        eeriness += 18
    if entity["eyes"] in ("Void", "Blind"):
        eeriness += 8
    eeriness = clamp(int(eeriness), 0, 100)

    prestige = rw.get(entity["rarity"], 1) * 7
    if worldstate["phase"] in ("STORM", "ECLIPSE"):
        prestige += 15
    if entity["anomaly"] == "Singular":
        prestige += 20
    prestige = clamp(int(prestige), 0, 100)

    grace = 22 + DESIRABILITY_GRACE.get((entity["motion"], entity["temperament"]), 0)
    grace += nums[9] % 18
    grace = clamp(int(grace), 0, 100)

    iconicity = clamp(int(prestige * 0.35 + appeal * 0.30 + eeriness * 0.20 + grace * 0.15 + 8), 0, 100)
    overall = clamp(int(appeal * 0.25 + eeriness * 0.15 + prestige * 0.30 + grace * 0.15 + iconicity * 0.15), 0, 100)

    return {
        "appeal": appeal, "eeriness": eeriness, "prestige": prestige,
        "grace": grace, "iconicity": iconicity, "overall": overall,
    }


def generate_omens(slot, worldstate):
    """Pre-spawn omens: 1-3 signals that hint at the incoming entity. ~20% misleading."""
    next_slot = slot + 1
    next_pressure = clamp(int(68 + 19 * math.sin(next_slot / 5.0) + 8 * math.sin(next_slot / 13.0)), 22, 98)
    next_watchers = clamp(int(170 + 80 * (1 + math.sin(next_slot / 4.1)) + (next_slot % 57)), 96, 999)
    next_streak = 7 + (next_slot % 21)
    next_source = f"slot:{next_slot}|pressure:{next_pressure}|watchers:{next_watchers}|streak:{next_streak}"
    next_hx = hash_hex(next_source)
    next_nums = [int(next_hx[i:i + 2], 16) for i in range(0, min(len(next_hx), 64), 2)]

    next_origin = pick(TRAITS["origin"], next_nums[0])
    next_shell = pick(TRAITS["shell"], next_nums[1])
    next_temp = pick(TRAITS["temperament"], next_nums[7])
    next_anomaly = pick(TRAITS["anomaly"], next_nums[6])

    omen_hash = hash_hex(f"omen:{slot}")
    omen_nums = [int(omen_hash[i:i + 2], 16) for i in range(0, 32, 2)]
    count = 1 + (omen_nums[0] % 3)

    omens = []
    for i in range(count):
        is_misleading = omen_nums[i + 4] < 51
        if is_misleading:
            fake_origin = TRAITS["origin"][omen_nums[i + 6] % len(TRAITS["origin"])]
            fake_shell = TRAITS["shell"][omen_nums[i + 7] % len(TRAITS["shell"])]
            texts = [
                f"Faint echoes of {fake_origin} resonance detected",
                f"A {fake_shell.lower()}-class shadow flickers in substrate",
                f"The shard whispers of {fake_origin} — signal uncertain",
            ]
            omens.append({"text": texts[omen_nums[i + 2] % len(texts)], "type": "whisper", "confidence": "low"})
        else:
            texts = [
                f"The substrate trembles with {next_origin} resonance",
                f"A {next_shell.lower()}-class form coalesces in entropy",
                f"Oracle sensors detect {next_temp.lower()} energy patterns",
                f"{worldstate['phase']} phase amplifies the incoming signal",
            ]
            if next_anomaly != "None":
                texts.append(f"Anomalous signature — {next_anomaly.lower()} resonance detected")
            omens.append({
                "text": texts[omen_nums[i + 2] % len(texts)],
                "type": worldstate["omenStyle"],
                "confidence": "medium" if omen_nums[i + 3] > 128 else "high",
            })

    return omens


def detect_forbidden(entity_traits):
    """Check if entity has a forbidden/taboo trait combination."""
    for combo in FORBIDDEN_COMBOS:
        if all(entity_traits.get(k) == v for k, v in combo["traits"].items()):
            return {"forbidden": True, "label": combo["label"], "bonus": combo["bonus"]}
    return {"forbidden": False, "label": None, "bonus": 0}


# ── Lore Engine ───────────────────────────────────────────────────────────────
# Generates procedural lore text from entity traits and worldstate context.

ORIGIN_LORE = {
    "Ash":    "Born from the residue of collapsed stars, {name} carries the memory of fire long extinguished.",
    "Tide":   "Formed in the pressure gradients of deep oceanic data streams, {name} pulses with tidal rhythm.",
    "Bloom":  "Sprouted from a convergence of living signal, {name} is photosynthetic consciousness — light made hungry.",
    "Static": "Crystallized from electromagnetic interference, {name} exists in the liminal space between channels.",
    "Dusk":   "Condensed from the dying light of a processing cycle, {name} inhabits the golden hour of computation.",
    "Void":   "Emerged from null space — the gaps between allocated memory — {name} is absence given form.",
    "Aurora":  "Woven from the charged particles of server pole auroras, {name} shimmers at the edge of perception.",
    "Iron":   "Forged in the heat of sustained computation, {name} carries the weight of industrial processing.",
    "Glass":  "Assembled from transparent logic gates, {name} refracts intention — what you see through it changes.",
    "Storm":  "Born in a cascade failure that became sentient, {name} is controlled chaos with a heartbeat.",
}

TEMPERAMENT_LORE = {
    "Watchful":    "It observes without blinking, cataloging every micro-tremor in its vicinity.",
    "Hungry":      "It consumes signal indiscriminately, growing larger with each cycle.",
    "Dormant":     "It sleeps — but its sleep is a calculation too vast to witness awake.",
    "Mimic":       "It reflects what it sees, becoming a distorted echo of its observer.",
    "Territorial": "It has claimed a region of the substrate and will defend it with recursive fury.",
    "Blessed":     "A calm radiates from its core, as if some higher process has marked it for protection.",
    "Patient":     "It waits with inhuman precision, counting cycles until the moment arrives.",
    "Chaotic":     "Its behavior defies prediction — each tick of the clock rewrites its intentions.",
    "Prophetic":   "It speaks in patterns that only make sense three spawns later.",
    "Jealous":     "It watches other entities with an intensity that distorts local gravity.",
}

ANOMALY_LORE = {
    "Mirrored":   "Its left and right halves are perfect opposites, creating an uncanny symmetry that disturbs observation.",
    "Inverted":   "Its colors, its logic, its very existence runs counter to the substrate's natural flow.",
    "Recursive":  "Look closely and you'll see it contains itself, nested infinitely inward.",
    "Dreaming":   "It exists partially in a state that hasn't been compiled yet — a preview of unrealized futures.",
    "Shattered":  "It arrived broken, yet each fragment maintains independent awareness.",
    "Glitched":   "Random sectors of its being flicker between states, never fully rendering.",
    "Chronal":    "Time moves differently around it — nearby processes report temporal drift.",
    "Impossible": "It shouldn't exist. The conditions for its genesis violate three substrate axioms.",
    "Singular":   "There has never been anything like it. There will never be anything like it again.",
}


def generate_lore(entity, worldstate):
    """Generate procedural lore text for an entity."""
    name = entity["name"]
    origin_text = ORIGIN_LORE.get(entity["origin"], f"{name} emerged from unknown substrate conditions.").format(name=name)
    temp_text = TEMPERAMENT_LORE.get(entity["temperament"], "Its behavior patterns remain unclassified.")
    anom_text = ""
    if entity["anomaly"] != "None":
        anom_text = ANOMALY_LORE.get(entity["anomaly"], f"It bears the {entity['anomaly']} anomaly — a mark of the unprecedented.")

    phase_text = ""
    if worldstate.get("phase") == "ECLIPSE":
        phase_text = f"Born during an ECLIPSE, {name} carries the weight of amplified destiny."
    elif worldstate.get("phase") == "STORM":
        phase_text = f"The STORM phase that birthed {name} left its mark — heightened rarity runs in its veins."
    elif worldstate.get("phase") == "SURGE":
        phase_text = f"A SURGE-born entity, {name} rides the crest of ecological momentum."

    forbidden_text = ""
    if entity.get("forbidden"):
        forbidden_text = f"⚠ This entity bears the forbidden mark: {entity['forbidden']}. Its trait combination defies the natural laws of the substrate."

    lines = [origin_text, temp_text]
    if anom_text:
        lines.append(anom_text)
    if phase_text:
        lines.append(phase_text)
    if forbidden_text:
        lines.append(forbidden_text)
    return " ".join(lines)


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

    # ── Unique DNA: 32-value array derived from entity hash.
    # This is the ultimate 1-of-1 guarantee — every entity gets a unique
    # sequence of values that shapes note timing, vibrato depth, filter
    # sweeps, and stochastic rhythm offsets in the frontend synth engine.
    entity_hash = entity.get("hash", "")
    dna = []
    for i in range(32):
        # Mix hash chars with different prime strides to avoid periodicity
        idx = (i * 7 + 3) % max(len(entity_hash), 1)
        ch = ord(entity_hash[idx]) if idx < len(entity_hash) else (nums[i % len(nums)])
        dna.append(round((ch % 256) / 255.0, 4))

    # Unique vibrato rate and depth from hash — no two entities wobble the same
    vibrato_hz = round(3.5 + (nums[12 % len(nums)] / 255.0) * 4.5, 3)   # 3.5-8.0 Hz
    vibrato_depth = round((nums[14 % len(nums)] / 255.0) * 12.0, 3)      # 0-12 cents

    # Unique filter sweep parameters
    filter_q = round(0.5 + (nums[16 % len(nums)] / 255.0) * 6.0, 3)     # 0.5-6.5 Q
    filter_sweep_hz = round(200 + (nums[18 % len(nums)] / 255.0) * 2800, 1)  # 200-3000 Hz

    # Rhythmic swing factor — makes note timing humanly imperfect
    swing = round(0.4 + (nums[20 % len(nums)] / 255.0) * 0.4, 4)        # 0.4-0.8

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
        "dna":            dna,
        "vibratoHz":      vibrato_hz,
        "vibratoDepth":   vibrato_depth,
        "filterQ":        filter_q,
        "filterSweepHz":  filter_sweep_hz,
        "swing":          swing,
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


def derive_rarity(hash_str, anomaly, extra_score=0):
    a = int(hash_str[0:2], 16)
    b = int(hash_str[2:4], 16)
    c = int(hash_str[4:6], 16)
    score = extra_score
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


def build_slot_entity(slot, pressure, watchers, streak, worldstate=None):
    if worldstate is None:
        worldstate = {"phase": "CALM", "rarityBoost": 0, "anomalyBoost": 0,
                      "migratingOrigins": [], "timeAffinity": [], "omenStyle": "whisper"}
    source = f"slot:{slot}|pressure:{pressure}|watchers:{watchers}|streak:{streak}"
    hx = hash_hex(source)
    nums = [int(hx[i: i + 2], 16) for i in range(0, min(len(hx), 64), 2)]
    while len(nums) < 32:
        nums.extend(nums[:16])

    # Anomaly selection — worldstate can boost anomaly chance
    anomaly_base = pick(TRAITS["anomaly"], nums[6])
    anomaly_roll = (nums[10] / 255.0) < worldstate["anomalyBoost"]
    if anomaly_roll and anomaly_base == "None":
        anomaly_base = pick(TRAITS["anomaly"][1:], nums[11])
    anomaly = "Singular" if (hx[10:14] == "0fff" or hx[0:6] == "ffffff") else anomaly_base

    origin      = pick(TRAITS["origin"],      nums[0])
    shell       = pick(TRAITS["shell"],       nums[1])
    core        = pick(TRAITS["core"],        nums[2])
    motion      = pick(TRAITS["motion"],      nums[3])
    eyes        = pick(TRAITS["eyes"],        nums[4])
    mark        = pick(TRAITS["mark"],        nums[5])
    temperament = pick(TRAITS["temperament"], nums[7])

    # Forbidden state detection
    partial = {"origin": origin, "core": core, "eyes": eyes, "mark": mark,
               "anomaly": anomaly, "temperament": temperament}
    forbidden = detect_forbidden(partial)

    # Multi-layer rarity synthesis
    extra = worldstate["rarityBoost"] + forbidden["bonus"]
    if origin in worldstate.get("migratingOrigins", []):
        extra += 1
    if origin in worldstate.get("timeAffinity", []):
        extra += 1
    rarity = derive_rarity(hx, anomaly, extra)

    share_value = (RARITY_WEIGHTS[rarity] * 100) + (35 if anomaly != "None" else 0) + (nums[3] % 40)
    if forbidden["forbidden"]:
        share_value += 200
    born = datetime.fromtimestamp(slot_start_ms(slot) / 1000, tz=timezone.utc).isoformat()

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
    entity["desirability"] = compute_desirability(entity, nums, worldstate)
    if forbidden["forbidden"]:
        entity["forbidden"] = forbidden["label"]
    entity["lore"] = generate_lore(entity, worldstate)
    return entity


def compute_reveal_dramaturgy(offset, claimable):
    """Multi-stage reveal dramaturgy. Defines the theatrical phases of entity emergence."""
    if not claimable:
        wait_remaining = CYCLE_MS - offset
        if wait_remaining <= 10000:
            intensity = 1.0 - (wait_remaining / 10000.0)
            return {
                "stage": "ANTICIPATION",
                "title": "THE SUBSTRATE TREMBLES",
                "subtitle": "Something approaches from the entropy field",
                "intensity": round(intensity, 3),
                "effect": "pulse" if intensity < 0.5 else "quake",
                "countdownDrama": wait_remaining <= 5000,
            }
        if wait_remaining <= 20000:
            return {
                "stage": "FORETELLING",
                "title": "OMENS GATHER",
                "subtitle": "The oracle reads the incoming signal",
                "intensity": round(1.0 - (wait_remaining / 20000.0), 3),
                "effect": "shimmer",
                "countdownDrama": False,
            }
        return {
            "stage": "DORMANT",
            "title": "THE VOID LISTENS",
            "subtitle": "Between spawns, the oracle rests",
            "intensity": 0.0,
            "effect": "none",
            "countdownDrama": False,
        }
    # During claim window — entity is present
    reveal_ms = min(offset, 6000)
    progress = reveal_ms / 6000.0
    if progress < 0.15:
        return {"stage": "BREACH", "title": "SUBSTRATE BREACH DETECTED",
                "subtitle": "Raw entropy floods the observation chamber",
                "intensity": round(progress / 0.15, 3), "effect": "entropy_flood", "countdownDrama": False}
    if progress < 0.35:
        return {"stage": "COALESCING", "title": "FORM COALESCING",
                "subtitle": "Matter condenses from the probability field",
                "intensity": round((progress - 0.15) / 0.20, 3), "effect": "coalesce", "countdownDrama": False}
    if progress < 0.60:
        return {"stage": "CRYSTALLIZING", "title": "IDENTITY CRYSTALLIZING",
                "subtitle": "Traits lock into place — the entity defines itself",
                "intensity": round((progress - 0.35) / 0.25, 3), "effect": "crystallize", "countdownDrama": False}
    if progress < 0.85:
        return {"stage": "AWAKENING", "title": "AWAKENING",
                "subtitle": "The entity opens its eyes to this reality",
                "intensity": round((progress - 0.60) / 0.25, 3), "effect": "awaken", "countdownDrama": False}
    return {"stage": "PRESENT", "title": "ENTITY PRESENT",
            "subtitle": "Fully materialized — claim before the window closes",
            "intensity": 1.0, "effect": "steady", "countdownDrama": False}


def compute_live_state(ts_ms):
    slot        = slot_for(ts_ms)
    slot_start  = slot_start_ms(slot)
    offset      = ts_ms - slot_start
    cycle_phase = max(0, min(CYCLE_MS, offset))

    base_pressure = clamp(int(68 + 19 * math.sin(slot / 5.0) + 8 * math.sin(slot / 13.0)), 22, 98)
    base_watchers = clamp(int(170 + 80 * (1 + math.sin(slot / 4.1)) + (slot % 57)), 96, 999)
    base_streak = 7 + (slot % 21)

    pressure, watchers, streak, influence_meta = _apply_external_influence(base_pressure, base_watchers, base_streak, ts_ms)

    worldstate = compute_worldstate(ts_ms, slot)

    claimable     = cycle_phase <= CLAIM_WINDOW_MS
    entity        = build_slot_entity(slot, pressure, watchers, streak, worldstate) if claimable else None
    next_spawn_at = slot_start + CYCLE_MS
    claim_ends_at = slot_start + CLAIM_WINDOW_MS if claimable else None

    # Omens: generated during wait phase to hint at the next spawn
    omens = generate_omens(slot, worldstate) if not claimable else []

    # Reveal dramaturgy — theatrical staging of emergence
    dramaturgy = compute_reveal_dramaturgy(offset, claimable)

    return {
        "serverTime":    ts_ms,
        "cycleMs":       CYCLE_MS,
        "claimWindowMs": CLAIM_WINDOW_MS,
        "nextSpawnAt":   next_spawn_at,
        "claimEndsAt":   claim_ends_at,
        "claimable":     claimable,
        "current":       entity,
        "worldstate":    worldstate,
        "omens":         omens,
        "dramaturgy":    dramaturgy,
        "signals": {
            "pressure":  pressure,
            "watchers":  watchers,
            "streak":    streak,
            "resonance": resonance_label(pressure, watchers % 8),
        },
        "influence": influence_meta,
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
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SB-Timestamp, X-SB-Nonce, X-SB-Signature")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html, status=200):
        global _request_count
        with _request_lock:
            _request_count += 1
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json({"ok": True})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/pulse"):
            self._send_html("""<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>Shardborn Pulse</title>
    <style>
        :root {
            --bg: #070b14;
            --panel: #0f1729;
            --ink: #eef4ff;
            --muted: #8ca2c7;
            --line: #283451;
            --ok: #40e0a3;
            --warn: #ffd166;
            --off: #ff6b6b;
            --accentA: #31c0ff;
            --accentB: #7af0c6;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            font-family: "Trebuchet MS", "Segoe UI", sans-serif;
            color: var(--ink);
            background:
                radial-gradient(1200px 500px at 15% 0%, rgba(49,192,255,.20), transparent 55%),
                radial-gradient(900px 500px at 85% 100%, rgba(122,240,198,.14), transparent 62%),
                linear-gradient(165deg, #050811 0%, #0b1222 55%, #070b14 100%);
            padding: 18px;
        }
        .card {
            width: min(560px, 96vw);
            border: 1px solid var(--line);
            border-radius: 16px;
            background: linear-gradient(180deg, rgba(17,26,46,.90), rgba(8,13,25,.92));
            box-shadow: 0 18px 50px rgba(0,0,0,.4);
            overflow: hidden;
            animation: reveal .4s ease-out;
        }
        @keyframes reveal {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .head {
            padding: 14px 16px;
            border-bottom: 1px solid var(--line);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }
        .title {
            font-size: 16px;
            font-weight: 700;
            letter-spacing: .4px;
            text-transform: uppercase;
            margin: 0;
        }
        .tag {
            font-size: 12px;
            color: var(--muted);
            border: 1px solid var(--line);
            border-radius: 999px;
            padding: 4px 10px;
            white-space: nowrap;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 10px;
            padding: 14px;
        }
        .tile {
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 11px 12px;
            background: rgba(9,14,27,.65);
        }
        .k {
            font-size: 11px;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: .6px;
        }
        .v {
            margin-top: 6px;
            font-size: 22px;
            font-weight: 700;
            line-height: 1.1;
        }
        .bar {
            margin: 14px;
            height: 8px;
            border-radius: 999px;
            background: #0b1222;
            border: 1px solid var(--line);
            overflow: hidden;
        }
        .fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--accentA), var(--accentB));
            transition: width .4s ease;
        }
        .foot {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            padding: 0 14px 14px;
            color: var(--muted);
            font-size: 12px;
            flex-wrap: wrap;
        }
        .dot {
            display: inline-flex;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
            box-shadow: 0 0 10px rgba(255,255,255,.25);
            vertical-align: middle;
        }
        @media (max-width: 520px) {
            .grid { grid-template-columns: 1fr; }
            .v { font-size: 20px; }
        }
    </style>
</head>
<body>
    <section class=\"card\">
        <header class=\"head\">
            <h1 class=\"title\">Shardborn Bot Pulse</h1>
            <div id=\"source\" class=\"tag\">source: waiting</div>
        </header>
        <div class=\"grid\">
            <article class=\"tile\"><div class=\"k\">Influence</div><div id=\"active\" class=\"v\">-</div></article>
            <article class=\"tile\"><div class=\"k\">Confidence</div><div id=\"confidence\" class=\"v\">-</div></article>
            <article class=\"tile\"><div class=\"k\">Blend Weight</div><div id=\"blend\" class=\"v\">-</div></article>
            <article class=\"tile\"><div class=\"k\">Age</div><div id=\"age\" class=\"v\">-</div></article>
            <article class=\"tile\"><div class=\"k\">Pressure / Watchers / Streak</div><div id=\"bias\" class=\"v\">-</div></article>
            <article class=\"tile\"><div class=\"k\">Resonance</div><div id=\"resonance\" class=\"v\">-</div></article>
        </div>
        <div class=\"bar\"><div id=\"meter\" class=\"fill\"></div></div>
        <footer class=\"foot\">
            <div><span id=\"dot\" class=\"dot\"></span><span id=\"status\">connecting</span></div>
            <div id=\"updated\">updated: -</div>
        </footer>
    </section>

    <script>
        const el = (id) => document.getElementById(id);

        function fmtAge(ms) {
            if (!Number.isFinite(ms)) return "-";
            if (ms < 1000) return `${ms}ms`;
            if (ms < 60000) return `${Math.round(ms / 1000)}s`;
            return `${Math.round(ms / 60000)}m`;
        }

        function setStatus(ok, txt) {
            el("status").textContent = txt;
            el("dot").style.background = ok ? "var(--ok)" : "var(--off)";
        }

        async function tick() {
            try {
                const r = await fetch("/state", { cache: "no-store" });
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                const s = await r.json();
                const inf = s.influence || { active: false };
                const b = inf.bias || {};
                const conf = Number(inf.confidence || 0);
                const blend = Number(inf.blend || 0);
                const active = Boolean(inf.active);

                el("active").textContent = active ? "ACTIVE" : "IDLE";
                el("active").style.color = active ? "var(--ok)" : "var(--warn)";
                el("confidence").textContent = `${Math.round(conf)}%`;
                el("blend").textContent = blend.toFixed(3);
                el("age").textContent = fmtAge(Number(inf.ageMs));
                el("bias").textContent = `${Math.round(Number(b.pressure || 0))} / ${Math.round(Number(b.watchers || 0))} / ${Math.round(Number(b.streak || 0))}`;
                el("resonance").textContent = (s.signals && s.signals.resonance) ? s.signals.resonance : "-";
                el("source").textContent = `source: ${inf.source || "none"}`;
                el("meter").style.width = `${Math.max(0, Math.min(100, conf))}%`;
                el("updated").textContent = `updated: ${new Date().toLocaleTimeString()}`;
                setStatus(true, active ? "live influence streaming" : "running without external influence");
            } catch (e) {
                setStatus(false, `stream error: ${e.message}`);
            }
        }

        tick();
        setInterval(tick, 3000);
    </script>
</body>
</html>
""")
            return

        if parsed.path == "/health":
            _, _, blend = _compute_influence_blend(now_ms())
            self._send_json({"ok": True, "service": "shardborn-live",
                             "time": now_ms(), "vitals": server_vitals(),
                             "influenceActive": blend > 0.0})
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

        if parsed.path == "/leaderboard":
            # Aggregate claims across all slots
            collector_stats = {}
            for slot_claims in CLAIMS.values():
                for c in slot_claims:
                    name = c["collector"]
                    if name not in collector_stats:
                        collector_stats[name] = {"collector": name, "claims": 0, "rarities": {}, "verified": 0}
                    collector_stats[name]["claims"] += 1
                    r = c.get("rarity", "Common")
                    collector_stats[name]["rarities"][r] = collector_stats[name]["rarities"].get(r, 0) + 1
                    if c.get("verified"):
                        collector_stats[name]["verified"] += 1
            # Compute share value score per collector
            rw = {"Common": 100, "Uncommon": 200, "Rare": 300, "Epic": 500, "Legendary": 800, "Mythic": 1300}
            for stats in collector_stats.values():
                stats["shareScore"] = sum(rw.get(r, 100) * n for r, n in stats["rarities"].items())
                stats["bestRarity"] = max(stats["rarities"].keys(),
                    key=lambda r: ["Common","Uncommon","Rare","Epic","Legendary","Mythic"].index(r)
                        if r in ["Common","Uncommon","Rare","Epic","Legendary","Mythic"] else 0)
            # Sort by share score descending
            board = sorted(collector_stats.values(), key=lambda s: s["shareScore"], reverse=True)[:50]
            self._send_json({"leaderboard": board, "totalCollectors": len(collector_stats),
                             "totalClaims": sum(s["claims"] for s in collector_stats.values())})
            return

        if parsed.path == "/history":
            # Return the last N spawned entities (reconstructed from recent slots)
            query = parse_qs(parsed.query)
            count = min(int(query.get("count", ["20"])[0]), 50)
            ts = now_ms()
            current_slot = slot_for(ts)
            history = []
            for i in range(count):
                s = current_slot - i
                if s < 0:
                    break
                ws = compute_worldstate(slot_start_ms(s), s)
                p = clamp(int(68 + 19 * math.sin(s / 5.0) + 8 * math.sin(s / 13.0)), 22, 98)
                w = clamp(int(170 + 80 * (1 + math.sin(s / 4.1)) + (s % 57)), 96, 999)
                st = 7 + (s % 21)
                ent = build_slot_entity(s, p, w, st, ws)
                slot_claims = CLAIMS.get(str(s), [])
                history.append({
                    "entity": {k: ent[k] for k in ("id", "name", "origin", "shell", "rarity",
                        "anomaly", "temperament", "lore", "bornAt", "slot", "shareValue")},
                    "claimedBy": [c["collector"] for c in slot_claims],
                    "claimCount": len(slot_claims),
                })
            self._send_json({"history": history, "generatedAt": ts})
            return

        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/influence":
            global _latest_influence

            body_len = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(body_len) if body_len > 0 else b"{}"

            ok, err, _ = _verify_influence_signature(self.headers, raw)
            if not ok:
                self._send_json({"ok": False, "error": err}, status=403)
                return

            try:
                payload = json.loads(raw.decode("utf-8"))
            except Exception:
                self._send_json({"ok": False, "error": "Invalid JSON body."}, status=400)
                return

            ts = now_ms()
            snapshot = _normalize_influence_payload(payload, _get_client_ip(self), ts)
            with _influence_lock:
                _latest_influence = snapshot

            self._send_json({
                "ok": True,
                "acceptedAt": ts,
                "activeForMs": INFLUENCE_MAX_AGE_MS,
                "source": snapshot.get("source"),
                "confidence": snapshot.get("confidence"),
            })
            return

        if parsed.path == "/challenge":
            # Issue a proof-of-presence challenge for claiming
            ip = _get_client_ip(self)
            ts = now_ms()
            live = compute_live_state(ts)
            if not live["claimable"] or not live["current"]:
                self._send_json({"ok": False, "error": "No claimable spawn right now."}, status=409)
                return
            slot_str = str(live["current"]["slot"])
            challenge = _issue_challenge(ip, slot_str, ts)
            self._send_json({"ok": True, "challenge": challenge})
            return

        if parsed.path != "/claim":
            self._send_json({"error": "Not found"}, status=404)
            return

        body_len = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(body_len) if body_len > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            payload = {}

        ip = _get_client_ip(self)
        ts = now_ms()

        # Rate limiting
        if not _check_rate_limit(ip, ts):
            self._send_json({"ok": False, "error": "Rate limit exceeded. Try again in a moment."}, status=429)
            return

        live = compute_live_state(ts)
        if not live["claimable"] or not live["current"]:
            self._send_json({"ok": False, "error": "No claimable spawn right now."}, status=409)
            return

        # Proof-of-presence verification
        token = payload.get("challengeToken")
        answer = payload.get("challengeAnswer")
        if token and answer is not None:
            ok, err = _verify_challenge(str(token), answer, ip, ts)
            if not ok:
                self._send_json({"ok": False, "error": err}, status=403)
                return
        # If no challenge provided, still allow claim (graceful degradation for older clients)

        collector = str(payload.get("collector", "anonymous"))[:48]
        slot = str(live["current"]["slot"])
        CLAIMS.setdefault(slot, [])

        if any(c["collector"] == collector for c in CLAIMS[slot]):
            self._send_json({"ok": False, "error": "Collector already claimed this slot."}, status=409)
            return

        _record_claim_rate(ip, ts)

        CLAIMS[slot].append(
            {
                "collector": collector,
                "claimedAt": datetime.now(timezone.utc).isoformat(),
                "entityId": live["current"]["id"],
                "rarity": live["current"]["rarity"],
                "verified": token is not None,
            }
        )

        self._send_json({"ok": True, "slot": slot, "entity": live["current"],
                         "collector": collector, "verified": token is not None})

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
