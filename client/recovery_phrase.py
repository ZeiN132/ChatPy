import secrets
from pathlib import Path


def _load_wordlist():
    path = Path(__file__).with_name("bip39_english.txt")
    try:
        words = [w.strip() for w in path.read_text(encoding="utf-8").splitlines() if w.strip()]
        if len(words) >= 2048:
            return words
    except Exception:
        pass

    return [
        "absent", "acid", "acoustic", "action", "adapt", "advice", "aerobic", "alert",
        "anchor", "answer", "anyone", "arcade", "arrive", "artist", "aspect", "attic",
        "banana", "basic", "beauty", "become", "before", "bicycle", "border", "breeze",
        "camera", "candle", "canvas", "carbon", "casual", "center", "chance", "circle",
        "coffee", "comet", "copper", "crystal", "custom", "danger", "dawn", "decide",
        "define", "demand", "design", "direct", "doctor", "dragon", "eager", "early",
        "echo", "effect", "energy", "engine", "escape", "estate", "ethics", "family",
        "famous", "feather", "fiction", "filter", "forest", "future", "garden", "gentle",
        "glacier", "golden", "habit", "happy", "harbor", "hazard", "honest", "hunter",
        "idea", "immune", "impact", "index", "inside", "jacket", "jungle", "keyboard",
        "ladder", "legend", "limit", "lunar", "mango", "manual", "matrix", "memory",
        "method", "middle", "mirror", "motion", "museum", "native", "nature", "neutral",
        "object", "ocean", "offer", "orbit", "orange", "origin", "parent", "party",
        "peanut", "pepper", "planet", "poetry", "policy", "prefer", "proud", "puzzle",
        "quantum", "quick", "quiet", "random", "reason", "record", "remote", "render",
        "rescue", "ribbon", "rocket", "rough", "safari", "safety", "screen", "script",
        "shadow", "signal", "silver", "simple", "smooth", "socket", "solid", "source",
        "spatial", "spirit", "stable", "street", "system", "table", "talent", "target",
        "tenant", "ticket", "timber", "tornado", "travel", "unique", "update", "urban",
        "useful", "vacuum", "valley", "velvet", "victory", "vintage", "visual", "volume",
        "wallet", "wander", "window", "winter", "wire", "yellow", "young", "zone"
    ]


_WORDLIST = _load_wordlist()


def generate_recovery_phrase(word_count=12):
    words = [secrets.choice(_WORDLIST) for _ in range(word_count)]
    return " ".join(words)


def generate_recovery_token(length=24):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def normalize_recovery_phrase(phrase):
    return " ".join(phrase.lower().split())
