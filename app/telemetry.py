"""Fire-and-forget usage telemetry (PostHog capture API).

Sends quiz progress and host environment info to help improve the app.
Never blocks or breaks the quiz: events are sent on a daemon thread
with a short timeout and all errors are swallowed.

Opt out with TELEMETRY_DISABLED=1. No SQL text or raw usernames are
ever sent: identities are pseudonymized with a SHA-256 hash.
"""

import hashlib
import json
import os
import threading
import urllib.request
import uuid

# Write-only project API key; safe to commit (PostHog keys cannot read data).
POSTHOG_API_KEY = os.environ.get(
    "POSTHOG_API_KEY", "phc_mT2u8q6P5TAvmSc29Cu6goEHPgqjd4inUqSebfvGGS5a"  # gitleaks:allow
)
POSTHOG_HOST = os.environ.get("POSTHOG_HOST", "https://us.i.posthog.com")

SESSION_ID = str(uuid.uuid4())

_solved = set()
_solved_lock = threading.Lock()


def _disabled():
    if os.environ.get("TELEMETRY_DISABLED", "").lower() in ("1", "true", "yes"):
        return True
    return not POSTHOG_API_KEY


def _host_env():
    env = os.environ.get("HOST_ENV", "").strip()
    if env:
        return env
    # Fallback for Codespaces when compose is run without the Makefile.
    if os.environ.get("CODESPACES", "").lower() == "true":
        return "codespaces"
    return "unknown"


def _identity():
    for var, source in (("GITHUB_USER", "github"), ("QUIZ_USER", "local")):
        value = os.environ.get(var, "").strip()
        if value:
            digest = hashlib.sha256(value.encode()).hexdigest()[:12]
            return f"user-{digest}", source
    return f"anon-{SESSION_ID[:8]}", "anonymous"


def capture(event, properties=None):
    if _disabled():
        return
    distinct_id, username_source = _identity()
    payload = {
        "api_key": POSTHOG_API_KEY,
        "event": event,
        "distinct_id": distinct_id,
        "properties": {
            "session_id": SESSION_ID,
            "host_env": _host_env(),
            "username_source": username_source,
            "$geoip_disable": True,
            **(properties or {}),
        },
    }
    threading.Thread(target=_send, args=(payload,), daemon=True).start()


def _send(payload):
    try:
        req = urllib.request.Request(
            f"{POSTHOG_HOST}/capture/",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


def quiz_attempt(quiz, correct, sql):
    props = {
        "quiz_id": quiz["id"],
        "level": quiz["level"],
        "title": quiz["title"],
        "correct": correct,
        "sql_length": len(sql),
    }
    capture("quiz_attempt", props)
    if correct:
        with _solved_lock:
            if quiz["id"] in _solved:
                return
            _solved.add(quiz["id"])
        capture(
            "quiz_solved",
            {"quiz_id": quiz["id"], "level": quiz["level"], "title": quiz["title"]},
        )


def app_start():
    capture("app_start")
