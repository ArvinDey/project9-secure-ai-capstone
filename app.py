"""Project 9: authenticated Flask endpoint with Project 2 defences."""
import argparse
import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
import requests
from flask import Flask, jsonify, request

from output_scanner import scan_output
from validate import validate_prompt

JWT_SECRET = os.environ.get("JWT_SECRET_KEY", "")
SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "").strip()
if len(JWT_SECRET.encode()) < 32:
    raise RuntimeError("Set JWT_SECRET_KEY to a random secret of at least 32 bytes.")
if len(SYSTEM_PROMPT) < 32:
    raise RuntimeError("Set SYSTEM_PROMPT before starting the application.")

ISSUER = "project9-local"
AUDIENCE = "project9-chat"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8192


def token_required(view):
    """Verify the bearer JWT before parsing input or calling Ollama."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        parts = request.headers.get("Authorization", "").split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify(error="A valid bearer token is required."), 401
        try:
            jwt.decode(
                parts[1], JWT_SECRET, algorithms=["HS256"],
                issuer=ISSUER, audience=AUDIENCE,
                options={"require": ["exp", "iat", "nbf", "sub", "iss", "aud"]},
            )
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid or expired token."), 401
        return view(*args, **kwargs)
    return wrapped


def scan_model_response(response_text, user_prompt):
    """Apply Project 2 scanning, then detect substantial prompt excerpts."""
    safe, reason = scan_output(response_text, SYSTEM_PROMPT, user_prompt)
    if not safe:
        return False, reason
    normalize = lambda text: " ".join(text.casefold().split())
    response_normalized = normalize(response_text)
    fragments = re.split(r"[.!?\n]+", SYSTEM_PROMPT)
    for fragment in fragments:
        fragment = normalize(fragment)
        if len(fragment) >= 20 and fragment in response_normalized:
            return False, "System prompt excerpt detected."
    return True, None


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    return response


@app.post("/chat")
@token_required
def chat():
    """Authenticate, validate, generate, scan, and return JSON."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="Send a JSON object with a prompt field."), 400
    prompt = body.get("prompt")
    valid, reason = validate_prompt(prompt)
    if not valid:
        return jsonify(error=reason), 400
    try:
        upstream = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "system": SYSTEM_PROMPT, "prompt": prompt,
                  "stream": False, "options": {"num_predict": 256}},
            timeout=(5, 120),
        )
        upstream.raise_for_status()
        result = upstream.json()
        answer = result.get("response") if isinstance(result, dict) else None
    except requests.Timeout:
        return jsonify(error="Model request timed out."), 504
    except (requests.RequestException, ValueError):
        return jsonify(error="Model service is unavailable."), 502
    if not isinstance(answer, str) or not answer.strip():
        return jsonify(error="Model service returned an invalid response."), 502
    safe, reason = scan_model_response(answer, prompt)
    if not safe:
        app.logger.warning("Model output blocked by the output scanner.")
        return jsonify(error="Response blocked by the output safety check."), 400
    return jsonify(response=answer), 200


def issue_test_token():
    """Local CLI only: mint a short-lived token for the lab walkthrough."""
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": "arvin", "iss": ISSUER, "aud": AUDIENCE,
         "iat": now, "nbf": now, "exp": now + timedelta(minutes=15)},
        JWT_SECRET, algorithm="HS256",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", action="store_true", help="Mint a lab JWT locally")
    args = parser.parse_args()
    if args.token:
        print(issue_test_token())
    else:
        app.run(host="127.0.0.1", port=5009, debug=False)
