#!/usr/bin/env python3
"""
app.py — Mongo-backed TXT queue + auth + user stats.

Serves index.html at / and API under /api/*.

Deploy on Render:
    Build:   pip install -r requirements.txt
    Start:   gunicorn -w 2 -b 0.0.0.0:$PORT app:app
    Env:     MONGO_URI=<atlas uri>
             MONGO_DB=txtloader
             JWT_SECRET=<64-char hex, set once>
             ADMIN_TOKEN=<optional>
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient


# ============================================================
#  Config
# ============================================================
BASE_DIR = Path(__file__).resolve().parent

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://tabisulajoshleepagud_db_user:SFVCKdbf36goxyU0@cluster0.g9snriw.mongodb.net")
DB_NAME   = os.environ.get("MONGO_DB", "txtloader")
PORT      = int(os.environ.get("PORT", os.environ.get("FLASK_PORT", "5000")))

JWT_SECRET    = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
JWT_ALGO      = "HS256"
JWT_TTL_HOURS = int(os.environ.get("JWT_TTL_HOURS", "720"))  # 30 days
ADMIN_TOKEN   = os.environ.get("ADMIN_TOKEN", "")

app = Flask(__name__, static_folder=None)
CORS(app)

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
db = client[DB_NAME]
lines_col = db.lines
keys_col  = db.keys
users_col = db.users

lines_col.create_index([("api_key", 1), ("created_at", 1)])
keys_col.create_index([("key", 1)], unique=True)
users_col.create_index([("username", 1)], unique=True)


def now():
    return datetime.now(timezone.utc)


# ============================================================
#  Auth
# ============================================================
def _hash_password(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", pw.encode("utf-8"), bytes.fromhex(salt), 120_000
    ).hex()


def _make_token(user_doc) -> str:
    iat = int(now().timestamp())
    exp = int((now() + timedelta(hours=JWT_TTL_HOURS)).timestamp())
    return jwt.encode(
        {"sub": user_doc["username"], "api_key": user_doc["api_key"],
         "iat": iat, "exp": exp},
        JWT_SECRET, algorithm=JWT_ALGO,
    )


def _decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None


def require_auth():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        p = _decode_token(auth[7:].strip())
        if not p:
            return None
        ak = p.get("api_key")
        un = p.get("sub")
        if not ak or not un:
            return None
        return ak, un
    legacy = request.headers.get("X-API-Key", "").strip()
    if legacy and len(legacy) >= 8:
        return legacy, None
    return None


# ============================================================
#  HTML
# ============================================================
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


# ============================================================
#  Health + stats
# ============================================================
@app.route("/api/health", methods=["GET"])
def health():
    try:
        client.admin.command("ping")
        return jsonify({"ok": True, "mongo": True, "db": DB_NAME})
    except Exception as e:
        return jsonify({"ok": False, "mongo": False, "error": str(e)}), 503


@app.route("/api/stats", methods=["GET"])
def public_stats():
    try:
        total_users = users_col.count_documents({"active": True})
    except Exception:
        total_users = 0
    try:
        total_lines = lines_col.estimated_document_count()
    except Exception:
        total_lines = 0

    out = {
        "ok": True,
        "total_users": total_users,
        "total_lines": total_lines,
        "server_time": now().isoformat(),
    }

    ctx = require_auth()
    if ctx:
        api_key, username = ctx
        out["username"] = username
        out["my_count"] = lines_col.count_documents({"api_key": api_key})
    return jsonify(out)


# ============================================================
#  Signup / login / me
# ============================================================
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))

    if not (3 <= len(username) <= 40):
        return jsonify({"error": "username 3-40 chars"}), 400
    if not username.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "username alnum/_/- only"}), 400
    if len(password) < 8:
        return jsonify({"error": "password at least 8 chars"}), 400
    if users_col.find_one({"username": username}):
        return jsonify({"error": "username taken"}), 409

    salt = secrets.token_hex(16)
    api_key = secrets.token_hex(18)
    user_doc = {
        "username": username, "salt": salt,
        "pw_hash": _hash_password(password, salt),
        "api_key": api_key, "created_at": now(), "active": True,
    }
    users_col.insert_one(user_doc)
    keys_col.insert_one({"key": api_key, "label": f"user:{username}",
                         "created_at": now(), "active": True})
    return jsonify({"ok": True, "token": _make_token(user_doc),
                    "username": username, "api_key": api_key})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    user = users_col.find_one({"username": username, "active": True})
    if not user:
        return jsonify({"error": "invalid credentials"}), 401
    if not hmac.compare_digest(_hash_password(password, user["salt"]), user["pw_hash"]):
        return jsonify({"error": "invalid credentials"}), 401

    return jsonify({"ok": True, "token": _make_token(user),
                    "username": username, "api_key": user["api_key"]})


@app.route("/api/me", methods=["GET"])
def me():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    api_key, username = ctx
    count = lines_col.count_documents({"api_key": api_key})
    user = users_col.find_one({"username": username}, {"_id": 0, "created_at": 1}) if username else None
    created = user["created_at"].isoformat() if user and user.get("created_at") else None
    return jsonify({"ok": True, "username": username, "api_key": api_key,
                    "count": count, "created_at": created})


# ============================================================
#  Queue
# ============================================================
@app.route("/api/count", methods=["GET"])
def api_count():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _ = ctx
    return jsonify({"count": lines_col.count_documents({"api_key": key})})


@app.route("/api/peek", methods=["GET"])
def api_peek():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _ = ctx
    try:
        amount = max(1, int(request.args.get("amount", 1)))
    except (TypeError, ValueError):
        amount = 1
    docs = list(lines_col.find({"api_key": key}).sort("created_at", 1).limit(amount))
    return jsonify({"lines": [d["text"] for d in docs]})


@app.route("/api/fetch", methods=["POST"])
def api_fetch():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _ = ctx
    data = request.get_json(silent=True) or {}
    try:
        amount = int(data.get("amount", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "amount must be int"}), 400
    if amount < 1:
        return jsonify({"error": "amount >= 1"}), 400
    docs = list(lines_col.find({"api_key": key}).sort("created_at", 1).limit(amount))
    if not docs:
        return jsonify({"lines": [], "remaining": 0})
    ids = [d["_id"] for d in docs]
    lines_col.delete_many({"_id": {"$in": ids}})
    remaining = lines_col.count_documents({"api_key": key})
    return jsonify({"lines": [d["text"] for d in docs], "remaining": remaining})


@app.route("/api/add", methods=["POST"])
def api_add():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _ = ctx
    data = request.get_json(silent=True) or {}
    raw = data.get("lines", [])
    if not isinstance(raw, list):
        return jsonify({"error": "lines must be list"}), 400
    new_lines = [str(t).strip() for t in raw if str(t).strip()]
    if not new_lines:
        return jsonify({"error": "no lines"}), 400
    docs = [{"api_key": key, "text": t, "created_at": now()} for t in new_lines]
    lines_col.insert_many(docs)
    total = lines_col.count_documents({"api_key": key})
    return jsonify({"added": len(docs), "total": total})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _ = ctx
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".txt"):
        return jsonify({"error": "only .txt allowed"}), 400
    raw = f.read().decode("utf-8", errors="replace")
    new_lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not new_lines:
        return jsonify({"error": "file empty"}), 400
    docs = [{"api_key": key, "text": t, "created_at": now()} for t in new_lines]
    lines_col.insert_many(docs)
    total = lines_col.count_documents({"api_key": key})
    return jsonify({"added": len(docs), "total": total})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _ = ctx
    r = lines_col.delete_many({"api_key": key})
    return jsonify({"deleted": r.deleted_count})


# ============================================================
#  Admin
# ============================================================
@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    if not ADMIN_TOKEN or request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN:
        return jsonify({"error": "forbidden"}), 403

    total_users = users_col.count_documents({"active": True})
    total_lines = lines_col.estimated_document_count()
    new_today = users_col.count_documents({
        "created_at": {"$gte": datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0)}
    })

    recent = []
    for u in users_col.find(
        {}, {"_id": 0, "username": 1, "created_at": 1, "active": 1}
    ).sort("created_at", -1).limit(20):
        if isinstance(u.get("created_at"), datetime):
            u["created_at"] = u["created_at"].isoformat()
        recent.append(u)

    return jsonify({"ok": True, "total_users": total_users,
                    "new_today": new_today, "total_lines": total_lines,
                    "recent_users": recent,
                    "server_time": now().isoformat()})


if __name__ == "__main__":
    masked = MONGO_URI.split("@")[-1] if "@" in MONGO_URI else MONGO_URI
    print(f"TXT Loader → http://0.0.0.0:{PORT}")
    print(f"Mongo: {masked}  db={DB_NAME}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
