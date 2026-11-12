#!/usr/bin/env python3
"""
app.py — Mongo-backed TXT pool with credits, roles, shared queue, fetch history.

Model:
    lines    — GLOBAL pool (no api_key). Every user pulls from here.
    fetched  — per-user archive of fetched lines.
    users    — accounts with role, credits, counters, timestamps.
    keys     — api key registry.
    credit_log — every credit change (grant/fetch/bonus), append-only.

Roles:
    'user'   — pays CREDITS_PER_LINE per fetched line.
    'owner'  — infinite credits, no per-fetch cost, admin endpoints.
    'admin'  — reserved.

Env:
    MONGO_URI, MONGO_DB, JWT_SECRET, ADMIN_TOKEN (optional)
    OWNER_USERNAME = 'LunarisOwner' (default)
    OWNER_PASSWORD — if set, creates the owner on boot (idempotent)
    CREDITS_PER_LINE = '0.2'
    START_CREDITS = '10'
    DAILY_BONUS = '1'
    ADMIN_SEED — comma-separated text lines seeded into pool on boot
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_DOWN
from pathlib import Path

import jwt
from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient, ReturnDocument


# ============================================================
#  Config
# ============================================================
BASE_DIR = Path(__file__).resolve().parent

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://tabisulajoshleepagud_db_user:SFVCKdbf36goxyU0@cluster0.g9snriw.mongodb.net")
DB_NAME   = os.environ.get("MONGO_DB", "txtloader")
PORT      = int(os.environ.get("PORT", os.environ.get("FLASK_PORT", "5000")))

JWT_SECRET    = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
JWT_ALGO      = "HS256"
JWT_TTL_HOURS = int(os.environ.get("JWT_TTL_HOURS", "720"))
ADMIN_TOKEN   = os.environ.get("ADMIN_TOKEN", "")

OWNER_USERNAME = os.environ.get("OWNER_USERNAME", "LunarisOwner")
OWNER_PASSWORD = os.environ.get("OWNER_PASSWORD", "")

CREDITS_PER_LINE = Decimal(os.environ.get("CREDITS_PER_LINE", "0.2"))
START_CREDITS    = Decimal(os.environ.get("START_CREDITS", "10"))
DAILY_BONUS      = Decimal(os.environ.get("DAILY_BONUS", "1"))

ADMIN_SEED = os.environ.get("ADMIN_SEED", "")

app = Flask(__name__, static_folder=None)
CORS(app)

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
db = client[DB_NAME]
lines_col     = db.lines
fetched_col   = db.fetched
users_col     = db.users
keys_col      = db.keys
credit_log    = db.credit_log

lines_col.create_index([("created_at", 1)])
fetched_col.create_index([("api_key", 1), ("fetched_at", -1)])
users_col.create_index([("username", 1)], unique=True)
users_col.create_index([("credits", -1)])
keys_col.create_index([("key", 1)], unique=True)
credit_log.create_index([("api_key", 1), ("created_at", -1)])


def now():
    return datetime.now(timezone.utc)


# ============================================================
#  Auth primitives
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
         "role": user_doc.get("role", "user"),
         "iat": iat, "exp": exp},
        JWT_SECRET, algorithm=JWT_ALGO,
    )


def _decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        return None


def require_auth():
    """Returns (api_key, username, role) or None."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        p = _decode_token(auth[7:].strip())
        if not p:
            return None
        ak = p.get("api_key")
        un = p.get("sub")
        role = p.get("role", "user")
        if not ak or not un:
            return None
        return ak, un, role
    legacy = request.headers.get("X-API-Key", "").strip()
    if legacy and len(legacy) >= 8:
        u = users_col.find_one({"api_key": legacy},
                               {"username": 1, "role": 1})
        return legacy, (u["username"] if u else None), (u.get("role", "user") if u else "user")
    return None


def require_owner():
    ctx = require_auth()
    if not ctx:
        return None
    if ctx[2] != "owner":
        return None
    return ctx


# ============================================================
#  Owner boot — create LunarisOwner if not exists
# ============================================================
def _ensure_owner():
    existing = users_col.find_one({"username": OWNER_USERNAME.lower()})
    if existing:
        if existing.get("role") != "owner":
            users_col.update_one({"_id": existing["_id"]},
                                 {"$set": {"role": "owner"}})
        return

    if not OWNER_PASSWORD:
        print(f"[owner] {OWNER_USERNAME} not present and OWNER_PASSWORD unset — skipping boot creation")
        return
    if len(OWNER_PASSWORD) < 8:
        print("[owner] OWNER_PASSWORD too short (<8) — skipping")
        return

    salt = secrets.token_hex(16)
    api_key = secrets.token_hex(18)
    users_col.insert_one({
        "username": OWNER_USERNAME.lower(),
        "display": OWNER_USERNAME,
        "salt": salt,
        "pw_hash": _hash_password(OWNER_PASSWORD, salt),
        "api_key": api_key,
        "role": "owner",
        "credits": "inf",
        "total_fetched": 0,
        "total_added": 0,
        "created_at": now(),
        "active": True,
        "daily_bonus_at": None,
    })
    keys_col.insert_one({"key": api_key, "label": f"owner:{OWNER_USERNAME}",
                         "created_at": now(), "active": True})
    print(f"[owner] created {OWNER_USERNAME}")


def _seed_pool_once():
    if not ADMIN_SEED:
        return
    if lines_col.estimated_document_count() > 0:
        return
    items = [s.strip() for s in ADMIN_SEED.split(",") if s.strip()]
    if not items:
        return
    docs = [{"text": t, "created_at": now(), "added_by": "owner"} for t in items]
    lines_col.insert_many(docs)
    print(f"[seed] pool seeded with {len(docs)} lines")


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
        "credits_per_line": str(CREDITS_PER_LINE),
        "server_time": now().isoformat(),
    }

    ctx = require_auth()
    if ctx:
        api_key, username, role = ctx
        user = users_col.find_one({"username": username}, {"credits": 1})
        credits = user.get("credits", 0) if user else 0
        out["username"] = username
        out["role"] = role
        out["credits"] = "inf" if credits == "inf" else str(credits)
        out["my_fetched"] = fetched_col.count_documents({"api_key": api_key})
        out["my_added"] = lines_col.count_documents({"added_by": username})
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
        "username": username,
        "display": data.get("display", username)[:40],
        "salt": salt,
        "pw_hash": _hash_password(password, salt),
        "api_key": api_key,
        "role": "user",
        "credits": str(START_CREDITS),
        "total_fetched": 0,
        "total_added": 0,
        "created_at": now(),
        "active": True,
        "daily_bonus_at": None,
    }
    users_col.insert_one(user_doc)
    keys_col.insert_one({"key": api_key, "label": f"user:{username}",
                         "created_at": now(), "active": True})
    credit_log.insert_one({
        "api_key": api_key, "username": username,
        "delta": str(START_CREDITS), "reason": "signup_bonus",
        "balance_after": str(START_CREDITS), "created_at": now(),
    })
    return jsonify({"ok": True, "token": _make_token(user_doc),
                    "username": username, "api_key": api_key,
                    "credits": str(START_CREDITS), "role": "user"})


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

    # daily bonus — fire at most once per 24h
    _maybe_daily_bonus(user)

    user = users_col.find_one({"username": username})
    credits = user.get("credits", 0)
    return jsonify({
        "ok": True,
        "token": _make_token(user),
        "username": username,
        "api_key": user["api_key"],
        "role": user.get("role", "user"),
        "credits": "inf" if credits == "inf" else str(credits),
    })


def _maybe_daily_bonus(user):
    if user.get("role") == "owner":
        return
    last = user.get("daily_bonus_at")
    if last:
        if isinstance(last, str):
            try:
                last = datetime.fromisoformat(last)
            except Exception:
                last = None
    if last and (now() - last) < timedelta(hours=24):
        return
    if DAILY_BONUS <= 0:
        return
    cur = Decimal(str(user.get("credits", "0")))
    new_balance = cur + DAILY_BONUS
    users_col.update_one({"_id": user["_id"]},
                         {"$set": {"credits": str(new_balance),
                                   "daily_bonus_at": now()}})
    credit_log.insert_one({
        "api_key": user["api_key"], "username": user["username"],
        "delta": str(DAILY_BONUS), "reason": "daily_bonus",
        "balance_after": str(new_balance), "created_at": now(),
    })


@app.route("/api/me", methods=["GET"])
def me():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    api_key, username, role = ctx
    user = users_col.find_one({"username": username}, {"_id": 0})
    if not user:
        return jsonify({"error": "user not found"}), 404
    credits = user.get("credits", 0)
    return jsonify({
        "ok": True,
        "username": username,
        "role": role,
        "credits": "inf" if credits == "inf" else str(credits),
        "total_fetched": user.get("total_fetched", 0),
        "total_added": user.get("total_added", 0),
        "my_fetched_server": fetched_col.count_documents({"api_key": api_key}),
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
    })


# ============================================================
#  Pool — global shared queue
# ============================================================
@app.route("/api/count", methods=["GET"])
def api_count():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"count": lines_col.estimated_document_count()})


@app.route("/api/peek", methods=["GET"])
def api_peek():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    try:
        amount = max(1, min(500, int(request.args.get("amount", 1))))
    except (TypeError, ValueError):
        amount = 1
    docs = list(lines_col.find().sort("created_at", 1).limit(amount))
    return jsonify({"lines": [d["text"] for d in docs]})


@app.route("/api/fetch", methods=["POST"])
def api_fetch():
    """
    Shared pool fetch with credit accounting.
    User role: costs CREDITS_PER_LINE per line, insufficient funds → 402.
    Owner role: no cost, unlimited.
    """
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, username, role = ctx

    data = request.get_json(silent=True) or {}
    try:
        amount = int(data.get("amount", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "amount must be int"}), 400
    if amount < 1:
        return jsonify({"error": "amount >= 1"}), 400
    if amount > 5000:
        return jsonify({"error": "amount too large (max 5000)"}), 400

    user = users_col.find_one({"username": username})
    if not user:
        return jsonify({"error": "user not found"}), 404

    is_owner = (role == "owner") or (user.get("role") == "owner")
    balance = user.get("credits", "0")
    if is_owner:
        balance_dec = None
    else:
        try:
            balance_dec = Decimal(str(balance))
        except Exception:
            balance_dec = Decimal("0")

    # atomic funds reservation for non-owner
    cost = (CREDITS_PER_LINE * Decimal(amount)).quantize(
        Decimal("0.01"), rounding=ROUND_DOWN)
    if not is_owner:
        if balance_dec < cost:
            affordable = int((balance_dec / CREDITS_PER_LINE).to_integral_value(
                rounding=ROUND_DOWN)) if CREDITS_PER_LINE > 0 else 0
            return jsonify({
                "error": f"insufficient credits (need {cost}, have {balance_dec})",
                "cost": str(cost), "have": str(balance_dec),
                "affordable_lines": affordable,
            }), 402

        # reserve first: inc balance by -cost; if the resulting credits go
        # negative due to a race, roll back and 402.
        res = users_col.find_one_and_update(
            {"_id": user["_id"],
             "credits": {"$gte": str(cost)} if not isinstance(balance, str) else {"$exists": True}},
            {"$inc": {}},
            return_document=ReturnDocument.AFTER,
        )
        # simpler reliable approach: guarded update below
        upd = users_col.update_one(
            {"_id": user["_id"], "credits": str(balance)},
            {"$set": {"credits": str(balance_dec - cost)}},
        )
        if upd.modified_count == 0:
            return jsonify({"error": "balance changed — retry"}), 409

    # pop lines from the global pool
    taken = []
    for _ in range(amount):
        doc = lines_col.find_one_and_delete({}, sort=[("created_at", 1)])
        if not doc:
            break
        taken.append(doc)

    if not taken:
        # refund the reserved cost
        if not is_owner and cost > 0:
            users_col.update_one({"_id": user["_id"]},
                                 {"$inc": {}})  # no-op guard
            cur = users_col.find_one({"_id": user["_id"]})
            cur_bal = Decimal(str(cur.get("credits", "0")))
            users_col.update_one({"_id": user["_id"]},
                                 {"$set": {"credits": str(cur_bal + cost)}})
        return jsonify({"lines": [], "remaining": 0, "cost": "0"})

    # if we couldn't take the full amount, refund the delta
    actual = len(taken)
    actual_cost = (CREDITS_PER_LINE * Decimal(actual)).quantize(
        Decimal("0.01"), rounding=ROUND_DOWN)
    if not is_owner and actual < amount:
        refund = cost - actual_cost
        if refund > 0:
            cur = users_col.find_one({"_id": user["_id"]})
            cur_bal = Decimal(str(cur.get("credits", "0")))
            users_col.update_one({"_id": user["_id"]},
                                 {"$set": {"credits": str(cur_bal + refund)}})

    # archive
    ts = now()
    archive = [{
        "api_key": key, "username": username,
        "text": d["text"], "queued_at": d.get("created_at"),
        "fetched_at": ts,
    } for d in taken]
    try:
        fetched_col.insert_many(archive, ordered=False)
    except Exception:
        pass

    # counters + credit log
    users_col.update_one({"_id": user["_id"]},
                         {"$inc": {"total_fetched": actual}})
    if not is_owner and actual_cost > 0:
        cur = users_col.find_one({"_id": user["_id"]})
        credit_log.insert_one({
            "api_key": key, "username": username,
            "delta": f"-{actual_cost}", "reason": "fetch",
            "lines": actual, "balance_after": str(cur.get("credits", "0")),
            "created_at": now(),
        })

    remaining = lines_col.estimated_document_count()
    cur = users_col.find_one({"_id": user["_id"]})
    new_balance = cur.get("credits", "0")

    return jsonify({
        "lines": [d["text"] for d in taken],
        "remaining": remaining,
        "cost": "0" if is_owner else str(actual_cost),
        "credits": "inf" if new_balance == "inf" else str(new_balance),
        "fetch_batch": ts.isoformat(),
    })


@app.route("/api/add", methods=["POST"])
def api_add():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    _, username, _ = ctx

    data = request.get_json(silent=True) or {}
    raw = data.get("lines", [])
    if not isinstance(raw, list):
        return jsonify({"error": "lines must be list"}), 400
    new_lines = [str(t).strip() for t in raw if str(t).strip()]
    if not new_lines:
        return jsonify({"error": "no lines"}), 400

    docs = [{"text": t, "created_at": now(), "added_by": username}
            for t in new_lines]
    lines_col.insert_many(docs)
    users_col.update_one({"username": username},
                         {"$inc": {"total_added": len(docs)}})
    return jsonify({"added": len(docs),
                    "total": lines_col.estimated_document_count()})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    _, username, _ = ctx

    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".txt"):
        return jsonify({"error": "only .txt allowed"}), 400
    raw = f.read().decode("utf-8", errors="replace")
    new_lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not new_lines:
        return jsonify({"error": "file empty"}), 400

    docs = [{"text": t, "created_at": now(), "added_by": username}
            for t in new_lines]
    lines_col.insert_many(docs)
    users_col.update_one({"username": username},
                         {"$inc": {"total_added": len(docs)}})
    return jsonify({"added": len(docs),
                    "total": lines_col.estimated_document_count()})


# ============================================================
#  Credit endpoints
# ============================================================
@app.route("/api/credits/history", methods=["GET"])
def credit_history():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    try:
        limit = min(200, max(1, int(request.args.get("limit", 50))))
    except (TypeError, ValueError):
        limit = 50
    out = []
    for d in credit_log.find({"api_key": key}).sort("created_at", -1).limit(limit):
        out.append({
            "delta": d.get("delta"),
            "reason": d.get("reason"),
            "balance_after": d.get("balance_after"),
            "lines": d.get("lines"),
            "created_at": d["created_at"].isoformat() if d.get("created_at") else None,
        })
    return jsonify({"ok": True, "history": out})


@app.route("/api/credits/redeem", methods=["POST"])
def credit_redeem():
    """
    Redeem a voucher code for credits. Admin creates vouchers via
    /api/admin/voucher. Vouchers are one-shot.
    """
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    _, username, _ = ctx

    data = request.get_json(silent=True) or {}
    code = str(data.get("code", "")).strip().upper()
    if not code:
        return jsonify({"error": "code required"}), 400

    v = db.vouchers.find_one({"code": code, "used": False})
    if not v:
        return jsonify({"error": "invalid or used voucher"}), 404

    amt = Decimal(str(v.get("amount", "0")))
    res = db.vouchers.update_one({"_id": v["_id"], "used": False},
                                 {"$set": {"used": True, "used_by": username,
                                           "used_at": now()}})
    if res.modified_count == 0:
        return jsonify({"error": "voucher already claimed"}), 409

    user = users_col.find_one({"username": username})
    if user.get("credits") == "inf":
        return jsonify({"ok": True, "credits": "inf", "granted": str(amt)})

    cur_bal = Decimal(str(user.get("credits", "0")))
    new_bal = cur_bal + amt
    users_col.update_one({"_id": user["_id"]},
                         {"$set": {"credits": str(new_bal)}})
    credit_log.insert_one({
        "api_key": user["api_key"], "username": username,
        "delta": str(amt), "reason": f"voucher:{code}",
        "balance_after": str(new_bal), "created_at": now(),
    })
    return jsonify({"ok": True, "credits": str(new_bal), "granted": str(amt)})


@app.route("/api/leaderboard", methods=["GET"])
def leaderboard():
    """Top 25 users by credits (excludes owner/inf)."""
    out = []
    for u in users_col.find({"role": "user", "active": True},
                            {"username": 1, "display": 1, "credits": 1,
                             "total_fetched": 1, "total_added": 1}) \
            .sort("total_fetched", -1).limit(25):
        out.append({
            "username": u.get("display") or u.get("username"),
            "credits": u.get("credits", "0"),
            "total_fetched": u.get("total_fetched", 0),
            "total_added": u.get("total_added", 0),
        })
    return jsonify({"ok": True, "leaders": out})


# ============================================================
#  Fetched history (per user)
# ============================================================
@app.route("/api/fetched", methods=["GET"])
def api_fetched():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    try:
        limit = min(500, max(1, int(request.args.get("limit", 100))))
    except (TypeError, ValueError):
        limit = 100
    out = []
    for d in fetched_col.find({"api_key": key}).sort("fetched_at", -1).limit(limit):
        out.append({
            "text": d.get("text"),
            "fetched_at": d["fetched_at"].isoformat() if d.get("fetched_at") else None,
        })
    total = fetched_col.count_documents({"api_key": key})
    return jsonify({"ok": True, "total": total, "lines": out})


@app.route("/api/fetched/count", methods=["GET"])
def api_fetched_count():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    return jsonify({"count": fetched_col.count_documents({"api_key": key})})


@app.route("/api/fetched/export", methods=["GET"])
def api_fetched_export():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    lines = [d["text"] for d in
             fetched_col.find({"api_key": key}).sort("fetched_at", 1)]
    if not lines:
        return jsonify({"error": "empty"}), 404
    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition":
                             'attachment; filename="fetched_lines.txt"'})


@app.route("/api/fetched/clear", methods=["POST"])
def api_fetched_clear():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    r = fetched_col.delete_many({"api_key": key})
    return jsonify({"deleted": r.deleted_count})


# ============================================================
#  Owner / admin endpoints
# ============================================================
@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    ctx = require_owner()
    if not ctx and (not ADMIN_TOKEN or
                    request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN):
        return jsonify({"error": "forbidden"}), 403

    total_users = users_col.count_documents({"active": True})
    total_lines = lines_col.estimated_document_count()
    total_fetched = fetched_col.estimated_document_count()
    new_today = users_col.count_documents({
        "created_at": {"$gte": datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0)}
    })

    recent = []
    for u in users_col.find(
        {}, {"_id": 0, "username": 1, "role": 1, "credits": 1,
             "created_at": 1, "active": 1, "total_fetched": 1}
    ).sort("created_at", -1).limit(25):
        if isinstance(u.get("created_at"), datetime):
            u["created_at"] = u["created_at"].isoformat()
        recent.append(u)

    return jsonify({
        "ok": True,
        "total_users": total_users,
        "new_today": new_today,
        "total_lines": total_lines,
        "total_fetched": total_fetched,
        "recent_users": recent,
        "credits_per_line": str(CREDITS_PER_LINE),
        "server_time": now().isoformat(),
    })


@app.route("/api/admin/grant", methods=["POST"])
def admin_grant():
    """Grant credits to a user. {username, amount}."""
    ctx = require_owner()
    if not ctx and (not ADMIN_TOKEN or
                    request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN):
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    try:
        amount = Decimal(str(data.get("amount", "0")))
    except Exception:
        return jsonify({"error": "amount must be numeric"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400

    user = users_col.find_one({"username": username})
    if not user:
        return jsonify({"error": "user not found"}), 404
    if user.get("credits") == "inf":
        return jsonify({"ok": True, "username": username, "credits": "inf"})

    cur = Decimal(str(user.get("credits", "0")))
    new = cur + amount
    users_col.update_one({"_id": user["_id"]},
                         {"$set": {"credits": str(new)}})
    credit_log.insert_one({
        "api_key": user["api_key"], "username": username,
        "delta": str(amount), "reason": "admin_grant",
        "balance_after": str(new), "created_at": now(),
    })
    return jsonify({"ok": True, "username": username, "credits": str(new)})


@app.route("/api/admin/voucher", methods=["POST"])
def admin_voucher():
    """Create a one-shot voucher. {amount, count?}."""
    ctx = require_owner()
    if not ctx and (not ADMIN_TOKEN or
                    request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN):
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    try:
        amount = Decimal(str(data.get("amount", "0")))
        count = int(data.get("count", 1))
    except Exception:
        return jsonify({"error": "amount/count invalid"}), 400
    if amount <= 0 or count < 1 or count > 500:
        return jsonify({"error": "amount>0 and count 1..500"}), 400

    codes = []
    for _ in range(count):
        code = "LUN-" + secrets.token_hex(6).upper()
        db.vouchers.insert_one({
            "code": code, "amount": str(amount),
            "used": False, "created_at": now(),
            "created_by": ctx[1] if ctx else "admin",
        })
        codes.append(code)
    return jsonify({"ok": True, "amount": str(amount), "codes": codes})


@app.route("/api/admin/pool/clear", methods=["POST"])
def admin_pool_clear():
    ctx = require_owner()
    if not ctx and (not ADMIN_TOKEN or
                    request.headers.get("X-Admin-Token", "") != ADMIN_TOKEN):
        return jsonify({"error": "forbidden"}), 403
    r = lines_col.delete_many({})
    return jsonify({"deleted": r.deleted_count})


@app.route("/api/admin/ban", methods=["POST"])
def admin_ban():
    """Toggle active flag for a user. {username, active}."""
    ctx = require_owner()
    if not ctx:
        return jsonify({"error": "forbidden"}), 403

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    active = bool(data.get("active", False))
    if username == OWNER_USERNAME.lower():
        return jsonify({"error": "cannot ban owner"}), 400

    user = users_col.find_one({"username": username})
    if not user:
        return jsonify({"error": "user not found"}), 404
    users_col.update_one({"_id": user["_id"]}, {"$set": {"active": active}})
    return jsonify({"ok": True, "username": username, "active": active})


# ============================================================
#  Boot
# ============================================================
_ensure_owner()
_seed_pool_once()


if __name__ == "__main__":
    masked = MONGO_URI.split("@")[-1] if "@" in MONGO_URI else MONGO_URI
    print(f"TXT Loader → http://0.0.0.0:{PORT}")
    print(f"Mongo: {masked}  db={DB_NAME}")
    print(f"Credits/line: {CREDITS_PER_LINE}  start: {START_CREDITS}  daily: {DAILY_BONUS}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
