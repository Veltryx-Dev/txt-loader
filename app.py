#!/usr/bin/env python3
"""
app.py — Mongo-backed TXT loader with LABELED SERIAL BATCHES.

Model:
    batches  — {batch_code, label, owner, created_at, archived}
    lines    — every line has batch_code
    fetched  — per-user archive, tagged with batch_code
    users    — accounts, roles, credits
    keys     — api key registry
    credit_log — append-only ledger

Endpoints:
    POST /api/batch/create    {label, code?}   → {batch_code, label}
    GET  /api/batch                            list with counts
    GET  /api/batch/<code>                     one batch
    POST /api/batch/<code>/archive             owner only
    POST /api/add             {batch_code, lines[]}
    POST /api/upload          multipart file + batch_code
    POST /api/fetch           {batch_code, amount}  atomic pop + credits
    GET  /api/peek?batch_code&amount
    GET  /api/count?batch_code
    GET  /api/fetched[?batch_code]
    GET  /api/fetched/export
    POST /api/fetched/clear
    GET  /api/credits/history
    POST /api/credits/redeem  {code}
    GET  /api/leaderboard
    POST /api/signup  /api/login  GET /api/me
    GET  /api/admin/stats  POST /api/admin/grant  /api/admin/voucher
    POST /api/admin/pool/clear?batch_code=X
    POST /api/admin/ban

Env: MONGO_URI, MONGO_DB, JWT_SECRET, OWNER_USERNAME, OWNER_PASSWORD,
     CREDITS_PER_LINE, START_CREDITS, DAILY_BONUS, DEFAULT_BATCH,
     ADMIN_TOKEN, ADMIN_SEED
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

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://tabisulajoshleepagud_db_user:SFVCKdbf36goxyU0@cluster0.g9snriw.mongodb.net)
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

DEFAULT_BATCH = os.environ.get("DEFAULT_BATCH", "LUN-DEFAULT")
ADMIN_SEED    = os.environ.get("ADMIN_SEED", "")

app = Flask(__name__, static_folder=None)
CORS(app)

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
db = client[DB_NAME]

lines_col   = db.lines
fetched_col = db.fetched
users_col   = db.users
keys_col    = db.keys
credit_log  = db.credit_log
batches_col = db.batches

lines_col.create_index([("batch_code", 1), ("created_at", 1), ("_id", 1)])
lines_col.create_index([("batch_code", 1), ("text", 1)])
fetched_col.create_index([("api_key", 1), ("fetched_at", -1)])
fetched_col.create_index([("batch_code", 1), ("fetched_at", -1)])
users_col.create_index([("username", 1)], unique=True)
keys_col.create_index([("key", 1)], unique=True)
credit_log.create_index([("api_key", 1), ("created_at", -1)])
batches_col.create_index([("batch_code", 1)], unique=True)


def now():
    return datetime.now(timezone.utc)


# ============================================================
#  Batch helpers
# ============================================================
def make_batch_code(label: str = "") -> str:
    for _ in range(6):
        code = "LUN-" + secrets.token_hex(3).upper()
        if not batches_col.find_one({"batch_code": code}):
            return code
    return "LUN-" + secrets.token_hex(4).upper()


def ensure_batch(code: str, label: str = "", owner: str = "system") -> dict:
    existing = batches_col.find_one({"batch_code": code})
    if existing:
        return existing
    doc = {
        "batch_code": code,
        "label": label or code,
        "owner": owner,
        "created_at": now(),
        "archived": False,
    }
    try:
        batches_col.insert_one(doc)
    except Exception:
        doc = batches_col.find_one({"batch_code": code}) or doc
    return doc


def batch_count(code: str) -> int:
    return lines_col.count_documents({"batch_code": code})


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
         "role": user_doc.get("role", "user"), "iat": iat, "exp": exp},
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
        ak, un, role = p.get("api_key"), p.get("sub"), p.get("role", "user")
        if not ak or not un:
            return None
        return ak, un, role
    legacy = request.headers.get("X-API-Key", "").strip()
    if legacy and len(legacy) >= 8:
        u = users_col.find_one({"api_key": legacy}, {"username": 1, "role": 1})
        return legacy, (u["username"] if u else None), (u.get("role", "user") if u else "user")
    return None


def require_owner():
    ctx = require_auth()
    if ctx and ctx[2] == "owner":
        return ctx
    if ADMIN_TOKEN and request.headers.get("X-Admin-Token", "") == ADMIN_TOKEN:
        return ("__admin__", "admin", "owner")
    return None


# ============================================================
#  Boot
# ============================================================
def _ensure_owner():
    existing = users_col.find_one({"username": OWNER_USERNAME.lower()})
    if existing:
        if existing.get("role") != "owner":
            users_col.update_one({"_id": existing["_id"]},
                                 {"$set": {"role": "owner"}})
        return
    if not OWNER_PASSWORD or len(OWNER_PASSWORD) < 8:
        print(f"[owner] skip — OWNER_PASSWORD unset or <8")
        return
    salt = secrets.token_hex(16)
    api_key = secrets.token_hex(18)
    users_col.insert_one({
        "username": OWNER_USERNAME.lower(), "display": OWNER_USERNAME,
        "salt": salt, "pw_hash": _hash_password(OWNER_PASSWORD, salt),
        "api_key": api_key, "role": "owner", "credits": "inf",
        "total_fetched": 0, "total_added": 0, "created_at": now(),
        "active": True, "daily_bonus_at": None,
    })
    keys_col.insert_one({"key": api_key, "label": f"owner:{OWNER_USERNAME}",
                         "created_at": now(), "active": True})
    print(f"[owner] created {OWNER_USERNAME}")


def _seed_default_batch():
    ensure_batch(DEFAULT_BATCH, label="Default pool", owner="system")
    if not ADMIN_SEED or batch_count(DEFAULT_BATCH) > 0:
        return
    items = [s.strip() for s in ADMIN_SEED.split(",") if s.strip()]
    if not items:
        return
    lines_col.insert_many([{"batch_code": DEFAULT_BATCH, "text": t,
                            "created_at": now(), "added_by": "owner"} for t in items])
    print(f"[seed] {len(items)} → {DEFAULT_BATCH}")


# ============================================================
#  HTML
# ============================================================
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


# ============================================================
#  Health / stats
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
    try: total_users = users_col.count_documents({"active": True})
    except Exception: total_users = 0
    try: total_lines = lines_col.estimated_document_count()
    except Exception: total_lines = 0
    try: total_batches = batches_col.count_documents({})
    except Exception: total_batches = 0

    out = {"ok": True, "total_users": total_users, "total_lines": total_lines,
           "total_batches": total_batches, "credits_per_line": str(CREDITS_PER_LINE),
           "server_time": now().isoformat()}
    ctx = require_auth()
    if ctx:
        api_key, username, role = ctx
        user = users_col.find_one({"username": username}, {"credits": 1})
        credits = user.get("credits", 0) if user else 0
        out.update({"username": username, "role": role,
                    "credits": "inf" if credits == "inf" else str(credits),
                    "my_fetched": fetched_col.count_documents({"api_key": api_key})})
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
    doc = {"username": username, "display": data.get("display", username)[:40],
           "salt": salt, "pw_hash": _hash_password(password, salt),
           "api_key": api_key, "role": "user", "credits": str(START_CREDITS),
           "total_fetched": 0, "total_added": 0, "created_at": now(),
           "active": True, "daily_bonus_at": None}
    users_col.insert_one(doc)
    keys_col.insert_one({"key": api_key, "label": f"user:{username}",
                         "created_at": now(), "active": True})
    credit_log.insert_one({"api_key": api_key, "username": username,
                           "delta": str(START_CREDITS), "reason": "signup_bonus",
                           "balance_after": str(START_CREDITS), "created_at": now()})
    return jsonify({"ok": True, "token": _make_token(doc), "username": username,
                    "api_key": api_key, "credits": str(START_CREDITS), "role": "user"})


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
    _maybe_daily_bonus(user)
    user = users_col.find_one({"username": username})
    credits = user.get("credits", 0)
    return jsonify({"ok": True, "token": _make_token(user), "username": username,
                    "api_key": user["api_key"], "role": user.get("role", "user"),
                    "credits": "inf" if credits == "inf" else str(credits)})


def _maybe_daily_bonus(user):
    if user.get("role") == "owner":
        return
    last = user.get("daily_bonus_at")
    if isinstance(last, str):
        try: last = datetime.fromisoformat(last)
        except Exception: last = None
    if last and (now() - last) < timedelta(hours=24):
        return
    if DAILY_BONUS <= 0:
        return
    cur = Decimal(str(user.get("credits", "0")))
    new_balance = cur + DAILY_BONUS
    users_col.update_one({"_id": user["_id"]},
                         {"$set": {"credits": str(new_balance),
                                   "daily_bonus_at": now()}})
    credit_log.insert_one({"api_key": user["api_key"], "username": user["username"],
                           "delta": str(DAILY_BONUS), "reason": "daily_bonus",
                           "balance_after": str(new_balance), "created_at": now()})


@app.route("/api/me", methods=["GET"])
def me():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    api_key, username, role = ctx
    user = users_col.find_one({"username": username})
    if not user:
        return jsonify({"error": "user not found"}), 404
    credits = user.get("credits", 0)
    return jsonify({
        "ok": True, "username": username, "role": role,
        "credits": "inf" if credits == "inf" else str(credits),
        "total_fetched": user.get("total_fetched", 0),
        "total_added": user.get("total_added", 0),
        "my_fetched_server": fetched_col.count_documents({"api_key": api_key}),
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
    })


# ============================================================
#  Batches
# ============================================================
@app.route("/api/batch", methods=["GET"])
def api_batch_list():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    role = ctx[2]
    out = []
    for b in batches_col.find({}).sort("created_at", -1).limit(200):
        code = b["batch_code"]
        if b.get("archived") and role != "owner":
            continue
        out.append({
            "batch_code": code,
            "label": b.get("label", code),
            "owner": b.get("owner", "system"),
            "count": batch_count(code),
            "created_at": b["created_at"].isoformat() if b.get("created_at") else None,
            "archived": bool(b.get("archived")),
        })
    return jsonify({"ok": True, "batches": out})


@app.route("/api/batch/create", methods=["POST"])
def api_batch_create():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    _, username, _ = ctx
    data = request.get_json(silent=True) or {}
    label = str(data.get("label", "")).strip()[:80]
    custom = str(data.get("code", "")).strip().upper()

    if custom:
        if len(custom) < 3 or len(custom) > 24:
            return jsonify({"error": "custom code 3-24 chars"}), 400
        if not all(c.isalnum() or c in "-_" for c in custom):
            return jsonify({"error": "custom code alnum/-/_ only"}), 400
        if batches_col.find_one({"batch_code": custom}):
            return jsonify({"error": "batch code already exists"}), 409
        code = custom
    else:
        code = make_batch_code(label)

    ensure_batch(code, label=label or code, owner=username)
    return jsonify({"ok": True, "batch_code": code, "label": label or code})


@app.route("/api/batch/<code>", methods=["GET"])
def api_batch_get(code):
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    b = batches_col.find_one({"batch_code": code})
    if not b:
        return jsonify({"error": "batch not found"}), 404
    return jsonify({"ok": True, "batch_code": code,
                    "label": b.get("label", code),
                    "owner": b.get("owner", "system"),
                    "count": batch_count(code),
                    "archived": bool(b.get("archived")),
                    "created_at": b["created_at"].isoformat() if b.get("created_at") else None})


@app.route("/api/batch/<code>/archive", methods=["POST"])
def api_batch_archive(code):
    ctx = require_owner()
    if not ctx:
        return jsonify({"error": "forbidden"}), 403
    batches_col.update_one({"batch_code": code}, {"$set": {"archived": True}})
    return jsonify({"ok": True, "batch_code": code, "archived": True})


# ============================================================
#  Pool — batch-scoped
# ============================================================
@app.route("/api/count", methods=["GET"])
def api_count():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    code = request.args.get("batch_code", "").strip()
    if code:
        return jsonify({"batch_code": code, "count": batch_count(code)})
    return jsonify({"count": lines_col.estimated_document_count()})


@app.route("/api/peek", methods=["GET"])
def api_peek():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    code = request.args.get("batch_code", DEFAULT_BATCH).strip()
    try:
        amount = max(1, min(500, int(request.args.get("amount", 1))))
    except (TypeError, ValueError):
        amount = 1
    docs = list(lines_col.find({"batch_code": code})
                        .sort("created_at", 1).limit(amount))
    label = (batches_col.find_one({"batch_code": code}, {"label": 1}) or {}).get("label") or code
    return jsonify({"batch_code": code, "batch_label": label,
                    "lines": [d["text"] for d in docs]})


@app.route("/api/fetch", methods=["POST"])
def api_fetch():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, username, role = ctx

    data = request.get_json(silent=True) or {}
    code = str(data.get("batch_code", DEFAULT_BATCH)).strip()
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
    balance_dec = None if is_owner else Decimal(str(balance))
    cost = (CREDITS_PER_LINE * Decimal(amount)).quantize(Decimal("0.01"), rounding=ROUND_DOWN)

    label_doc = batches_col.find_one({"batch_code": code}, {"label": 1}) or {}
    label = label_doc.get("label") or code

    def _refund(amount_dec: Decimal):
        if is_owner or amount_dec <= 0:
            return
        cur = users_col.find_one({"_id": user["_id"]})
        cur_bal = Decimal(str(cur.get("credits", "0")))
        users_col.update_one({"_id": user["_id"]},
                             {"$set": {"credits": str(cur_bal + amount_dec)}})

    if not is_owner:
        if balance_dec < cost:
            affordable = int((balance_dec / CREDITS_PER_LINE).to_integral_value(
                rounding=ROUND_DOWN)) if CREDITS_PER_LINE > 0 else 0
            return jsonify({"error": f"insufficient credits (need {cost}, have {balance_dec})",
                            "cost": str(cost), "have": str(balance_dec),
                            "affordable_lines": affordable}), 402
        upd = users_col.update_one(
            {"_id": user["_id"], "credits": str(balance)},
            {"$set": {"credits": str(balance_dec - cost)}},
        )
        if upd.modified_count == 0:
            return jsonify({"error": "balance changed — retry"}), 409

    # batch pop
    cand = list(lines_col.find({"batch_code": code},
                               {"_id": 1, "text": 1, "created_at": 1})
                         .sort("created_at", 1).limit(amount))

    if not cand:
        _refund(cost)
        return jsonify({"batch_code": code, "batch_label": label,
                        "lines": [], "remaining": 0, "cost": "0"})

    ids = [d["_id"] for d in cand]
    deleted = lines_col.delete_many({"_id": {"$in": ids}})
    taken = cand[:deleted.deleted_count] if deleted.deleted_count < len(cand) else cand
    if not taken:
        _refund(cost)
        return jsonify({"batch_code": code, "batch_label": label,
                        "lines": [], "remaining": 0, "cost": "0"})

    actual = len(taken)
    actual_cost = (CREDITS_PER_LINE * Decimal(actual)).quantize(Decimal("0.01"),
                                                                rounding=ROUND_DOWN)
    if not is_owner and actual < amount:
        _refund(cost - actual_cost)

    ts = now()
    archive = [{"api_key": key, "username": username, "batch_code": code,
                "text": d["text"], "queued_at": d.get("created_at"),
                "fetched_at": ts} for d in taken]
    if len(archive) > 500:
        for i in range(0, len(archive), 500):
            try: fetched_col.insert_many(archive[i:i + 500], ordered=False)
            except Exception: pass
    else:
        try: fetched_col.insert_many(archive, ordered=False)
        except Exception: pass

    users_col.update_one({"_id": user["_id"]}, {"$inc": {"total_fetched": actual}})
    if not is_owner and actual_cost > 0:
        cur = users_col.find_one({"_id": user["_id"]})
        credit_log.insert_one({"api_key": key, "username": username,
                               "delta": f"-{actual_cost}", "reason": f"fetch:{code}",
                               "lines": actual,
                               "balance_after": str(cur.get("credits", "0")),
                               "created_at": now()})

    cur = users_col.find_one({"_id": user["_id"]})
    new_balance = cur.get("credits", "0")
    return jsonify({
        "batch_code": code, "batch_label": label,
        "lines": [d["text"] for d in taken],
        "remaining": batch_count(code),
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
    code = str(data.get("batch_code", DEFAULT_BATCH)).strip()
    raw = data.get("lines", [])
    if not isinstance(raw, list):
        return jsonify({"error": "lines must be list"}), 400
    new_lines = [str(t).strip() for t in raw if str(t).strip()]
    if not new_lines:
        return jsonify({"error": "no lines"}), 400
    ensure_batch(code, owner=username)
    lines_col.insert_many([{"batch_code": code, "text": t,
                            "created_at": now(), "added_by": username}
                           for t in new_lines])
    users_col.update_one({"username": username}, {"$inc": {"total_added": len(new_lines)}})
    return jsonify({"batch_code": code, "added": len(new_lines),
                    "total": batch_count(code)})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    _, username, _ = ctx
    code = request.form.get("batch_code", DEFAULT_BATCH).strip()
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files["file"]
    if not f.filename or not f.filename.lower().endswith(".txt"):
        return jsonify({"error": "only .txt allowed"}), 400
    raw = f.read().decode("utf-8", errors="replace")
    new_lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not new_lines:
        return jsonify({"error": "file empty"}), 400
    ensure_batch(code, owner=username)
    lines_col.insert_many([{"batch_code": code, "text": t,
                            "created_at": now(), "added_by": username}
                           for t in new_lines])
    users_col.update_one({"username": username}, {"$inc": {"total_added": len(new_lines)}})
    return jsonify({"batch_code": code, "added": len(new_lines),
                    "total": batch_count(code)})


# ============================================================
#  Credits / leaderboard
# ============================================================
@app.route("/api/credits/history", methods=["GET"])
def credit_history():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    try: limit = min(200, max(1, int(request.args.get("limit", 50))))
    except (TypeError, ValueError): limit = 50
    out = []
    for d in credit_log.find({"api_key": key}).sort("created_at", -1).limit(limit):
        out.append({"delta": d.get("delta"), "reason": d.get("reason"),
                    "balance_after": d.get("balance_after"), "lines": d.get("lines"),
                    "created_at": d["created_at"].isoformat() if d.get("created_at") else None})
    return jsonify({"ok": True, "history": out})


@app.route("/api/credits/redeem", methods=["POST"])
def credit_redeem():
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
    users_col.update_one({"_id": user["_id"]}, {"$set": {"credits": str(new_bal)}})
    credit_log.insert_one({"api_key": user["api_key"], "username": username,
                           "delta": str(amt), "reason": f"voucher:{code}",
                           "balance_after": str(new_bal), "created_at": now()})
    return jsonify({"ok": True, "credits": str(new_bal), "granted": str(amt)})


@app.route("/api/leaderboard", methods=["GET"])
def leaderboard():
    out = []
    for u in users_col.find({"role": "user", "active": True},
                            {"username": 1, "display": 1, "credits": 1,
                             "total_fetched": 1, "total_added": 1}) \
            .sort("total_fetched", -1).limit(25):
        out.append({"username": u.get("display") or u.get("username"),
                    "credits": u.get("credits", "0"),
                    "total_fetched": u.get("total_fetched", 0),
                    "total_added": u.get("total_added", 0)})
    return jsonify({"ok": True, "leaders": out})


# ============================================================
#  Fetched history
# ============================================================
@app.route("/api/fetched", methods=["GET"])
def api_fetched():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    batch = request.args.get("batch_code", "").strip()
    try: limit = min(500, max(1, int(request.args.get("limit", 100))))
    except (TypeError, ValueError): limit = 100
    q = {"api_key": key}
    if batch: q["batch_code"] = batch
    out = []
    for d in fetched_col.find(q).sort("fetched_at", -1).limit(limit):
        out.append({"text": d.get("text"), "batch_code": d.get("batch_code"),
                    "fetched_at": d["fetched_at"].isoformat() if d.get("fetched_at") else None})
    return jsonify({"ok": True, "total": fetched_col.count_documents(q), "lines": out})


@app.route("/api/fetched/export", methods=["GET"])
def api_fetched_export():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    batch = request.args.get("batch_code", "").strip()
    q = {"api_key": key}
    if batch: q["batch_code"] = batch
    lines = [d["text"] for d in fetched_col.find(q).sort("fetched_at", 1)]
    if not lines:
        return jsonify({"error": "empty"}), 404
    body = "\n".join(lines) + "\n"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition":
                             f'attachment; filename="fetched_{batch or "all"}.txt"'})


@app.route("/api/fetched/clear", methods=["POST"])
def api_fetched_clear():
    ctx = require_auth()
    if not ctx:
        return jsonify({"error": "unauthorized"}), 401
    key, _, _ = ctx
    batch = request.args.get("batch_code", "").strip()
    q = {"api_key": key}
    if batch: q["batch_code"] = batch
    r = fetched_col.delete_many(q)
    return jsonify({"deleted": r.deleted_count})


# ============================================================
#  Owner
# ============================================================
@app.route("/api/admin/stats", methods=["GET"])
def admin_stats():
    ctx = require_owner()
    if not ctx:
        return jsonify({"error": "forbidden"}), 403
    total_users = users_col.count_documents({"active": True})
    total_lines = lines_col.estimated_document_count()
    total_fetched = fetched_col.estimated_document_count()
    total_batches = batches_col.count_documents({})
    new_today = users_col.count_documents({
        "created_at": {"$gte": datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0)}
    })
    batches = []
    for b in batches_col.find({}).sort("created_at", -1).limit(50):
        batches.append({"batch_code": b["batch_code"], "label": b.get("label"),
                        "count": batch_count(b["batch_code"]),
                        "archived": bool(b.get("archived"))})
    return jsonify({"ok": True, "total_users": total_users, "new_today": new_today,
                    "total_lines": total_lines, "total_fetched": total_fetched,
                    "total_batches": total_batches, "batches": batches,
                    "credits_per_line": str(CREDITS_PER_LINE),
                    "server_time": now().isoformat()})


@app.route("/api/admin/grant", methods=["POST"])
def admin_grant():
    ctx = require_owner()
    if not ctx:
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    try: amount = Decimal(str(data.get("amount", "0")))
    except Exception: return jsonify({"error": "amount numeric"}), 400
    if amount <= 0:
        return jsonify({"error": "amount > 0"}), 400
    user = users_col.find_one({"username": username})
    if not user:
        return jsonify({"error": "user not found"}), 404
    if user.get("credits") == "inf":
        return jsonify({"ok": True, "username": username, "credits": "inf"})
    cur = Decimal(str(user.get("credits", "0")))
    new = cur + amount
    users_col.update_one({"_id": user["_id"]}, {"$set": {"credits": str(new)}})
    credit_log.insert_one({"api_key": user["api_key"], "username": username,
                           "delta": str(amount), "reason": "admin_grant",
                           "balance_after": str(new), "created_at": now()})
    return jsonify({"ok": True, "username": username, "credits": str(new)})


@app.route("/api/admin/voucher", methods=["POST"])
def admin_voucher():
    ctx = require_owner()
    if not ctx:
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    try:
        amount = Decimal(str(data.get("amount", "0")))
        count = int(data.get("count", 1))
    except Exception:
        return jsonify({"error": "invalid amount/count"}), 400
    if amount <= 0 or count < 1 or count > 500:
        return jsonify({"error": "amount>0, count 1..500"}), 400
    codes = []
    for _ in range(count):
        code = "LUN-" + secrets.token_hex(6).upper()
        db.vouchers.insert_one({"code": code, "amount": str(amount),
                                "used": False, "created_at": now(),
                                "created_by": ctx[1] if ctx else "admin"})
        codes.append(code)
    return jsonify({"ok": True, "amount": str(amount), "codes": codes})


@app.route("/api/admin/pool/clear", methods=["POST"])
def admin_pool_clear():
    ctx = require_owner()
    if not ctx:
        return jsonify({"error": "forbidden"}), 403
    code = request.args.get("batch_code", "").strip()
    q = {"batch_code": code} if code else {}
    r = lines_col.delete_many(q)
    return jsonify({"deleted": r.deleted_count, "batch_code": code or "ALL"})


@app.route("/api/admin/ban", methods=["POST"])
def admin_ban():
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
_seed_default_batch()


if __name__ == "__main__":
    masked = MONGO_URI.split("@")[-1] if "@" in MONGO_URI else MONGO_URI
    print(f"TXT Loader → http://0.0.0.0:{PORT}")
    print(f"Mongo: {masked}  db={DB_NAME}")
    print(f"Default batch: {DEFAULT_BATCH}")
    app.run(host="0.0.0.0", port=PORT, debug=False)
