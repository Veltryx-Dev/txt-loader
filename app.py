from flask import Flask, request, jsonify, send_from_directory
from pymongo import MongoClient
from datetime import datetime
import os

app = Flask(__name__, static_folder='.', static_url_path='')

MONGO_URI = os.environ.get('MONGO_URI', 'mongodb+srv://tabisulajoshleepagud_db_user:SFVCKdbf36goxyU0@cluster0.g9snriw.mongodb.net')
DB_NAME = os.environ.get('MONGO_DB', 'txtloader')

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
db = client[DB_NAME]
lines_col = db.lines
lines_col.create_index([('api_key', 1), ('created_at', 1)])


def require_key():
    key = request.headers.get('X-API-Key', '').strip()
    if not key or len(key) < 8:
        return None
    return key


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/api/upload', methods=['POST'])
def upload():
    key = require_key()
    if not key:
        return jsonify({'error': 'missing or invalid X-API-Key'}), 401
    if 'file' not in request.files:
        return jsonify({'error': 'no file'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.txt'):
        return jsonify({'error': 'only .txt allowed'}), 400
    raw = f.read().decode('utf-8', errors='replace')
    new_lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not new_lines:
        return jsonify({'error': 'file empty'}), 400
    docs = [{'api_key': key, 'text': t, 'created_at': datetime.utcnow()} for t in new_lines]
    lines_col.insert_many(docs)
    total = lines_col.count_documents({'api_key': key})
    return jsonify({'added': len(docs), 'total': total})


@app.route('/api/add', methods=['POST'])
def add():
    key = require_key()
    if not key:
        return jsonify({'error': 'missing or invalid X-API-Key'}), 401
    data = request.get_json(silent=True) or {}
    raw = data.get('lines', [])
    if not isinstance(raw, list):
        return jsonify({'error': 'lines must be a list'}), 400
    new_lines = [str(t).strip() for t in raw if str(t).strip()]
    if not new_lines:
        return jsonify({'error': 'no lines'}), 400
    docs = [{'api_key': key, 'text': t, 'created_at': datetime.utcnow()} for t in new_lines]
    lines_col.insert_many(docs)
    total = lines_col.count_documents({'api_key': key})
    return jsonify({'added': len(docs), 'total': total})


@app.route('/api/fetch', methods=['POST'])
def fetch():
    key = require_key()
    if not key:
        return jsonify({'error': 'missing or invalid X-API-Key'}), 401
    data = request.get_json(silent=True) or {}
    try:
        amount = int(data.get('amount', 1))
    except (TypeError, ValueError):
        return jsonify({'error': 'amount must be int'}), 400
    if amount < 1:
        return jsonify({'error': 'amount >= 1'}), 400
    docs = list(lines_col.find({'api_key': key}).sort('created_at', 1).limit(amount))
    if not docs:
        return jsonify({'lines': [], 'remaining': 0})
    ids = [d['_id'] for d in docs]
    lines_col.delete_many({'_id': {'$in': ids}})
    remaining = lines_col.count_documents({'api_key': key})
    return jsonify({'lines': [d['text'] for d in docs], 'remaining': remaining})


@app.route('/api/peek', methods=['GET'])
def peek():
    key = require_key()
    if not key:
        return jsonify({'error': 'missing or invalid X-API-Key'}), 401
    try:
        amount = max(1, int(request.args.get('amount', 1)))
    except (TypeError, ValueError):
        amount = 1
    docs = list(lines_col.find({'api_key': key}).sort('created_at', 1).limit(amount))
    return jsonify({'lines': [d['text'] for d in docs]})


@app.route('/api/count', methods=['GET'])
def count():
    key = require_key()
    if not key:
        return jsonify({'error': 'missing or invalid X-API-Key'}), 401
    return jsonify({'count': lines_col.count_documents({'api_key': key})})


@app.route('/api/clear', methods=['POST'])
def clear():
    key = require_key()
    if not key:
        return jsonify({'error': 'missing or invalid X-API-Key'}), 401
    result = lines_col.delete_many({'api_key': key})
    return jsonify({'deleted': result.deleted_count})


@app.route('/api/health', methods=['GET'])
def health():
    try:
        client.admin.command('ping')
        return jsonify({'ok': True, 'mongo': True})
    except Exception as e:
        return jsonify({'ok': False, 'mongo': False, 'error': str(e)}), 503


if __name__ == '__main__':
    print('TXT Loader Pro → http://127.0.0.1:5000')
    print(f'Mongo: {MONGO_URI}  db={DB_NAME}')
    app.run(host='0.0.0.0', port=5000, debug=False)
