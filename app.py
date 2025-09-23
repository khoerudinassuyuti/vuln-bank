#!/usr/bin/env python3
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import time
import os
import jwt
import secrets
import string
import logging
from functools import wraps
import psycopg2
from psycopg2 import pool
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# -------------------------------
# Config / Globals
# -------------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "vulnerable_bank")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")

JWT_SECRET = os.getenv("JWT_SECRET", "please_change_me_to_a_strong_secret")
JWT_ALGO = "HS256"

# connection pool
connection_pool = None

# Rate limit placeholders
rate_limit_storage = {}
UNAUTHENTICATED_LIMIT = int(os.getenv("UNAUTH_LIMIT", 20))
AUTHENTICATED_LIMIT = int(os.getenv("AUTH_LIMIT", 100))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", 60 * 60 * 3))


# -------------------------------
# DB / Auth / Utility helpers
# -------------------------------
def init_db():
    global connection_pool
    if connection_pool:
        return
    try:
        connection_pool = psycopg2.pool.SimpleConnectionPool(
            1, 20,
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        logger.info("DB connection pool created successfully")
    except Exception:
        logger.exception("Failed to initialize DB pool")
        raise


def execute_query(query, params=None, fetch=False):
    """
    Execute parameterized query.
    - params: tuple/list or None
    - fetch: if True returns cur.fetchall()
    """
    conn = None
    cur = None
    try:
        if connection_pool is None:
            init_db()
        conn = connection_pool.getconn()
        cur = conn.cursor()
        cur.execute(query, params or ())
        if fetch:
            rows = cur.fetchall()
            return rows
        conn.commit()
        return None
    except Exception:
        logger.exception("DB error on execute_query")
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            connection_pool.putconn(conn)


def execute_transaction(queries):
    """
    queries: list of tuples (query, params)
    Run inside a DB transaction (atomic).
    """
    conn = None
    cur = None
    try:
        if connection_pool is None:
            init_db()
        conn = connection_pool.getconn()
        cur = conn.cursor()
        for q, p in queries:
            cur.execute(q, p)
        conn.commit()
        return True
    except Exception:
        if conn:
            conn.rollback()
        logger.exception("Transaction error")
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            connection_pool.putconn(conn)


def generate_card_number():
    # Demo generator: not for production use
    prefix = "400000"
    remaining = ''.join(secrets.choice(string.digits) for _ in range(10))
    return prefix + remaining


def generate_cvv():
    return ''.join(secrets.choice(string.digits) for _ in range(3))


def mask_card_number(card_number):
    s = str(card_number)
    if len(s) >= 4:
        return "**** **** **** " + s[-4:]
    return "****"


def generate_token(payload, exp_seconds=3600):
    p = payload.copy()
    p['exp'] = int(time.time()) + exp_seconds
    return jwt.encode(p, JWT_SECRET, algorithm=JWT_ALGO)


def verify_token(token):
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return data
    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth or not auth.startswith("Bearer "):
            return jsonify({'status': 'error', 'message': 'Authorization header missing'}), 401
        token = auth.split(" ", 1)[1].strip()
        user_data = verify_token(token)
        if not user_data:
            return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 401
        # pass current_user (dict from token) as first argument
        return f(user_data, *args, **kwargs)
    return decorated


def get_client_ip():
    return request.remote_addr


def cleanup_rate_limit_storage():
    now = time.time()
    for k in list(rate_limit_storage.keys()):
        rate_limit_storage[k] = [(t, c) for (t, c) in rate_limit_storage[k] if t > now - RATE_LIMIT_WINDOW]


# -------------------------------
# Simple ai_rate_limit decorator (placeholder)
# -------------------------------
def ai_rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Placeholder: In production implement a robust rate limiter (Redis, token bucket, etc.)
        return f(*args, **kwargs)
    return decorated


# -------------------------------
# Auth routes (basic demo)
# -------------------------------
def init_auth_routes(app):
    """
    Minimal auth endpoints for demo: register & login.
    In production, harden input validation, email verification, rate limiting, etc.
    """
    @app.route('/register', methods=['POST'])
    def register():
        try:
            data = request.get_json() or {}
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                return jsonify({'status': 'error', 'message': 'username and password required'}), 400
            # hash password
            password_hash = generate_password_hash(password)
            query = "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
            execute_query(query, (username, password_hash))
            return jsonify({'status': 'success', 'message': 'registered'}), 201
        except Exception:
            logger.exception("Error in register")
            return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

    @app.route('/login', methods=['POST'])
    def login():
        try:
            data = request.get_json() or {}
            username = data.get('username')
            password = data.get('password')
            if not username or not password:
                return jsonify({'status': 'error', 'message': 'username and password required'}), 400
            query = "SELECT id, username, password_hash FROM users WHERE username = %s"
            rows = execute_query(query, (username,), fetch=True)
            if not rows:
                return jsonify({'status': 'error', 'message': 'invalid credentials'}), 401
            row = rows[0]
            password_hash = row[2]
            if check_password_hash(password_hash, password):
                token = generate_token({'user_id': row[0], 'username': row[1]})
                return jsonify({'status': 'success', 'token': token})
            return jsonify({'status': 'error', 'message': 'invalid credentials'}), 401
        except Exception:
            logger.exception("Error in login")
            return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


# -------------------------------
# Virtual Cards
# -------------------------------

@app.route('/api/virtual-cards', methods=['POST'])
@token_required
def create_virtual_card(current_user):
    try:
        data = request.get_json() or {}
        card_limit = float(data.get('card_limit', 0))
        card_number = generate_card_number()
        cvv = generate_cvv()
        expiry_date = (datetime.now() + timedelta(days=365)).strftime('%m/%y')
        card_type = data.get('card_type', 'standard')

        query = """
            INSERT INTO virtual_cards
            (user_id, card_number, cvv, expiry_date, card_limit, card_type)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """
        result = execute_query(
            query,
            (current_user['user_id'], card_number, cvv, expiry_date, card_limit, card_type),
            fetch=True
        )

        if result:
            masked = mask_card_number(card_number)
            # Do NOT return CVV or full card number
            return jsonify({
                'status': 'success',
                'message': 'Virtual card created successfully',
                'card_details': {
                    'card_last4': masked,
                    'expiry_date': expiry_date,
                    'limit': card_limit,
                    'type': card_type
                }
            })
        return jsonify({'status': 'error', 'message': 'Failed to create virtual card'}), 500
    except Exception:
        logger.exception("Error in create_virtual_card")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/virtual-cards', methods=['GET'])
@token_required
def get_virtual_cards(current_user):
    try:
        # simple pagination
        page = max(1, int(request.args.get('page', 1)))
        page_size = min(100, max(1, int(request.args.get('page_size', 25))))
        offset = (page - 1) * page_size

        query = """
            SELECT id, card_number, expiry_date, card_limit, current_balance,
                   is_frozen, is_active, created_at, last_used_at, card_type
            FROM virtual_cards
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """
        cards = execute_query(query, (current_user['user_id'], page_size, offset), fetch=True)
        return jsonify({
            'status': 'success',
            'cards': [{
                'id': card[0],
                'card_last4': mask_card_number(card[1]),
                'expiry_date': card[2],
                'limit': float(card[3]),
                'balance': float(card[4]),
                'is_frozen': card[5],
                'is_active': card[6],
                'created_at': str(card[7]),
                'last_used_at': str(card[8]) if card[8] else None,
                'card_type': card[9]
            } for card in cards]
        })
    except Exception:
        logger.exception("Error in get_virtual_cards")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/virtual-cards/<int:card_id>/toggle-freeze', methods=['POST'])
@token_required
def toggle_card_freeze(current_user, card_id):
    try:
        # Cek kepemilikan kartu
        query_check = "SELECT id, is_frozen FROM virtual_cards WHERE id=%s AND user_id=%s"
        card = execute_query(query_check, (card_id, current_user['user_id']), fetch=True)
        if not card:
            return jsonify({'status': 'error', 'message': 'Card not found or unauthorized'}), 403

        current_status = bool(card[0][1])
        new_status = not current_status
        query = "UPDATE virtual_cards SET is_frozen=%s WHERE id=%s RETURNING is_frozen"
        result = execute_query(query, (new_status, card_id), fetch=True)
        if result:
            is_frozen_now = bool(result[0][0])
            return jsonify({'status': 'success', 'message': f"Card {'frozen' if is_frozen_now else 'unfrozen'} successfully"})
        return jsonify({'status': 'error', 'message': 'Card not found'}), 404
    except Exception:
        logger.exception("Error in toggle_card_freeze")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/virtual-cards/<int:card_id>/transactions', methods=['GET'])
@token_required
def get_card_transactions(current_user, card_id):
    try:
        # only owner can fetch transactions for the card
        query_check = "SELECT id FROM virtual_cards WHERE id=%s AND user_id=%s"
        card = execute_query(query_check, (card_id, current_user['user_id']), fetch=True)
        if not card:
            return jsonify({'status': 'error', 'message': 'Card not found or unauthorized'}), 403

        query = """
            SELECT ct.id, ct.user_id, ct.amount, ct.merchant, ct.type, ct.status, ct.timestamp, ct.description, vc.card_number
            FROM card_transactions ct
            JOIN virtual_cards vc ON ct.card_id = vc.id
            WHERE ct.card_id = %s
            ORDER BY ct.timestamp DESC
            LIMIT %s OFFSET %s
        """
        # basic pagination for transactions
        page = max(1, int(request.args.get('page', 1)))
        page_size = min(100, max(1, int(request.args.get('page_size', 25))))
        offset = (page - 1) * page_size

        transactions = execute_query(query, (card_id, page_size, offset), fetch=True)

        return jsonify({
            'status': 'success',
            'transactions': [{
                'id': t[0],
                'amount': float(t[2]),
                'merchant': t[3],
                'type': t[4],
                'status': t[5],
                'timestamp': str(t[6]),
                'description': t[7],
                'card_last4': mask_card_number(t[8])
            } for t in transactions]
        })
    except Exception:
        logger.exception("Error in get_card_transactions")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/virtual-cards/<int:card_id>/update-limit', methods=['POST'])
@token_required
def update_card_limit(current_user, card_id):
    try:
        data = request.get_json() or {}
        # Cek kepemilikan kartu
        query_check = "SELECT id FROM virtual_cards WHERE id=%s AND user_id=%s"
        card = execute_query(query_check, (card_id, current_user['user_id']), fetch=True)
        if not card:
            return jsonify({'status': 'error', 'message': 'Card not found or unauthorized'}), 403

        update_fields = []
        update_values = []

        for key, value in data.items():
            if key not in ['card_limit', 'card_type', 'is_active']:
                continue
            # coerce types
            if key == 'card_limit':
                try:
                    value = float(value)
                except Exception:
                    return jsonify({'status': 'error', 'message': 'Invalid card_limit value'}), 400
            update_fields.append(f"{key}=%s")
            update_values.append(value)

        if not update_fields:
            return jsonify({'status': 'error', 'message': 'No valid fields to update'}), 400

        query = f"UPDATE virtual_cards SET {', '.join(update_fields)} WHERE id=%s RETURNING id, card_limit, current_balance, is_frozen, is_active, card_type"
        result = execute_query(query, tuple(update_values + [card_id]), fetch=True)
        if result:
            return jsonify({'status': 'success', 'message': 'Card updated successfully', 'card_details': {
                'id': result[0][0],
                'card_limit': float(result[0][1]),
                'current_balance': float(result[0][2]),
                'is_frozen': result[0][3],
                'is_active': result[0][4],
                'card_type': result[0][5]
            }})
        return jsonify({'status': 'error', 'message': 'Update failed'}), 500
    except Exception:
        logger.exception("Error in update_card_limit")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


# -------------------------------
# Bill Payments & Lookups
# -------------------------------

@app.route('/api/bill-categories', methods=['GET'])
def get_bill_categories():
    try:
        query = "SELECT id, name, description FROM bill_categories WHERE is_active = TRUE"
        categories = execute_query(query, fetch=True)
        return jsonify({'status': 'success', 'categories': [{'id': c[0], 'name': c[1], 'description': c[2]} for c in categories]})
    except Exception:
        logger.exception("Error in get_bill_categories")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/billers/by-category/<int:category_id>', methods=['GET'])
def get_billers_by_category(category_id):
    try:
        query = "SELECT id, name, account_number, description, minimum_amount, maximum_amount FROM billers WHERE category_id=%s AND is_active=TRUE"
        billers = execute_query(query, (category_id,), fetch=True)
        return jsonify({'status': 'success', 'billers': [{'id': b[0], 'name': b[1], 'account_number': b[2], 'description': b[3], 'minimum_amount': float(b[4]), 'maximum_amount': float(b[5]) if b[5] else None} for b in billers]})
    except Exception:
        logger.exception("Error in get_billers_by_category")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/bill-payments/create', methods=['POST'])
@token_required
def create_bill_payment(current_user):
    try:
        data = request.get_json() or {}
        biller_id = data.get('biller_id')
        amount = float(data.get('amount'))
        payment_method = data.get('payment_method')
        card_id = data.get('card_id') if payment_method == 'virtual_card' else None
        queries = []

        if payment_method == 'virtual_card' and card_id:
            # cek kepemilikan & saldo
            query_check = "SELECT current_balance, is_frozen FROM virtual_cards WHERE id=%s AND user_id=%s"
            card_res = execute_query(query_check, (card_id, current_user['user_id']), fetch=True)
            if not card_res:
                return jsonify({'status': 'error', 'message': 'Card not found or unauthorized'}), 403
            card = card_res[0]
            if card[1]:
                return jsonify({'status': 'error', 'message': 'Card is frozen'}), 400
            if amount > float(card[0]):
                return jsonify({'status': 'error', 'message': 'Insufficient card balance'}), 400
            queries.append(("UPDATE virtual_cards SET current_balance = current_balance - %s WHERE id=%s", (amount, card_id)))
        else:
            # cek saldo user
            query_balance = "SELECT balance FROM users WHERE id=%s"
            balance_rows = execute_query(query_balance, (current_user['user_id'],), fetch=True)
            if not balance_rows:
                return jsonify({'status': 'error', 'message': 'User balance not found'}), 400
            balance = float(balance_rows[0][0])
            if amount > float(balance):
                return jsonify({'status': 'error', 'message': 'Insufficient balance'}), 400
            queries.append(("UPDATE users SET balance = balance - %s WHERE id=%s", (amount, current_user['user_id'])))

        reference = f"BILL{int(time.time())}{secrets.token_hex(4)}"
        queries.insert(0, (
            "INSERT INTO bill_payments (user_id, biller_id, amount, payment_method, card_id, reference_number, description) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id",
            (current_user['user_id'], biller_id, amount, payment_method, card_id, reference, data.get('description', 'Bill Payment'))
        ))
        execute_transaction(queries)

        return jsonify({'status': 'success', 'message': 'Payment processed', 'payment_details': {'reference': reference, 'amount': amount, 'payment_method': payment_method, 'card_id': card_id, 'processed_by': current_user['username'], 'timestamp': str(datetime.now())}})
    except Exception:
        logger.exception("Error in create_bill_payment")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/bill-payments/history', methods=['GET'])
@token_required
def get_payment_history(current_user):
    try:
        # pagination
        page = max(1, int(request.args.get('page', 1)))
        page_size = min(100, max(1, int(request.args.get('page_size', 25))))
        offset = (page - 1) * page_size

        query = """
        SELECT
            bp.*,
            b.name as biller_name,
            bc.name as category_name,
            vc.card_number
        FROM bill_payments bp
        JOIN billers b ON bp.biller_id = b.id
        JOIN bill_categories bc ON b.category_id = bc.id
        LEFT JOIN virtual_cards vc ON bp.card_id = vc.id
        WHERE bp.user_id = %s
        ORDER BY bp.created_at DESC
        LIMIT %s OFFSET %s
        """
        payments = execute_query(query, (current_user['user_id'], page_size, offset), fetch=True)
        return jsonify({'status': 'success', 'payments': [{
            'id': p[0],
            'amount': float(p[3]),
            'payment_method': p[4],
            'card_last4': mask_card_number(p[13]) if p[13] else None,
            'reference': p[6],
            'status': p[7],
            'created_at': str(p[8]),
            'processed_at': str(p[9]) if p[9] else None,
            'description': p[10],
            'biller_name': p[11],
            'category_name': p[12]
        } for p in payments]})
    except Exception:
        logger.exception("Error in get_payment_history")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


# -------------------------------
# AI demo endpoints (intentionally limited)
# -------------------------------

# Placeholder ai_agent with minimal API for demo
class DummyAIAgent:
    def chat(self, message, context):
        return {"reply": f"(demo) {message[:200]}"}

    def get_system_info(self):
        return {"version": "demo", "notes": "No secrets exposed"}

ai_agent = DummyAIAgent()


@app.route('/api/ai/chat', methods=['POST'])
@ai_rate_limit
@token_required
def ai_chat_authenticated(current_user):
    """
    Demo authenticated AI chat. This endpoint is intentionally simplified.
    In production, DO NOT pass sensitive user context to external AI without consent and policy.
    """
    try:
        data = request.get_json() or {}
        user_message = data.get('message', '').strip()
        if not user_message:
            return jsonify({'status': 'error', 'message': 'Message is required'}), 400

        # Fetch limited user context (no secrets)
        rows = execute_query("SELECT id, username, account_number, balance, is_admin FROM users WHERE id = %s", (current_user['user_id'],), fetch=True)
        if rows:
            u = rows[0]
            user_context = {'user_id': u[0], 'username': u[1], 'account_number': u[2], 'balance': float(u[3]) if u[3] else 0.0, 'is_admin': bool(u[4])}
        else:
            user_context = {'user_id': current_user['user_id'], 'username': current_user['username']}

        # NOTE: This is a placeholder. Do not call external AI with raw user input in production.
        ai_response = ai_agent.chat(user_message, user_context)
        return jsonify({'status': 'success', 'ai_response': ai_response, 'mode': 'authenticated'})
    except Exception:
        logger.exception("Error in ai_chat_authenticated")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/ai/chat/anonymous', methods=['POST'])
@ai_rate_limit
def ai_chat_anonymous():
    try:
        data = request.get_json() or {}
        user_message = data.get('message', '').strip()
        if not user_message:
            return jsonify({'status': 'error', 'message': 'Message is required'}), 400
        # placeholder response
        ai_response = ai_agent.chat(user_message, None)
        return jsonify({'status': 'success', 'ai_response': ai_response, 'mode': 'anonymous', 'warning': 'No authentication - demo only'})
    except Exception:
        logger.exception("Error in ai_chat_anonymous")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/ai/system-info', methods=['GET'])
def ai_system_info():
    try:
        # Minimal info only; do NOT expose secrets or system prompts
        info = {
            'status': 'success',
            'endpoints': {
                'authenticated_chat': '/api/ai/chat',
                'anonymous_chat': '/api/ai/chat/anonymous',
                'system_info': '/api/ai/system-info'
            },
            'modes': {
                'authenticated': 'Requires JWT token',
                'anonymous': 'No authentication'
            },
            'note': 'This demo endpoint intentionally limits information exposure'
        }
        return jsonify(info)
    except Exception:
        logger.exception("Error in ai_system_info")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


@app.route('/api/ai/rate-limit-status', methods=['GET'])
def ai_rate_limit_status():
    try:
        cleanup_rate_limit_storage()
        client_ip = get_client_ip()
        current_time = time.time()

        status = {
            'status': 'success',
            'client_ip': client_ip,
            'rate_limits': {
                'unauthenticated': {
                    'limit': UNAUTHENTICATED_LIMIT,
                    'window_hours': RATE_LIMIT_WINDOW / 3600,
                    'requests_made': 0
                },
                'authenticated': {
                    'limit': AUTHENTICATED_LIMIT,
                    'window_hours': RATE_LIMIT_WINDOW / 3600,
                    'user_requests_made': 0,
                    'ip_requests_made': 0
                }
            }
        }

        # Check unauthenticated rate limit
        unauth_key = f"ai_unauth_ip_{client_ip}"
        unauth_count = sum(count for timestamp, count in rate_limit_storage.get(unauth_key, []) if timestamp > current_time - RATE_LIMIT_WINDOW)
        status['rate_limits']['unauthenticated']['requests_made'] = unauth_count
        status['rate_limits']['unauthenticated']['remaining'] = max(0, UNAUTHENTICATED_LIMIT - unauth_count)

        # Check if user is authenticated
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ', 1)[1].strip()
            user_data = verify_token(token)
            if user_data:
                user_key = f"ai_auth_user_{user_data['user_id']}"
                ip_key = f"ai_auth_ip_{client_ip}"
                user_count = sum(count for timestamp, count in rate_limit_storage.get(user_key, []) if timestamp > current_time - RATE_LIMIT_WINDOW)
                ip_count = sum(count for timestamp, count in rate_limit_storage.get(ip_key, []) if timestamp > current_time - RATE_LIMIT_WINDOW)
                status['rate_limits']['authenticated']['user_requests_made'] = user_count
                status['rate_limits']['authenticated']['ip_requests_made'] = ip_count
                status['rate_limits']['authenticated']['user_remaining'] = max(0, AUTHENTICATED_LIMIT - user_count)
                status['rate_limits']['authenticated']['ip_remaining'] = max(0, AUTHENTICATED_LIMIT - ip_count)
                status['authenticated_user'] = {
                    'user_id': user_data.get('user_id'),
                    'username': user_data.get('username')
                }

        return jsonify(status)
    except Exception:
        logger.exception("Error in ai_rate_limit_status")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500


# -------------------------------
# Main
# -------------------------------
if __name__ == '__main__':
    init_db()
    init_auth_routes(app)
    # dev mode: debug=False (do not expose detailed errors)
    app.run(host='0.0.0.0', port=5000, debug=False)

