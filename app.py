from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VoiceGrant
from twilio.twiml.voice_response import VoiceResponse, Dial
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ========= DATABASE =========
DB_HOST = os.getenv("DB_HOST")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

# ========= TWILIO =========
ACCOUNT_SID = os.getenv("ACCOUNT_SID")          # AC...
API_KEY_SID = os.getenv("API_KEY_SID")          # SK...
API_KEY_SECRET = os.getenv("API_KEY_SECRET")
TWIML_APP_SID = os.getenv("TWIML_APP_SID")      # AP...

# ===========================

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ========= REGISTER =========
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'username and password required'}), 400

    hashed = hash_password(password)

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hashed)
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({'error': 'username already exists'}), 400
    finally:
        cur.close()
        conn.close()

    return jsonify({'message': 'registered'})

# ========= LOGIN =========
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    hashed = hash_password(password)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user:
        return jsonify({'error': 'user not found'}), 404
    if user['password'] != hashed:
        return jsonify({'error': 'invalid password'}), 401

    token = AccessToken(
        ACCOUNT_SID,
        API_KEY_SID,
        API_KEY_SECRET,
        identity=username
    )

    voice_grant = VoiceGrant(
        outgoing_application_sid=TWIML_APP_SID,
        incoming_allow=True
    )

    token.add_grant(voice_grant)

    return jsonify({
        'token': token.to_jwt(),
        'identity': username
    })

# ========= USERS =========
@app.route('/users', methods=['GET'])
def users():
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT username FROM users")
    users = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify(users)

# ========= VOICE ROUTING =========
@app.route('/voice', methods=['POST'])
def voice():
    """
    TWILIO ПРИХОДИТ СЮДА
    """
    to = request.form.get('To')

    response = VoiceResponse()
    dial = Dial()
    dial.client(to)

    response.append(dial)

    return Response(str(response), mimetype='text/xml')

# ========= RUN =========
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
