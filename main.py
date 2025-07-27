# main.py
import os
import datetime
from functools import wraps
import jwt
import bcrypt
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
import mysql.connector

# Initialize Flask app
app = Flask(__name__)

# ========================
# Configuration
# ========================

# CORS Setup
allowed_origins = [
    "http://localhost:5000",
    "http://localhost:8080",
]

# Dynamic origins for Codespaces/Cloud Run
if os.environ.get('CODESPACE_NAME'):
    codespace_name = os.environ['CODESPACE_NAME']
    allowed_origins.extend([
        f"https://*-{codespace_name}.github.dev",
        f"https://8080-{codespace_name}.github.dev"
    ])

if os.environ.get('K_SERVICE_URL'):
    allowed_origins.append(os.environ['K_SERVICE_URL'])

CORS(app, 
     resources={r"/*": {
         "origins": allowed_origins,
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization"],
         "supports_credentials": True
     }})

# JWT Config
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'fallback_secret_key_32_chars_long')
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600

# Database Config
DB_CONFIG = {
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', ''),
    'database': os.environ.get('DB_NAME', 'csuf454'),
    'host': os.environ.get('DB_HOST', '127.0.0.1'),
    'port': os.environ.get('DB_PORT', '3306'),
    'unix_socket': os.environ.get('DB_SOCKET_PATH')
}

# ========================
# Helper Functions
# ========================

def get_db_connection():
    """Establishes and returns a database connection."""
    try:
        # Remove None values from config
        config = {k: v for k, v in DB_CONFIG.items() if v is not None}
        return mysql.connector.connect(**config)
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None

def token_required(f):
    """JWT authentication decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(' ')[1] if 'Bearer ' in request.headers['Authorization'] else None

        if not token:
            return jsonify({"error": "Unauthorized", "message": "Token missing"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            g.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            return jsonify({"error": "Token processing failed"}), 401

        return f(*args, **kwargs)
    return decorated

# ========================
# Routes
# ========================

@app.route('/')
def serve_index():
    """Serve the frontend index.html."""
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files."""
    return send_from_directory('.', path)

@app.route('/health_check')
def health_check():
    return jsonify({"status": "ok"})

@app.route('/register', methods=['POST'])
def register():
    """User registration endpoint."""
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing credentials"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Database unavailable"}), 500

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (data['username'],))
        if cursor.fetchone():
            return jsonify({"error": "User already exists"}), 409

        hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)", 
                      (data['username'], hashed_pw))
        conn.commit()

        user_id = cursor.lastrowid
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
        }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        return jsonify({
            "message": "Registration successful",
            "token": token,
            "user_id": user_id
        }), 201

    except mysql.connector.Error as err:
        return jsonify({"error": f"Database error: {err}"}), 500
    finally:
        if conn: conn.close()

# ... (Include other endpoints like /login, /save_file, etc. with similar simplifications) ...

# ========================
# Main Execution
# ========================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
