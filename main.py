# main.py
import os
import datetime
from functools import wraps
import jwt
import bcrypt
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
import mysql.connector

app = Flask(__name__)

# ========================
# Configuration
# ========================

# CORS Setup - Updated for better flexibility
allowed_origins = [
    "http://localhost:5000",
    "http://localhost:8080",
    "http://localhost:3000",  # For React/Vue dev servers
]

# Dynamic origins for Codespaces/Cloud Run
if os.environ.get('CODESPACE_NAME'):
    codespace_name = os.environ['CODESPACE_NAME']
    allowed_origins.extend([
        f"https://*-{codespace_name}.github.dev",
        f"https://8080-{codespace_name}.github.dev"
    ])

# Cloud Run service URL
if os.environ.get('K_SERVICE_URL'):
    service_url = os.environ['K_SERVICE_URL']
    allowed_origins.append(service_url)
    print(f"Added Cloud Run service URL to CORS: {service_url}")

# Print allowed origins for debugging
print(f"CORS allowed origins: {allowed_origins}")

# Initialize CORS with the dynamic list of origins
CORS(app, 
     resources={r"/*": {
         "origins": allowed_origins,
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization"],
         "expose_headers": ["Authorization"],
         "supports_credentials": True
     }})

# JWT Config
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'fallback_secret_key_32_chars_long')
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600

# Database Config - Simplified and more robust
DB_CONFIG = {
    'user': os.environ.get('DB_USER', 'root'),
    'password': os.environ.get('DB_PASSWORD', ''),
    'database': os.environ.get('DB_NAME', 'csuf454'),
    'host': os.environ.get('DB_HOST', '127.0.0.1'),
    'port': os.environ.get('DB_PORT', '3306'),
    'unix_socket': os.environ.get('DB_SOCKET_PATH'),
    'use_pure': True  # Avoid SSL issues in Cloud Run
}

print(f"Database configuration: {DB_CONFIG}")

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
        print(f"Database connection error: {err}")
        return None

def token_required(f):
    """JWT authentication decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            return jsonify({"error": "Unauthorized", "message": "Authentication token is missing!"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            g.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Unauthorized", "message": "Authentication token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Unauthorized", "message": "Invalid authentication token"}), 401
        except Exception as e:
            print(f"Token decoding error: {e}")
            return jsonify({"error": "Unauthorized", "message": "Authentication token processing error"}), 401
        
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

@app.route('/health_check', methods=['GET'])
def health_check():
    """Simple health check endpoint."""
    return jsonify({
        "status": "ok", 
        "message": "Cipher backend is running!",
        "environment": os.environ.get('ENVIRONMENT', 'development'),
        "database": "Connected" if get_db_connection() else "Not connected"
    }), 200

@app.route('/register', methods=['POST'])
def register_user():
    """Registers a new user with username (email) and password."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request", "message": "No JSON data provided"}), 400
        
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials", "message": "Username (email) and password are required"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database error", "message": "Could not connect to database"}), 500

    try:
        cursor = conn.cursor()
        
        # Hash password with bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Check if user already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (username,))
        if cursor.fetchone():
            return jsonify({"error": "Conflict", "message": "Username (email) already exists"}), 409

        # Create new user
        query = "INSERT INTO users (email, password_hash) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password))
        conn.commit()

        user_id = cursor.lastrowid
        
        # Generate JWT token
        payload = {
            'user_id': user_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        return jsonify({
            "message": "User registered and logged in successfully", 
            "token": token, 
            "user_id": user_id
        }), 201
        
    except mysql.connector.Error as err:
        print(f"Error registering user: {err}")
        if err.errno == 1062:  # Duplicate entry error
            return jsonify({"error": "Conflict", "message": "Username (email) already exists"}), 409
        return jsonify({"error": "Database error", "message": f"Failed to register user: {err}"}), 500
    except Exception as e:
        print(f"Unexpected error during registration: {e}")
        return jsonify({"error": "Server error", "message": f"An unexpected error occurred: {e}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/login', methods=['POST'])
def login_user():
    """Logs in a user and returns a JWT."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request", "message": "No JSON data provided"}), 400
        
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials", "message": "Username (email) and password are required"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database error", "message": "Could not connect to database"}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, password_hash FROM users WHERE email = %s", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            # Generate JWT token
            payload = {
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
            }
            token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
            return jsonify({
                "message": "Login successful", 
                "token": token, 
                "user_id": user['id']
            }), 200
        else:
            return jsonify({"error": "Unauthorized", "message": "Invalid username or password"}), 401
    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({"error": "Server error", "message": f"An error occurred during login: {e}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/save_file', methods=['POST'])
@token_required
def save_file():
    """Saves a processed file to Cloud SQL."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request", "message": "No JSON data provided"}), 400

    file_name = data.get('fileName')
    cipher_type = data.get('cipherType')
    content = data.get('content')
    save_type = data.get('saveType')

    if not all([file_name, cipher_type, content, save_type]):
        return jsonify({"error": "Missing data", "message": "Required fields: fileName, cipherType, content, saveType"}), 400

    if save_type not in ['private', 'public']:
        return jsonify({"error": "Invalid save type", "message": "saveType must be 'private' or 'public'"}), 400

    user_id = g.user_id

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database error", "message": "Could not connect to database"}), 500

    try:
        cursor = conn.cursor()
        query = """
            INSERT INTO files (user_id, file_name, cipher_type, content, save_type, timestamp)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        # Use UTC time for consistency across environments
        cursor.execute(query, (user_id, file_name, cipher_type, content, save_type, datetime.datetime.utcnow()))
        conn.commit()
        return jsonify({
            "message": "File saved successfully", 
            "id": cursor.lastrowid
        }), 201
    except mysql.connector.Error as err:
        print(f"Error saving file to DB: {err}")
        return jsonify({"error": "Database error", "message": f"Failed to save file: {err}"}), 500
    except Exception as e:
        print(f"Unexpected error during file save: {e}")
        return jsonify({"error": "Server error", "message": f"An unexpected error occurred: {e}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/get_files', methods=['GET'])
@token_required
def get_files():
    """Retrieves saved files for the authenticated user and public files."""
    user_id = g.user_id

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database error", "message": "Could not connect to database"}), 500

    try:
        cursor = conn.cursor(dictionary=True)

        # Get private files
        cursor.execute("""
            SELECT id, file_name, cipher_type, save_type, content, timestamp 
            FROM files 
            WHERE user_id = %s AND save_type = 'private'
        """, (user_id,))
        private_files = cursor.fetchall()

        # Get public files
        cursor.execute("""
            SELECT id, file_name, cipher_type, save_type, content, timestamp 
            FROM files 
            WHERE save_type = 'public'
        """)
        public_files = cursor.fetchall()

        all_files = private_files + public_files
        
        # Format timestamps to ISO format
        for file_data in all_files:
            if isinstance(file_data.get('timestamp'), datetime.datetime):
                file_data['timestamp'] = file_data['timestamp'].isoformat() + 'Z'

        return jsonify({"files": all_files}), 200
    except mysql.connector.Error as err:
        print(f"Error retrieving files from DB: {err}")
        return jsonify({"error": "Database error", "message": f"Failed to retrieve files: {err}"}), 500
    except Exception as e:
        print(f"Unexpected error during file retrieval: {e}")
        return jsonify({"error": "Server error", "message": f"An unexpected error occurred: {e}"}), 500
    finally:
        if conn:
            conn.close()

@app.route('/delete_file/<int:file_id>', methods=['DELETE'])
@token_required
def delete_file(file_id):
    """Deletes a file, ensuring the user owns it or it's a public file."""
    user_id = g.user_id

    conn = get_db_connection()
    if conn is None:
        return jsonify({"error": "Database error", "message": "Could not connect to database"}), 500

    try:
        cursor = conn.cursor(dictionary=True)

        # Check file ownership
        cursor.execute("""
            SELECT user_id, save_type 
            FROM files 
            WHERE id = %s
        """, (file_id,))
        file_info = cursor.fetchone()

        if not file_info:
            return jsonify({"error": "Not Found", "message": "File not found"}), 404

        owner_id = file_info['user_id']
        save_type = file_info['save_type']

        # Check permissions
        if save_type == 'private' and owner_id != user_id:
            return jsonify({"error": "Forbidden", "message": "You do not have permission to delete this private file"}), 403
        
        # Delete the file
        cursor.execute("DELETE FROM files WHERE id = %s", (file_id,))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "Not Found", "message": "File not found"}), 404
        
        return jsonify({"message": "File deleted successfully"}), 200
    except mysql.connector.Error as err:
        print(f"Error deleting file from DB: {err}")
        return jsonify({"error": "Database error", "message": f"Failed to delete file: {err}"}), 500
    except Exception as e:
        print(f"Unexpected error during file deletion: {e}")
        return jsonify({"error": "Server error", "message": f"An unexpected error occurred: {e}"}), 500
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    # Use PORT environment variable or default to 8080 for Cloud Run
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "False") == "True"
    
    print(f"Starting server on port {port} in {'debug' if debug else 'production'} mode")
    app.run(host="0.0.0.0", port=port, debug=debug)
