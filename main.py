# main.py
import io
import os
import re
import json
import uuid
import base64
import datetime
from pathlib import Path

import fitz  # PyMuPDF
from docx import Document
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)

# ========================
# Configuration
# ========================

CORS(app, resources={r"/*": {"origins": ["http://localhost:8080", "http://127.0.0.1:8080"]}})

# Local storage directory
DATA_DIR = Path.home() / ".cloud-data-cleaner"
FILES_DIR = DATA_DIR / "files"


def ensure_data_dirs():
    """Create data directories with owner-only permissions."""
    DATA_DIR.mkdir(mode=0o700, exist_ok=True)
    FILES_DIR.mkdir(mode=0o700, exist_ok=True)
    # Fix permissions if directories already existed with wrong perms
    os.chmod(DATA_DIR, 0o700)
    os.chmod(FILES_DIR, 0o700)


ensure_data_dirs()


# ========================
# Crypto Helpers
# ========================

def derive_fernet_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from a password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return key


def aes_encrypt(plaintext: str, password: str) -> dict:
    """Encrypt plaintext with AES-256 via Fernet using a password-derived key.
    Returns dict with salt (hex) and ciphertext (base64)."""
    salt = os.urandom(16)
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    ciphertext = f.encrypt(plaintext.encode("utf-8"))
    return {
        "salt": salt.hex(),
        "ciphertext": ciphertext.decode("utf-8"),
    }


def aes_decrypt(salt_hex: str, ciphertext: str, password: str) -> str:
    """Decrypt ciphertext using the password and stored salt."""
    salt = bytes.fromhex(salt_hex)
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext.encode("utf-8"))
    return plaintext.decode("utf-8")


# ========================
# Routes
# ========================

@app.route("/")
def serve_index():
    """Serve the frontend index.html."""
    return send_from_directory(".", "index.html")


@app.route("/<path:path>")
def serve_static(path):
    """Serve static files."""
    return send_from_directory(".", path)


@app.route("/health_check", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok",
        "message": "Local cipher tool is running.",
        "storage": str(DATA_DIR),
    }), 200


@app.route("/encrypt", methods=["POST"])
def encrypt():
    """Encrypt content using AES-256 (Fernet + PBKDF2)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    content = data.get("content")
    password = data.get("password")

    if not content or not password:
        return jsonify({"error": "Both 'content' and 'password' are required"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    result = aes_encrypt(content, password)
    return jsonify({"encrypted": result}), 200


@app.route("/decrypt", methods=["POST"])
def decrypt():
    """Decrypt AES-256 encrypted content."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    salt = data.get("salt")
    ciphertext = data.get("ciphertext")
    password = data.get("password")

    if not all([salt, ciphertext, password]):
        return jsonify({"error": "'salt', 'ciphertext', and 'password' are required"}), 400

    try:
        plaintext = aes_decrypt(salt, ciphertext, password)
        return jsonify({"decrypted": plaintext}), 200
    except InvalidToken:
        return jsonify({"error": "Decryption failed. Wrong password or corrupted data."}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption error: {e}"}), 400


@app.route("/save_file", methods=["POST"])
def save_file():
    """Save a processed file as JSON to local storage."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    file_name = data.get("fileName")
    cipher_type = data.get("cipherType")
    content = data.get("content")

    if not all([file_name, cipher_type, content]):
        return jsonify({"error": "Required fields: fileName, cipherType, content"}), 400

    file_id = str(uuid.uuid4())
    file_record = {
        "id": file_id,
        "file_name": file_name,
        "cipher_type": cipher_type,
        "content": content,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }

    file_path = FILES_DIR / f"{file_id}.json"
    with open(file_path, "w") as f:
        json.dump(file_record, f)
    os.chmod(file_path, 0o600)

    return jsonify({"message": "File saved successfully", "id": file_id}), 201


@app.route("/get_files", methods=["GET"])
def get_files():
    """Retrieve all saved files from local storage."""
    files = []
    for file_path in FILES_DIR.glob("*.json"):
        try:
            with open(file_path) as f:
                files.append(json.load(f))
        except (json.JSONDecodeError, OSError):
            continue

    files.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify({"files": files}), 200


@app.route("/delete_file/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    """Delete a saved file by ID."""
    # Validate UUID format to prevent path traversal
    try:
        uuid.UUID(file_id)
    except ValueError:
        return jsonify({"error": "Invalid file ID"}), 400

    file_path = FILES_DIR / f"{file_id}.json"

    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404

    file_path.unlink()
    return jsonify({"message": "File deleted successfully"}), 200


# ========================
# Redaction
# ========================

REDACT_PATTERNS = {
    "ssn":         r'\b\d{3}-\d{2}-\d{4}\b',
    "email":       r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    "phone":       r'\b(\+1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b',
    "credit_card": r'\b(?:\d{4}[\s\-]?){3}\d{4}\b',
    "ip_address":  r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "date":        r'\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b',
}


def _redact_pdf(file_bytes: bytes, compiled_patterns: list) -> io.BytesIO:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    for page in doc:
        text = page.get_text()
        matched_strings = set()
        for pattern in compiled_patterns:
            for m in pattern.finditer(text):
                matched_strings.add(m.group())
        for s in matched_strings:
            for rect in page.search_for(s):
                page.add_redact_annot(rect, fill=(0, 0, 0))
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


def _redact_text_in_run(run_text: str, compiled_patterns: list) -> str:
    for pattern in compiled_patterns:
        run_text = pattern.sub("[REDACTED]", run_text)
    return run_text


def _redact_docx(file_bytes: bytes, compiled_patterns: list) -> io.BytesIO:
    doc = Document(io.BytesIO(file_bytes))

    def redact_paragraphs(paragraphs):
        for para in paragraphs:
            for run in para.runs:
                run.text = _redact_text_in_run(run.text, compiled_patterns)

    redact_paragraphs(doc.paragraphs)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                redact_paragraphs(cell.paragraphs)

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


@app.route("/redact", methods=["POST"])
def redact():
    """Redact sensitive patterns from PDF or DOCX files."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded = request.files["file"]
    filename = uploaded.filename or "document"
    ext = Path(filename).suffix.lower()

    if ext not in (".pdf", ".docx"):
        return jsonify({"error": f"Unsupported file type '{ext}'. Supported: .pdf, .docx"}), 400

    patterns_json = request.form.get("patterns", "[]")
    try:
        selected = json.loads(patterns_json)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid patterns JSON"}), 400

    compiled = []
    for p in selected:
        ptype = p.get("type", "")
        if ptype in REDACT_PATTERNS:
            compiled.append(re.compile(REDACT_PATTERNS[ptype], re.IGNORECASE))
        elif ptype == "custom":
            raw = p.get("pattern", "").strip()
            if raw:
                try:
                    compiled.append(re.compile(raw))
                except re.error as e:
                    return jsonify({"error": f"Invalid regex '{raw}': {e}"}), 400

    if not compiled:
        return jsonify({"error": "No valid patterns selected"}), 400

    file_bytes = uploaded.read()
    redacted_name = f"redacted_{filename}"

    try:
        if ext == ".pdf":
            result = _redact_pdf(file_bytes, compiled)
            mime = "application/pdf"
        else:
            result = _redact_docx(file_bytes, compiled)
            mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    except Exception as e:
        return jsonify({"error": f"Redaction failed: {e}"}), 500

    return send_file(result, mimetype=mime, as_attachment=True, download_name=redacted_name)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "False") == "True"
    print(f"Starting local server on http://localhost:{port}")
    print(f"Data directory: {DATA_DIR}")
    app.run(host="127.0.0.1", port=port, debug=debug)
