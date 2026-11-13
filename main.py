# main.py
import io
import os
import re
import json
import uuid
import base64
import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

import anthropic
import fitz  # PyMuPDF
import spacy
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
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
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

@dataclass
class RedactRule:
    name: str
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]] = None
    value_group: int = 0  # 0 = redact full match; 1 = redact captured group only (named fields)


# ---------- Validators ----------

def _luhn_check(value: str) -> bool:
    """Credit card: Luhn checksum."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _aba_routing_check(value: str) -> bool:
    """US ABA routing number: 9-digit checksum + valid Federal Reserve prefix."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) != 9:
        return False
    prefix = digits[0] * 10 + digits[1]
    if not ((1 <= prefix <= 12) or (21 <= prefix <= 32)):
        return False
    total = (3 * (digits[0] + digits[3] + digits[6]) +
             7 * (digits[1] + digits[4] + digits[7]) +
             1 * (digits[2] + digits[5] + digits[8]))
    return total % 10 == 0


# IBAN: country code -> expected total character length (ISO 13616)
_IBAN_LENGTHS = {
    'AL': 28, 'AD': 24, 'AT': 20, 'AZ': 28, 'BH': 22, 'BY': 28, 'BE': 16,
    'BA': 20, 'BR': 29, 'BG': 22, 'CR': 22, 'HR': 21, 'CY': 28, 'CZ': 24,
    'DK': 18, 'DO': 28, 'SV': 28, 'EE': 20, 'EG': 29, 'FO': 18, 'FI': 18,
    'FR': 27, 'GE': 22, 'DE': 22, 'GI': 23, 'GR': 27, 'GL': 18, 'GT': 28,
    'HU': 28, 'IS': 26, 'IQ': 23, 'IE': 22, 'IL': 23, 'IT': 27, 'JO': 30,
    'KZ': 20, 'XK': 20, 'KW': 30, 'LV': 21, 'LB': 28, 'LY': 25, 'LI': 21,
    'LT': 20, 'LU': 20, 'MT': 31, 'MR': 27, 'MU': 30, 'MD': 24, 'MC': 27,
    'MN': 20, 'ME': 22, 'NL': 18, 'MK': 19, 'NO': 15, 'PK': 24, 'PS': 29,
    'PL': 28, 'PT': 25, 'QA': 29, 'RO': 24, 'RU': 33, 'LC': 32, 'SM': 27,
    'ST': 25, 'SA': 24, 'RS': 22, 'SC': 31, 'SK': 24, 'SI': 19, 'ES': 24,
    'SD': 18, 'SE': 24, 'CH': 21, 'TL': 23, 'TN': 24, 'TR': 26, 'UA': 29,
    'AE': 23, 'GB': 22, 'VA': 22, 'VG': 24, 'YE': 30,
}


def _iban_check(value: str) -> bool:
    """IBAN: MOD-97 checksum + ISO country length validation."""
    clean = re.sub(r'[\s\-]', '', value).upper()
    country = clean[:2]
    if not country.isalpha():
        return False
    expected = _IBAN_LENGTHS.get(country)
    if expected is None or len(clean) != expected:
        return False
    rearranged = clean[4:] + clean[:4]
    numeric = ''.join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    # Process in chunks to avoid int overflow on long IBANs
    remainder = 0
    for i in range(0, len(numeric), 9):
        remainder = int(str(remainder) + numeric[i:i + 9]) % 97
    return remainder == 1


def _swift_bic_check(value: str) -> bool:
    """SWIFT/BIC: structural validation (length 8 or 11, correct character classes)."""
    clean = re.sub(r'\s', '', value).upper()
    if len(clean) not in (8, 11):
        return False
    return bool(re.match(r'^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$', clean))


# ---------- Pattern registry ----------

# Standalone patterns (value_group=0 — full match is the sensitive span).
REDACT_PATTERNS = {
    # Personal
    "ssn":          r'\b\d{3}-\d{2}-\d{4}\b',
    "email":        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    "phone":        r'\b(\+1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b',
    "date":         r'\b\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b',
    "ip_address":   r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    # Financial (all have validators to minimise false positives)
    "credit_card":  r'\b(?:\d{4}[\s\-]?){3}\d{4}\b',
    "iban":         r'\b[A-Z]{2}\d{2}(?:[A-Z0-9]{1,4}\s?){3,8}\b',
    "swift_bic":    r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b',
    "aba_routing":  r'\b\d{9}\b',
    "uk_sort_code": r'\b\d{2}[-\s]\d{2}[-\s]\d{2}\b',
}

PATTERN_VALIDATORS: dict[str, Callable] = {
    "credit_card":  _luhn_check,
    "iban":         _iban_check,
    "swift_bic":    _swift_bic_check,
    "aba_routing":  _aba_routing_check,
    # uk_sort_code: purely structural, no algorithmic checksum exists
}

# Context-aware patterns (value_group=1 — capture group 1 is the sensitive value;
# the label is matched but kept visible). Format: (regex_string, value_group).
NAMED_FIELD_PATTERNS: dict[str, tuple[str, int]] = {
    # Financial
    "nf_account":   (r'(?:account\s*(?:number|num|no|#))\s*[:=\-]\s*(\d[\d\s\-]{5,19}\d)', 1),
    "nf_routing":   (r'(?:routing\s*(?:number|num|no|#|transit)?)\s*[:=\-]\s*(\d{9})', 1),
    "nf_iban":      (r'(?:iban)\s*[:=\-]\s*([A-Z]{2}\d{2}[A-Z0-9 ]{10,30})', 1),
    "nf_swift":     (r'(?:swift(?:\s*/?bic)?|bic(?:\s*code)?)\s*[:=\-]\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2,5})', 1),
    "nf_sort_code": (r'(?:sort\s*code)\s*[:=\-]\s*(\d{2}[-\s]\d{2}[-\s]\d{2})', 1),
    # Personal
    "nf_dob":       (r'(?:dob|date\s+of\s+birth|birth\s*date)\s*[:=\-]\s*(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})', 1),
    "nf_ssn":       (r'(?:ssn|social\s+security(?:\s+number)?)\s*[:=\-]\s*(\d{3}[-\s]?\d{2}[-\s]?\d{4})', 1),
    "nf_passport":  (r'(?:passport\s*(?:number|num|no|#)?)\s*[:=\-]\s*([A-Z0-9]{6,9})', 1),
    "nf_dl":        (r'(?:driver(?:\'s)?\s+licen[sc]e|dl)\s*[:=\-]\s*([A-Z0-9\-]{4,20})', 1),
    "nf_email":     (r'(?:email|e-mail)\s*[:=\-]\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})', 1),
    "nf_phone":     (r'(?:phone|tel|telephone|mobile|cell)\s*[:=\-]\s*([\+\d][\d\s\-\(\)\.]{7,20})', 1),
}

# Named-field validators applied to the extracted value (group 1).
NF_VALIDATORS: dict[str, Callable] = {
    "nf_routing":  _aba_routing_check,
    "nf_iban":     _iban_check,
    "nf_swift":    _swift_bic_check,
}


# ---------- Allowlist helpers ----------

def _normalize(value: str) -> str:
    """Normalize for allowlist comparison: strip spaces/dashes, uppercase."""
    return re.sub(r'[\s\-]+', '', value).upper()


# ---------- spaCy NER ----------

_nlp = None  # lazy-loaded on first use


def _get_nlp():
    global _nlp
    if _nlp is None:
        _nlp = spacy.load("en_core_web_sm")
    return _nlp


def _spacy_persons(text: str, allowlist: set[str]) -> set[str]:
    """Return the set of PERSON entity strings found by spaCy NER."""
    nlp = _get_nlp()
    doc = nlp(text)
    found = set()
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            name = ent.text.strip()
            if name and _normalize(name) not in allowlist:
                found.add(name)
    return found


# ---------- Rule compilation ----------

def _build_rules(selected: list[dict], names: list[str]) -> tuple[list[RedactRule], bool]:
    """Compile selected patterns into RedactRules.

    Returns (rules, use_spacy). spacy_ner is pulled out of the list and
    signalled via the boolean rather than being represented as a RedactRule,
    because NER works at document/paragraph level rather than per-pattern.
    Custom names are compiled into word-boundary exact-match rules.
    """
    rules = []
    use_spacy = False

    for p in selected:
        ptype = p.get("type", "")
        if ptype == "spacy_ner":
            use_spacy = True
        elif ptype in REDACT_PATTERNS:
            # SWIFT/BIC codes are uppercase by spec; skip IGNORECASE to avoid
            # false positives on common English words (e.g. "Referred", "redacted").
            flags = 0 if ptype == "swift_bic" else re.IGNORECASE
            rules.append(RedactRule(
                name=ptype,
                pattern=re.compile(REDACT_PATTERNS[ptype], flags),
                validator=PATTERN_VALIDATORS.get(ptype),
                value_group=0,
            ))
        elif ptype in NAMED_FIELD_PATTERNS:
            raw, grp = NAMED_FIELD_PATTERNS[ptype]
            rules.append(RedactRule(
                name=ptype,
                pattern=re.compile(raw, re.IGNORECASE),
                validator=NF_VALIDATORS.get(ptype),
                value_group=grp,
            ))
        elif ptype == "custom":
            raw = p.get("pattern", "").strip()
            if raw:
                try:
                    rules.append(RedactRule(
                        name="custom",
                        pattern=re.compile(raw),
                        validator=None,
                        value_group=0,
                    ))
                except re.error as e:
                    raise ValueError(f"Invalid regex '{raw}': {e}")

    for name in names:
        name = name.strip()
        if name:
            rules.append(RedactRule(
                name=f"name:{name}",
                pattern=re.compile(r'\b' + re.escape(name) + r'\b', re.IGNORECASE),
                validator=None,
                value_group=0,
            ))

    return rules, use_spacy


# ---------- Redaction helpers ----------

def _make_run_replacer(rule: RedactRule, allowlist: set[str], pre_text: str):
    """Return a re.sub callable for one rule pass.

    pre_text is the run text *before* this rule's substitution — match
    positions align with it, so we can check surrounding characters to
    detect spans that an earlier rule already marked as [REDACTED].
    """
    def replacer(m: re.Match) -> str:
        # If this match sits immediately inside a prior [REDACTED] marker
        # (character before is '[' and character after is ']'), skip it.
        s, e = m.start(), m.end()
        if s > 0 and e < len(pre_text) and pre_text[s - 1] == "[" and pre_text[e] == "]":
            return m.group(0)
        try:
            candidate = m.group(rule.value_group)
        except IndexError:
            candidate = m.group(0)
        if candidate is None:
            return m.group(0)
        if _normalize(candidate) in allowlist:
            return m.group(0)
        if rule.validator and not rule.validator(candidate):
            return m.group(0)
        if rule.value_group == 0:
            return "[REDACTED]"
        # Named field: keep the label, replace only the captured value span.
        full = m.group(0)
        start = m.start(rule.value_group) - m.start(0)
        end = m.end(rule.value_group) - m.start(0)
        return full[:start] + "[REDACTED]" + full[end:]
    return replacer


def _redact_pdf(file_bytes: bytes, rules: list[RedactRule], allowlist: set[str],
                use_spacy: bool = False) -> io.BytesIO:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    for page in doc:
        text = page.get_text()
        to_redact: set[str] = set()

        # Pattern-based matches
        for rule in rules:
            for m in rule.pattern.finditer(text):
                try:
                    candidate = m.group(rule.value_group)
                except IndexError:
                    candidate = m.group(0)
                if not candidate:
                    continue
                if _normalize(candidate) in allowlist:
                    continue
                if rule.validator and not rule.validator(candidate):
                    continue
                to_redact.add(candidate)

        # spaCy PERSON entities
        if use_spacy:
            to_redact.update(_spacy_persons(text, allowlist))

        for s in to_redact:
            for rect in page.search_for(s):
                page.add_redact_annot(rect, fill=(0, 0, 0))
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


def _redact_text_in_run(run_text: str, rules: list[RedactRule], allowlist: set[str]) -> str:
    for rule in rules:
        pre = run_text  # snapshot before this rule modifies the text
        run_text = rule.pattern.sub(_make_run_replacer(rule, allowlist, pre), pre)
    return run_text


def _redact_docx(file_bytes: bytes, rules: list[RedactRule], allowlist: set[str],
                 use_spacy: bool = False) -> io.BytesIO:
    doc = Document(io.BytesIO(file_bytes))

    def redact_paragraphs(paragraphs):
        for para in paragraphs:
            # spaCy: run NER on full paragraph text for cross-run context,
            # then compile found names into a combined pattern applied to each run.
            extra_pattern = None
            if use_spacy:
                para_text = "".join(run.text for run in para.runs)
                names = _spacy_persons(para_text, allowlist)
                if names:
                    extra_pattern = re.compile(
                        "|".join(r"\b" + re.escape(n) + r"\b" for n in names),
                        re.IGNORECASE,
                    )
            for run in para.runs:
                run.text = _redact_text_in_run(run.text, rules, allowlist)
                if extra_pattern:
                    run.text = extra_pattern.sub("[REDACTED]", run.text)

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

    try:
        selected = json.loads(request.form.get("patterns", "[]"))
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid patterns JSON"}), 400

    try:
        allowlist_raw = json.loads(request.form.get("allowlist", "[]"))
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid allowlist JSON"}), 400

    try:
        names_raw = json.loads(request.form.get("names", "[]"))
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid names JSON"}), 400

    allowlist = {_normalize(s) for s in allowlist_raw if isinstance(s, str) and s.strip()}
    names = [s for s in names_raw if isinstance(s, str) and s.strip()]

    try:
        rules, use_spacy = _build_rules(selected, names)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not rules and not use_spacy:
        return jsonify({"error": "No valid patterns selected"}), 400

    file_bytes = uploaded.read()
    redacted_name = f"redacted_{filename}"

    try:
        if ext == ".pdf":
            result = _redact_pdf(file_bytes, rules, allowlist, use_spacy)
            mime = "application/pdf"
        else:
            result = _redact_docx(file_bytes, rules, allowlist, use_spacy)
            mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    except Exception as e:
        return jsonify({"error": f"Redaction failed: {e}"}), 500

    return send_file(result, mimetype=mime, as_attachment=True, download_name=redacted_name)


# ========================
# AI Advisor
# ========================

_ALL_PATTERN_KEYS = (
    list(REDACT_PATTERNS.keys()) + list(NAMED_FIELD_PATTERNS.keys()) + ["spacy_ner"]
)

_PATTERN_DESCRIPTIONS = {
    "ssn":          "Social Security Numbers (123-45-6789)",
    "email":        "Email addresses",
    "phone":        "Phone numbers",
    "date":         "Dates in MM/DD/YYYY format",
    "ip_address":   "IP addresses",
    "credit_card":  "Credit card numbers (Luhn-validated)",
    "iban":         "International Bank Account Numbers (MOD-97 validated)",
    "swift_bic":    "SWIFT/BIC codes",
    "aba_routing":  "US ABA routing numbers (checksum validated)",
    "uk_sort_code": "UK sort codes (20-00-00)",
    "spacy_ner":    "Person names detected by AI — may have false positives",
    "nf_account":   "Account Number labeled fields (e.g. Account Number: 123456)",
    "nf_routing":   "Routing Number labeled fields",
    "nf_iban":      "IBAN labeled fields (e.g. IBAN: GB82 WEST...)",
    "nf_swift":     "SWIFT/BIC labeled fields",
    "nf_sort_code": "Sort Code labeled fields",
    "nf_ssn":       "SSN labeled fields",
    "nf_dob":       "Date of Birth labeled fields",
    "nf_passport":  "Passport Number labeled fields",
    "nf_dl":        "Driver's License labeled fields",
    "nf_email":     "Email labeled fields",
    "nf_phone":     "Phone labeled fields",
}

_ADVISOR_SYSTEM = (
    "You are a privacy and data redaction expert. "
    "You help users decide which types of sensitive data to redact from documents "
    "based solely on the document type — you never see the actual document content. "
    "Be practical: recommend patterns that are realistically likely to appear in the "
    "described document. Avoid recommending patterns that would almost never appear."
)


@app.route("/ai_advisor", methods=["POST"])
def ai_advisor():
    """Recommend redaction patterns based on document type description (no content sent)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    doc_type = (data.get("doc_type") or "").strip()
    notes = (data.get("notes") or "").strip()

    if not doc_type:
        return jsonify({"error": "doc_type is required"}), 400

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return jsonify({"error": "ANTHROPIC_API_KEY environment variable is not set."}), 503

    pattern_list = "\n".join(
        f"- {k}: {_PATTERN_DESCRIPTIONS[k]}" for k in _ALL_PATTERN_KEYS
    )

    user_prompt = (
        f"Document type: {doc_type}\n"
        + (f"Additional context: {notes}\n" if notes else "")
        + f"\nAvailable redaction patterns:\n{pattern_list}\n\n"
        "Which patterns should be applied to this document type? "
        "Return a JSON object with:\n"
        '- "patterns": array of pattern keys to enable (only keys from the list above)\n'
        '- "explanation": one short paragraph explaining your choices'
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-5-5",
            max_tokens=1024,
            system=_ADVISOR_SYSTEM,
            messages=[{"role": "user", "content": user_prompt}],
            output_config={
                "format": {
                    "type": "json_schema",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "patterns": {
                                "type": "array",
                                "items": {"type": "string", "enum": _ALL_PATTERN_KEYS},
                            },
                            "explanation": {"type": "string"},
                        },
                        "required": ["patterns", "explanation"],
                        "additionalProperties": False,
                    },
                }
            },
        )
        if response.stop_reason == "refusal":
            return jsonify({"error": "The AI advisor declined this request."}), 502
        # Newer models may return a thinking block before the text block.
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            return jsonify({"error": "AI advisor returned no answer."}), 502
        result = json.loads(text)
        valid_patterns = [p for p in result.get("patterns", []) if p in _ALL_PATTERN_KEYS]
        return jsonify({"patterns": valid_patterns, "explanation": result.get("explanation", "")}), 200

    except anthropic.AuthenticationError:
        return jsonify({"error": "Invalid ANTHROPIC_API_KEY. Check your key and try again."}), 401
    except Exception as e:
        return jsonify({"error": f"AI advisor error: {e}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "False") == "True"
    print(f"Starting local server on http://localhost:{port}")
    print(f"Data directory: {DATA_DIR}")
    app.run(host="127.0.0.1", port=port, debug=debug)
