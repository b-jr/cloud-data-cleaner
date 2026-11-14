# Cloud Data Cleaner

**A local, privacy-focused tool for encrypting, decrypting, and redacting sensitive data. Your document content never leaves your machine.**

> The previous cloud-based version (GCP, MySQL, JWT) has been replaced with this local-only tool. See [README.old.md](README.old.md) for the archived cloud version docs.

---

## Features

- **AES-256 encryption** — password-based encryption using Fernet (PBKDF2 + AES-128-CBC + HMAC-SHA256)
- **Caesar Cipher** — classic shift cipher with configurable shift value (0–25)
- **Polybius Square** — standard 5x5 grid or custom grid via CSV upload
- **Document redaction** — permanently burn out sensitive data in PDF and DOCX files
- **AI Advisor** — describe your document type and Claude recommends which patterns to redact (your document content is never sent)
- **Local file storage** — save and manage encrypted files locally
- **Web-based UI** — simple browser interface served on localhost

---

## Tech Stack

| Layer    | Technology                                           |
|----------|------------------------------------------------------|
| Frontend | HTML, CSS (Tailwind), JavaScript                     |
| Backend  | Python 3 (Flask)                                     |
| Crypto   | cryptography library (Fernet / PBKDF2)               |
| Redaction | PyMuPDF (PDF), python-docx (DOCX), spaCy NER        |
| AI Advisor | Anthropic API — Claude Sonnet 5.5                  |
| Storage  | Local JSON files (`~/.cloud-data-cleaner/files/`)    |

---

## Getting Started

### Prerequisites

- Python 3.11+
- pip
- An Anthropic API key (only required for the AI Advisor feature — get one free at https://console.anthropic.com)

### Installation

```bash
# Clone the repository
git clone https://github.com/b-jr/cloud-data-cleaner.git
cd cloud-data-cleaner

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download the spaCy language model (required for name detection)
python -m spacy download en_core_web_sm
```

The virtual environment keeps the app's packages separate from your system Python.
Run `source .venv/bin/activate` in each new terminal before starting the app.

### Running the App

```bash
./run.sh
```

`run.sh` starts the app with the virtual environment, so you don't need to activate it first.
(Running `python3 main.py` without the virtual environment fails with `No module named 'anthropic'`.)

The server starts at **http://localhost:8080**. Open this URL in your browser.

To enable the AI Advisor, set your Anthropic API key before starting:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
./run.sh
```

To enable debug mode:

```bash
DEBUG=True ./run.sh
```

---

## Usage

### Encrypting a CSV File

1. Open http://localhost:8080 in your browser
2. Select a cipher from the dropdown (default: AES-256)
3. Upload a `.csv` file
4. For AES-256: enter a password (minimum 8 characters)
5. Click **Encrypt File**
6. Click **Download Processed File** to save the encrypted output, or **Save Locally** to store it on disk

### Decrypting a File

1. Select the same cipher used for encryption
2. Upload the encrypted file (for AES-256, upload the `.json` file produced during encryption)
3. Enter the same password / shift value used during encryption
4. Click **Decrypt File**
5. Download or save the decrypted result

### Managing Saved Files

- Click **View Saved Files** to see all locally stored files
- From the modal, you can **Download** or **Delete** any saved file

### Redacting a Document

1. Go to the **Redact Documents** tab
2. Upload a `.pdf` or `.docx` file
3. Select the patterns to redact (SSN, email, credit card, etc.)
4. Optionally add specific names to always redact, or an allowlist of values to preserve
5. Click **Redact & Download** — a new file is downloaded with sensitive data permanently removed

**Supported redaction patterns:**

| Category | Patterns |
|----------|----------|
| Personal | SSN, Email, Phone, Date, IP Address, Person Names (NER) |
| Financial | Credit Card (Luhn), IBAN (MOD-97), SWIFT/BIC, ABA Routing, UK Sort Code |
| Named Fields | Labeled fields like `Account Number: ...`, `DOB: ...`, `Passport No: ...` |

### Using the AI Advisor

The AI Advisor helps you choose which patterns to enable without ever seeing your document content.

1. Go to the **AI Advisor** tab
2. Describe your document type (e.g. "US bank statement", "employee HR file")
3. Add any optional context (e.g. "already removed names, focus on financial data")
4. Click **Ask Claude** — Claude recommends patterns and explains why
5. Click **Apply to Redact Tab** to auto-check those patterns and switch to the Redact tab

> Your document content is never sent to the AI. Only your text description is used.

---

## Security

- AES-256 encryption uses PBKDF2 with 600,000 iterations and a random 16-byte salt
- Passwords are never stored — you must remember your encryption password
- Encrypted files are saved with `0600` permissions (owner read/write only)
- Data directory uses `0700` permissions (owner access only)
- Server binds to `127.0.0.1` only — not accessible from the network
- File IDs use UUID format with validation to prevent path traversal
- PDF redaction uses permanent black-rectangle overlays (not reversible)
- The AI Advisor only receives your document type description — no file content is ever transmitted

---

## API Endpoints

| Method | Endpoint              | Description                                      |
|--------|-----------------------|--------------------------------------------------|
| GET    | `/`                   | Serve the frontend                               |
| GET    | `/health_check`       | Check if the server is running                   |
| POST   | `/encrypt`            | Encrypt content (AES-256)                        |
| POST   | `/decrypt`            | Decrypt content (AES-256)                        |
| POST   | `/save_file`          | Save processed file locally                      |
| GET    | `/get_files`          | List all saved files                             |
| DELETE | `/delete_file/<id>`   | Delete a saved file by UUID                      |
| POST   | `/redact`             | Redact a PDF or DOCX file                        |
| POST   | `/ai_advisor`         | Get AI-recommended redaction patterns            |

---

## Project Structure

```
cloud-data-cleaner/
├── main.py            # Flask backend (encryption, redaction, AI advisor)
├── run.sh             # Starts the app using .venv
├── index.html         # Frontend UI (three tabs: Cipher, Redact, AI Advisor)
├── requirements.txt   # Python dependencies
├── tests/             # unittest suite (see tests/README.md)
├── README.md          # This file
└── README.old.md      # Archived cloud version documentation
```

---

## License

This project is for personal and educational use.
