# Cloud Data Cleaner

**A local, privacy-focused tool for encrypting, decrypting, and masking CSV files using AES-256 and classic ciphers. Your data never leaves your machine.**

> The previous cloud-based version (GCP, MySQL, JWT) has been replaced with this local-only tool. See [README.old.md](README.old.md) for the archived cloud version docs.

---

## Features

- **AES-256 encryption** — password-based encryption using Fernet (PBKDF2 + AES-128-CBC + HMAC-SHA256)
- **Caesar Cipher** — classic shift cipher with configurable shift value (0–25)
- **Polybius Square** — standard 5x5 grid or custom grid via CSV upload
- **Local file storage** — save and manage encrypted files locally
- **Download processed files** — export encrypted or decrypted results as CSV/JSON
- **Web-based UI** — simple browser interface served on localhost

---

## Tech Stack

| Layer    | Technology                              |
|----------|-----------------------------------------|
| Frontend | HTML, CSS (Tailwind), JavaScript        |
| Backend  | Python 3 (Flask)                        |
| Crypto   | cryptography library (Fernet / PBKDF2)  |
| Storage  | Local JSON files (`~/.cloud-data-cleaner/files/`) |

---

## Getting Started

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/cloud-data-cleaner.git
cd cloud-data-cleaner

# Install dependencies
pip install -r requirements.txt
```

### Running the App

```bash
python3 main.py
```

The server starts at **http://localhost:8080**. Open this URL in your browser.

To enable debug mode:

```bash
DEBUG=True python3 main.py
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

---

## Security

- AES-256 encryption uses PBKDF2 with 600,000 iterations and a random 16-byte salt
- Passwords are never stored — you must remember your encryption password
- Encrypted files are saved with `0600` permissions (owner read/write only)
- Data directory uses `0700` permissions (owner access only)
- Server binds to `127.0.0.1` only — not accessible from the network
- File IDs use UUID format with validation to prevent path traversal

---

## API Endpoints

| Method | Endpoint              | Description                     |
|--------|-----------------------|---------------------------------|
| GET    | `/`                   | Serve the frontend              |
| GET    | `/health_check`       | Check if the server is running  |
| POST   | `/encrypt`            | Encrypt content (AES-256)       |
| POST   | `/decrypt`            | Decrypt content (AES-256)       |
| POST   | `/save_file`          | Save processed file locally     |
| GET    | `/get_files`          | List all saved files            |
| DELETE | `/delete_file/<id>`   | Delete a saved file by UUID     |

---

## Project Structure

```
cloud-data-cleaner/
├── main.py            # Flask backend (encryption, storage, API)
├── index.html         # Frontend UI (ciphers, file upload/download)
├── requirements.txt   # Python dependencies
├── README.md          # This file
└── README.old.md      # Archived cloud version documentation
```

---

## License

This project is for personal and educational use.
