# Test Summary

**Result:** 26 tests, all passing (`python3 -m unittest discover -s tests`)

The suite is split into five groups:

## 1. Health Check (1 test)
`GET /health_check` returns `200` with `status: "ok"`.

## 2. Encryption & Decryption (5 tests)
- AES (Fernet + PBKDF2) encrypts and decrypts back to the original text.
- A random salt makes the same input encrypt differently every time.
- The `/encrypt` → `/decrypt` round trip works over HTTP.
- A wrong password returns `400` ("Decryption failed").
- A missing field or a password shorter than 8 characters is rejected.

## 3. Local File Storage (4 tests)
- Saving, listing and deleting a file all work, and the saved file has `0600` permissions.
- `/save_file` rejects requests with missing fields.
- `/delete_file` rejects IDs that aren't UUIDs (path-traversal guard) and returns `404` for unknown IDs.

## 4. Validators & Text Redaction (11 tests)
- Luhn (credit card), ABA routing, IBAN MOD-97 and SWIFT/BIC checks accept valid values and reject invalid ones.
- SSNs and emails are replaced with `[REDACTED]`, but card numbers that fail the Luhn check are left alone.
- Named fields keep their label (`Account Number: [REDACTED]`).
- Allowlisted values are kept, and custom names are redacted.
- SWIFT/BIC matching is case-sensitive, so ordinary words like "Referred" aren't redacted.
- An invalid custom regex raises `ValueError`.

## 5. Redact Endpoint & AI Advisor (5 tests)
- `/redact` on a DOCX returns `redacted_<name>.docx` with the sensitive values removed.
- Unsupported file types and empty pattern lists return `400`.
- `/ai_advisor` returns `503` without `ANTHROPIC_API_KEY` and `400` without `doc_type`.

---

**Not covered yet:** PDF redaction, spaCy name detection (`spacy_ner`), and a successful AI Advisor call (this would need a mocked Claude response).
