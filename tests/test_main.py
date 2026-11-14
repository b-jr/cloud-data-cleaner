"""Tests for cloud-data-cleaner (main.py).

Run from the project root:
    python3 -m unittest discover -s tests -v
"""
import io
import json
import os
import sys
import tempfile
import types
import unittest
import uuid
from pathlib import Path
from unittest import mock

# Make main.py importable when running from the project root or tests/.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# The `anthropic` SDK is only needed by /ai_advisor. Stub it if it isn't
# installed so the rest of the suite can still run.
try:
    import anthropic  # noqa: F401
except ImportError:
    stub = types.ModuleType("anthropic")

    class _AuthenticationError(Exception):
        pass

    stub.AuthenticationError = _AuthenticationError
    stub.Anthropic = mock.MagicMock()
    sys.modules["anthropic"] = stub

import main  # noqa: E402

from docx import Document  # noqa: E402


class BaseTestCase(unittest.TestCase):
    """Gives every test a Flask client and an isolated, temporary FILES_DIR."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._patch = mock.patch.object(main, "FILES_DIR", Path(self._tmp.name))
        self._patch.start()
        main.app.config["TESTING"] = True
        self.client = main.app.test_client()

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()


# ------------------------------------------------------------------
# 1. Health check
# ------------------------------------------------------------------
class TestHealthCheck(BaseTestCase):
    def test_health_check_ok(self):
        resp = self.client.get("/health_check")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "ok")


# ------------------------------------------------------------------
# 2. Encryption / decryption
# ------------------------------------------------------------------
class TestCrypto(BaseTestCase):
    PASSWORD = "correct-horse-battery"

    def test_round_trip(self):
        enc = main.aes_encrypt("name,ssn\nAlice,123-45-6789", self.PASSWORD)
        self.assertIn("salt", enc)
        self.assertIn("ciphertext", enc)
        out = main.aes_decrypt(enc["salt"], enc["ciphertext"], self.PASSWORD)
        self.assertEqual(out, "name,ssn\nAlice,123-45-6789")

    def test_same_input_gives_different_ciphertext(self):
        a = main.aes_encrypt("hello", self.PASSWORD)
        b = main.aes_encrypt("hello", self.PASSWORD)
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["ciphertext"], b["ciphertext"])

    def test_endpoints_round_trip(self):
        resp = self.client.post("/encrypt", json={"content": "secret", "password": self.PASSWORD})
        self.assertEqual(resp.status_code, 200)
        enc = resp.get_json()["encrypted"]

        resp = self.client.post("/decrypt", json={**enc, "password": self.PASSWORD})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["decrypted"], "secret")

    def test_wrong_password_rejected(self):
        enc = main.aes_encrypt("secret", self.PASSWORD)
        resp = self.client.post("/decrypt", json={**enc, "password": "wrong-password"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Decryption failed", resp.get_json()["error"])

    def test_encrypt_validation(self):
        self.assertEqual(self.client.post("/encrypt", json={"content": "x"}).status_code, 400)
        short = self.client.post("/encrypt", json={"content": "x", "password": "short"})
        self.assertEqual(short.status_code, 400)
        self.assertIn("at least 8", short.get_json()["error"])


# ------------------------------------------------------------------
# 3. Local file storage
# ------------------------------------------------------------------
class TestFileStorage(BaseTestCase):
    def _save(self, name="data.csv"):
        return self.client.post("/save_file", json={
            "fileName": name, "cipherType": "aes", "content": "abc",
        })

    def test_save_list_delete(self):
        resp = self._save()
        self.assertEqual(resp.status_code, 201)
        file_id = resp.get_json()["id"]

        saved = main.FILES_DIR / f"{file_id}.json"
        self.assertTrue(saved.exists())
        self.assertEqual(os.stat(saved).st_mode & 0o777, 0o600)

        files = self.client.get("/get_files").get_json()["files"]
        self.assertEqual([f["id"] for f in files], [file_id])

        self.assertEqual(self.client.delete(f"/delete_file/{file_id}").status_code, 200)
        self.assertFalse(saved.exists())

    def test_save_requires_fields(self):
        resp = self.client.post("/save_file", json={"fileName": "x"})
        self.assertEqual(resp.status_code, 400)

    def test_delete_rejects_non_uuid(self):
        self.assertEqual(self.client.delete("/delete_file/not-a-uuid").status_code, 400)

    def test_delete_missing_file(self):
        resp = self.client.delete(f"/delete_file/{uuid.uuid4()}")
        self.assertEqual(resp.status_code, 404)


# ------------------------------------------------------------------
# 4. Validators and text redaction
# ------------------------------------------------------------------
class TestValidators(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(main._luhn_check("4111 1111 1111 1111"))
        self.assertFalse(main._luhn_check("4111 1111 1111 1112"))

    def test_aba_routing(self):
        self.assertTrue(main._aba_routing_check("021000021"))
        self.assertFalse(main._aba_routing_check("123456789"))

    def test_iban(self):
        self.assertTrue(main._iban_check("GB82 WEST 1234 5698 7654 32"))
        self.assertFalse(main._iban_check("GB82 WEST 1234 5698 7654 33"))

    def test_swift_bic(self):
        self.assertTrue(main._swift_bic_check("DEUTDEFF"))
        self.assertTrue(main._swift_bic_check("DEUTDEFF500"))
        self.assertFalse(main._swift_bic_check("DEUT"))


class TestTextRedaction(unittest.TestCase):
    def redact(self, text, types_, names=(), allowlist=()):
        rules, _ = main._build_rules([{"type": t} for t in types_], list(names))
        allow = {main._normalize(a) for a in allowlist}
        return main._redact_text_in_run(text, rules, allow)

    def test_ssn_and_email(self):
        out = self.redact("SSN 123-45-6789, mail bob@example.com", ["ssn", "email"])
        self.assertEqual(out, "SSN [REDACTED], mail [REDACTED]")

    def test_ssn_with_spaces(self):
        out = self.redact("SSN 123 45 6789 on file", ["ssn"])
        self.assertEqual(out, "SSN [REDACTED] on file")

    def test_ssn_mixed_separators_not_matched(self):
        # Separators must match, so "123 45-6789" is left alone.
        self.assertEqual(self.redact("123 45-6789", ["ssn"]), "123 45-6789")

    def test_ssn_no_dashes(self):
        out = self.redact("SSN 123456789 on file", ["ssn_nodash"])
        self.assertEqual(out, "SSN [REDACTED] on file")

    def test_ssn_no_dashes_is_opt_in(self):
        # The regular SSN pattern must not catch bare 9-digit numbers.
        self.assertEqual(self.redact("123456789", ["ssn"]), "123456789")

    def test_ssn_no_dashes_skips_impossible_numbers(self):
        for n in ["000123456", "666123456", "900123456", "123004567", "123450000"]:
            self.assertEqual(self.redact(n, ["ssn_nodash"]), n, n)

    def test_ssn_no_dashes_ignores_longer_numbers(self):
        self.assertEqual(self.redact("Order 1234567890", ["ssn_nodash"]), "Order 1234567890")

    def test_invalid_card_not_redacted(self):
        out = self.redact("card 4111 1111 1111 1112", ["credit_card"])
        self.assertIn("4111 1111 1111 1112", out)

    def test_named_field_keeps_label(self):
        out = self.redact("Account Number: 12345678", ["nf_account"])
        self.assertEqual(out, "Account Number: [REDACTED]")

    def test_allowlist_preserves_value(self):
        out = self.redact("a@b.com and c@d.com", ["email"], allowlist=["a@b.com"])
        self.assertEqual(out, "a@b.com and [REDACTED]")

    def test_custom_names(self):
        out = self.redact("Report by Jane Doe.", [], names=["Jane Doe"])
        self.assertEqual(out, "Report by [REDACTED].")

    def test_custom_name_ending_in_initial(self):
        # A trailing "." used to break the \b word-boundary match.
        out = self.redact("Patient: Johnson, Michael R. was seen.", [], names=["Johnson, Michael R."])
        self.assertEqual(out, "Patient: [REDACTED] was seen.")

    def test_custom_name_matches_other_orders(self):
        for entry in ["Michael R. Johnson", "Johnson, Michael R."]:
            for text in ["Johnson, Michael R. signed", "Johnson,  Michael R signed",
                         "Michael R. Johnson signed", "Michael Johnson signed",
                         "Johnson, Michael signed"]:
                with self.subTest(entry=entry, text=text):
                    self.assertEqual(self.redact(text, [], names=[entry]), "[REDACTED] signed")

    def test_custom_name_without_middle_allows_initial(self):
        out = self.redact("Johnson, Michael R. and Michael R. Johnson", [], names=["Michael Johnson"])
        self.assertEqual(out, "[REDACTED] and [REDACTED]")

    def test_custom_name_leaves_partial_words(self):
        text = "Michael Johnsonville, Johnson Michaels, Michael alone, Johnson alone"
        self.assertEqual(self.redact(text, [], names=["Michael Johnson"]), text)

    def test_custom_name_does_not_swallow_next_word(self):
        out = self.redact("Johnson, Michael a day late", [], names=["Michael Johnson"])
        self.assertEqual(out, "[REDACTED] a day late")

    def test_swift_ignores_ordinary_words(self):
        # Mixed-case words must not match; a real uppercase BIC must.
        out = self.redact("This was Referred to bank DEUTDEFF", ["swift_bic"])
        self.assertEqual(out, "This was Referred to bank [REDACTED]")

    def test_invalid_custom_regex_raises(self):
        with self.assertRaises(ValueError):
            main._build_rules([{"type": "custom", "pattern": "("}], [])


# ------------------------------------------------------------------
# 5. /redact endpoint (DOCX) and /ai_advisor input checks
# ------------------------------------------------------------------
class TestRedactEndpoint(BaseTestCase):
    def _docx_bytes(self, text):
        doc = Document()
        doc.add_paragraph(text)
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()

    def _post(self, data_bytes, filename, patterns):
        return self.client.post("/redact", data={
            "file": (io.BytesIO(data_bytes), filename),
            "patterns": json.dumps(patterns),
        }, content_type="multipart/form-data")

    def test_redacts_docx(self):
        src = self._docx_bytes("Contact: jane@example.com SSN 123-45-6789")
        resp = self._post(src, "letter.docx", [{"type": "email"}, {"type": "ssn"}])
        self.assertEqual(resp.status_code, 200)
        self.assertIn("redacted_letter.docx", resp.headers["Content-Disposition"])

        text = "\n".join(p.text for p in Document(io.BytesIO(resp.data)).paragraphs)
        self.assertNotIn("jane@example.com", text)
        self.assertNotIn("123-45-6789", text)
        self.assertIn("[REDACTED]", text)

    def test_redacts_spaced_ssn_in_pdf(self):
        import fitz
        src = fitz.open()
        page = src.new_page()
        page.insert_text((72, 72), "Employee SSN 123 45 6789 and 987-65-4321")
        pdf_bytes = src.tobytes()

        resp = self._post(pdf_bytes, "form.pdf", [{"type": "ssn"}])
        self.assertEqual(resp.status_code, 200)
        text = fitz.open(stream=resp.data, filetype="pdf")[0].get_text()
        self.assertNotIn("123 45 6789", text)
        self.assertNotIn("987-65-4321", text)
        self.assertIn("Employee SSN", text)

    def _post_names(self, data_bytes, filename, patterns, names):
        return self.client.post("/redact", data={
            "file": (io.BytesIO(data_bytes), filename),
            "patterns": json.dumps(patterns),
            "names": json.dumps(names),
        }, content_type="multipart/form-data")

    def _pdf_bytes(self, text):
        import fitz
        doc = fitz.open()
        doc.new_page().insert_text((72, 72), text)
        return doc.tobytes()

    def _pdf_text(self, data):
        import fitz
        return fitz.open(stream=data, filetype="pdf")[0].get_text()

    def _docx_text(self, data):
        return "\n".join(p.text for p in Document(io.BytesIO(data)).paragraphs)

    def test_custom_last_first_name_in_docx_and_pdf(self):
        text = "Patient: Johnson, Michael R. was admitted."
        resp = self._post_names(self._docx_bytes(text), "a.docx", [], ["Michael R. Johnson"])
        self.assertEqual(self._docx_text(resp.data), "Patient: [REDACTED] was admitted.")

        resp = self._post_names(self._pdf_bytes(text), "a.pdf", [], ["Michael R. Johnson"])
        out = self._pdf_text(resp.data)
        self.assertNotIn("Johnson", out)
        self.assertNotIn("Michael", out)
        self.assertIn("was admitted", out)

    def test_ner_last_first_name_in_docx(self):
        try:
            main._get_nlp()
        except OSError:
            self.skipTest("spaCy model en_core_web_sm not installed")
        text = "Patient: Johnson, Michael R. was admitted."
        resp = self._post(self._docx_bytes(text), "a.docx", [{"type": "spacy_ner"}])
        out = self._docx_text(resp.data)
        self.assertNotIn("Johnson", out)
        self.assertNotIn("Michael", out)

    def test_rejects_unsupported_type(self):
        resp = self._post(b"hello", "notes.txt", [{"type": "email"}])
        self.assertEqual(resp.status_code, 400)

    def test_requires_patterns(self):
        resp = self._post(self._docx_bytes("x"), "a.docx", [])
        self.assertEqual(resp.status_code, 400)

    def test_ai_advisor_needs_api_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            resp = self.client.post("/ai_advisor", json={"doc_type": "bank statement"})
        self.assertEqual(resp.status_code, 503)

    def test_ai_advisor_needs_doc_type(self):
        resp = self.client.post("/ai_advisor", json={"doc_type": "  "})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
