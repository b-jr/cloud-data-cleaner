# Tests

Unit and API tests for `main.py`, written with Python's built-in `unittest` (no pytest required).

## Run

From the project root:

```bash
python -m unittest discover -s tests -v
```

## Requirements

- The app's dependencies: `flask`, `flask-cors`, `cryptography`, `pymupdf`, `python-docx`, `spacy`
- `anthropic` is optional. If it isn't installed, the tests stub it out.

## Notes

- Each test uses its own temporary folder for saved files, so your real `~/.cloud-data-cleaner/files/` is never touched.
- No network calls are made. The AI Advisor tests only check input validation.
- See [SUMMARY.md](SUMMARY.md) for what each test group covers.
