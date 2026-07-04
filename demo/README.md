# QuickNotes — scanner demo target

A single-file (~260 LOC) deliberately-vulnerable Flask app for demoing the
Kolega scanner live. **Do not deploy.** Every route hides one realistic,
exploitable flaw spanning the scanner's main categories:

| File location | Flaw | CWE |
|---|---|---|
| `SECRET_KEY` / `AWS_*` | Hardcoded secrets | 798 / 312 |
| `hash_password` | Unsalted MD5 | 916 / 327 |
| `register` / `login` | SQL injection | 89 |
| `get_note` | IDOR (broken object-level authz) | 639 |
| `delete_note` | Missing authorization | 862 |
| `admin_list_users` | Missing authentication | 306 |
| `admin_run` | OS command injection | 78 |
| `download` | Path traversal | 22 |
| `import_notes` | XXE | 611 |
| `restore` | Insecure deserialization (pickle) | 502 |
| `fetch_url` | SSRF | 918 |
| `open_redirect` | Open redirect | 601 |
| `greet` | Reflected XSS | 79 |
| `debug_info` | Info exposure | 200 |
| `app.run(debug=True)` | Debug console / RCE surface | 94 |

## Scan it

```bash
kolega-scan scan demo/ --out findings.json  # default scanner: kolega-scan-oss-v1
```
