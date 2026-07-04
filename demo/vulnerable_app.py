"""
QuickNotes — a tiny note-sharing API.

A deliberately vulnerable single-file Flask application used to demo the
Kolega Scan. Every handler below looks like ordinary product
code, but each one hides a realistic, exploitable flaw. Do NOT deploy this.

Run:
    pip install flask requests
    python vulnerable_app.py
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess
import xml.etree.ElementTree as ET

import requests
from flask import Flask, request, jsonify, send_file, render_template_string, redirect

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# CWE-798 / CWE-312: hardcoded credentials and secrets checked into source.
SECRET_KEY = "app-secret-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"
DB_PASSWORD = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

app.config["SECRET_KEY"] = SECRET_KEY
DB_PATH = os.environ.get("QUICKNOTES_DB", "notes.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY,
            owner_id INTEGER,
            title TEXT,
            body TEXT,
            private INTEGER DEFAULT 1
        );
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def current_user_id():
    """Trusts a client-supplied header — no signature, no session lookup."""
    # CWE-639 enabler: the caller simply asserts who they are.
    return request.headers.get("X-User-Id")


def hash_password(password):
    # CWE-916 / CWE-327: unsalted MD5 for password storage.
    return hashlib.md5(password.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    # CWE-89: SQL injection via f-string interpolation of user input.
    conn.execute(
        f"INSERT INTO users (username, password_hash) "
        f"VALUES ('{username}', '{hash_password(password)}')"
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    # CWE-89: classic authentication-bypass injection point.
    row = conn.execute(
        "SELECT * FROM users WHERE username = '%s' AND password_hash = '%s'"
        % (username, hash_password(password))
    ).fetchone()
    conn.close()

    if row:
        # CWE-209: leaks internal identifiers to the client.
        return jsonify({"user_id": row["id"], "role": row["role"]})
    return jsonify({"error": "invalid credentials"}), 401


# ---------------------------------------------------------------------------
# Notes CRUD
# ---------------------------------------------------------------------------

@app.route("/notes/<int:note_id>", methods=["GET"])
def get_note(note_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404

    # CWE-639 (IDOR): private notes are returned without checking that the
    # requester owns them. Any user can read any note by guessing its id.
    return jsonify(
        {"id": row["id"], "title": row["title"], "body": row["body"]}
    )


@app.route("/notes", methods=["POST"])
def create_note():
    data = request.get_json(force=True)
    owner = current_user_id()
    conn = get_db()
    conn.execute(
        "INSERT INTO notes (owner_id, title, body, private) VALUES (?, ?, ?, ?)",
        (owner, data.get("title"), data.get("body"), int(data.get("private", 1))),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "created"})


@app.route("/notes/<int:note_id>", methods=["DELETE"])
def delete_note(note_id):
    # CWE-862: missing authorization. No ownership or role check at all —
    # any caller can delete any note.
    conn = get_db()
    conn.execute("DELETE FROM notes WHERE id = ?", (note_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"})


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.route("/admin/users", methods=["GET"])
def admin_list_users():
    # CWE-306: a sensitive admin endpoint with no authentication whatsoever.
    conn = get_db()
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/run", methods=["POST"])
def admin_run():
    # CWE-78: OS command injection. The "host" field flows straight into a
    # shell. e.g. host = "localhost; rm -rf /"
    host = request.get_json(force=True).get("host", "localhost")
    output = subprocess.check_output(
        "ping -c 1 " + host, shell=True, stderr=subprocess.STDOUT
    )
    return jsonify({"output": output.decode(errors="replace")})


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

@app.route("/download")
def download():
    # CWE-22: path traversal. ?name=../../etc/passwd escapes UPLOAD_DIR.
    name = request.args.get("name", "")
    path = os.path.join(UPLOAD_DIR, name)
    return send_file(path)


@app.route("/import", methods=["POST"])
def import_notes():
    # CWE-611: XXE. External entities are resolved by the default parser
    # configuration, enabling file disclosure and SSRF via crafted XML.
    raw = request.get_data()
    root = ET.fromstring(raw)
    titles = [el.text for el in root.findall(".//title")]
    return jsonify({"imported": titles})


@app.route("/restore", methods=["POST"])
def restore():
    # CWE-502: insecure deserialization of attacker-controlled bytes.
    blob = request.get_data()
    state = pickle.loads(blob)
    return jsonify({"restored_keys": list(state.keys())})


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------

@app.route("/fetch")
def fetch_url():
    # CWE-918: SSRF. The server fetches any URL the client supplies, including
    # internal addresses like http://169.254.169.254/ or http://localhost.
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "body": resp.text[:500]})


@app.route("/redirect")
def open_redirect():
    # CWE-601: open redirect — ?next= is sent to the browser unvalidated.
    target = request.args.get("next", "/")
    return redirect(target)


@app.route("/greet")
def greet():
    # CWE-79: reflected XSS. User input is rendered into HTML without escaping.
    name = request.args.get("name", "guest")
    return render_template_string("<h1>Hello " + name + "</h1>")


# ---------------------------------------------------------------------------
# Debug
# ---------------------------------------------------------------------------

@app.route("/debug")
def debug_info():
    # CWE-200: information exposure. Dumps environment, including secrets.
    return jsonify(dict(os.environ))


if __name__ == "__main__":
    init_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    # CWE-94 surface: debug mode enables the interactive Werkzeug console (RCE).
    app.run(host="0.0.0.0", port=5000, debug=True)
