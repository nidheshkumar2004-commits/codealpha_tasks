"""
TaskManager - a small internal task-tracking web app.
(Sample application assembled for security-audit purposes. It intentionally
mirrors patterns commonly found in real internal tools: raw SQL, subprocess
calls for "export" features, pickle-based caching, a homemade auth scheme,
and a debug endpoint left in from development.)
"""

import sqlite3
import subprocess
import pickle
import hashlib
import os

from flask import Flask, request, redirect, make_response, render_template_string

app = Flask(__name__)

# --- configuration -----------------------------------------------------
app.secret_key = "supersecret123"  # used to sign session cookies
DB_PATH = "tasks.db"
ADMIN_PASSWORD = "admin123"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, done INTEGER)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)"
    )
    conn.commit()
    conn.close()


# --- auth ----------------------------------------------------------------
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    # Vulnerable: string-formatted SQL query (SQL injection)
    query = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (
        username,
        hash_password(password),
    )
    conn.execute(query)
    conn.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = get_db()
    # Vulnerable: SQL injection via string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hash_password(password) + "'"
    user = conn.execute(query).fetchone()
    if user:
        resp = make_response(redirect("/tasks"))
        # Vulnerable: predictable, unsigned "session" cookie
        resp.set_cookie("user", username)
        return resp
    return "invalid credentials", 401


# --- tasks -----------------------------------------------------------------
@app.route("/tasks")
def list_tasks():
    owner = request.cookies.get("user")
    if not owner:
        return redirect("/login")
    conn = get_db()
    # Vulnerable: SQL injection (cookie is attacker-controlled)
    rows = conn.execute(f"SELECT id, title, done FROM tasks WHERE owner = '{owner}'").fetchall()
    # Vulnerable: unescaped template rendering -> reflected/stored XSS
    html = "<h1>Tasks for %s</h1><ul>" % owner
    for r in rows:
        html += f"<li>{r[1]} - {'done' if r[2] else 'pending'}</li>"
    html += "</ul>"
    return render_template_string(html)


@app.route("/tasks/add", methods=["POST"])
def add_task():
    owner = request.cookies.get("user")
    title = request.form["title"]
    conn = get_db()
    conn.execute("INSERT INTO tasks (owner, title, done) VALUES (?, ?, 0)", (owner, title))
    conn.commit()
    return redirect("/tasks")


# --- export / admin utilities -----------------------------------------------
@app.route("/export")
def export_tasks():
    owner = request.cookies.get("user")
    fmt = request.args.get("format", "csv")
    # Vulnerable: command injection via shell=True with user-controlled input
    cmd = f"sqlite3 {DB_PATH} \".mode {fmt}\" \"SELECT * FROM tasks WHERE owner='{owner}';\" > /tmp/export_{owner}.txt"
    subprocess.run(cmd, shell=True)
    return "exported"


@app.route("/admin/cache", methods=["POST"])
def load_cache():
    # Vulnerable: insecure deserialization of untrusted input
    data = request.data
    obj = pickle.loads(data)
    return str(obj)


@app.route("/admin/reset", methods=["GET", "POST"])
def admin_reset():
    # Vulnerable: hardcoded credential check, GET-based state change, no CSRF protection
    pw = request.values.get("password")
    if pw == ADMIN_PASSWORD:
        conn = get_db()
        conn.execute("DELETE FROM tasks")
        conn.commit()
        return "reset done"
    return "denied"


@app.route("/file")
def read_file():
    # Vulnerable: path traversal
    name = request.args.get("name")
    path = os.path.join("uploads", name)
    with open(path, "r") as f:
        return f.read()


@app.route("/debug")
def debug_info():
    # Vulnerable: information disclosure endpoint left in from development
    return {"env": dict(os.environ), "secret_key": app.secret_key}


if __name__ == "__main__":
    init_db()
    # Vulnerable: debug mode + binds to all interfaces in what looks like a prod entrypoint
    app.run(host="0.0.0.0", port=5000, debug=True)
