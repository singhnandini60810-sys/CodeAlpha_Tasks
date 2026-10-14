# Secure Code Review Report: "Notes Vault" (Python / Flask)

**Internship:** CodeAlpha Cyber Security | **Task 3:** Secure Coding Review
**Language / framework:** Python 3, Flask, SQLite
**Target:** `vulnerable_app.py` (103 lines, 11 routes) | **Remediated build:** `secure_app.py`
**Methods:** (1) manual line-by-line review against the OWASP Top 10 (2021) and OWASP ASVS, (2) static analysis with **Bandit**, (3) proof-of-concept tests (`test_audit.py`) run only against this sample app.

---

## 1. Executive summary

The application was reviewed for common web-application weaknesses. **14 findings** were recorded: **6 Critical, 4 High, 3 Medium, 1 Low**. Bandit reported 14 raw issues covering only **7 of the 14 findings**; it **missed the other 7** (template injection/XSS, IDOR/missing auth, CSRF, path traversal, cookie flags, security headers, brute-force protection), which shows why manual review has to accompany automated scanning. After remediation Bandit reports only 1 Low informational note (the `subprocess` import), and the automated tests confirm every demonstrated attack is blocked.

| Severity | Count | Findings |
|---|---|---|
| Critical | 6 | F-01 SQL injection, F-04 Template injection/XSS, F-05 Insecure deserialization, F-06 Command injection, F-10 Debug mode + bind 0.0.0.0, F-08 Broken access control (IDOR) |
| High | 4 | F-02 Hard-coded secrets, F-03 Weak password hashing, F-13 Path traversal, F-09 CSRF |
| Medium | 3 | F-07 Insecure cookie flags, F-12 No brute-force protection, F-14 Predictable reset token |
| Low | 1 | F-11 Missing security headers / verbose errors |

---

## 2. Detailed findings

Line numbers refer to `vulnerable_app.py`. Fix references are to `secure_app.py`.

### F-01: SQL Injection (Critical) | CWE-89 | OWASP A03:2021 Injection
- **Where:** `register()` line 38, `login()` line 47, `search()` line 66. Detected by Bandit B608.
- **Issue:** User input is concatenated or formatted straight into SQL strings.
- **Impact:** Authentication bypass, data theft, data modification or deletion. PoC: username `' OR '1'='1' --` logs in with no password.
- **Vulnerable:** `f"SELECT id FROM users WHERE username='{u}' AND password='{h}'"`
- **Fix:** Parameterised queries: `db().execute("SELECT id, password FROM users WHERE username=?", (u,))`. Add input validation (username regex) and escape `LIKE` wildcards.

### F-02: Hard-coded Secrets (High) | CWE-798 | A07:2021
- **Where:** lines 16-17 (`app.secret_key = "supersecret123"`, `ADMIN_PASSWORD = "admin@123"`). Bandit B105.
- **Impact:** Anyone with repository access can forge session cookies or use the admin password; secrets stay in Git history forever.
- **Fix:** Load from environment (`NOTES_SECRET_KEY`), fail to start if missing. Remove the unused admin password. Rotate any secret that was ever committed.

### F-03: Weak Password Hashing (High) | CWE-327 / CWE-916 | A02:2021
- **Where:** lines 36, 46 (`hashlib.md5`). Bandit B324.
- **Impact:** MD5 is fast and unsalted, so a stolen database is cracked with rainbow tables or GPUs in minutes.
- **Fix:** `werkzeug.security.generate_password_hash` / `check_password_hash` (salted scrypt/PBKDF2). Enforce a minimum password length. A dummy hash check on unknown users keeps login timing uniform.

### F-04: Reflected XSS and Server-Side Template Injection (Critical) | CWE-79 / CWE-1336 | A03:2021
- **Where:** `search()` line 67, `render_template_string("<h1>Results for " + q + ...)`. **Not detected by Bandit.**
- **Impact:** `?q={{7*7}}` returns 49 (template code executes on the server and can escalate to remote code execution); `?q=<script>` runs JavaScript in the victim's browser.
- **Fix:** Never build a template from user input. Return JSON (`jsonify`) or use a static template with auto-escaped variables. A restrictive CSP is added as defence in depth (F-11).

### F-05: Insecure Deserialization (Critical) | CWE-502 | A08:2021
- **Where:** lines 52 and 59. Session data is pickled into a cookie and `pickle.loads()` is called on a client-controlled value. Bandit B301/B403.
- **Impact:** A crafted cookie gives **remote code execution**.
- **Fix:** Use Flask's signed session (`session["uid"]`), which is serialised as JSON and signed with the secret key. Never unpickle untrusted data.

### F-06: OS Command Injection (Critical) | CWE-78 | A03:2021
- **Where:** `ping()` line 87, `subprocess.check_output("ping -c 1 " + host, shell=True)`. Bandit B602.
- **Impact:** `?host=; <any command>` runs arbitrary commands on the server. PoC `; echo INJECTED` output was returned.
- **Fix:** Validate with `ipaddress.ip_address()`, call `subprocess.run([...], shell=False, timeout=5)` with a fixed argument list, require login. Better still: remove the feature if it is not needed.

### F-07: Insecure Session Cookie Attributes (Medium) | CWE-1004 / CWE-614 / CWE-1275 | A05:2021
- **Where:** `resp.set_cookie("session", token)`, line 53 (no HttpOnly, Secure or SameSite).
- **Impact:** Cookie is readable by JavaScript (XSS theft), sent over plain HTTP, and attached to cross-site requests.
- **Fix:** `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE="Lax"`.

### F-08: Broken Access Control / IDOR / Missing Authentication (Critical) | CWE-639 / CWE-306 | A01:2021
- **Where:** `get_note()` line 79 and `add_note()` line 71. Notes are returned by numeric ID with no login and no ownership check; the note owner is taken from a form field. **Not detected by Bandit.**
- **Impact:** Anyone can enumerate `/note/1`, `/note/2`, ... and read every user's notes, or write notes as another user.
- **Fix:** `@login_required`, store `owner_id` from the server-side session, and query `WHERE id=? AND owner_id=?` (return 404 otherwise).

### F-09: Cross-Site Request Forgery (High) | CWE-352 | A01:2021
- **Where:** all state-changing POST routes (e.g. line 70). **Not detected by Bandit.**
- **Impact:** A malicious page can make a logged-in user's browser submit actions.
- **Fix:** Per-session CSRF token checked in `before_request` with a constant-time compare, plus `SameSite=Lax` cookies.

### F-10: Debug Mode Enabled and Bound to All Interfaces (Critical) | CWE-489 / CWE-668 | A05:2021
- **Where:** line 103, `app.run(host="0.0.0.0", debug=True)`. Bandit B201/B104.
- **Impact:** The Werkzeug interactive debugger gives remote code execution to anyone who reaches the port, and stack traces leak source code and paths.
- **Fix:** `debug=False`, bind to `127.0.0.1`, run behind Gunicorn + a reverse proxy in production, and return a generic 500 error body.

### F-11: Missing Security Headers (Low) | CWE-693 | A05:2021
- **Impact:** Weaker defence against XSS, clickjacking and MIME sniffing.
- **Fix:** `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` in `after_request`.

### F-12: No Brute-Force Protection (Medium) | CWE-307 | A07:2021
- **Impact:** Unlimited password guessing against `/login`.
- **Fix:** Rate limiting (5 attempts per minute per IP in the demo; use Redis / Flask-Limiter in production), generic error messages, and account lockout or MFA for real deployments.

### F-13: Path Traversal (High) | CWE-22 | A01:2021
- **Where:** `download()` line 93, `send_file(os.path.join(UPLOAD_DIR, name))`. **Not detected by Bandit.**
- **Impact:** `?file=../secret.txt` (or `../../etc/passwd`) downloads files outside the upload folder.
- **Fix:** `send_from_directory(UPLOAD_DIR, name)`, which uses `safe_join` and rejects traversal, plus login required.

### F-14: Predictable Password-Reset Token (Medium) | CWE-330 / CWE-640 | A07:2021
- **Where:** `reset()` line 98, `random.randint(1000, 9999)`. Bandit B311.
- **Impact:** Only 9,000 possibilities, guessable in seconds, and the token is returned directly in the response.
- **Fix:** `secrets.token_urlsafe(32)`, store only a hash with a 15-minute expiry, deliver by e-mail, never return it in the API response, and rate-limit the endpoint.

---

## 3. Tool results

| Tool | vulnerable_app.py | secure_app.py |
|---|---|---|
| Bandit (`bandit_before.txt`, `bandit_after.txt`) | 14 issues: 4 High, 5 Medium, 5 Low | 1 Low (informational `import subprocess`; the call itself is fixed-argv, no shell, reviewed and annotated) |
| Manual review | 14 findings | 0 open |
| `test_audit.py` | 7/7 attacks succeed | 14/14 checks pass (attacks blocked, legitimate use still works) |

**Tool limitation worth noting:** Bandit found 7 of 14 issues. The other 7 are logic and design flaws (access control, CSRF, template injection, traversal, cookie flags, headers, rate limiting) that need manual review or dynamic testing (e.g. OWASP ZAP, Burp Suite).

---

## 4. Secure coding best practices (summary)

1. **Never trust input:** validate on the server (allow-lists), and use parameterised queries / ORMs.
2. **Authenticate and authorise on every request,** and check object ownership server-side.
3. **Hash passwords** with a slow, salted algorithm (scrypt, bcrypt, Argon2).
4. **Keep secrets out of code:** environment variables or a secrets manager; rotate on exposure.
5. **Avoid dangerous APIs:** `pickle` on untrusted data, `eval`, `shell=True`, `render_template_string` with user input.
6. **Use CSPRNG (`secrets`)** for tokens, never `random`.
7. **Harden sessions and responses:** cookie flags, CSRF tokens, security headers, no debug mode, generic errors.
8. **Throttle** authentication and reset endpoints; log security events without logging secrets.
9. **Automate:** run Bandit/Semgrep and `pip-audit` in CI, add dependency updates, and perform periodic manual reviews.

## 5. Remediation priority

1. **Immediately:** F-01, F-04, F-05, F-06, F-10, F-08 (remote code execution or full data exposure).
2. **Next sprint:** F-02, F-03, F-09, F-13.
3. **Hardening:** F-07, F-11, F-12, F-14.

## 6. Scope and limitations

The audit covers a single-file demonstration application written for this exercise. Dependency scanning, infrastructure configuration, TLS and business-logic testing beyond the routes listed were out of scope. The proof-of-concept tests were run only against the included sample code.
