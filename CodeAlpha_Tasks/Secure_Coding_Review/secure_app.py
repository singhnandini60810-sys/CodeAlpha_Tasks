"""
Notes Vault - REMEDIATED version of vulnerable_app.py.
Each fix is tagged with the finding ID (F-01 ... F-14) from REPORT.md.
"""
import hashlib
import ipaddress
import os
import re
import secrets
import sqlite3
import subprocess
import time
from collections import defaultdict
from functools import wraps

from flask import Flask, abort, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# F-02: secrets come from the environment, never from source control
_key = os.environ.get("NOTES_SECRET_KEY")
if not _key:
    raise RuntimeError("Set NOTES_SECRET_KEY (e.g. python -c 'import secrets;print(secrets.token_hex(32))')")
app.config.update(
    SECRET_KEY=_key,
    SESSION_COOKIE_HTTPONLY=True,                                   # F-07
    SESSION_COOKIE_SAMESITE="Lax",                                  # F-07 / F-09
    SESSION_COOKIE_SECURE=os.environ.get("NOTES_DEV") != "1",       # F-07 (off only for local http dev)
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)
DB = os.environ.get("NOTES_DB", "notes.db")
UPLOAD_DIR = os.path.abspath("uploads")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
_DUMMY_HASH = generate_password_hash("dummy-password")
_attempts = defaultdict(list)                                       # F-12 (use Redis in production)
_reset_tokens = {}


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    with db() as con:
        con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, body TEXT NOT NULL)")


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if "uid" not in session:
            abort(401)
        return fn(*a, **kw)
    return wrapper


def rate_limited(key, limit=5, window=60):
    now = time.time()
    _attempts[key] = [t for t in _attempts[key] if now - t < window]
    if len(_attempts[key]) >= limit:
        return True
    _attempts[key].append(now)
    return False


@app.before_request
def csrf_protect():                                                 # F-09
    if request.method in ("POST", "PUT", "DELETE"):
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(403)


@app.after_request
def security_headers(resp):                                         # F-11
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(500)
def server_error(_):
    return jsonify(error="internal error"), 500                     # F-10: no stack traces


@app.get("/csrf")
def csrf_token():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    return jsonify(csrf_token=session["csrf"])


@app.post("/register")
def register():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    if not USERNAME_RE.match(u) or len(p) < 10:
        return jsonify(error="username 3-32 chars [A-Za-z0-9_], password >= 10 chars"), 400
    try:
        with db() as con:
            con.execute("INSERT INTO users(username,password) VALUES(?,?)",        # F-01, F-03
                        (u, generate_password_hash(p)))
    except sqlite3.IntegrityError:
        return jsonify(error="could not register"), 400
    return jsonify(status="registered"), 201


@app.post("/login")
def login():
    if rate_limited(request.remote_addr or "?"):                    # F-12
        return jsonify(error="too many attempts"), 429
    u, p = request.form.get("username", ""), request.form.get("password", "")
    row = db().execute("SELECT id, password FROM users WHERE username=?", (u,)).fetchone()   # F-01
    ok = check_password_hash(row["password"] if row else _DUMMY_HASH, p)
    if not (row and ok):
        return jsonify(error="invalid credentials"), 401
    csrf = secrets.token_urlsafe(32)
    session.clear()                                                 # F-05 / session fixation
    session["uid"], session["csrf"] = row["id"], csrf
    return jsonify(status="ok", csrf_token=csrf)


@app.get("/profile")
@login_required
def profile():
    row = db().execute("SELECT username FROM users WHERE id=?", (session["uid"],)).fetchone()
    return jsonify(user=row["username"])                            # F-05: signed session, no pickle


@app.get("/search")
@login_required
def search():
    q = request.args.get("q", "")[:100]
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    rows = db().execute("SELECT id, body FROM notes WHERE owner_id=? AND body LIKE ? ESCAPE '\\'",
                        (session["uid"], like)).fetchall()          # F-01, F-04 (JSON, no template injection)
    return jsonify(query=q, results=[dict(r) for r in rows])


@app.post("/note")
@login_required
def add_note():
    body = request.form.get("body", "").strip()
    if not body or len(body) > 2000:
        return jsonify(error="body required (max 2000 chars)"), 400
    with db() as con:
        con.execute("INSERT INTO notes(owner_id, body) VALUES(?,?)", (session["uid"], body))   # F-08
    return jsonify(status="saved"), 201


@app.get("/note/<int:note_id>")
@login_required
def get_note(note_id):
    row = db().execute("SELECT body FROM notes WHERE id=? AND owner_id=?",
                       (note_id, session["uid"])).fetchone()        # F-08: ownership enforced
    if not row:
        abort(404)
    return jsonify(body=row["body"])


@app.get("/ping")
@login_required
def ping():
    try:
        ip = ipaddress.ip_address(request.args.get("host", ""))     # F-06: strict allow-list parse
    except ValueError:
        return jsonify(error="host must be a valid IP address"), 400
    out = subprocess.run(["/bin/ping", "-c", "1", "-W", "2", str(ip)],   # nosec B603 - fixed argv, validated IP, no shell
                         capture_output=True, text=True, timeout=5, check=False)
    return jsonify(output=out.stdout)


@app.get("/download")
@login_required
def download():
    name = request.args.get("file", "")
    return send_from_directory(UPLOAD_DIR, name)                    # F-13: safe_join blocks ../


@app.post("/reset")
def reset():
    if rate_limited("reset:" + (request.remote_addr or "?"), limit=3, window=300):
        return jsonify(error="too many attempts"), 429
    token = secrets.token_urlsafe(32)                               # F-14: CSPRNG, 256-bit
    _reset_tokens[hashlib.sha256(token.encode()).hexdigest()] = time.time() + 900   # store hash, 15 min expiry
    # In production: e-mail the token to the account owner. Never return it in the response.
    return jsonify(status="if the account exists, a reset link was sent")


if __name__ == "__main__":
    init_db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    app.run(host="127.0.0.1", port=5000, debug=False)               # F-10
