"""
Notes Vault - INTENTIONALLY VULNERABLE Flask app (audit target).
For educational use only. Never deploy this.
"""
import base64
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

from flask import Flask, request, render_template_string, make_response, send_file

app = Flask(__name__)
app.secret_key = "supersecret123"          # hard-coded secret
ADMIN_PASSWORD = "admin@123"               # hard-coded credential
DB = "notes.db"
UPLOAD_DIR = "uploads"


def db():
    return sqlite3.connect(DB)


def init_db():
    con = db()
    con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    con.commit()


@app.route("/register", methods=["POST"])
def register():
    u, p = request.form["username"], request.form["password"]
    h = hashlib.md5(p.encode()).hexdigest()                       # weak hash, no salt
    con = db()
    con.execute("INSERT INTO users(username,password) VALUES('%s','%s')" % (u, h))   # SQLi
    con.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["username"], request.form["password"]
    h = hashlib.md5(p.encode()).hexdigest()
    q = f"SELECT id FROM users WHERE username='{u}' AND password='{h}'"            # SQLi
    row = db().execute(q).fetchone()
    if not row:
        return "invalid", 401
    resp = make_response("ok")
    token = base64.b64encode(pickle.dumps({"user": u})).decode()                   # pickle session
    resp.set_cookie("session", token)                                              # no HttpOnly/Secure/SameSite
    return resp


@app.route("/profile")
def profile():
    data = pickle.loads(base64.b64decode(request.cookies.get("session", "")))      # insecure deserialization
    return "Hello " + data["user"]


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = db().execute("SELECT body FROM notes WHERE body LIKE '%" + q + "%'").fetchall()   # SQLi
    return render_template_string("<h1>Results for " + q + "</h1>" + str(rows))               # XSS / SSTI


@app.route("/note", methods=["POST"])                  # no CSRF protection, no auth
def add_note():
    con = db()
    con.execute("INSERT INTO notes(owner,body) VALUES(?,?)", (request.form["owner"], request.form["body"]))
    con.commit()
    return "saved"


@app.route("/note/<int:note_id>")
def get_note(note_id):                                  # IDOR: no ownership check
    row = db().execute("SELECT body FROM notes WHERE id=?", (note_id,)).fetchone()
    return row[0] if row else ("not found", 404)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output("ping -c 1 " + host, shell=True)               # command injection


@app.route("/download")
def download():
    name = request.args.get("file")
    return send_file(os.path.join(UPLOAD_DIR, name))                               # path traversal


@app.route("/reset")
def reset():
    return str(random.randint(1000, 9999))                                         # predictable 4-digit token


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", debug=True)                                            # Werkzeug debugger exposed
