"""
Proof-of-concept checks run against the sample app only (your own code, local test client).
Part 1 shows each flaw is exploitable in vulnerable_app.py; Part 2 shows secure_app.py blocks it.
Run:  python test_audit.py
"""
import importlib.util, os, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
results = []


def check(label, passed):
    results.append((label, passed))
    print(("PASS  " if passed else "FAIL  ") + label)


def load(filename, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sandbox():
    d = tempfile.mkdtemp()
    os.chdir(d)
    os.makedirs("uploads", exist_ok=True)
    open("uploads/ok.txt", "w").write("public file")
    open("secret.txt", "w").write("TOP-SECRET")
    return d


# ---------------- Part 1: vulnerable app ----------------
print("=== BEFORE: vulnerable_app.py (each line should show the attack WORKING) ===")
sandbox()
v = load("vulnerable_app.py", "vuln")
v.init_db()
c = v.app.test_client()
c.post("/register", data={"username": "alice", "password": "Pass#12345"})
c.post("/note", data={"owner": "alice", "body": "alice private note"})

r = c.post("/login", data={"username": "' OR '1'='1' --", "password": "x"})
check("F-01 SQL injection: login bypass without a password", r.status_code == 200)
r = c.get("/search", query_string={"q": "{{7*7}}"})
check("F-04 Template injection / XSS: {{7*7}} evaluated server-side", b"49" in r.data)
r = c.get("/note/1")
check("F-08 IDOR: unauthenticated user reads note #1", b"alice private note" in r.data)
r = c.get("/ping", query_string={"host": "; echo INJECTED"})
check("F-06 Command injection: injected shell command executed", b"INJECTED" in r.data)
r = c.get("/download", query_string={"file": "../secret.txt"})
check("F-13 Path traversal: file outside uploads/ downloaded", b"TOP-SECRET" in r.data)
r = c.get("/reset")
check("F-14 Weak reset token: only 4 digits (10,000 combinations)", r.data.decode().isdigit() and len(r.data) == 4)
import hashlib
check("F-03 MD5 password hash is unsalted and fast", hashlib.md5(b"Pass#12345").hexdigest() ==
      v.db().execute("SELECT password FROM users WHERE username='alice'").fetchone()[0])

# ---------------- Part 2: secure app ----------------
print("\n=== AFTER: secure_app.py (each line should show the attack BLOCKED) ===")
d = sandbox()
os.environ.update(NOTES_SECRET_KEY="test-key-" + "x" * 32, NOTES_DEV="1", NOTES_DB=os.path.join(d, "notes.db"))
s = load("secure_app.py", "sec")
s.init_db()


def client():
    cl = s.app.test_client()
    tok = cl.get("/csrf").get_json()["csrf_token"]
    return cl, {"X-CSRF-Token": tok}


alice, ha = client()
bob, hb = client()
s._attempts.clear()
alice.post("/register", data={"username": "alice", "password": "Pass#12345"}, headers=ha)
bob.post("/register", data={"username": "bob", "password": "Pass#67890"}, headers=hb)
ha = {"X-CSRF-Token": alice.post("/login", data={"username": "alice", "password": "Pass#12345"}, headers=ha).get_json()["csrf_token"]}
hb = {"X-CSRF-Token": bob.post("/login", data={"username": "bob", "password": "Pass#67890"}, headers=hb).get_json()["csrf_token"]}
alice.post("/note", data={"body": "alice private note"}, headers=ha)

probe, hp = client()
check("F-01 SQL injection payload rejected at login",
      probe.post("/login", data={"username": "' OR '1'='1' --", "password": "x"}, headers=hp).status_code == 401)
r = alice.get("/search", query_string={"q": "{{7*7}}"})
check("F-04 {{7*7}} returned as inert JSON text, not evaluated",
      r.is_json and r.get_json()["query"] == "{{7*7}}" and r.mimetype == "application/json")
check("F-08 Other user (bob) cannot read alice's note", bob.get("/note/1").status_code == 404)
check("F-08 Owner (alice) can read her note", alice.get("/note/1").status_code == 200)
check("F-08 Anonymous request is rejected", s.app.test_client().get("/note/1").status_code == 401)
check("F-06 Command injection rejected (400)", alice.get("/ping", query_string={"host": "; echo INJECTED"}).status_code == 400)
check("F-13 Path traversal blocked", alice.get("/download", query_string={"file": "../secret.txt"}).status_code == 404)
check("F-13 Legitimate download still works", alice.get("/download", query_string={"file": "ok.txt"}).data == b"public file")
check("F-09 POST without CSRF token rejected (403)", alice.post("/note", data={"body": "x"}).status_code == 403)
forged = s.app.test_client()
forged.set_cookie("session", "gASVDwAAAAAAAAB9lIwEdXNlcpSMBWFkbWlulHMu")
check("F-05 Forged pickle/session cookie not accepted", forged.get("/profile").status_code == 401)
rr = probe.post("/reset", headers=hp)
check("F-14 Reset token is never returned in the response", rr.is_json and "token" not in rr.get_data(as_text=True).lower().replace("reset link", ""))
cookie = alice.post("/login", data={"username": "alice", "password": "Pass#12345"}, headers=ha).headers.get("Set-Cookie", "")
check("F-07 Session cookie has HttpOnly + SameSite", "HttpOnly" in cookie and "SameSite=Lax" in cookie)
h = alice.get("/profile").headers
check("F-11 Security headers present (CSP, nosniff, XFO)", all(k in h for k in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options")))
s._attempts.clear()
codes = [probe.post("/login", data={"username": "alice", "password": "wrong"}, headers=hp).status_code for _ in range(7)]
check("F-12 Brute-force login throttled (429 after 5 tries)", 429 in codes)

print(f"\n{sum(p for _, p in results)}/{len(results)} checks behaved as expected")
