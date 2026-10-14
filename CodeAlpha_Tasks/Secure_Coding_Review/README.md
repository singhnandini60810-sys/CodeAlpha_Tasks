# CodeAlpha_SecureCodingReview

CodeAlpha Cyber Security Internship, **Task 3: Secure Coding Review**.

A security audit of a deliberately vulnerable Flask app ("Notes Vault"): 14 vulnerabilities found by manual review + Bandit, each documented with severity, CWE/OWASP mapping, impact and remediation, then fixed in a hardened version and verified with automated tests.

| File | Purpose |
|---|---|
| `REPORT.md` | Full audit report (findings, severity, remediation, best practices) |
| `vulnerable_app.py` | Audit target. **Intentionally insecure. Never deploy.** |
| `secure_app.py` | Remediated version |
| `test_audit.py` | Proof-of-concept tests (before = exploitable, after = blocked) |
| `bandit_before.txt` / `bandit_after.txt` | Static-analysis output |

## Run it
```bash
pip install -r requirements.txt
python test_audit.py                       # expect: 21/21 checks behaved as expected
bandit -r vulnerable_app.py                # static analysis (before)
bandit -r secure_app.py                    # static analysis (after)

# Run the hardened app locally
export NOTES_SECRET_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")
NOTES_DEV=1 python secure_app.py
```
> `NOTES_DEV=1` only disables the Secure-cookie flag for local HTTP testing. Do not use it in production.

*Ethics note: all testing was done locally against code written for this exercise.*
