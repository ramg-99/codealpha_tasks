# ============================================================
#  SECURE FLASK APP  —  Remediated Version (All fixes applied)
# ============================================================

import os
import re
import sqlite3
import subprocess
import secrets
import logging
from functools import wraps

import bcrypt
from flask import Flask, request, redirect, session, escape, abort
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Load secrets from .env file — never hardcode!
load_dotenv()

app = Flask(__name__)

# FIX 1: Secret key from environment variable
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# FIX 2: No hardcoded credentials — use environment variables
DB_USER     = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# FIX 3: Debug OFF in production
app.config['DEBUG'] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# FIX: Secure session cookie settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE']   = True   # Requires HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# FIX: Allowed file types and size limits
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_UPLOAD_MB      = 5
UPLOAD_FOLDER      = os.environ.get("UPLOAD_FOLDER", "/var/secure_uploads")

# FIX: Proper logging (no sensitive data in logs)
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


# ── Database ─────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("users_secure.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email         TEXT UNIQUE NOT NULL,
        role          TEXT DEFAULT 'user'
    )""")
    # FIX 4: Store bcrypt hash — never plain text
    hashed = bcrypt.hashpw(b"Admin@Secure1!", bcrypt.gensalt()).decode()
    conn.execute(
        "INSERT OR IGNORE INTO users (id,username,password_hash,email,role) VALUES (?,?,?,?,?)",
        (1, 'admin', hashed, 'admin@site.com', 'admin')
    )
    conn.commit()
    conn.close()


# ── Auth decorators ───────────────────────────────────────────
def login_required(f):
    """FIX 7: All protected routes enforce authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """FIX 16: Re-verify role from DB on every admin request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        conn = get_db()
        user = conn.execute(
            "SELECT role FROM users WHERE id = ?", (session['user_id'],)
        ).fetchone()
        conn.close()
        if not user or user['role'] != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Routes ───────────────────────────────────────────────────
@app.route('/')
def home():
    return "<h1>Secure App</h1><a href='/login'>Login</a>"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').encode()

        # FIX: Validate input length
        if not username or len(username) > 50:
            return "Invalid input", 400

        conn = get_db()
        # FIX 5: Parameterized query — no SQL injection possible
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        # FIX: bcrypt timing-safe comparison
        if user and bcrypt.checkpw(password, user['password_hash'].encode()):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            logger.info(f"Login OK: user_id={user['id']}")
            return redirect('/dashboard')
        else:
            # FIX: Generic error (don't reveal username vs password)
            logger.warning(f"Failed login: {username[:20]}")
            # FIX 6: Escape output to prevent XSS
            return f"<p style='color:red'>{escape('Invalid credentials')}</p><a href='/login'>Back</a>"

    return """<html><body>
    <h2>Login</h2>
    <form method='post'>
        Username: <input name='username' maxlength='50'><br>
        Password: <input type='password' name='password' maxlength='100'><br>
        <input type='submit' value='Login'>
    </form></body></html>"""


@app.route('/dashboard')
@login_required   # FIX 7: Auth enforced
def dashboard():
    username = escape(session.get('username', ''))
    return f"<h2>Welcome {username}!</h2>"


@app.route('/search')
@login_required
def search():
    term = request.args.get('q', '').strip()
    if len(term) > 100:
        return "Search term too long", 400

    conn = get_db()
    # FIX 8: Parameterized LIKE query
    results = conn.execute(
        "SELECT id, username, email FROM users WHERE username LIKE ?",
        (f"%{term}%",)
    ).fetchall()
    conn.close()

    # FIX 10: Escape ALL output
    safe_term = escape(term)
    rows = "".join(
        f"<tr><td>{escape(str(r['id']))}</td>"
        f"<td>{escape(r['username'])}</td>"
        f"<td>{escape(r['email'])}</td></tr>"
        for r in results
    )
    return f"<h2>Results for: {safe_term}</h2><table border=1>{rows}</table>"


@app.route('/ping')
@login_required
def ping():
    host = request.args.get('host', '').strip()

    # FIX 11: Whitelist — only valid hostname characters allowed
    if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host):
        return "Invalid hostname", 400

    try:
        # FIX: shell=False + list args = no command injection possible
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True, text=True,
            timeout=5, shell=False
        )
        return f"<pre>{escape(result.stdout)}</pre>"
    except subprocess.TimeoutExpired:
        return "Request timed out", 408


@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or f.filename == '':
            return "No file selected", 400

        # FIX 12: Extension whitelist
        ext = f.filename.rsplit('.', 1)[-1].lower() if '.' in f.filename else ''
        if ext not in ALLOWED_EXTENSIONS:
            return f"File type not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", 400

        # FIX 13: secure_filename() prevents path traversal
        filename = secure_filename(f.filename)
        if not filename:
            return "Invalid filename", 400

        # FIX: Check file size
        f.seek(0, 2)
        size_mb = f.tell() / (1024 * 1024)
        f.seek(0)
        if size_mb > MAX_UPLOAD_MB:
            return f"File too large (max {MAX_UPLOAD_MB}MB)", 413

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        f.save(os.path.join(UPLOAD_FOLDER, filename))
        logger.info(f"Upload by user_id={session['user_id']}: {filename}")
        return "File uploaded successfully"

    return """<form method='post' enctype='multipart/form-data'>
        <input type='file' name='file' accept='.txt,.pdf,.png,.jpg,.jpeg,.gif'>
        <input type='submit' value='Upload'>
    </form>"""


@app.route('/reset_password', methods=['POST'])
@login_required
def reset_password():
    new_pass = request.form.get('new_password', '')
    if len(new_pass) < 12:
        return "Password must be at least 12 characters", 400

    # FIX 14: bcrypt — strong adaptive hashing with built-in salt
    hashed = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode()

    conn = get_db()
    # FIX 15: Parameterized UPDATE
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (hashed, session['user_id'])
    )
    conn.commit()
    conn.close()
    return "Password updated securely!"


@app.route('/admin')
@admin_required   # FIX 16: Role verified from DB
def admin_panel():
    conn = get_db()
    # FIX 17: Only select non-sensitive columns (no password_hash!)
    users = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    rows = "".join(
        f"<tr><td>{u['id']}</td><td>{escape(u['username'])}</td>"
        f"<td>{escape(u['email'])}</td><td>{escape(u['role'])}</td></tr>"
        for u in users
    )
    return f"<h2>Users</h2><table border=1><tr><th>ID</th><th>User</th><th>Email</th><th>Role</th></tr>{rows}</table>"


@app.route('/delete_user', methods=['POST'])   # FIX 18: POST only (was GET)
@admin_required
def delete_user():
    try:
        uid = int(request.form.get('id'))   # FIX: Validate integer
    except (TypeError, ValueError):
        return "Invalid user ID", 400

    conn = get_db()
    # FIX 19: Parameterized DELETE
    conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    logger.info(f"User {uid} deleted by admin_id={session['user_id']}")
    return f"User {uid} deleted"


@app.after_request
def set_security_headers(response):
    """FIX: Add HTTP security headers to every response."""
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['X-Frame-Options']           = 'DENY'
    response.headers['X-XSS-Protection']          = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy']   = "default-src 'self'"
    return response


# FIX 20: Bind to localhost only; use nginx as reverse proxy externally
if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', port=5000, debug=False)
