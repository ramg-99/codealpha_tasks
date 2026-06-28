"""
VULNERABLE FLASK APPLICATION - FOR SECURITY AUDIT PURPOSES ONLY
This file intentionally contains multiple security vulnerabilities
to demonstrate common coding mistakes.
"""

import os
import sqlite3
import subprocess
import hashlib
from flask import Flask, request, render_template_string, redirect, session

app = Flask(__name__)

# ❌ VULNERABILITY 1: Hardcoded secret key (predictable/weak)
app.secret_key = "mysecretkey123"

# ❌ VULNERABILITY 2: Hardcoded database credentials
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "admin123"
DB_NAME = "users_db"

# ❌ VULNERABILITY 3: Debug mode ON in production
app.config['DEBUG'] = True

# ─── Database Setup ────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect("users.db")
    return conn

def init_db():
    conn = get_db()
    # Create users table with plain-text passwords
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    # ❌ VULNERABILITY 4: Storing plain-text passwords
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin@site.com','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','password','alice@site.com','user')")
    conn.commit()
    conn.close()


# ─── Routes ────────────────────────────────────────────────────────

@app.route('/')
def home():
    return "<h1>Welcome to the Vulnerable App</h1><a href='/login'>Login</a>"


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        # ❌ VULNERABILITY 5: SQL Injection - user input directly in query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor = conn.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user'] = username
            session['role'] = user[4]
            return redirect('/dashboard')
        else:
            error = "Invalid credentials"

    # ❌ VULNERABILITY 6: XSS - user input reflected without sanitization
    html = f"""
    <html><body>
    <h2>Login</h2>
    <p style='color:red'>{error}</p>
    <form method='post'>
        Username: <input name='username'><br>
        Password: <input type='password' name='password'><br>
        <input type='submit' value='Login'>
    </form>
    </body></html>
    """
    return render_template_string(html)


@app.route('/dashboard')
def dashboard():
    # ❌ VULNERABILITY 7: No authentication check — anyone can access
    username = session.get('user', 'Guest')
    return f"<h2>Welcome {username}!</h2><a href='/search'>Search Users</a> | <a href='/ping'>Ping Tool</a> | <a href='/upload'>Upload File</a>"


@app.route('/search')
def search():
    term = request.args.get('q', '')
    conn = get_db()
    # ❌ VULNERABILITY 8: Another SQL Injection via GET parameter
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{term}%'"
    try:
        cursor = conn.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        # ❌ VULNERABILITY 9: Exposing internal error to user
        return f"Database error: {str(e)}", 500
    finally:
        conn.close()

    rows = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td></tr>" for r in results)
    # ❌ VULNERABILITY 10: XSS - search term reflected in page
    return f"<h2>Results for: {term}</h2><table border=1>{rows}</table>"


@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # ❌ VULNERABILITY 11: OS Command Injection
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{result}</pre>"


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        f = request.files.get('file')
        if f:
            # ❌ VULNERABILITY 12: Unrestricted file upload (no type/size validation)
            # ❌ VULNERABILITY 13: Path traversal — user controls the filename
            filename = f.filename
            save_path = os.path.join("/tmp/uploads", filename)
            f.save(save_path)
            return f"Uploaded to: {save_path}"
    return """<form method='post' enctype='multipart/form-data'>
        <input type='file' name='file'><input type='submit' value='Upload'>
    </form>"""


@app.route('/reset_password', methods=['POST'])
def reset_password():
    username = request.form['username']
    new_pass = request.form['new_password']

    # ❌ VULNERABILITY 14: Using MD5 for hashing (broken/weak algorithm)
    hashed = hashlib.md5(new_pass.encode()).hexdigest()

    conn = get_db()
    # ❌ VULNERABILITY 15: SQL Injection in UPDATE statement
    conn.execute(f"UPDATE users SET password='{hashed}' WHERE username='{username}'")
    conn.commit()
    conn.close()
    return "Password updated!"


@app.route('/admin')
def admin_panel():
    # ❌ VULNERABILITY 16: Broken access control — checks role from session only (easily manipulated)
    role = session.get('role', 'user')
    if role == 'admin':
        conn = get_db()
        # ❌ VULNERABILITY 17: Dumps entire users table to browser (sensitive data exposure)
        users = conn.execute("SELECT * FROM users").fetchall()
        conn.close()
        return f"<h2>All Users</h2><pre>{users}</pre>"
    return "Access denied", 403


@app.route('/delete_user')
def delete_user():
    uid = request.args.get('id')
    conn = get_db()
    # ❌ VULNERABILITY 18: No CSRF protection on destructive action
    # ❌ VULNERABILITY 19: SQL Injection in DELETE
    conn.execute(f"DELETE FROM users WHERE id={uid}")
    conn.commit()
    conn.close()
    return f"User {uid} deleted"


# ❌ VULNERABILITY 20: Running with host='0.0.0.0' exposes to all interfaces
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
