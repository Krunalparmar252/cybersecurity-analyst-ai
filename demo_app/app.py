import sqlite3
from flask import Flask, request

app = Flask(__name__)

# SEEDED BUG 1: Hardcoded Secret
AWS_SECRET_KEY = "AKIA1234567890EXAMPLE_SECRET_KEY_EXPOSED"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    # SEEDED BUG 2: SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    
    return {"status": "success" if user else "failed"}

@app.route("/profile")
def profile():
    bio = request.args.get("bio", "")
    # SEEDED BUG 3: Reflected XSS
    return f"<h1>User Profile</h1><div>{bio}</div>"

# SEEDED BUG 4: SQL Injection via %-formatting (SQLI-002)
@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = '%s'" % term)  # GT:SQLI-002-pct
    return {"results": cursor.fetchall()}

# SEEDED BUG 5: SQL Injection via str.format() (SQLI-002)
@app.route("/lookup")
def lookup():
    sku = request.args.get("sku", "")
    cursor = sqlite3.connect("database.db").cursor()
    cursor.execute("SELECT * FROM items WHERE sku = '{}'".format(sku))  # GT:SQLI-002-fmt
    return {"results": cursor.fetchall()}

# SAFE: parameterised query, must NOT fire
@app.route("/search_safe")
def search_safe():
    term = request.args.get("q", "")
    cursor = sqlite3.connect("database.db").cursor()
    cursor.execute("SELECT * FROM items WHERE name = ?", (term,))  # SAFE
    return {"results": cursor.fetchall()}

# SEEDED BUG 6: plaintext password comparison (AUTH-001)
@app.route("/admin", methods=["POST"])
def admin():
    password = request.form.get("password", "")
    stored_password = app.config.get("ADMIN_PASSWORD")
    if password == stored_password:  # GT:AUTH-001
        return {"status": "admin"}
    return {"status": "denied"}

# SAFE: hash verification, must NOT fire
def admin_safe(password, stored_hash):
    from werkzeug.security import check_password_hash
    return check_password_hash(stored_hash, password)  # SAFE

# SEEDED BUG 7: weak password hash (AUTH-002)
def hash_password(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()  # GT:AUTH-002

# SEEDED BUG 8: Jinja2 autoescape disabled (XSS-003)
COMMENT_TEMPLATE = "<p>{{ comment|safe }}</p>"  # GT:XSS-003

# SEEDED BUG 9: Command Injection (CMDINJ-001)
@app.route("/ping")
def ping():
    import os
    host = request.args.get("host", "")
    os.system(f"ping -c 1 {host}")  # GT:CMDINJ-001
    return {"status": "sent"}

# SEEDED BUGS 10-14: more hardcoded secrets (values are public doc examples / random fakes)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # GT:SECRET-001
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # GT:SECRET-002
GITHUB_TOKEN = "ghp_u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8d"  # GT:SECRET-003
build_blob = "YgCfrL1spNxnyVmihA/2O76UMFxFkM/R"  # GT:SECRET-006
DEPLOY_KEY = "-----BEGIN RSA PRIVATE KEY-----\n(demo fixture: no real key material)"  # GT:SECRET-007

if __name__ == "__main__":
    app.run(debug=True)