import os
import requests
from flask import Flask, request, make_response, render_template_string
from werkzeug.security import check_password_hash

app = Flask(__name__)

ALLOWED_DOMAINS = ["https://api.internal.service", "https://trusted.partner.com"]

# SEEDED BUG 1: Hardcoded JWT Secret Literal (SECRET-004)
HARDCODED_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# SAFE: JWT loaded from environment variable
SAFE_JWT = os.environ.get("SERVICE_JWT_TOKEN", "")

# SAFE: Placeholder/test token format (must NOT fire)
TEST_JWT_PLACEHOLDER = "eyJhbGciOi_example_placeholder_test_token_xxxx.dummy.sample"

# SEEDED BUG 2: Server-Side Template Injection via render_template_string (XSS-004)
@app.route("/render")
def render_custom():
    user_name = request.args.get("name", "Guest")
    return render_template_string(f"<h1>Hello, {user_name}!</h1>")

# SAFE: Parameterized template rendering (must NOT fire)
@app.route("/render_safe")
def render_safe():
    user_name = request.args.get("name", "Guest")
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=user_name)

# SEEDED BUG 3: Unprotected Authentication Route with No Rate Limiter (AUTH-003)
@app.route("/auth/login", methods=["POST"])
def auth_login():
    password = request.form.get("password", "")
    stored_hash = "$2b$12$e80yVbF..."
    if check_password_hash(stored_hash, password):
        resp = make_response({"status": "authenticated"})
        # SEEDED BUG 4: Insecure Session Cookie lacking HttpOnly & Secure flags (AUTH-004)
        resp.set_cookie("session", "user_session_token_xyz")
        return resp
    return {"status": "unauthorized"}, 401

# SAFE: Rate-limited authentication route (must NOT fire AUTH-003)
class FakeLimiter:
    @staticmethod
    def limit(rate):
        def decorator(f):
            return f
        return decorator

limiter = FakeLimiter()

@app.route("/auth/login_safe", methods=["POST"])
@limiter.limit("5/minute")
def auth_login_safe():
    password = request.form.get("password", "")
    stored_hash = "$2b$12$e80yVbF..."
    if check_password_hash(stored_hash, password):
        resp = make_response({"status": "authenticated"})
        # SAFE: Session cookie with HttpOnly and Secure flags (must NOT fire AUTH-004)
        resp.set_cookie("session", "secure_session_token", httponly=True, secure=True, samesite="Lax")
        return resp
    return {"status": "unauthorized"}, 401

# SAFE: Non-auth route without rate limiting (must NOT fire AUTH-003)
@app.route("/dashboard")
def dashboard():
    return {"dashboard": "metrics"}

# SEEDED BUG 5: SSRF via user-controlled URL reaching requests.get (SSRF-001)
@app.route("/fetch_url")
def fetch_user_url():
    target = request.args.get("url", "")
    response = requests.get(target)
    return {"status": response.status_code, "data": response.text[:100]}

# SAFE: SSRF allowlist validation preceding requests.get (must NOT fire SSRF-001)
@app.route("/fetch_url_safe")
def fetch_user_url_safe():
    target = request.args.get("url", "")
    if target in ALLOWED_DOMAINS:
        response = requests.get(target)
        return {"status": response.status_code}
    return {"error": "disallowed target"}, 400

# SAFE: Constant URL passed to requests.get (must NOT fire SSRF-001)
@app.route("/health_check")
def health_check():
    response = requests.get("https://api.internal.service/health")
    return {"health": response.status_code}
