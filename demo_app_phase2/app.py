import hashlib
import os
import random
import secrets
import tarfile
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, make_response
from flask_cors import CORS
import jwt
import requests
import jinja2
from Crypto.Cipher import ARC4, AES

app = Flask(__name__)

# 1. CORS-001 (Line 16)
CORS(app, supports_credentials=True, origins="*")
# SAFE: CORS(app, supports_credentials=True, origins=["https://app.example.com"])

ALLOWED_DOMAINS = ["https://trusted.com", "https://example.com"]

@app.route("/redirect")
def open_redirect():
    target = request.args.get("url", "/")
    # 2. REDIR-001 (Line 24)
    return redirect(target)

@app.route("/redirect_safe")
def safe_redirect():
    target = request.args.get("url", "/")
    if target in ALLOWED_DOMAINS or target.startswith("/"):
        return redirect(target)  # SAFE: allowlist check
    return redirect("/dashboard")  # SAFE: constant target

@app.route("/hash_token")
def weak_crypto_hash():
    token = request.args.get("token", "")
    # 3. CRYPTO-001 (Line 36)
    auth_token = hashlib.md5(token.encode()).hexdigest()
    # SAFE tricky negative: non-security cache key
    cache_key = hashlib.md5(b"cache_response_page_1").hexdigest()
    return f"{auth_token}:{cache_key}"

@app.route("/encrypt")
def weak_cipher():
    key = b"12345678"
    # 4. CRYPTO-002 (Line 45)
    cipher = ARC4.new(key)
    # SAFE: AES-GCM mode
    safe_cipher = AES.new(b"1234567812345678", AES.MODE_GCM, nonce=b"123456781234")
    return "encrypted"

@app.route("/random_token")
def insecure_random():
    # 5. CRYPTO-003 (Line 53)
    reset_token = "".join(random.choice("0123456789") for _ in range(6))
    # SAFE tricky negative: game dice roll
    dice_roll = random.randint(1, 6)
    # SAFE crypto secret:
    secure_token = secrets.token_hex(16)
    return f"{reset_token}:{dice_roll}:{secure_token}"

@app.route("/fetch_data")
def insecure_tls():
    # 6. TLS-001 (Line 63)
    resp = requests.get("https://internal.service/api", verify=False)
    # SAFE: verify enabled
    safe_resp = requests.get("https://api.github.com/status", verify=True)
    return "ok"

@app.route("/set_pref")
def insecure_cookie():
    resp = make_response("pref saved")
    # 7. CONFIG-002 (Line 72)
    resp.set_cookie("user_pref", "dark_mode", httponly=False)
    # SAFE: hardened cookie
    resp.set_cookie("auth_session", "xyz", httponly=True, secure=True, samesite="Lax")
    return resp

@app.route("/verify_jwt")
def insecure_jwt():
    token = request.args.get("token", "")
    # 8. JWT-001 (Line 81)
    payload = jwt.decode(token, verify=False)
    # SAFE: verified with algorithm
    safe_payload = jwt.decode(token, "secret_key", algorithms=["HS256"])
    return "verified"

@app.route("/parse_xml")
def unsafe_xml():
    xml_path = "data.xml"
    # 9. XXE-001 (Line 89)
    tree = ET.parse(xml_path)
    return "parsed"

@app.route("/render_template")
def ssti_render():
    user_tpl = request.args.get("template", "Hello")
    # 10. SSTI-001 (Line 96)
    tpl = jinja2.Template(user_tpl)
    # SAFE: constant template with kwargs
    safe_tpl = jinja2.Template("<h1>Hello {{ name }}</h1>").render(name=user_tpl)
    return tpl.render()

def extract_archive(tar_path, extract_dir):
    with tarfile.open(tar_path) as tar:
        # 11. ZIPSLIP-001 (Line 105)
        tar.extractall(extract_dir)

def safe_extract_archive(tar_path, extract_dir):
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            target_path = os.path.join(extract_dir, member.name)
            if os.path.commonpath([extract_dir, target_path]) == extract_dir:
                tar.extract(member, extract_dir)  # SAFE: commonpath validation

# 12. CONFIG-001 (Line 118)
DEBUG = True
# SAFE: DEBUG = os.getenv("DEBUG", "False").lower() == "true"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
