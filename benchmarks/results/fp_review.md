# Unlabeled Findings Manual Review Queue
Findings in benchmark repositories located on lines or files without ground-truth labels.
These are NOT counted as false positives in the primary metric, but are sampled here
so the team can inspect them and classify them as True Positive (TP), False Positive (FP), or Unsure.

Instructions: Fill in `verdict: TP`, `verdict: FP`, or `verdict: unsure`, then run `recompute_with_reviews.py`.

---

## PYGOAT — Config: `native-only` (Sampled 30 of 82 unlabeled findings)

### Entry 01: `SECRET-006` (Hardcoded Secrets) at `setup.py:20`
- **File:** `setup.py` (Line 20)
- **Snippet:**
```text
url="ht*************************************at<len=41>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `REDIR-001` (Open Redirect) at `challenge/labs/security_headers_lab/app.py:99`
- **File:** `challenge/labs/security_headers_lab/app.py` (Line 99)
- **Snippet:**
```text
redirect(url_for("login"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `REDIR-001` (Open Redirect) at `challenge/labs/bopla_lab/app.py:140`
- **File:** `challenge/labs/bopla_lab/app.py` (Line 140)
- **Snippet:**
```text
redirect(url_for("index"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `AUTH-003` (Broken Authentication) at `dockerized_labs/broken_auth_lab/app.py:47`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 47)
- **Snippet:**
```text
@app.route("/login", methods=["POST"])
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `AUTH-003` (Broken Authentication) at `dockerized_labs/broken_access_lab/main.py:34`
- **File:** `dockerized_labs/broken_access_lab/main.py` (Line 34)
- **Snippet:**
```text
@app.route("/lab/login", methods=["GET", "POST"])
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:208`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 208)
- **Snippet:**
```text
response.set_cookie("session_id", "", expires=0)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `REDIR-001` (Open Redirect) at `dockerized_labs/a9_uckv_lab/app.py:52`
- **File:** `dockerized_labs/a9_uckv_lab/app.py` (Line 52)
- **Snippet:**
```text
redirect(url_for("lab1"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `REDIR-001` (Open Redirect) at `challenge/labs/security_headers_lab/app.py:91`
- **File:** `challenge/labs/security_headers_lab/app.py` (Line 91)
- **Snippet:**
```text
redirect(url_for("index"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 09: `SECRET-005` (Hardcoded Secrets) at `dockerized_labs/ssrf_lab/app.py:6`
- **File:** `dockerized_labs/ssrf_lab/app.py` (Line 6)
- **Snippet:**
```text
app.secret_key = "yo****************re<len=20>"  # Required for flash messages
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 10: `AUTH-003` (Broken Authentication) at `challenge/labs/security_headers_lab/app.py:71`
- **File:** `challenge/labs/security_headers_lab/app.py` (Line 71)
- **Snippet:**
```text
@app.route("/login", methods=["GET", "POST"])
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 11: `REDIR-001` (Open Redirect) at `dockerized_labs/insecure_design_lab/app.py:74`
- **File:** `dockerized_labs/insecure_design_lab/app.py` (Line 74)
- **Snippet:**
```text
redirect(url_for("register"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 12: `SECRET-005` (Hardcoded Secrets) at `challenge/labs/business_logic_lab/app.py:5`
- **File:** `challenge/labs/business_logic_lab/app.py` (Line 5)
- **Snippet:**
```text
app.secret_key = "bu**************************24<len=30>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 13: `SECRET-006` (Hardcoded Secrets) at `scoring/migrations/0001_initial.py:277`
- **File:** `scoring/migrations/0001_initial.py` (Line 277)
- **Snippet:**
```text
fields=["user", "content_type"], name="sc**************************dx<len=30>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 14: `SSRF-001` (Server-Side Request Forgery) at `introduction/static/js/lab_manager.js:129`
- **File:** `introduction/static/js/lab_manager.js` (Line 129)
- **Snippet:**
```text
fetch(`/challenge/start-lab/${imageName}/`)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 15: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:112`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 112)
- **Snippet:**
```text
response.set_cookie("email", email)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 16: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:227`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 227)
- **Snippet:**
```text
response.set_cookie("session_id", session_id)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 17: `SECRET-005` (Hardcoded Secrets) at `dockerized_labs/sec_misconfig/app.py:115`
- **File:** `dockerized_labs/sec_misconfig/app.py` (Line 115)
- **Snippet:**
```text
secret = "se*****23<len=9>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 18: `SSRF-001` (Server-Side Request Forgery) at `introduction/static/js/lab_manager.js:336`
- **File:** `introduction/static/js/lab_manager.js` (Line 336)
- **Snippet:**
```text
fetch(`/challenge/stop-lab/${labName}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken
      }
    })
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 19: `AUTH-001` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:215`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 215)
- **Snippet:**
```text
USERS[username]["password"] == password_hash
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 20: `REDIR-001` (Open Redirect) at `dockerized_labs/broken_auth_lab/app.py:140`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 140)
- **Snippet:**
```text
redirect(url_for("lab"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 21: `REDIR-001` (Open Redirect) at `dockerized_labs/broken_auth_lab/app.py:92`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 92)
- **Snippet:**
```text
redirect(url_for("lab"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 22: `REDIR-001` (Open Redirect) at `dockerized_labs/broken_auth_lab/app.py:126`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 126)
- **Snippet:**
```text
redirect(url_for("lab"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 23: `AUTH-001` (Broken Authentication) at `dockerized_labs/broken_auth_lab/app.py:53`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 53)
- **Snippet:**
```text
users[username]["password"] == password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 24: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:105`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 105)
- **Snippet:**
```text
response.set_cookie("email", email)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 25: `SECRET-006` (Hardcoded Secrets) at `scoring/migrations/0001_initial.py:283`
- **File:** `scoring/migrations/0001_initial.py` (Line 283)
- **Snippet:**
```text
fields=["completed_at"], name="sc**************************dx<len=30>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 26: `SECRET-006` (Hardcoded Secrets) at `pygoat/settings.py:23`
- **File:** `pygoat/settings.py` (Line 23)
- **Snippet:**
```text
SECRET_KEY = "lr**********************************************ml<len=50>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 27: `AUTH-004` (Broken Authentication) at `dockerized_labs/broken_auth_lab/app.py:66`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 66)
- **Snippet:**
```text
response.set_cookie("session", session_token)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 28: `SECRET-006` (Hardcoded Secrets) at `introduction/views.py:27`
- **File:** `introduction/views.py` (Line 27)
- **Snippet:**
```text
login(request, user, backend="dj*************************************nd<len=41>")
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 29: `AUTH-001` (Broken Authentication) at `dockerized_labs/insecure_design_lab/app.py:56`
- **File:** `dockerized_labs/insecure_design_lab/app.py` (Line 56)
- **Snippet:**
```text
user.password == password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 30: `AUTH-001` (Broken Authentication) at `challenge/labs/bopla_lab/app.py:73`
- **File:** `challenge/labs/bopla_lab/app.py` (Line 73)
- **Snippet:**
```text
users[username]["password"] == password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## PYGOAT — Config: `merged` (Sampled 30 of 82 unlabeled findings)

### Entry 01: `SECRET-006` (Hardcoded Secrets) at `setup.py:20`
- **File:** `setup.py` (Line 20)
- **Snippet:**
```text
url="ht*************************************at<len=41>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `REDIR-001` (Open Redirect) at `challenge/labs/security_headers_lab/app.py:99`
- **File:** `challenge/labs/security_headers_lab/app.py` (Line 99)
- **Snippet:**
```text
redirect(url_for("login"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `REDIR-001` (Open Redirect) at `challenge/labs/bopla_lab/app.py:140`
- **File:** `challenge/labs/bopla_lab/app.py` (Line 140)
- **Snippet:**
```text
redirect(url_for("index"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `AUTH-003` (Broken Authentication) at `dockerized_labs/broken_auth_lab/app.py:47`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 47)
- **Snippet:**
```text
@app.route("/login", methods=["POST"])
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `AUTH-003` (Broken Authentication) at `dockerized_labs/broken_access_lab/main.py:34`
- **File:** `dockerized_labs/broken_access_lab/main.py` (Line 34)
- **Snippet:**
```text
@app.route("/lab/login", methods=["GET", "POST"])
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:208`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 208)
- **Snippet:**
```text
response.set_cookie("session_id", "", expires=0)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `REDIR-001` (Open Redirect) at `dockerized_labs/a9_uckv_lab/app.py:52`
- **File:** `dockerized_labs/a9_uckv_lab/app.py` (Line 52)
- **Snippet:**
```text
redirect(url_for("lab1"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `REDIR-001` (Open Redirect) at `challenge/labs/security_headers_lab/app.py:91`
- **File:** `challenge/labs/security_headers_lab/app.py` (Line 91)
- **Snippet:**
```text
redirect(url_for("index"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 09: `SECRET-005` (Hardcoded Secrets) at `dockerized_labs/ssrf_lab/app.py:6`
- **File:** `dockerized_labs/ssrf_lab/app.py` (Line 6)
- **Snippet:**
```text
app.secret_key = "yo****************re<len=20>"  # Required for flash messages
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 10: `AUTH-003` (Broken Authentication) at `challenge/labs/security_headers_lab/app.py:71`
- **File:** `challenge/labs/security_headers_lab/app.py` (Line 71)
- **Snippet:**
```text
@app.route("/login", methods=["GET", "POST"])
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 11: `REDIR-001` (Open Redirect) at `dockerized_labs/insecure_design_lab/app.py:74`
- **File:** `dockerized_labs/insecure_design_lab/app.py` (Line 74)
- **Snippet:**
```text
redirect(url_for("register"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 12: `SECRET-005` (Hardcoded Secrets) at `challenge/labs/business_logic_lab/app.py:5`
- **File:** `challenge/labs/business_logic_lab/app.py` (Line 5)
- **Snippet:**
```text
app.secret_key = "bu**************************24<len=30>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 13: `SECRET-006` (Hardcoded Secrets) at `scoring/migrations/0001_initial.py:277`
- **File:** `scoring/migrations/0001_initial.py` (Line 277)
- **Snippet:**
```text
fields=["user", "content_type"], name="sc**************************dx<len=30>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 14: `SSRF-001` (Server-Side Request Forgery) at `introduction/static/js/lab_manager.js:129`
- **File:** `introduction/static/js/lab_manager.js` (Line 129)
- **Snippet:**
```text
fetch(`/challenge/start-lab/${imageName}/`)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 15: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:112`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 112)
- **Snippet:**
```text
response.set_cookie("email", email)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 16: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:227`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 227)
- **Snippet:**
```text
response.set_cookie("session_id", session_id)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 17: `SECRET-005` (Hardcoded Secrets) at `dockerized_labs/sec_misconfig/app.py:115`
- **File:** `dockerized_labs/sec_misconfig/app.py` (Line 115)
- **Snippet:**
```text
secret = "se*****23<len=9>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 18: `SSRF-001` (Server-Side Request Forgery) at `introduction/static/js/lab_manager.js:336`
- **File:** `introduction/static/js/lab_manager.js` (Line 336)
- **Snippet:**
```text
fetch(`/challenge/stop-lab/${labName}/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken
      }
    })
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 19: `AUTH-001` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:215`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 215)
- **Snippet:**
```text
USERS[username]["password"] == password_hash
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 20: `REDIR-001` (Open Redirect) at `dockerized_labs/broken_auth_lab/app.py:140`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 140)
- **Snippet:**
```text
redirect(url_for("lab"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 21: `REDIR-001` (Open Redirect) at `dockerized_labs/broken_auth_lab/app.py:92`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 92)
- **Snippet:**
```text
redirect(url_for("lab"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 22: `REDIR-001` (Open Redirect) at `dockerized_labs/broken_auth_lab/app.py:126`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 126)
- **Snippet:**
```text
redirect(url_for("lab"))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 23: `AUTH-001` (Broken Authentication) at `dockerized_labs/broken_auth_lab/app.py:53`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 53)
- **Snippet:**
```text
users[username]["password"] == password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 24: `CONFIG-002` (Broken Authentication) at `dockerized_labs/auth_failure_lab/app.py:105`
- **File:** `dockerized_labs/auth_failure_lab/app.py` (Line 105)
- **Snippet:**
```text
response.set_cookie("email", email)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 25: `SECRET-006` (Hardcoded Secrets) at `scoring/migrations/0001_initial.py:283`
- **File:** `scoring/migrations/0001_initial.py` (Line 283)
- **Snippet:**
```text
fields=["completed_at"], name="sc**************************dx<len=30>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 26: `SECRET-006` (Hardcoded Secrets) at `pygoat/settings.py:23`
- **File:** `pygoat/settings.py` (Line 23)
- **Snippet:**
```text
SECRET_KEY = "lr**********************************************ml<len=50>"
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 27: `AUTH-004` (Broken Authentication) at `dockerized_labs/broken_auth_lab/app.py:66`
- **File:** `dockerized_labs/broken_auth_lab/app.py` (Line 66)
- **Snippet:**
```text
response.set_cookie("session", session_token)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 28: `SECRET-006` (Hardcoded Secrets) at `introduction/views.py:27`
- **File:** `introduction/views.py` (Line 27)
- **Snippet:**
```text
login(request, user, backend="dj*************************************nd<len=41>")
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 29: `AUTH-001` (Broken Authentication) at `dockerized_labs/insecure_design_lab/app.py:56`
- **File:** `dockerized_labs/insecure_design_lab/app.py` (Line 56)
- **Snippet:**
```text
user.password == password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 30: `AUTH-001` (Broken Authentication) at `challenge/labs/bopla_lab/app.py:73`
- **File:** `challenge/labs/bopla_lab/app.py` (Line 73)
- **Snippet:**
```text
users[username]["password"] == password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## NODEGOAT — Config: `native-only` (Sampled 8 of 8 unlabeled findings)

### Entry 01: `SECRET-005` (Hardcoded Secrets) at `app/routes/session.js:172`
- **File:** `app/routes/session.js` (Line 172)
- **Snippet:**
```text
errors.passwordError = "Pa*******************************rs<len=35>" +
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SECRET-005` (Hardcoded Secrets) at `app/routes/session.js:61`
- **File:** `app/routes/session.js` (Line 61)
- **Snippet:**
```text
const invalidPasswordErrorMessage = "In************rd<len=16>";
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `SECRET-006` (Hardcoded Secrets) at `Gruntfile.js:136`
- **File:** `Gruntfile.js` (Line 136)
- **Snippet:**
```text
jsRepository: "ht*********************************************************************on<len=73>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `REDIR-001` (Open Redirect) at `app/routes/session.js:117`
- **File:** `app/routes/session.js` (Line 117)
- **Snippet:**
```text
res.redirect(user.isAdmin ? "/benefits" : "/dashboard")
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `CMDINJ-002` (Command Injection) at `Gruntfile.js:165`
- **File:** `Gruntfile.js` (Line 165)
- **Snippet:**
```text
exec(
            cmd + "node artifacts/db-reset.js",
            function(err, stdout, stderr) {
                if (err) {
                    grunt.log.error("db-reset:");
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `SECRET-006` (Hardcoded Secrets) at `Gruntfile.js:137`
- **File:** `Gruntfile.js` (Line 137)
- **Snippet:**
```text
nodeRepository: "ht**********************************************************************on<len=74>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `SECRET-006` (Hardcoded Secrets) at `config/env/test.js:6`
- **File:** `config/env/test.js` (Line 6)
- **Snippet:**
```text
zapApiKey: "v9**********************d1<len=26>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `SECRET-006` (Hardcoded Secrets) at `config/env/development.js:6`
- **File:** `config/env/development.js` (Line 6)
- **Snippet:**
```text
zapApiKey: "v9**********************d1<len=26>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## NODEGOAT — Config: `merged` (Sampled 8 of 8 unlabeled findings)

### Entry 01: `SECRET-005` (Hardcoded Secrets) at `app/routes/session.js:172`
- **File:** `app/routes/session.js` (Line 172)
- **Snippet:**
```text
errors.passwordError = "Pa*******************************rs<len=35>" +
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SECRET-005` (Hardcoded Secrets) at `app/routes/session.js:61`
- **File:** `app/routes/session.js` (Line 61)
- **Snippet:**
```text
const invalidPasswordErrorMessage = "In************rd<len=16>";
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `SECRET-006` (Hardcoded Secrets) at `Gruntfile.js:136`
- **File:** `Gruntfile.js` (Line 136)
- **Snippet:**
```text
jsRepository: "ht*********************************************************************on<len=73>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `REDIR-001` (Open Redirect) at `app/routes/session.js:117`
- **File:** `app/routes/session.js` (Line 117)
- **Snippet:**
```text
res.redirect(user.isAdmin ? "/benefits" : "/dashboard")
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `CMDINJ-002` (Command Injection) at `Gruntfile.js:165`
- **File:** `Gruntfile.js` (Line 165)
- **Snippet:**
```text
exec(
            cmd + "node artifacts/db-reset.js",
            function(err, stdout, stderr) {
                if (err) {
                    grunt.log.error("db-reset:");
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `SECRET-006` (Hardcoded Secrets) at `Gruntfile.js:137`
- **File:** `Gruntfile.js` (Line 137)
- **Snippet:**
```text
nodeRepository: "ht**********************************************************************on<len=74>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `SECRET-006` (Hardcoded Secrets) at `config/env/test.js:6`
- **File:** `config/env/test.js` (Line 6)
- **Snippet:**
```text
zapApiKey: "v9**********************d1<len=26>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `SECRET-006` (Hardcoded Secrets) at `config/env/development.js:6`
- **File:** `config/env/development.js` (Line 6)
- **Snippet:**
```text
zapApiKey: "v9**********************d1<len=26>",
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## VULPY — Config: `native-only` (Sampled 19 of 19 unlabeled findings)

### Entry 01: `AUTH-001` (Broken Authentication) at `bad/mod_user.py:72`
- **File:** `bad/mod_user.py` (Line 72)
- **Snippet:**
```text
password != password_again
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SQLI-002` (SQL Injection) at `bad/db_init.py:20`
- **File:** `bad/db_init.py` (Line 20)
- **Snippet:**
```text
c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(u, p, 0, 0, ''))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `SECRET-006` (Hardcoded Secrets) at `good/libsession.py:9`
- **File:** `good/libsession.py` (Line 9)
- **Snippet:**
```text
key = 'JH****************************************0=<len=44>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `SECRET-005` (Hardcoded Secrets) at `good/libapi.py:10`
- **File:** `good/libapi.py` (Line 10)
- **Snippet:**
```text
secret = 'MY************EY<len=16>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `SSRF-001` (Server-Side Request Forgery) at `utils/httpbrute.py:25`
- **File:** `utils/httpbrute.py` (Line 25)
- **Snippet:**
```text
requests.post(url, data = {'username': username, 'password': password})
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `SQLI-002` (SQL Injection) at `bad/libuser.py:25`
- **File:** `bad/libuser.py` (Line 25)
- **Snippet:**
```text
c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(username, password, 0, 0, ''))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `SQLI-002` (SQL Injection) at `good/libuser.py:61`
- **File:** `good/libuser.py` (Line 61)
- **Snippet:**
```text
c.execute("INSERT INTO users (username, password, salt, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%s', '%d', '%d', '%s')" %(username, '', '', 0, 0, ''))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `CONFIG-002` (Broken Authentication) at `bad/libsession.py:28`
- **File:** `bad/libsession.py` (Line 28)
- **Snippet:**
```text
response.set_cookie('vulpy_session', '', expires=0)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 09: `CONFIG-002` (Broken Authentication) at `good/libsession.py:60`
- **File:** `good/libsession.py` (Line 60)
- **Snippet:**
```text
response.set_cookie('vulpy_session', '', expires=0)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 10: `SECRET-006` (Hardcoded Secrets) at `utils/generate_bad_passwords.py:9`
- **File:** `utils/generate_bad_passwords.py` (Line 9)
- **Snippet:**
```text
URL = 'ht**********************************************************************************************************************************xt<len=134>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 11: `AUTH-001` (Broken Authentication) at `good/libuser.py:131`
- **File:** `good/libuser.py` (Line 131)
- **Snippet:**
```text
password == p
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 12: `SECRET-006` (Hardcoded Secrets) at `good/httpbrute.py:5`
- **File:** `good/httpbrute.py` (Line 5)
- **Snippet:**
```text
URL = 'ht****************************in<len=32>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 13: `SSRF-001` (Server-Side Request Forgery) at `utils/generate_bad_passwords.py:21`
- **File:** `utils/generate_bad_passwords.py` (Line 21)
- **Snippet:**
```text
requests.get(url, stream=True)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 14: `CONFIG-001` (Security Misconfiguration) at `good/vulpy.py:53`
- **File:** `good/vulpy.py` (Line 53)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', port=5001, extra_files='csp.txt')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 15: `CONFIG-001` (Security Misconfiguration) at `bad/vulpy.py:55`
- **File:** `bad/vulpy.py` (Line 55)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', port=5000, extra_files='csp.txt')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 16: `CONFIG-002` (Broken Authentication) at `good/libsession.py:32`
- **File:** `good/libsession.py` (Line 32)
- **Snippet:**
```text
response.set_cookie('vulpy_session', fernet.encrypt(
        (username + '|' + country).encode()
    ))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 17: `CONFIG-001` (Security Misconfiguration) at `bad/vulpy-ssl.py:29`
- **File:** `bad/vulpy-ssl.py` (Line 29)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 18: `AUTH-001` (Broken Authentication) at `good/mod_user.py:77`
- **File:** `good/mod_user.py` (Line 77)
- **Snippet:**
```text
new_password != new_password_again
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 19: `CONFIG-001` (Security Misconfiguration) at `good/vulpy-ssl.py:29`
- **File:** `good/vulpy-ssl.py` (Line 29)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## VULPY — Config: `merged` (Sampled 19 of 19 unlabeled findings)

### Entry 01: `AUTH-001` (Broken Authentication) at `bad/mod_user.py:72`
- **File:** `bad/mod_user.py` (Line 72)
- **Snippet:**
```text
password != password_again
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SQLI-002` (SQL Injection) at `bad/db_init.py:20`
- **File:** `bad/db_init.py` (Line 20)
- **Snippet:**
```text
c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(u, p, 0, 0, ''))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `SECRET-006` (Hardcoded Secrets) at `good/libsession.py:9`
- **File:** `good/libsession.py` (Line 9)
- **Snippet:**
```text
key = 'JH****************************************0=<len=44>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `SECRET-005` (Hardcoded Secrets) at `good/libapi.py:10`
- **File:** `good/libapi.py` (Line 10)
- **Snippet:**
```text
secret = 'MY************EY<len=16>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `SSRF-001` (Server-Side Request Forgery) at `utils/httpbrute.py:25`
- **File:** `utils/httpbrute.py` (Line 25)
- **Snippet:**
```text
requests.post(url, data = {'username': username, 'password': password})
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `SQLI-002` (SQL Injection) at `bad/libuser.py:25`
- **File:** `bad/libuser.py` (Line 25)
- **Snippet:**
```text
c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%d', '%d', '%s')" %(username, password, 0, 0, ''))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `SQLI-002` (SQL Injection) at `good/libuser.py:61`
- **File:** `good/libuser.py` (Line 61)
- **Snippet:**
```text
c.execute("INSERT INTO users (username, password, salt, failures, mfa_enabled, mfa_secret) VALUES ('%s', '%s', '%s', '%d', '%d', '%s')" %(username, '', '', 0, 0, ''))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `CONFIG-002` (Broken Authentication) at `bad/libsession.py:28`
- **File:** `bad/libsession.py` (Line 28)
- **Snippet:**
```text
response.set_cookie('vulpy_session', '', expires=0)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 09: `CONFIG-002` (Broken Authentication) at `good/libsession.py:60`
- **File:** `good/libsession.py` (Line 60)
- **Snippet:**
```text
response.set_cookie('vulpy_session', '', expires=0)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 10: `SECRET-006` (Hardcoded Secrets) at `utils/generate_bad_passwords.py:9`
- **File:** `utils/generate_bad_passwords.py` (Line 9)
- **Snippet:**
```text
URL = 'ht**********************************************************************************************************************************xt<len=134>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 11: `AUTH-001` (Broken Authentication) at `good/libuser.py:131`
- **File:** `good/libuser.py` (Line 131)
- **Snippet:**
```text
password == p
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 12: `SECRET-006` (Hardcoded Secrets) at `good/httpbrute.py:5`
- **File:** `good/httpbrute.py` (Line 5)
- **Snippet:**
```text
URL = 'ht****************************in<len=32>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 13: `SSRF-001` (Server-Side Request Forgery) at `utils/generate_bad_passwords.py:21`
- **File:** `utils/generate_bad_passwords.py` (Line 21)
- **Snippet:**
```text
requests.get(url, stream=True)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 14: `CONFIG-001` (Security Misconfiguration) at `good/vulpy.py:53`
- **File:** `good/vulpy.py` (Line 53)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', port=5001, extra_files='csp.txt')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 15: `CONFIG-001` (Security Misconfiguration) at `bad/vulpy.py:55`
- **File:** `bad/vulpy.py` (Line 55)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', port=5000, extra_files='csp.txt')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 16: `CONFIG-002` (Broken Authentication) at `good/libsession.py:32`
- **File:** `good/libsession.py` (Line 32)
- **Snippet:**
```text
response.set_cookie('vulpy_session', fernet.encrypt(
        (username + '|' + country).encode()
    ))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 17: `CONFIG-001` (Security Misconfiguration) at `bad/vulpy-ssl.py:29`
- **File:** `bad/vulpy-ssl.py` (Line 29)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 18: `AUTH-001` (Broken Authentication) at `good/mod_user.py:77`
- **File:** `good/mod_user.py` (Line 77)
- **Snippet:**
```text
new_password != new_password_again
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 19: `CONFIG-001` (Security Misconfiguration) at `good/vulpy-ssl.py:29`
- **File:** `good/vulpy-ssl.py` (Line 29)
- **Snippet:**
```text
app.run(debug=True, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## DVPWA — Config: `native-only` (Sampled 3 of 3 unlabeled findings)

### Entry 01: `CMDINJ-002` (Command Injection) at `sqli/static/js/materialize.js:553`
- **File:** `sqli/static/js/materialize.js` (Line 553)
- **Snippet:**
```text
a.exec(e)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SECRET-006` (Hardcoded Secrets) at `sqli/static/js/materialize.js:5228`
- **File:** `sqli/static/js/materialize.js` (Line 5228)
- **Snippet:**
```text
var placeholderBase64 = 'da******************************************************************************==<len=82>';
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `DESER-002` (Unsafe Deserialization) at `sqli/static/js/materialize.js:6283`
- **File:** `sqli/static/js/materialize.js` (Line 6283)
- **Snippet:**
```text
new Function(callback)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## DVPWA — Config: `merged` (Sampled 3 of 3 unlabeled findings)

### Entry 01: `CMDINJ-002` (Command Injection) at `sqli/static/js/materialize.js:553`
- **File:** `sqli/static/js/materialize.js` (Line 553)
- **Snippet:**
```text
a.exec(e)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SECRET-006` (Hardcoded Secrets) at `sqli/static/js/materialize.js:5228`
- **File:** `sqli/static/js/materialize.js` (Line 5228)
- **Snippet:**
```text
var placeholderBase64 = 'da******************************************************************************==<len=82>';
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `DESER-002` (Unsafe Deserialization) at `sqli/static/js/materialize.js:6283`
- **File:** `sqli/static/js/materialize.js` (Line 6283)
- **Snippet:**
```text
new Function(callback)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## JUICE-SHOP — Config: `native-only` (Sampled 30 of 194 unlabeled findings)

### Entry 01: `SSRF-001` (Server-Side Request Forgery) at `routes/profileImageUrlUpload.ts:24`
- **File:** `routes/profileImageUrlUpload.ts` (Line 24)
- **Snippet:**
```text
fetch(url)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/faucet/faucet.component.ts:33`
- **File:** `frontend/src/app/faucet/faucet.component.ts` (Line 33)
- **Snippet:**
```text
const nftAddress = '0x**************************************39<len=42>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `SECRET-005` (Hardcoded Secrets) at `data/static/codefixes/loginAdminChallenge_2.ts:15`
- **File:** `data/static/codefixes/loginAdminChallenge_2.ts` (Line 15)
- **Snippet:**
```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${*********************************| <len=37>'')}' AND deletedAt IS NULL`,
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `DESER-003` (Unsafe Deserialization) at `rsn/rsnUtil.ts:135`
- **File:** `rsn/rsnUtil.ts` (Line 135)
- **Snippet:**
```text
yaml.load(content)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/address.service.ts:26`
- **File:** `frontend/src/app/Services/address.service.ts` (Line 26)
- **Snippet:**
```text
this.http.get(`${this.host}/${id}`)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.ts:10`
- **File:** `frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.ts` (Line 10)
- **Snippet:**
```text
templateUrl: './*************************************************ml<len=53>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/product-details/product-details.component.ts:34`
- **File:** `frontend/src/app/product-details/product-details.component.ts` (Line 34)
- **Snippet:**
```text
templateUrl: './****************************ml<len=32>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `SECRET-004` (Hardcoded Secrets) at `frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:78`
- **File:** `frontend/src/app/last-login-ip/last-login-ip.component.spec.ts` (Line 78)
- **Snippet:**
```text
localStorage.setItem('token', 'ey********************************************************************************************Lw<len=96>')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 09: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/coding-challenge-page/components/coding-challenge-fix-it/coding-challenge-fix-it.component.ts:30`
- **File:** `frontend/src/app/coding-challenge-page/components/coding-challenge-fix-it/coding-challenge-fix-it.component.ts` (Line 30)
- **Snippet:**
```text
templateUrl: './************************************ml<len=40>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 10: `AUTH-005` (Broken Authentication) at `routes/verify.ts:25`
- **File:** `routes/verify.ts` (Line 25)
- **Snippet:**
```text
req.body.password === ''
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 11: `SECRET-006` (Hardcoded Secrets) at `lib/startup/validateConfig.ts:18`
- **File:** `lib/startup/validateConfig.ts` (Line 18)
- **Snippet:**
```text
{ name: '"Leaked Unsafe Product" challenge product', key: 'ke********************************ge<len=36>', extra: null }
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 12: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.ts:42`
- **File:** `frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.ts` (Line 42)
- **Snippet:**
```text
templateUrl: './******************************************ml<len=46>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 13: `AUTH-005` (Broken Authentication) at `routes/changePassword.ts:39`
- **File:** `routes/changePassword.ts` (Line 39)
- **Snippet:**
```text
security.hash(currentPassword) !== loggedInUser.data.password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 14: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/user.service.ts:29`
- **File:** `frontend/src/app/Services/user.service.ts` (Line 29)
- **Snippet:**
```text
this.http.get(this.hostServer + '/rest/user/authentication-details/', { params })
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 15: `SECRET-005` (Hardcoded Secrets) at `data/static/codefixes/loginBenderChallenge_1.ts:18`
- **File:** `data/static/codefixes/loginBenderChallenge_1.ts` (Line 18)
- **Snippet:**
```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${*********************************| <len=37>'')}' AND deletedAt IS NULL`, { model: models.User, plain: true })
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 16: `SQLI-001` (SQL Injection) at `data/static/codefixes/loginAdminChallenge_2.ts:15`
- **File:** `data/static/codefixes/loginAdminChallenge_2.ts` (Line 15)
- **Snippet:**
```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
      { bind: [ req.body.email ], model: models.User, p
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 17: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/challenge-status-badge/challenge-status-badge.component.ts:24`
- **File:** `frontend/src/app/challenge-status-badge/challenge-status-badge.component.ts` (Line 24)
- **Snippet:**
```text
templateUrl: './***********************************ml<len=39>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 18: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/photo-wall/photo-wall.component.spec.ts:259`
- **File:** `frontend/src/app/photo-wall/photo-wall.component.spec.ts` (Line 259)
- **Snippet:**
```text
application: { social: { twitterUrl: 'https://twitter.com/juice', blueSkyUrl: 'https://bsky.app/profile/juice', mastodonUrl: 'ht**************************ce<len=30>' } }
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 19: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/purchase-basket/purchase-basket.component.ts:29`
- **File:** `frontend/src/app/purchase-basket/purchase-basket.component.ts` (Line 29)
- **Snippet:**
```text
templateUrl: './****************************ml<len=32>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 20: `SECRET-006` (Hardcoded Secrets) at `frontend/src/hacking-instructor/challenges/reflectedXss.ts:54`
- **File:** `frontend/src/hacking-instructor/challenges/reflectedXss.ts` (Line 54)
- **Snippet:**
```text
'Use: <code>&lt;iframe src="ja***************************;)<len=31>"&gt;</code> as a city name.',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 21: `AUTH-005` (Broken Authentication) at `routes/login.ts:59`
- **File:** `routes/login.ts` (Line 59)
- **Snippet:**
```text
req.body.password === 'admin123'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 22: `AUTH-005` (Broken Authentication) at `server.ts:437`
- **File:** `server.ts` (Line 437)
- **Snippet:**
```text
req.body.password !== undefined
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 23: `SSRF-001` (Server-Side Request Forgery) at `lib/webhook.ts:18`
- **File:** `lib/webhook.ts` (Line 18)
- **Snippet:**
```text
fetch(webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      solution: {
        challenge: challenge.key,
        hintsAvailable,
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 24: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/payment/payment.component.ts:270`
- **File:** `frontend/src/app/payment/payment.component.ts` (Line 270)
- **Snippet:**
```text
data: 'da***********************************kW<len=39>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 25: `AUTH-005` (Broken Authentication) at `routes/resetPassword.ts:30`
- **File:** `routes/resetPassword.ts` (Line 30)
- **Snippet:**
```text
newPassword !== repeatPassword
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 26: `SECRET-006` (Hardcoded Secrets) at `routes/web3Wallet.ts:9`
- **File:** `routes/web3Wallet.ts` (Line 9)
- **Snippet:**
```text
const web3WalletAddress = '0x**************************************b0<len=42>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 27: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/two-factor-auth-service.ts:44`
- **File:** `frontend/src/app/Services/two-factor-auth-service.ts` (Line 44)
- **Snippet:**
```text
this.http.get<TwoFactorAuthStatusPayload>(`${environment.hostServer}/rest/2fa/status`)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 28: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/privacy-security/privacy-security.component.ts:12`
- **File:** `frontend/src/app/privacy-security/privacy-security.component.ts` (Line 12)
- **Snippet:**
```text
templateUrl: './*****************************ml<len=33>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 29: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/user.service.ts:76`
- **File:** `frontend/src/app/Services/user.service.ts` (Line 76)
- **Snippet:**
```text
this.http.get(this.hostServer + '/rest/deluxe-membership')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 30: `AUTH-005` (Broken Authentication) at `routes/changePassword.ts:28`
- **File:** `routes/changePassword.ts` (Line 28)
- **Snippet:**
```text
token === null
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## JUICE-SHOP — Config: `merged` (Sampled 30 of 194 unlabeled findings)

### Entry 01: `SSRF-001` (Server-Side Request Forgery) at `routes/profileImageUrlUpload.ts:24`
- **File:** `routes/profileImageUrlUpload.ts` (Line 24)
- **Snippet:**
```text
fetch(url)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/faucet/faucet.component.ts:33`
- **File:** `frontend/src/app/faucet/faucet.component.ts` (Line 33)
- **Snippet:**
```text
const nftAddress = '0x**************************************39<len=42>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `SECRET-005` (Hardcoded Secrets) at `data/static/codefixes/loginAdminChallenge_2.ts:15`
- **File:** `data/static/codefixes/loginAdminChallenge_2.ts` (Line 15)
- **Snippet:**
```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${*********************************| <len=37>'')}' AND deletedAt IS NULL`,
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `DESER-003` (Unsafe Deserialization) at `rsn/rsnUtil.ts:135`
- **File:** `rsn/rsnUtil.ts` (Line 135)
- **Snippet:**
```text
yaml.load(content)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/address.service.ts:26`
- **File:** `frontend/src/app/Services/address.service.ts` (Line 26)
- **Snippet:**
```text
this.http.get(`${this.host}/${id}`)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 06: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.ts:10`
- **File:** `frontend/src/app/score-board/components/coding-challenge-progress-score-card/coding-challenge-progress-score-card.component.ts` (Line 10)
- **Snippet:**
```text
templateUrl: './*************************************************ml<len=53>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 07: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/product-details/product-details.component.ts:34`
- **File:** `frontend/src/app/product-details/product-details.component.ts` (Line 34)
- **Snippet:**
```text
templateUrl: './****************************ml<len=32>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 08: `SECRET-004` (Hardcoded Secrets) at `frontend/src/app/last-login-ip/last-login-ip.component.spec.ts:78`
- **File:** `frontend/src/app/last-login-ip/last-login-ip.component.spec.ts` (Line 78)
- **Snippet:**
```text
localStorage.setItem('token', 'ey********************************************************************************************Lw<len=96>')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 09: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/coding-challenge-page/components/coding-challenge-fix-it/coding-challenge-fix-it.component.ts:30`
- **File:** `frontend/src/app/coding-challenge-page/components/coding-challenge-fix-it/coding-challenge-fix-it.component.ts` (Line 30)
- **Snippet:**
```text
templateUrl: './************************************ml<len=40>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 10: `AUTH-005` (Broken Authentication) at `routes/verify.ts:25`
- **File:** `routes/verify.ts` (Line 25)
- **Snippet:**
```text
req.body.password === ''
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 11: `SECRET-006` (Hardcoded Secrets) at `lib/startup/validateConfig.ts:18`
- **File:** `lib/startup/validateConfig.ts` (Line 18)
- **Snippet:**
```text
{ name: '"Leaked Unsafe Product" challenge product', key: 'ke********************************ge<len=36>', extra: null }
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 12: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.ts:42`
- **File:** `frontend/src/app/challenge-solved-notification/challenge-solved-notification.component.ts` (Line 42)
- **Snippet:**
```text
templateUrl: './******************************************ml<len=46>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 13: `AUTH-005` (Broken Authentication) at `routes/changePassword.ts:39`
- **File:** `routes/changePassword.ts` (Line 39)
- **Snippet:**
```text
security.hash(currentPassword) !== loggedInUser.data.password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 14: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/user.service.ts:29`
- **File:** `frontend/src/app/Services/user.service.ts` (Line 29)
- **Snippet:**
```text
this.http.get(this.hostServer + '/rest/user/authentication-details/', { params })
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 15: `SECRET-005` (Hardcoded Secrets) at `data/static/codefixes/loginBenderChallenge_1.ts:18`
- **File:** `data/static/codefixes/loginBenderChallenge_1.ts` (Line 18)
- **Snippet:**
```text
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${*********************************| <len=37>'')}' AND deletedAt IS NULL`, { model: models.User, plain: true })
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 16: `SQLI-001` (SQL Injection) at `data/static/codefixes/loginAdminChallenge_2.ts:15`
- **File:** `data/static/codefixes/loginAdminChallenge_2.ts` (Line 15)
- **Snippet:**
```text
models.sequelize.query(`SELECT * FROM Users WHERE email = $1 AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
      { bind: [ req.body.email ], model: models.User, p
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 17: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/challenge-status-badge/challenge-status-badge.component.ts:24`
- **File:** `frontend/src/app/challenge-status-badge/challenge-status-badge.component.ts` (Line 24)
- **Snippet:**
```text
templateUrl: './***********************************ml<len=39>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 18: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/photo-wall/photo-wall.component.spec.ts:259`
- **File:** `frontend/src/app/photo-wall/photo-wall.component.spec.ts` (Line 259)
- **Snippet:**
```text
application: { social: { twitterUrl: 'https://twitter.com/juice', blueSkyUrl: 'https://bsky.app/profile/juice', mastodonUrl: 'ht**************************ce<len=30>' } }
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 19: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/purchase-basket/purchase-basket.component.ts:29`
- **File:** `frontend/src/app/purchase-basket/purchase-basket.component.ts` (Line 29)
- **Snippet:**
```text
templateUrl: './****************************ml<len=32>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 20: `SECRET-006` (Hardcoded Secrets) at `frontend/src/hacking-instructor/challenges/reflectedXss.ts:54`
- **File:** `frontend/src/hacking-instructor/challenges/reflectedXss.ts` (Line 54)
- **Snippet:**
```text
'Use: <code>&lt;iframe src="ja***************************;)<len=31>"&gt;</code> as a city name.',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 21: `AUTH-005` (Broken Authentication) at `routes/login.ts:59`
- **File:** `routes/login.ts` (Line 59)
- **Snippet:**
```text
req.body.password === 'admin123'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 22: `AUTH-005` (Broken Authentication) at `server.ts:437`
- **File:** `server.ts` (Line 437)
- **Snippet:**
```text
req.body.password !== undefined
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 23: `SSRF-001` (Server-Side Request Forgery) at `lib/webhook.ts:18`
- **File:** `lib/webhook.ts` (Line 18)
- **Snippet:**
```text
fetch(webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      solution: {
        challenge: challenge.key,
        hintsAvailable,
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 24: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/payment/payment.component.ts:270`
- **File:** `frontend/src/app/payment/payment.component.ts` (Line 270)
- **Snippet:**
```text
data: 'da***********************************kW<len=39>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 25: `AUTH-005` (Broken Authentication) at `routes/resetPassword.ts:30`
- **File:** `routes/resetPassword.ts` (Line 30)
- **Snippet:**
```text
newPassword !== repeatPassword
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 26: `SECRET-006` (Hardcoded Secrets) at `routes/web3Wallet.ts:9`
- **File:** `routes/web3Wallet.ts` (Line 9)
- **Snippet:**
```text
const web3WalletAddress = '0x**************************************b0<len=42>'
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 27: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/two-factor-auth-service.ts:44`
- **File:** `frontend/src/app/Services/two-factor-auth-service.ts` (Line 44)
- **Snippet:**
```text
this.http.get<TwoFactorAuthStatusPayload>(`${environment.hostServer}/rest/2fa/status`)
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 28: `SECRET-006` (Hardcoded Secrets) at `frontend/src/app/privacy-security/privacy-security.component.ts:12`
- **File:** `frontend/src/app/privacy-security/privacy-security.component.ts` (Line 12)
- **Snippet:**
```text
templateUrl: './*****************************ml<len=33>',
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 29: `SSRF-001` (Server-Side Request Forgery) at `frontend/src/app/Services/user.service.ts:76`
- **File:** `frontend/src/app/Services/user.service.ts` (Line 76)
- **Snippet:**
```text
this.http.get(this.hostServer + '/rest/deluxe-membership')
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 30: `AUTH-005` (Broken Authentication) at `routes/changePassword.ts:28`
- **File:** `routes/changePassword.ts` (Line 28)
- **Snippet:**
```text
token === null
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## DVNA — Config: `native-only` (Sampled 5 of 5 unlabeled findings)

### Entry 01: `AUTH-005` (Broken Authentication) at `core/appHandler.js:152`
- **File:** `core/appHandler.js` (Line 152)
- **Snippet:**
```text
req.body.password == req.body.cpassword
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `AUTH-003` (Broken Authentication) at `routes/main.js:51`
- **File:** `routes/main.js` (Line 51)
- **Snippet:**
```text
router.post('/login', passport.authenticate('login', {
		successRedirect: '/learn',
		failureRedirect: '/login',
		failureFlash: true
	}))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `AUTH-005` (Broken Authentication) at `core/passport.js:64`
- **File:** `core/passport.js` (Line 64)
- **Snippet:**
```text
req.body.cpassword == req.body.password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `AUTH-005` (Broken Authentication) at `core/authHandler.js:71`
- **File:** `core/authHandler.js` (Line 71)
- **Snippet:**
```text
req.body.password == req.body.cpassword
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `AUTH-003` (Broken Authentication) at `routes/main.js:10`
- **File:** `routes/main.js` (Line 10)
- **Snippet:**
```text
router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		res.render('login')
	})
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

## DVNA — Config: `merged` (Sampled 5 of 5 unlabeled findings)

### Entry 01: `AUTH-005` (Broken Authentication) at `core/appHandler.js:152`
- **File:** `core/appHandler.js` (Line 152)
- **Snippet:**
```text
req.body.password == req.body.cpassword
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 02: `AUTH-003` (Broken Authentication) at `routes/main.js:51`
- **File:** `routes/main.js` (Line 51)
- **Snippet:**
```text
router.post('/login', passport.authenticate('login', {
		successRedirect: '/learn',
		failureRedirect: '/login',
		failureFlash: true
	}))
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 03: `AUTH-005` (Broken Authentication) at `core/passport.js:64`
- **File:** `core/passport.js` (Line 64)
- **Snippet:**
```text
req.body.cpassword == req.body.password
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 04: `AUTH-005` (Broken Authentication) at `core/authHandler.js:71`
- **File:** `core/authHandler.js` (Line 71)
- **Snippet:**
```text
req.body.password == req.body.cpassword
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

### Entry 05: `AUTH-003` (Broken Authentication) at `routes/main.js:10`
- **File:** `routes/main.js` (Line 10)
- **Snippet:**
```text
router.get('/login', authHandler.isNotAuthenticated, function (req, res) {
		res.render('login')
	})
```
- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)
- **Notes:** 

