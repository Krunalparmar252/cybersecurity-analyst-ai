# Benchmark Ground Truth Review Queue
Every label in the benchmark ground truth starts with `reviewed: false`.
This queue displays each label with its file, line number, rule class, and a 3-line code excerpt.
Team members must inspect each excerpt before marking `reviewed: true` in `benchmarks/labels/<repo>.json`.

| ID | Repo | Class | File:Line | Source | Reviewed |
|---|---|---|---|---|---|
| `GT-PYGOAT-SQLI-01` | pygoat | SQL Injection | `dockerized_labs/sql_injection_lab/app.py:57` | lesson source code | False |
| `GT-PYGOAT-CMDINJ-01` | pygoat | Command Injection | `dockerized_labs/command_injection_lab/app.py:29` | lesson source code | False |
| `GT-PYGOAT-SSRF-01` | pygoat | Server-Side Request Forgery | `dockerized_labs/ssrf_lab/app.py:37` | lesson source code | False |
| `GT-PYGOAT-DESER-01` | pygoat | Unsafe Deserialization | `dockerized_labs/insec_des_lab/main.py:40` | lesson source code | False |
| `GT-PYGOAT-DESER-02` | pygoat | Unsafe Deserialization | `dockerized_labs/software_integrity_lab/app.py:44` | lesson source code | False |
| `GT-PYGOAT-DESER-03` | pygoat | Unsafe Deserialization | `dockerized_labs/a9_uckv_lab/app.py:62` | lesson source code | False |
| `GT-PYGOAT-AUTH-01` | pygoat | Broken Authentication | `dockerized_labs/crypto_failure_lab/app.py:25` | lesson source code | False |
| `GT-PYGOAT-AUTH-02` | pygoat | Broken Authentication | `dockerized_labs/crypto_failure_lab/app.py:38` | lesson source code | False |
| `GT-PYGOAT-CRYPTO-01` | pygoat | Insecure Cryptography | `dockerized_labs/broken_auth_lab/app.py:103` | lesson source code | False |
| `GT-PYGOAT-XXE-01` | pygoat | XML External Entity | `dockerized_labs/xxe_lab/app.py:61` | lesson source code | False |
| `GT-PYGOAT-CONFIG-01` | pygoat | Broken Authentication | `dockerized_labs/xss_lab/app.py:86` | lesson source code | False |
| `GT-NODEGOAT-DESER-01` | nodegoat | Unsafe Deserialization | `app/routes/contributions.js:32` | lesson comments in source | False |
| `GT-NODEGOAT-DESER-02` | nodegoat | Unsafe Deserialization | `app/routes/contributions.js:33` | lesson comments in source | False |
| `GT-NODEGOAT-DESER-03` | nodegoat | Unsafe Deserialization | `app/routes/contributions.js:34` | lesson comments in source | False |
| `GT-NODEGOAT-SQLI-01` | nodegoat | SQL Injection | `app/data/allocations-dao.js:78` | lesson comments in source | False |
| `GT-NODEGOAT-REDIR-01` | nodegoat | Open Redirect | `app/routes/index.js:72` | lesson comments in source | False |
| `GT-NODEGOAT-AUTH-01` | nodegoat | Broken Authentication | `app/data/user-dao.js:61` | lesson comments in source | False |
| `GT-NODEGOAT-CRYPTO-01` | nodegoat | Insecure Cryptography | `app/data/user-dao.js:51` | lesson comments in source | False |
| `GT-VULPY-SQLI-01` | vulpy | SQL Injection | `bad/libuser.py:12` | project source comparison (bad vs good) | False |
| `GT-VULPY-SQLI-02` | vulpy | SQL Injection | `bad/libuser.py:53` | project source comparison (bad vs good) | False |
| `GT-VULPY-CONFIG-01` | vulpy | Broken Authentication | `bad/libsession.py:7` | project source comparison (bad vs good) | False |
| `GT-VULPY-SSRF-01` | vulpy | Server-Side Request Forgery | `bad/api_list.py:10` | project source comparison (bad vs good) | False |
| `GT-VULPY-SQLI-03` | vulpy | SQL Injection | `bad/db.py:19` | project source comparison (bad vs good) | False |
| `GT-DVPWA-AUTH-01` | dvpwa | Broken Authentication | `sqli/dao/user.py:41` | project source code | False |
| `GT-DVPWA-SQLI-01` | dvpwa | SQL Injection | `sqli/dao/student.py:45` | project source code | False |
| `GT-DVPWA-SQLI-02` | dvpwa | SQL Injection | `sqli/dao/course.py:47` | project source code | False |
| `GT-JUICE-directoryListingChallenge-290` | juice-shop | Path Traversal | `server.ts:290` | vuln-code-snippet annotation | False |
| `GT-JUICE-directoryListingChallenge-291` | juice-shop | Path Traversal | `server.ts:291` | vuln-code-snippet annotation | False |
| `GT-JUICE-accessLogDisclosureChallenge-302` | juice-shop | Path Traversal | `server.ts:302` | vuln-code-snippet annotation | False |
| `GT-JUICE-accessLogDisclosureChallenge-304` | juice-shop | Path Traversal | `server.ts:304` | vuln-code-snippet annotation | False |
| `GT-JUICE-redirectCryptoCurrencyChallenge-124` | juice-shop | Open Redirect | `lib/insecurity.ts:124` | vuln-code-snippet annotation | False |
| `GT-JUICE-redirectCryptoCurrencyChallenge-125` | juice-shop | Open Redirect | `lib/insecurity.ts:125` | vuln-code-snippet annotation | False |
| `GT-JUICE-redirectCryptoCurrencyChallenge-126` | juice-shop | Open Redirect | `lib/insecurity.ts:126` | vuln-code-snippet annotation | False |
| `GT-JUICE-redirectChallenge-136` | juice-shop | Open Redirect | `lib/insecurity.ts:136` | vuln-code-snippet annotation | False |
| `GT-JUICE-weakPasswordChallenge-73` | juice-shop | Broken Authentication | `models/user.ts:73` | vuln-code-snippet annotation | False |
| `GT-JUICE-loginAdminChallenge-34` | juice-shop | SQL Injection | `routes/login.ts:34` | vuln-code-snippet annotation | False |
| `GT-JUICE-unionSqlInjectionChallenge-23` | juice-shop | SQL Injection | `routes/search.ts:23` | vuln-code-snippet annotation | False |
| `GT-JUICE-noSqlReviewsChallenge-18` | juice-shop | SQL Injection | `routes/updateProductReviews.ts:18` | vuln-code-snippet annotation | False |
| `GT-JUICE-noSqlReviewsChallenge-20` | juice-shop | SQL Injection | `routes/updateProductReviews.ts:20` | vuln-code-snippet annotation | False |
| `GT-DVNA-SQLI-01` | dvna | SQL Injection | `core/appHandler.js:11` | project documentation and vulns.js | False |
| `GT-DVNA-CMDINJ-01` | dvna | Command Injection | `core/appHandler.js:39` | project documentation and vulns.js | False |
| `GT-DVNA-REDIR-01` | dvna | Open Redirect | `core/appHandler.js:188` | project documentation and vulns.js | False |
| `GT-DVNA-DESER-01` | dvna | Unsafe Deserialization | `core/appHandler.js:218` | project documentation and vulns.js | False |
| `GT-DVNA-CRYPTO-01` | dvna | Insecure Cryptography | `core/authHandler.js:49` | project documentation and vulns.js | False |
| `GT-DVNA-SECRET-01` | dvna | Hardcoded Secrets | `server.js:24` | project source code | False |
| `GT-DVNA-CONFIG-01` | dvna | Broken Authentication | `server.js:27` | project source code | False |

## Code Excerpts for Manual Review

### PYGOAT (11 labels)
#### `GT-PYGOAT-SQLI-01` — SQL Injection (`SQLI-001`)
- **Location:** `pygoat/dockerized_labs/sql_injection_lab/app.py:57`
- **Description:** sqlite3 cursor.execute with raw f-string formatted query from form input
- **Source:** lesson source code | **Reviewed:** False

```text
     56 |             c = conn.cursor()
 >   57 |             result = c.execute(sql_query).fetchone()
     58 |             conn.close()
```
#### `GT-PYGOAT-CMDINJ-01` — Command Injection (`CMDINJ-001`)
- **Location:** `pygoat/dockerized_labs/command_injection_lab/app.py:29`
- **Description:** subprocess.Popen with shell=True executing user-controlled command
- **Source:** lesson source code | **Reviewed:** False

```text
     28 |             # Intentionally vulnerable command execution
 >   29 |             process = subprocess.Popen(
     30 |                 command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
```
#### `GT-PYGOAT-SSRF-01` — Server-Side Request Forgery (`SSRF-001`)
- **Location:** `pygoat/dockerized_labs/ssrf_lab/app.py:37`
- **Description:** requests.get called with untrusted user-supplied url parameter
- **Source:** lesson source code | **Reviewed:** False

```text
     36 |         try:
 >   37 |             response = requests.get(url)
     38 |             flash("Successfully fetched URL!", "success")
```
#### `GT-PYGOAT-DESER-01` — Unsafe Deserialization (`DESER-001`)
- **Location:** `pygoat/dockerized_labs/insec_des_lab/main.py:40`
- **Description:** pickle.loads called on base64-decoded user cookie data
- **Source:** lesson source code | **Reviewed:** False

```text
     39 |         # Intentionally vulnerable deserialization, matching PyGoat
 >   40 |         user = pickle.loads(decoded_data)
     41 | 
```
#### `GT-PYGOAT-DESER-02` — Unsafe Deserialization (`DESER-001`)
- **Location:** `pygoat/dockerized_labs/software_integrity_lab/app.py:44`
- **Description:** pickle.loads on base64-decoded token payload
- **Source:** lesson source code | **Reviewed:** False

```text
     43 |             token = base64.b64decode(token)
 >   44 |             admin = pickle.loads(
     45 |                 token
```
#### `GT-PYGOAT-DESER-03` — Unsafe Deserialization (`DESER-001`)
- **Location:** `pygoat/dockerized_labs/a9_uckv_lab/app.py:62`
- **Description:** yaml.load with Loader=yaml.Loader on untrusted uploaded file
- **Source:** lesson source code | **Reviewed:** False

```text
     61 |             # Intentionally vulnerable YAML loading
 >   62 |             data = yaml.load(file.stream, Loader=yaml.Loader)
     63 |             return render_template("result.html", content=data, filename=file.filename)
```
#### `GT-PYGOAT-AUTH-01` — Broken Authentication (`AUTH-002`)
- **Location:** `pygoat/dockerized_labs/crypto_failure_lab/app.py:25`
- **Description:** hashlib.sha1 applied to password
- **Source:** lesson source code | **Reviewed:** False

```text
     24 | def custom_hash(password):
 >   25 |     return hashlib.sha1(password.encode()).hexdigest()
     26 | 
```
#### `GT-PYGOAT-AUTH-02` — Broken Authentication (`AUTH-002`)
- **Location:** `pygoat/dockerized_labs/crypto_failure_lab/app.py:38`
- **Description:** hashlib.md5 applied to password
- **Source:** lesson source code | **Reviewed:** False

```text
     37 |         password = request.form.get("password")
 >   38 |         password_hash = hashlib.md5(password.encode()).hexdigest()
     39 |         if username in LAB1_USERS and LAB1_USERS[username] == password_hash:
```
#### `GT-PYGOAT-CRYPTO-01` — Insecure Cryptography (`CRYPTO-001`)
- **Location:** `pygoat/dockerized_labs/broken_auth_lab/app.py:103`
- **Description:** hashlib.md5 used to generate password reset token
- **Source:** lesson source code | **Reviewed:** False

```text
    102 |             # Vulnerable: Predictable token generation
 >  103 |             token = hashlib.md5(f"{email}:{datetime.now()}".encode()).hexdigest()
    104 |             password_reset_tokens[token] = username
```
#### `GT-PYGOAT-XXE-01` — XML External Entity (`XXE-001`)
- **Location:** `pygoat/dockerized_labs/xxe_lab/app.py:61`
- **Description:** parseString with feature_external_ges enabled without defusedxml
- **Source:** lesson source code | **Reviewed:** False

```text
     60 |             # Parse the XML data
 >   61 |             doc = parseString(request.data.decode("utf-8"), parser=parser)
     62 | 
```
#### `GT-PYGOAT-CONFIG-01` — Broken Authentication (`CONFIG-002`)
- **Location:** `pygoat/dockerized_labs/xss_lab/app.py:86`
- **Description:** Cookie set without secure or httponly flags
- **Source:** lesson source code | **Reviewed:** False

```text
     85 |     current = request.cookies.get("theme", "light")
 >   86 |     resp.set_cookie("theme", "dark" if current == "light" else "light")
     87 |     return resp
```

### NODEGOAT (7 labels)
#### `GT-NODEGOAT-DESER-01` — Unsafe Deserialization (`DESER-002`)
- **Location:** `nodegoat/app/routes/contributions.js:32`
- **Description:** Insecure use of eval() to evaluate user-supplied input (preTax)
- **Source:** lesson comments in source | **Reviewed:** False

```text
     31 |         // Insecure use of eval() to parse inputs
 >   32 |         const preTax = eval(req.body.preTax);
     33 |         const afterTax = eval(req.body.afterTax);
```
#### `GT-NODEGOAT-DESER-02` — Unsafe Deserialization (`DESER-002`)
- **Location:** `nodegoat/app/routes/contributions.js:33`
- **Description:** Insecure use of eval() to evaluate user-supplied input (afterTax)
- **Source:** lesson comments in source | **Reviewed:** False

```text
     32 |         const preTax = eval(req.body.preTax);
 >   33 |         const afterTax = eval(req.body.afterTax);
     34 |         const roth = eval(req.body.roth);
```
#### `GT-NODEGOAT-DESER-03` — Unsafe Deserialization (`DESER-002`)
- **Location:** `nodegoat/app/routes/contributions.js:34`
- **Description:** Insecure use of eval() to evaluate user-supplied input (roth)
- **Source:** lesson comments in source | **Reviewed:** False

```text
     33 |         const afterTax = eval(req.body.afterTax);
 >   34 |         const roth = eval(req.body.roth);
     35 | 
```
#### `GT-NODEGOAT-SQLI-01` — SQL Injection (`SQLI-001`)
- **Location:** `nodegoat/app/data/allocations-dao.js:78`
- **Description:** NoSQL $where clause with unsanitized threshold parameter
- **Source:** lesson comments in source | **Reviewed:** False

```text
     77 |                 return {
 >   78 |                     $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
     79 |                 };
```
#### `GT-NODEGOAT-REDIR-01` — Open Redirect (`REDIR-001`)
- **Location:** `nodegoat/app/routes/index.js:72`
- **Description:** res.redirect takes user-controlled url from query string
- **Source:** lesson comments in source | **Reviewed:** False

```text
     71 |         // Insecure way to handle redirects by taking redirect url from query string
 >   72 |         return res.redirect(req.query.url);
     73 |     });
```
#### `GT-NODEGOAT-AUTH-01` — Broken Authentication (`AUTH-005`)
- **Location:** `nodegoat/app/data/user-dao.js:61`
- **Description:** Plain === equality check for stored password instead of bcrypt compare
- **Source:** lesson comments in source | **Reviewed:** False

```text
     60 |         const comparePassword = (fromDB, fromUser) => {
 >   61 |             return fromDB === fromUser;
     62 |             /*
```
#### `GT-NODEGOAT-CRYPTO-01` — Insecure Cryptography (`CRYPTO-003`)
- **Location:** `nodegoat/app/data/user-dao.js:51`
- **Description:** Math.random() used to generate security-sensitive user data
- **Source:** lesson comments in source | **Reviewed:** False

```text
     50 |         const today = new Date();
 >   51 |         const day = (Math.floor(Math.random() * 10) + today.getDay()) % 29;
     52 |         const month = (Math.floor(Math.random() * 10) + today.getMonth()) % 12;
```

### VULPY (5 labels)
#### `GT-VULPY-SQLI-01` — SQL Injection (`SQLI-002`)
- **Location:** `vulpy/bad/libuser.py:12`
- **Description:** sqlite3 cursor.execute with .format() query concatenation in user login
- **Source:** project source comparison (bad vs good) | **Reviewed:** False

```text
     11 | 
 >   12 |     user = c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)).fetchone()
     13 | 
```
#### `GT-VULPY-SQLI-02` — SQL Injection (`SQLI-002`)
- **Location:** `vulpy/bad/libuser.py:53`
- **Description:** sqlite3 cursor.execute with .format() query concatenation in user update
- **Source:** project source comparison (bad vs good) | **Reviewed:** False

```text
     52 | 
 >   53 |     c.execute("UPDATE users SET password = '{}' WHERE username = '{}'".format(password, username))
     54 |     conn.commit()
```
#### `GT-VULPY-CONFIG-01` — Broken Authentication (`CONFIG-002`)
- **Location:** `vulpy/bad/libsession.py:7`
- **Description:** set_cookie for session cookie without secure/httponly flags
- **Source:** project source comparison (bad vs good) | **Reviewed:** False

```text
      6 |     session = base64.b64encode(json.dumps({'username': username}).encode())
 >    7 |     response.set_cookie('vulpy_session', session)
      8 |     return response
```
#### `GT-VULPY-SSRF-01` — Server-Side Request Forgery (`SSRF-001`)
- **Location:** `vulpy/bad/api_list.py:10`
- **Description:** requests.get with user-controlled parameter concatenation
- **Source:** project source comparison (bad vs good) | **Reviewed:** False

```text
      9 | 
 >   10 |     r = requests.get('http://127.0.1.1:5000/api/post/{}'.format(username))
     11 |     if r.status_code != 200:
```
#### `GT-VULPY-SQLI-03` — SQL Injection (`SQLI-002`)
- **Location:** `vulpy/bad/db.py:19`
- **Description:** cursor.execute with % format string interpolation
- **Source:** project source comparison (bad vs good) | **Reviewed:** False

```text
     18 |     for u,p in users:
 >   19 |         c.execute("INSERT INTO users (user, password, failures) VALUES ('%s', '%s', '%d')" %(u, p, 0))
     20 | 
```

### DVPWA (3 labels)
#### `GT-DVPWA-AUTH-01` — Broken Authentication (`AUTH-002`)
- **Location:** `dvpwa/sqli/dao/user.py:41`
- **Description:** md5 applied to password in check_password
- **Source:** project source code | **Reviewed:** False

```text
     40 |     def check_password(self, password: str):
 >   41 |         return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()
```
#### `GT-DVPWA-SQLI-01` — SQL Injection (`SQLI-002`)
- **Location:** `dvpwa/sqli/dao/student.py:45`
- **Description:** cur.execute with % interpolation in INSERT query
- **Source:** project source code | **Reviewed:** False

```text
     44 |         async with conn.cursor() as cur:
 >   45 |             await cur.execute(q)
     46 | 
```
#### `GT-DVPWA-SQLI-02` — SQL Injection (`SQLI-002`)
- **Location:** `dvpwa/sqli/dao/course.py:47`
- **Description:** cur.execute with dynamically composed SQL query
- **Source:** project source code | **Reviewed:** False

```text
     46 |         async with conn.cursor() as cur:
 >   47 |             await cur.execute(q, {'title': title,
     48 |                                   'description': description})
```

### JUICE-SHOP (13 labels)
#### `GT-JUICE-directoryListingChallenge-290` — Path Traversal (`PATHTRAV-002`)
- **Location:** `juice-shop/server.ts:290`
- **Description:** Juice Shop challenge 'Confidential Document' (directoryListingChallenge): Sensitive Data Exposure
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    289 |   /* /ftp directory browsing and file download */ // vuln-code-snippet neutral-line directoryListingChallenge
 >  290 |   app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })) // vuln-code-snippet vuln-line directoryListingChallenge
    291 |   app.use('/ftp(?!/quarantine)/:file', servePublicFiles()) // vuln-code-snippet vuln-line directoryListingChallenge
```
#### `GT-JUICE-directoryListingChallenge-291` — Path Traversal (`PATHTRAV-002`)
- **Location:** `juice-shop/server.ts:291`
- **Description:** Juice Shop challenge 'Confidential Document' (directoryListingChallenge): Sensitive Data Exposure
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    290 |   app.use('/ftp', serveIndexMiddleware, serveIndex('ftp', { icons: true })) // vuln-code-snippet vuln-line directoryListingChallenge
 >  291 |   app.use('/ftp(?!/quarantine)/:file', servePublicFiles()) // vuln-code-snippet vuln-line directoryListingChallenge
    292 |   app.use('/ftp/quarantine/:file', serveQuarantineFiles()) // vuln-code-snippet neutral-line directoryListingChallenge
```
#### `GT-JUICE-accessLogDisclosureChallenge-302` — Path Traversal (`PATHTRAV-002`)
- **Location:** `juice-shop/server.ts:302`
- **Description:** Juice Shop challenge 'Access Log' (accessLogDisclosureChallenge): Observability Failures
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    301 |   /* /logs directory browsing */ // vuln-code-snippet neutral-line accessLogDisclosureChallenge
 >  302 |   app.use('/support/logs', serveIndexMiddleware, serveIndex('logs', { icons: true, view: 'details' })) // vuln-code-snippet vuln-line accessLogDisclosureChallenge
    303 |   app.use('/support/logs', verify.accessControlChallenges()) // vuln-code-snippet hide-line
```
#### `GT-JUICE-accessLogDisclosureChallenge-304` — Path Traversal (`PATHTRAV-002`)
- **Location:** `juice-shop/server.ts:304`
- **Description:** Juice Shop challenge 'Access Log' (accessLogDisclosureChallenge): Observability Failures
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    303 |   app.use('/support/logs', verify.accessControlChallenges()) // vuln-code-snippet hide-line
 >  304 |   app.use('/support/logs/:file', serveLogFiles()) // vuln-code-snippet vuln-line accessLogDisclosureChallenge
    305 | 
```
#### `GT-JUICE-redirectCryptoCurrencyChallenge-124` — Open Redirect (`REDIR-001`)
- **Location:** `juice-shop/lib/insecurity.ts:124`
- **Description:** Juice Shop challenge 'Outdated Allowlist' (redirectCryptoCurrencyChallenge): Unvalidated Redirects
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    123 |   'https://github.com/juice-shop/juice-shop',
 >  124 |   'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
    125 |   'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
```
#### `GT-JUICE-redirectCryptoCurrencyChallenge-125` — Open Redirect (`REDIR-001`)
- **Location:** `juice-shop/lib/insecurity.ts:125`
- **Description:** Juice Shop challenge 'Outdated Allowlist' (redirectCryptoCurrencyChallenge): Unvalidated Redirects
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    124 |   'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
 >  125 |   'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
    126 |   'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
```
#### `GT-JUICE-redirectCryptoCurrencyChallenge-126` — Open Redirect (`REDIR-001`)
- **Location:** `juice-shop/lib/insecurity.ts:126`
- **Description:** Juice Shop challenge 'Outdated Allowlist' (redirectCryptoCurrencyChallenge): Unvalidated Redirects
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    125 |   'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
 >  126 |   'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
    127 |   'http://shop.spreadshirt.com/juiceshop',
```
#### `GT-JUICE-redirectChallenge-136` — Open Redirect (`REDIR-001`)
- **Location:** `juice-shop/lib/insecurity.ts:136`
- **Description:** Juice Shop challenge 'Allowlist Bypass' (redirectChallenge): Unvalidated Redirects
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
    135 |   for (const allowedUrl of redirectAllowlist) {
 >  136 |     allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
    137 |   }
```
#### `GT-JUICE-weakPasswordChallenge-73` — Broken Authentication (`AUTH-006`)
- **Location:** `juice-shop/models/user.ts:73`
- **Description:** Juice Shop challenge 'Password Strength' (weakPasswordChallenge): Broken Authentication
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
     72 |         set (clearTextPassword: string) {
 >   73 |           this.setDataValue('password', security.hash(clearTextPassword)) // vuln-code-snippet vuln-line weakPasswordChallenge
     74 |         }
```
#### `GT-JUICE-loginAdminChallenge-34` — SQL Injection (`SQLI-001`)
- **Location:** `juice-shop/routes/login.ts:34`
- **Description:** Juice Shop challenge 'Login Admin' (loginAdminChallenge): Injection
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
     33 |     verifyPreLoginChallenges(req) // vuln-code-snippet hide-line
 >   34 |     models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true }) // vuln-code-snippet vuln-line loginAdminChallenge loginBenderChallenge loginJimChallenge
     35 |       .then((authenticatedUser) => { // vuln-code-snippet neutral-line loginAdminChallenge loginBenderChallenge loginJimChallenge
```
#### `GT-JUICE-unionSqlInjectionChallenge-23` — SQL Injection (`SQLI-001`)
- **Location:** `juice-shop/routes/search.ts:23`
- **Description:** Juice Shop challenge 'User Credentials' (unionSqlInjectionChallenge): Injection
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
     22 |     criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
 >   23 |     models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
     24 |       .then(([products]: any) => {
```
#### `GT-JUICE-noSqlReviewsChallenge-18` — SQL Injection (`SQLI-001`)
- **Location:** `juice-shop/routes/updateProductReviews.ts:18`
- **Description:** Juice Shop challenge 'NoSQL Manipulation' (noSqlReviewsChallenge): Injection
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
     17 |     db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
 >   18 |       { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
     19 |       { $set: { message: req.body.message } },
```
#### `GT-JUICE-noSqlReviewsChallenge-20` — SQL Injection (`SQLI-001`)
- **Location:** `juice-shop/routes/updateProductReviews.ts:20`
- **Description:** Juice Shop challenge 'NoSQL Manipulation' (noSqlReviewsChallenge): Injection
- **Source:** vuln-code-snippet annotation | **Reviewed:** False

```text
     19 |       { $set: { message: req.body.message } },
 >   20 |       { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
     21 |     ).then(
```

### DVNA (7 labels)
#### `GT-DVNA-SQLI-01` — SQL Injection (`SQLI-001`)
- **Location:** `dvna/core/appHandler.js:11`
- **Description:** db.sequelize.query with raw string concatenation of req.body.login
- **Source:** project documentation and vulns.js | **Reviewed:** False

```text
     10 | 	var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
 >   11 | 	db.sequelize.query(query, {
     12 | 		model: db.User
```
#### `GT-DVNA-CMDINJ-01` — Command Injection (`CMDINJ-002`)
- **Location:** `dvna/core/appHandler.js:39`
- **Description:** child_process.exec with concatenated user address parameter
- **Source:** project documentation and vulns.js | **Reviewed:** False

```text
     38 | module.exports.ping = function (req, res) {
 >   39 | 	exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
     40 | 		output = stdout + stderr
```
#### `GT-DVNA-REDIR-01` — Open Redirect (`REDIR-001`)
- **Location:** `dvna/core/appHandler.js:188`
- **Description:** res.redirect called with unsanitized req.query.url parameter
- **Source:** project documentation and vulns.js | **Reviewed:** False

```text
    187 | 	if (req.query.url) {
 >  188 | 		res.redirect(req.query.url)
    189 | 	} else {
```
#### `GT-DVNA-DESER-01` — Unsafe Deserialization (`DESER-003`)
- **Location:** `dvna/core/appHandler.js:218`
- **Description:** serialize.unserialize called on user-supplied uploaded file data
- **Source:** project documentation and vulns.js | **Reviewed:** False

```text
    217 | 	if(req.files.products){
 >  218 | 		var products = serialize.unserialize(req.files.products.data.toString('utf8'))
    219 | 		products.forEach( function (product) {
```
#### `GT-DVNA-CRYPTO-01` — Insecure Cryptography (`CRYPTO-001`)
- **Location:** `dvna/core/authHandler.js:49`
- **Description:** md5 applied to security verification token
- **Source:** project documentation and vulns.js | **Reviewed:** False

```text
     48 | 			if (user) {
 >   49 | 				if (req.query.token == md5(req.query.login)) {
     50 | 					res.render('resetpw', {
```
#### `GT-DVNA-SECRET-01` — Hardcoded Secrets (`SECRET-001`)
- **Location:** `dvna/server.js:24`
- **Description:** Hardcoded session secret 'keyboard cat'
- **Source:** project source code | **Reviewed:** False

```text
     23 | app.use(session({
 >   24 |   secret: 'keyboard cat',
     25 |   resave: true,
```
#### `GT-DVNA-CONFIG-01` — Broken Authentication (`CONFIG-002`)
- **Location:** `dvna/server.js:27`
- **Description:** Session cookie configured with secure: false
- **Source:** project source code | **Reviewed:** False

```text
     26 |   saveUninitialized: true,
 >   27 |   cookie: { secure: false }
     28 | }))
```
