const express = require('express');
const child_process = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const serialize = require('node-serialize');
const yaml = require('js-yaml');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

const ALLOWED_URLS = ['https://api.internal.service', 'https://trusted.partner.com'];
const SAFE_BASE_DIR = path.resolve(__dirname, 'public');

// SEEDED BUG 1: Hardcoded JWT Secret Literal (SECRET-004)
const HARDCODED_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// SAFE: JWT from environment variable
const safeJwt = process.env.SERVICE_JWT_TOKEN || "";

// SAFE: Placeholder / test JWT format (must NOT fire)
const testJwtPlaceholder = "eyJhbGciOi_example_placeholder_jwt_token_xxxx.dummy.sample";

// SEEDED BUG 2: Authentication route with no rate limiting (AUTH-003)
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = { username: 'admin', passwordHash: 'plain_secret_password' };

    // SEEDED BUG 3: Plaintext / Insecure Password Comparison (AUTH-005)
    if (password === user.passwordHash) {
        // SEEDED BUG 4: MD5 / Weak Hash applied to password (AUTH-006)
        const passwordMd5 = crypto.createHash('md5').update(password).digest('hex');

        // SEEDED BUG 5: Session cookie missing httpOnly & secure flags (AUTH-004)
        res.cookie('session', 'session_token_user_123');
        return res.json({ status: 'authenticated', token: passwordMd5 });
    }
    return res.status(401).json({ error: 'unauthorized' });
});

// SAFE: Rate limiter middleware
const rateLimiter = (req, res, next) => next();

// SAFE: Rate-limited authentication route (must NOT fire AUTH-003)
app.post('/api/auth/login_safe', rateLimiter, async (req, res) => {
    const { username, password } = req.body;
    const user = { username: 'admin', passwordHash: '$2b$12$e80yVbF...' };

    // SAFE: Bcrypt hash comparison (must NOT fire AUTH-005)
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (valid) {
        // SAFE: Secure cookie options with httpOnly and secure (must NOT fire AUTH-004)
        res.cookie('session', 'secure_token_456', { httpOnly: true, secure: true, sameSite: 'strict' });
        return res.json({ status: 'authenticated' });
    }
    return res.status(401).json({ error: 'unauthorized' });
});

// SAFE: Non-auth endpoint without rate limiter (must NOT fire AUTH-003)
app.get('/api/status', (req, res) => {
    return res.json({ status: 'operational' });
});

// SAFE: SHA-256 hash applied to non-password data (must NOT fire AUTH-006)
app.post('/api/checksum', (req, res) => {
    const fileChecksum = crypto.createHash('sha256').update(req.body.content || '').digest('hex');
    return res.json({ checksum: fileChecksum });
});

// SEEDED BUG 6: Command Injection via child_process.exec (CMDINJ-002)
app.get('/api/ping', (req, res) => {
    const host = req.query.host;
    child_process.exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// SAFE: Parameterized spawn without shell: true (must NOT fire CMDINJ-002)
app.get('/api/ping_safe', (req, res) => {
    const host = req.query.host;
    const proc = child_process.spawn('ping', ['-c', '1', host]);
    proc.stdout.on('data', (d) => res.write(d));
    proc.on('close', () => res.end());
});

// SAFE: Constant literal command passed to execSync (must NOT fire CMDINJ-002)
app.get('/api/version', (req, res) => {
    const gitRev = child_process.execSync('git rev-parse HEAD').toString().trim();
    res.json({ commit: gitRev });
});

// SEEDED BUG 7: Path Traversal via fs.readFile with untrusted path (PATHTRAV-002)
app.get('/api/read_file', (req, res) => {
    const userFile = req.query.filename;
    fs.readFile(userFile, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

// SAFE: Path resolution with base directory validation (must NOT fire PATHTRAV-002)
app.get('/api/read_file_safe', (req, res) => {
    const filename = req.query.filename || '';
    const safePath = path.resolve(SAFE_BASE_DIR, filename);
    if (safePath.startsWith(SAFE_BASE_DIR)) {
        return fs.readFile(safePath, 'utf8', (err, data) => {
            if (err) return res.status(404).send('Not found');
            res.send(data);
        });
    }
    return res.status(403).send('Forbidden');
});

// SAFE: Constant path passed to readFileSync (must NOT fire PATHTRAV-002)
app.get('/api/config', (req, res) => {
    const staticConfig = fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8');
    res.type('json').send(staticConfig);
});

// SEEDED BUG 8: Insecure Deserialization via node-serialize (DESER-003)
app.post('/api/unserialize', (req, res) => {
    const payload = req.body.payload;
    const restored = serialize.unserialize(payload);
    res.json({ result: restored });
});

// SAFE: Safe JSON parsing and safe YAML schema (must NOT fire DESER-003)
app.post('/api/parse_safe', (req, res) => {
    const yamlData = req.body.yamlText || '';
    const parsedYaml = yaml.load(yamlData, { schema: yaml.FAILSAFE_SCHEMA });
    const parsedJson = JSON.parse(req.body.jsonText || '{}');
    res.json({ yaml: parsedYaml, json: parsedJson });
});

// SEEDED BUG 9: Server-Side Request Forgery via fetch with unvalidated URL (SSRF-001)
app.get('/api/proxy', async (req, res) => {
    const targetUrl = req.query.url;
    const response = await fetch(targetUrl);
    const body = await response.text();
    res.send(body);
});

// SAFE: SSRF allowlist check preceding fetch (must NOT fire SSRF-001)
app.get('/api/proxy_safe', async (req, res) => {
    const targetUrl = req.query.url;
    if (ALLOWED_URLS.includes(targetUrl)) {
        const response = await fetch(targetUrl);
        const body = await response.text();
        return res.send(body);
    }
    return res.status(403).send('Disallowed host');
});

// SAFE: Constant URL passed to fetch (must NOT fire SSRF-001)
app.get('/api/internal_health', async (req, res) => {
    const response = await fetch('https://api.internal.service/health');
    res.json({ ok: response.ok });
});
