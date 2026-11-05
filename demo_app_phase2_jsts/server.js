const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const ejs = require('ejs');
const libxmljs = require('libxmljs');
const AdmZip = require('adm-zip');

const app = express();
app.use(express.json());

// 1. CORS-001 (Line 14)
app.use(cors({ origin: '*', credentials: true }));
// SAFE: app.use(cors({ origin: 'https://trusted.app.com', credentials: true }));

const ALLOWED_URLS = ['https://trusted.com/callback', 'https://example.com'];

app.get('/redirect', (req, res) => {
  const target = req.query.url;
  // 2. REDIR-001 (Line 22)
  res.redirect(target);
});

app.get('/redirect_safe', (req, res) => {
  const target = req.query.url;
  if (ALLOWED_URLS.includes(target) || (target && target.startsWith('/'))) {
    return res.redirect(target);  // SAFE: allowlist check
  }
  return res.redirect('/dashboard');  // SAFE: constant target
});

app.get('/hash_token', (req, res) => {
  const token = req.query.token || '';
  // 3. CRYPTO-001 (Line 35)
  const authKey = crypto.createHash('md5').update(token).digest('hex');
  // SAFE tricky negative: content file checksum
  const fileHash = crypto.createHash('md5').update('static_content').digest('hex');
  res.send({ authKey, fileHash });
});

app.get('/cipher', (req, res) => {
  const key = Buffer.alloc(8);
  // 4. CRYPTO-002 (Line 44)
  const cipher = crypto.createCipheriv('des-ecb', key, null);
  // SAFE: aes-256-gcm
  const safeCipher = crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(12));
  res.send('cipher initialized');
});

app.get('/token', (req, res) => {
  // 5. CRYPTO-003 (Line 52)
  const resetToken = Math.random().toString(36).substring(2);
  // SAFE tricky negative: non-security random float
  const diceValue = Math.floor(Math.random() * 6) + 1;
  // SAFE crypto:
  const secureToken = crypto.randomBytes(16).toString('hex');
  res.send({ resetToken, diceValue, secureToken });
});

app.get('/tls_check', (req, res) => {
  // 6. TLS-001 (Line 62)
  const agentOpts = { rejectUnauthorized: false };
  // SAFE: rejectUnauthorized: true
  const safeOpts = { rejectUnauthorized: true };
  res.json({ agentOpts, safeOpts });
});

app.get('/cookie', (req, res) => {
  // 7. CONFIG-002 (Line 70)
  res.cookie('theme_pref', 'dark', { httpOnly: false });
  // SAFE: hardened cookie
  res.cookie('session_id', 'xyz', { httpOnly: true, secure: true, sameSite: 'strict' });
  res.send('cookie set');
});

app.post('/jwt_verify', (req, res) => {
  const token = req.body.token;
  // 8. JWT-001 (Line 79)
  const decoded = jwt.verify(token, 'key', { algorithms: ['none'] });
  // SAFE: standard HS256
  const safeDecoded = jwt.verify(token, 'key', { algorithms: ['HS256'] });
  res.json({ decoded });
});

app.post('/xml', (req, res) => {
  const xmlData = req.body.xml;
  // 9. XXE-001 (Line 88)
  const doc = libxmljs.parseXml(xmlData, { noent: true });
  res.send('xml parsed');
});

app.get('/render', (req, res) => {
  const userTemplate = req.query.tpl || 'Hello';
  // 10. SSTI-001 (Line 95)
  const html = ejs.render(userTemplate, { name: 'guest' });
  // SAFE: static template with kwargs
  const safeHtml = ejs.render('<h1><%= name %></h1>', { name: userTemplate });
  res.send(html);
});

function unpackArchive(zipPath, outDir) {
  const zip = new AdmZip(zipPath);
  // 11. ZIPSLIP-001 (Line 104)
  zip.extractAllTo(outDir);
}

function safeUnpackArchive(zipPath, outDir) {
  const zip = new AdmZip(zipPath);
  const entries = zip.getEntries();
  entries.forEach(entry => {
    if (entry.entryName.indexOf('..') === -1) {
      zip.extractEntryTo(entry, outDir);  // SAFE: no path traversal characters
    }
  });
}

// 12. CONFIG-001 (Line 118)
app.set('env', 'development');

app.listen(3000, () => {
  console.log('Server running on 3000');
});

