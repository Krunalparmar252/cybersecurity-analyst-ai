const express = require('express');
const app = express();

const apiSecretToken = "super_secret_token_123456";

app.get('/user', (req, res) => {
    const userId = req.query.id;
    db.query(`SELECT * FROM users WHERE id = '${userId}'`);

    res.send(`<div>Hello <span>${req.query.name}</span></div>`);
});

// SEEDED BUG: eval() of request input (DESER-002)
app.post('/calc', (req, res) => {
    const result = eval(req.body.expr);  // GT:DESER-002-eval
    res.json({ result });
});

// SAFE: eval of a constant literal, must NOT fire
const two = eval('1 + 1');  // SAFE

// SEEDED BUG: EJS unescaped output (XSS-003)
const commentView = "<p><%- comment %></p>";  // GT:XSS-003

// SEEDED BUGS: more hardcoded secrets (public doc examples / random fakes)
const awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";  // GT:SECRET-001
const aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";  // GT:SECRET-002
const githubToken = "ghp_u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8d";  // GT:SECRET-003
