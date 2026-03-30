const express = require('express');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());

// Hardcoded credentials
const DB_PASSWORD = 'root';
const JWT_SECRET = 'mysecretkey123';

// SQL Injection (symulacja – bez prawdziwej bazy)
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    // PODATNOŚĆ: SQL Injection
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    res.json({
        vulnerability: "SQL Injection",
        query: query,
        message: "This query would be executed if database existed"
    });
});

// Command Injection
app.get('/ping', (req, res) => {
    const ip = req.query.ip || '127.0.0.1';
    // PODATNOŚĆ: Command Injection
    exec(`ping -c 1 ${ip}`, (error, stdout, stderr) => {
        if (error) {
            res.send(`Error: ${error.message}`);
        } else {
            res.send(stdout);
        }
    });
});

// Path Traversal
app.get('/file', (req, res) => {
    const filename = req.query.filename;
    // PODATNOŚĆ: Path Traversal
    const filePath = path.join('/tmp/uploads', filename);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            res.send('File not found');
        } else {
            res.send(data);
        }
    });
});

// Environment leak
app.get('/env', (req, res) => {
    // PODATNOŚĆ: Exposing environment variables
    res.json(process.env);
});

// Insecure eval
app.post('/eval', (req, res) => {
    const code = req.body.code;
    // PODATNOŚĆ: Insecure eval
    try {
        const result = eval(code);
        res.json({ result });
    } catch(e) {
        res.json({ error: e.message });
    }
});

// No rate limiting
app.get('/api/data', (req, res) => {
    // PODATNOŚĆ: No rate limiting (DoS vulnerability)
    res.json({ data: 'sensitive information' });
});

// Insecure cookie
app.get('/login', (req, res) => {
    const token = 'fake-jwt-token';
    // PODATNOŚĆ: Cookie without httpOnly flag
    res.cookie('session', token, { httpOnly: false });
    res.send('Logged in');
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Vulnerable endpoints:');
    console.log('  GET  /user/:id     - SQL Injection');
    console.log('  GET  /ping?ip=     - Command Injection');
    console.log('  GET  /file?file=   - Path Traversal');
    console.log('  GET  /env          - Environment Leak');
    console.log('  POST /eval         - Insecure Eval');
    console.log('  GET  /api/data     - No Rate Limiting');
    console.log('  GET  /login        - Insecure Cookie');
});
