from flask import Flask, request, redirect
import sqlite3
import subprocess
import pickle
import os
import hashlib

app = Flask(__name__)

# =========================
# HARD CODED SECRETS
# =========================
API_KEY = "sk-test-123456"
DB_PASSWORD = "admin123"
SECRET_TOKEN = "super-secret-token"

# =========================
# HOME
# =========================
@app.route("/")
def home():
    return """
    <h1>Vulnerable Flask App</h1>
    <ul>
        <li>/user?username=admin</li>
        <li>/ping?host=127.0.0.1</li>
        <li>/calc?expr=2+2</li>
        <li>/search?q=test</li>
        <li>/redirect?url=http://example.com</li>
        <li>/file?file=test.txt</li>
        <li>/admin</li>
    </ul>
    """

# =========================
# SQL INJECTION
# =========================
@app.route("/user")
def get_user():
    username = request.args.get("username")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # VULNERABLE

    return str(cursor.fetchone())

# =========================
# COMMAND INJECTION
# =========================
@app.route("/ping")
def ping():
    host = request.args.get("host")
    return str(subprocess.call(f"ping -c 1 {host}", shell=True))

# =========================
# EVAL INJECTION
# =========================
@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))  # VULNERABLE

# =========================
# PICKLE RCE
# =========================
@app.route("/load", methods=["POST"])
def load():
    data = request.data
    obj = pickle.loads(data)  # VULNERABLE
    return str(obj)

# =========================
# WEAK HASH (MD5)
# =========================
@app.route("/hash")
def weak_hash():
    password = request.args.get("password", "test")
    return hashlib.md5(password.encode()).hexdigest()

# =========================
# PATH TRAVERSAL
# =========================
@app.route("/file")
def read_file():
    filename = request.args.get("file")
    path = f"/var/data/{filename}"

    with open(path, "r") as f:
        return f.read()

# =========================
# XSS
# =========================
@app.route("/search")
def search():
    q = request.args.get("q")
    return f"<h1>Results for {q}</h1>"  # VULNERABLE

# =========================
# OPEN REDIRECT
# =========================
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url")
    return redirect(url)  # VULNERABLE

# =========================
# BROKEN AUTH
# =========================
@app.route("/admin")
def admin():
    return "Admin panel - no auth!"  # VULNERABLE

# =========================
# INSECURE FILE UPLOAD
# =========================
@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    path = os.path.join("/tmp", f.filename)
    f.save(path)  # brak walidacji
    return "Uploaded!"

# =========================
# DEBUG INFO LEAK
# =========================
@app.route("/debug")
def debug():
    return str(os.environ)  # VULNERABLE

# =========================
# INSECURE RANDOM TOKEN
# =========================
@app.route("/token")
def token():
    return str(hash("static-seed"))  # przewidywalne

# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
