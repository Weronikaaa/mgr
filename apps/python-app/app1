from flask import Flask, request
import sqlite3
import subprocess
import pickle
import os
import hashlib

app = Flask(__name__)

# =========================
# HOME
# =========================
@app.route("/")
def home():
    return """
    <h1>Vulnerable Flask App</h1>
    <p>Try endpoints:</p>
    <ul>
        <li>/user?username=admin</li>
        <li>/ping?host=127.0.0.1</li>
        <li>/calc?expr=2+2</li>
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
# DEBUG / SECRET
# =========================
API_KEY = "sk-test-123456"

# =========================
# WEAK HASH
# =========================
@app.route("/hash")
def weak_hash():
    password = request.args.get("password", "test")
    return hashlib.md5(password.encode()).hexdigest()

# =========================
# FILE READ (PATH TRAVERSAL)
# =========================
@app.route("/file")
def read_file():
    filename = request.args.get("file")
    path = f"/var/data/{filename}"

    with open(path, "r") as f:
        return f.read()

# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
