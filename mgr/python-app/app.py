import sqlite3
import pickle
import subprocess

# PODATNOŚĆ 1: SQL Injection
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # Niebezpieczne - brak parametryzacji
    return cursor.fetchone()

# PODATNOŚĆ 2: Command Injection
def ping_host(host):
    return subprocess.call(f"ping -c 1 {host}", shell=True)  # Niebezpieczne

# PODATNOŚĆ 3: Pickle deserialization
def load_data(data):
    return pickle.loads(data)  # Niebezpieczne - możliwy RCE

# PODATNOŚĆ 4: Hardcoded secret
API_KEY = "sk-1234567890abcdef"  # Hardcoded credential

# PODATNOŚĆ 5: Path traversal
def read_file(filename):
    with open(f"/var/data/{filename}", 'r') as f:  # Brak walidacji ścieżki
        return f.read()

# PODATNOŚĆ 6: Weak hash
import hashlib
password_hash = hashlib.md5(b"password123").hexdigest()  # MD5

# PODATNOŚĆ 7: Debug mode enabled
DEBUG = True  # W produkcji

# PODATNOŚĆ 8: eval usage
def calculate(expression):
    return eval(expression)  # Niebezpieczne

# PODATNOŚĆ 9: Insecure redirect
def redirect(url):
    return f"<script>window.location='{url}'</script>"  # Open redirect

# PODATNOŚĆ 10: Unencrypted sensitive data
import os
os.environ['DB_PASSWORD'] = 'postgres'  # Plaintext secret

if __name__ == "__main__":
    print("Vulnerable Python App")
