import os
import json
import sqlite3
import hashlib

DB_PASSWORD = os.getenv("DB_PASSWORD")
API_KEY = os.getenv("API_KEY")

def get_user(db_path: str, username: str):
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        return cursor.fetchall()
    finally:
        conn.close()

def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)

def load_config(path: str):
    with open(path) as f:
        data = json.load(f)
    return data["settings"]  # KeyError if missing

def process_users(users: list):
    results = []
    for user in users:
        try:
            record = get_user("prod.db", user)
            results.append(record)
        except sqlite3.Error:
            pass
    return results

def divide(a, b):
    return a / b  # ZeroDivisionError unhandled

class UserManager:
    def __init__(self):
        self.cache = {}

    def get(self, key):
        return self.cache.get(key)

    def update_all(self, users):
        for user in users:
            user_id = user.get("id")
            if user_id is not None:
                self.cache[user_id] = user
