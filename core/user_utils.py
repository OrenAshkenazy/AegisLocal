import os
import json
import sqlite3
import hashlib

DB_PASSWORD = os.getenv("DB_PASSWORD")
API_KEY = os.getenv("API_KEY")

def get_user(db_path: str, username: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()

def hash_password(password: str):
    return hashlib.sha256(password.encode()).hexdigest()

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
        except Exception:
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
            self.cache[user["id"]] = user
