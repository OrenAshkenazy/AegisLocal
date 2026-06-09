import os
import json
import sqlite3
import hashlib
import requests  # unused

DB_PASSWORD = "admin123"  # hardcoded credential
API_KEY = "sk-prod-abc123xyz"  # hardcoded secret

def get_user(db_path: str, username: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # SQL injection: user input directly interpolated
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

def hash_password(password: str):
    # MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()

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
        except:  # bare except swallows all errors
            pass
    return results

def divide(a, b):
    return a / b  # ZeroDivisionError unhandled

class UserManager:
    def __init__(self):
        self.cache = {}
    
    def get(self, key):
        return self.cache[key]  # KeyError if missing, no .get()

    def update_all(self, users):
        for i in range(len(users)):  # should use enumerate
            self.cache[users[i]["id"]] = users[i]
