import json
import sqlite3
import hashlib
import os


def get_user(db_path, username):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()
    finally:
        conn.close()


def hash_password(password, salt=None, iterations=200_000):
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = salt.encode()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "%d$%s$%s" % (iterations, salt.hex(), dk.hex())


def load_config(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["settings"]


def process_users(users, db_path="prod.db", results=None):
    if results is None:
        results = []
    if not users:
        return results
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        placeholders = ",".join("?" for _ in users)
        query = "SELECT * FROM users WHERE username IN (%s)" % placeholders
        cursor.execute(query, users)
        for row in cursor.fetchall():
            results.append(row)
        return results
    except sqlite3.Error:
        return results
    finally:
        conn.close()


class UserManager:
    def __init__(self):
        self.cache = {}

    def get(self, key):
        return self.cache.get(key)

    def update_all(self, users):
        for user in users:
            self.cache[user["id"]] = user
