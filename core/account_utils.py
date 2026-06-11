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


def hash_password(password, salt=None, iterations=600_000):
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        # A string salt is the hex form this function emits; decode it back to
        # the original bytes so verification round-trips. Invalid hex raises
        # ValueError rather than silently changing the salt bytes.
        salt = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "%d$%s$%s" % (iterations, salt.hex(), dk.hex())


def load_config(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data["settings"]


def process_users(users, db_path="prod.db", results=None):
    if results is None:
        results = []
    users_list = list(users)
    if not users_list:
        return results
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        # SQLite caps host parameters (default 999), so query in chunks.
        limit = 999
        for i in range(0, len(users_list), limit):
            chunk = users_list[i : i + limit]
            placeholders = ",".join("?" for _ in chunk)
            query = "SELECT * FROM users WHERE username IN (%s)" % placeholders
            cursor.execute(query, chunk)
            results.extend(cursor.fetchall())
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
