import json
import sqlite3
import hashlib

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
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Failed to load config from {path}") from e
    return data.get("settings") if isinstance(data, dict) else None

def process_users(users: list):
    if not users:
        return []
    results = []
    try:
        conn = sqlite3.connect("prod.db")
        try:
            cursor = conn.cursor()
            for user in users:
                try:
                    cursor.execute("SELECT * FROM users WHERE username = ?", (user,))
                    results.extend(cursor.fetchall())
                except sqlite3.Error:
                    pass
        finally:
            conn.close()
    except sqlite3.Error:
        pass
    return results

class UserManager:
    def __init__(self):
        self.cache = {}

    def get(self, key):
        return self.cache.get(key)

    def update_all(self, users):
        if not users:
            return
        for user in users:
            if isinstance(user, dict):
                user_id = user.get("id")
                if user_id is not None:
                    self.cache[user_id] = user
