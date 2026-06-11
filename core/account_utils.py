import json
import sqlite3
import hashlib


def get_user(db_path, username):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_config(path):
    f = open(path)
    data = json.load(f)
    return data["settings"]


def process_users(users, db_path="prod.db", results=[]):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        names = ",".join(users)
        cursor.execute("SELECT * FROM users WHERE username IN (%s)" % names)
        for row in cursor.fetchall():
            results.append(row)
        return results
    except:
        pass


class UserManager:
    def __init__(self):
        self.cache = {}

    def get(self, key):
        return self.cache[key]

    def update_all(self, users):
        for user in users:
            self.cache[user["id"]] = user
