#!/usr/bin/env python3
"""
db.py — SQLite persistence for users + scan history
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "recon.db"))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            subdomains_found INTEGER DEFAULT 0,
            exposed_found INTEGER DEFAULT 0,
            bypasses_found INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()


# ── USERS ────────────────────────────────────────
def create_user(username, email, password_hash):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, datetime.utcnow().isoformat()),
        )
        conn.commit()
        return True, None
    except sqlite3.IntegrityError as e:
        msg = "Username already taken" if "username" in str(e) else "Email already registered"
        return False, msg
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


# ── SCAN HISTORY ─────────────────────────────────
def save_scan(user_id, domain, subdomains_found, exposed_found, bypasses_found):
    conn = get_db()
    conn.execute(
        """INSERT INTO scan_history
           (user_id, domain, subdomains_found, exposed_found, bypasses_found, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, domain, subdomains_found, exposed_found, bypasses_found,
         datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def get_history(user_id, limit=25):
    conn = get_db()
    rows = conn.execute(
        """SELECT * FROM scan_history WHERE user_id = ?
           ORDER BY created_at DESC LIMIT ?""",
        (user_id, limit),
    ).fetchall()
    conn.close()
    return rows
