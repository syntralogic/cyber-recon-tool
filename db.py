#!/usr/bin/env python3
"""
db.py — persistence layer for users + scan history.

Uses Postgres when DATABASE_URL is set (e.g. Render's free Postgres add-on),
and falls back to a local SQLite file for local development.

IMPORTANT: on Render's free web service tier, the local filesystem is wiped
on every restart/redeploy/spin-down — so SQLite alone will silently reset
all accounts and cause user/session mix-ups. Postgres persists independently
of the web service, so it survives restarts.
"""

import os
import time
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError

db = SQLAlchemy()


def _normalized_db_uri():
    uri = os.environ.get("DATABASE_URL")
    if uri:
        # Render/Heroku-style URLs use postgres://, SQLAlchemy needs postgresql://
        if uri.startswith("postgres://"):
            uri = uri.replace("postgres://", "postgresql://", 1)
        return uri
    # Local dev fallback
    return "sqlite:///" + os.path.join(os.path.dirname(__file__), "recon.db")


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("ScanHistory", backref="user", cascade="all, delete-orphan")


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    subdomains_found = db.Column(db.Integer, default=0)
    exposed_found = db.Column(db.Integer, default=0)
    bypasses_found = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def init_app(app):
    app.config["SQLALCHEMY_DATABASE_URI"] = _normalized_db_uri()
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
    db.init_app(app)

    attempts, delay = 5, 2
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            with app.app_context():
                db.create_all()
            return
        except OperationalError as e:
            last_error = e
            app.logger.warning(
                "Database not reachable yet (attempt %d/%d): %s", attempt, attempts, e
            )
            time.sleep(delay)
    app.logger.error(
        "Could not connect to the database after %d attempts. "
        "Check that DATABASE_URL is set correctly (use the Internal Database URL "
        "from your Render Postgres instance).", attempts
    )
    raise last_error


# ── USERS ────────────────────────────────────────
def create_user(username, email, password_hash):
    if User.query.filter_by(username=username).first():
        return False, "Username already taken"
    if User.query.filter_by(email=email).first():
        return False, "Email already registered"
    user = User(username=username, email=email, password_hash=password_hash)
    db.session.add(user)
    db.session.commit()
    return True, None


def get_user_by_username(username):
    return User.query.filter_by(username=username).first()


def get_user_by_id(user_id):
    return db.session.get(User, int(user_id))


# ── SCAN HISTORY ─────────────────────────────────
def save_scan(user_id, domain, subdomains_found, exposed_found, bypasses_found):
    entry = ScanHistory(
        user_id=user_id, domain=domain,
        subdomains_found=subdomains_found,
        exposed_found=exposed_found,
        bypasses_found=bypasses_found,
    )
    db.session.add(entry)
    db.session.commit()


def get_history(user_id, limit=25):
    return (
        ScanHistory.query.filter_by(user_id=user_id)
        .order_by(ScanHistory.created_at.desc())
        .limit(limit)
        .all()
    )
