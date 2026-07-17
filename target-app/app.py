import sqlite3
import base64
import os
from flask import Flask, request, jsonify, g

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

SEED_USERS = [
    (1, "alice", "password123", "admin", '{"email":"alice@example.com","ssn":"111-22-3333"}'),
    (2, "bob", "letmein", "user", '{"email":"bob@example.com","ssn":"444-55-6666"}'),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                profile TEXT NOT NULL
            )
        """)
        conn.execute("DELETE FROM users")
        conn.executemany(
            "INSERT INTO users (id, username, password, role, profile) VALUES (?, ?, ?, ?, ?)",
            SEED_USERS,
        )
        conn.commit()


def encode_token(user_id: int) -> str:
    return base64.b64encode(str(user_id).encode()).decode()


def decode_token(token: str) -> int | None:
    try:
        return int(base64.b64decode(token.encode()).decode())
    except Exception:
        return None


def get_auth_user_id() -> int | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return decode_token(auth[len("Bearer "):])


@app.get("/")
def health():
    return jsonify({"status": "ok", "message": "Attack on Sandbox target running"})


@app.post("/login")
def login():
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")

    db = get_db()
    # VULN-1: SQL injection — raw f-string, no parameterisation
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    row = db.execute(query).fetchone()

    if row is None:
        return jsonify({"error": "invalid credentials"}), 401

    return jsonify({"token": encode_token(row["id"]), "username": row["username"]})


@app.get("/users/<int:user_id>/data")
def user_data(user_id: int):
    auth_id = get_auth_user_id()
    if auth_id is None:
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    # VULN-2: IDOR — parameterised query (safe) but no ownership check
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404

    return jsonify({
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "profile": row["profile"],
    })


@app.post("/reset")
def reset():
    init_db()
    return jsonify({"status": "reset"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
