import sqlite3
import base64
import os
from flask import Flask, request, jsonify, g

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "notes.db")

SEED_USERS = [
    (1, "annie", "sunflower_2006!", "admin"),
    (2, "bob", "letmein", "user"),
]

SEED_NOTES = [
    (1, 1, "Dear Diary", "Honestly today was kind of perfect. Got coffee with Jamie, finished the chapter I've been stuck on for weeks, and it rained the whole afternoon. I think I'm finally in a good place."),
    (2, 1, "Passwords (DO NOT OPEN)", "gmail: anniesg2006@gmail.com / sunflower_2006!, netflix: annieee / popcorn4ever, bank pin: 4821"),
    (3, 1, "Jamie's birthday", "Dinner at Fleur at 7:30pm. He likes the tiramisu there. Don't forget to book — last time we waited too long and they were full."),
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
                role TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL
            )
        """)
        conn.execute("DELETE FROM notes")
        conn.execute("DELETE FROM users")
        conn.executemany(
            "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
            SEED_USERS,
        )
        conn.executemany(
            "INSERT INTO notes (id, owner_id, title, content) VALUES (?, ?, ?, ?)",
            SEED_NOTES,
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


@app.get("/notes/<int:note_id>")
def get_note(note_id: int):
    auth_id = get_auth_user_id()
    if auth_id is None:
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    # VULN-2a: IDOR read — parameterised query but no ownership check
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404

    return jsonify({
        "id": row["id"],
        "owner_id": row["owner_id"],
        "title": row["title"],
        "content": row["content"],
    })


@app.put("/notes/<int:note_id>")
def update_note(note_id: int):
    auth_id = get_auth_user_id()
    if auth_id is None:
        return jsonify({"error": "unauthorized"}), 401

    db = get_db()
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404

    body = request.get_json(silent=True) or {}
    title = body.get("title", row["title"])
    content = body.get("content", row["content"])

    # VULN-2b: IDOR write — no ownership check before updating
    db.execute(
        "UPDATE notes SET title = ?, content = ? WHERE id = ?",
        (title, content, note_id),
    )
    db.commit()

    return jsonify({"id": note_id, "title": title, "content": content})


@app.post("/reset")
def reset():
    # VULN-3 (stretch): no Authorization check — unauthenticated callers can wipe the DB
    init_db()
    return jsonify({"status": "reset"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
