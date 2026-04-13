import os
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Depends,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import bcrypt as _bcrypt
from pydantic import BaseModel, EmailStr

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SECRET_KEY = os.getenv("JWT_SECRET", "reelscholar-super-secret-key")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24
DB_PATH = os.getenv("DB_PATH", "messaging.db")

def _hash_pw(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()

def _verify_pw(password: str, hashed: str) -> bool:
    return _bcrypt.checkpw(password.encode(), hashed.encode())

security = HTTPBearer()

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT    UNIQUE NOT NULL,
            username    TEXT    UNIQUE NOT NULL,
            name        TEXT    NOT NULL,
            password_hash TEXT  NOT NULL,
            is_online   INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS conversations (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        -- Which users belong to each conversation (always exactly 2 for DMs)
        CREATE TABLE IF NOT EXISTS conversation_participants (
            conversation_id INTEGER NOT NULL REFERENCES conversations(id),
            user_id         INTEGER NOT NULL REFERENCES users(id),
            PRIMARY KEY (conversation_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL REFERENCES conversations(id),
            sender_id       INTEGER NOT NULL REFERENCES users(id),
            text            TEXT    NOT NULL,
            is_read         INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user_id(creds: HTTPAuthorizationCredentials = Depends(security)) -> int:
    return decode_token(creds.credentials)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    name: str
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    username: str
    name: str


class UserProfile(BaseModel):
    id: int
    email: str
    username: str
    name: str
    is_online: bool


class SendMessageRequest(BaseModel):
    text: str


class StartConversationRequest(BaseModel):
    other_user_id: int


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    """Tracks live WebSocket connections keyed by user_id."""

    def __init__(self):
        # user_id -> WebSocket
        self._active: dict[int, WebSocket] = {}

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
        self._active[user_id] = ws
        self._set_online(user_id, True)

    def disconnect(self, user_id: int) -> None:
        self._active.pop(user_id, None)
        self._set_online(user_id, False)

    async def send_to(self, user_id: int, payload: dict) -> None:
        ws = self._active.get(user_id)
        if ws:
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                self.disconnect(user_id)

    @staticmethod
    def _set_online(user_id: int, online: bool) -> None:
        conn = get_conn()
        conn.execute(
            "UPDATE users SET is_online = ? WHERE id = ?",
            (1 if online else 0, user_id),
        )
        conn.commit()
        conn.close()


manager = ConnectionManager()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="ReelScholar Messaging API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=AuthResponse, status_code=201)
def register(req: RegisterRequest):
    conn = get_conn()
    existing = conn.execute(
        "SELECT id FROM users WHERE email = ? OR username = ?",
        (req.email, req.username),
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, "Email or username already taken")

    hashed = _hash_pw(req.password)
    cur = conn.execute(
        "INSERT INTO users (email, username, name, password_hash) VALUES (?, ?, ?, ?)",
        (req.email, req.username, req.name, hashed),
    )
    user_id = cur.lastrowid
    conn.commit()
    conn.close()

    return AuthResponse(
        access_token=create_token(user_id),
        user_id=user_id,
        username=req.username,
        name=req.name,
    )


@app.post("/auth/login", response_model=AuthResponse)
def login(req: LoginRequest):
    conn = get_conn()
    row = conn.execute(
        "SELECT id, username, name, password_hash FROM users WHERE email = ?",
        (req.email,),
    ).fetchone()
    conn.close()

    if not row or not _verify_pw(req.password, row["password_hash"]):
        raise HTTPException(400, "Invalid email or password")

    return AuthResponse(
        access_token=create_token(row["id"]),
        user_id=row["id"],
        username=row["username"],
        name=row["name"],
    )


# ---------------------------------------------------------------------------
# User routes
# ---------------------------------------------------------------------------

@app.get("/users/me", response_model=UserProfile)
def me(user_id: int = Depends(get_current_user_id)):
    conn = get_conn()
    row = conn.execute(
        "SELECT id, email, username, name, is_online FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "User not found")
    return dict(row)


@app.get("/users/search")
def search_users(q: str, user_id: int = Depends(get_current_user_id)):
    """Search users by name or username (excludes self)."""
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT id, username, name, is_online
        FROM users
        WHERE id != ?
          AND (username LIKE ? OR name LIKE ? OR email LIKE ?)
        LIMIT 20
        """,
        (user_id, f"%{q}%", f"%{q}%", f"%{q}%"),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Conversation routes
# ---------------------------------------------------------------------------

@app.get("/conversations")
def list_conversations(user_id: int = Depends(get_current_user_id)):
    """
    Return all conversations for the current user, with the other participant's
    info, the last message, and the count of unread messages.
    """
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT
            c.id            AS conversation_id,
            u.id            AS other_user_id,
            u.name          AS other_name,
            u.username      AS other_username,
            u.is_online     AS other_is_online,
            (
                SELECT text FROM messages
                WHERE conversation_id = c.id
                ORDER BY created_at DESC LIMIT 1
            )               AS last_message,
            (
                SELECT created_at FROM messages
                WHERE conversation_id = c.id
                ORDER BY created_at DESC LIMIT 1
            )               AS last_message_at,
            (
                SELECT COUNT(*) FROM messages
                WHERE conversation_id = c.id
                  AND sender_id != ?
                  AND is_read = 0
            )               AS unread_count
        FROM conversations c
        JOIN conversation_participants cp  ON cp.conversation_id = c.id AND cp.user_id = ?
        JOIN conversation_participants cp2 ON cp2.conversation_id = c.id AND cp2.user_id != ?
        JOIN users u ON u.id = cp2.user_id
        ORDER BY last_message_at DESC NULLS LAST
        """,
        (user_id, user_id, user_id),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/conversations", status_code=201)
def start_conversation(
    req: StartConversationRequest,
    user_id: int = Depends(get_current_user_id),
):
    """
    Get or create a DM conversation between the current user and other_user_id.
    Returns {conversation_id}.
    """
    if req.other_user_id == user_id:
        raise HTTPException(400, "Cannot message yourself")

    conn = get_conn()

    # Check the other user exists
    other = conn.execute(
        "SELECT id FROM users WHERE id = ?", (req.other_user_id,)
    ).fetchone()
    if not other:
        conn.close()
        raise HTTPException(404, "User not found")

    # Look for an existing conversation between the two users
    existing = conn.execute(
        """
        SELECT cp1.conversation_id
        FROM conversation_participants cp1
        JOIN conversation_participants cp2
          ON cp1.conversation_id = cp2.conversation_id
        WHERE cp1.user_id = ? AND cp2.user_id = ?
        LIMIT 1
        """,
        (user_id, req.other_user_id),
    ).fetchone()

    if existing:
        conn.close()
        return {"conversation_id": existing["conversation_id"]}

    cur = conn.execute("INSERT INTO conversations DEFAULT VALUES")
    conv_id = cur.lastrowid
    conn.execute(
        "INSERT INTO conversation_participants VALUES (?, ?)", (conv_id, user_id)
    )
    conn.execute(
        "INSERT INTO conversation_participants VALUES (?, ?)", (conv_id, req.other_user_id)
    )
    conn.commit()
    conn.close()
    return {"conversation_id": conv_id}


# ---------------------------------------------------------------------------
# Message routes
# ---------------------------------------------------------------------------

@app.get("/conversations/{conv_id}/messages")
def get_messages(
    conv_id: int,
    limit: int = 50,
    before_id: Optional[int] = None,
    user_id: int = Depends(get_current_user_id),
):
    conn = get_conn()

    # Verify user is a participant
    member = conn.execute(
        "SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ?",
        (conv_id, user_id),
    ).fetchone()
    if not member:
        conn.close()
        raise HTTPException(403, "Not a participant in this conversation")

    # Mark messages from the other person as read
    conn.execute(
        """
        UPDATE messages SET is_read = 1
        WHERE conversation_id = ? AND sender_id != ? AND is_read = 0
        """,
        (conv_id, user_id),
    )
    conn.commit()

    # Fetch messages (newest first, reversed for display)
    if before_id:
        rows = conn.execute(
            """
            SELECT m.id, m.text, m.sender_id, m.is_read, m.created_at,
                   u.name AS sender_name, u.username AS sender_username
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.conversation_id = ? AND m.id < ?
            ORDER BY m.id DESC LIMIT ?
            """,
            (conv_id, before_id, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT m.id, m.text, m.sender_id, m.is_read, m.created_at,
                   u.name AS sender_name, u.username AS sender_username
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.conversation_id = ?
            ORDER BY m.id DESC LIMIT ?
            """,
            (conv_id, limit),
        ).fetchall()
    conn.close()

    # Return in chronological order
    messages = [dict(r) for r in reversed(rows)]
    for m in messages:
        m["is_mine"] = m["sender_id"] == user_id
    return messages


@app.post("/conversations/{conv_id}/messages", status_code=201)
def send_message_http(
    conv_id: int,
    req: SendMessageRequest,
    user_id: int = Depends(get_current_user_id),
):
    """REST fallback for sending a message (WebSocket is preferred)."""
    conn = get_conn()

    member = conn.execute(
        "SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ?",
        (conv_id, user_id),
    ).fetchone()
    if not member:
        conn.close()
        raise HTTPException(403, "Not a participant")

    cur = conn.execute(
        "INSERT INTO messages (conversation_id, sender_id, text) VALUES (?, ?, ?)",
        (conv_id, user_id, req.text.strip()),
    )
    msg_id = cur.lastrowid
    conn.commit()

    row = conn.execute(
        """
        SELECT m.id, m.text, m.sender_id, m.is_read, m.created_at,
               u.name AS sender_name, u.username AS sender_username
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.id = ?
        """,
        (msg_id,),
    ).fetchone()
    conn.close()

    return {**dict(row), "is_mine": True}


# ---------------------------------------------------------------------------
# WebSocket  –  /ws?token=<jwt>
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str):
    """
    Single WebSocket connection per user.

    Client sends:
        {"type": "message", "conversation_id": 1, "text": "Hello!"}

    Server pushes to both sender and recipient:
        {
          "type": "message",
          "id": 42,
          "conversation_id": 1,
          "sender_id": 7,
          "sender_name": "Tatenda Moyo",
          "sender_username": "tatenda",
          "text": "Hello!",
          "created_at": "2026-04-01T12:00:00",
          "is_mine": false   (true when echoed back to sender)
        }

    Server also pushes:
        {"type": "status", "user_id": 7, "is_online": true}
    """
    try:
        user_id = decode_token(token)
    except HTTPException:
        await ws.close(code=4001)
        return

    await manager.connect(user_id, ws)

    # Notify all active connections that this user is online
    await _broadcast_status(user_id, True)

    try:
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({"type": "error", "detail": "Invalid JSON"}))
                continue

            msg_type = data.get("type")

            if msg_type == "message":
                await _handle_ws_message(user_id, data, ws)
            elif msg_type == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
            else:
                await ws.send_text(
                    json.dumps({"type": "error", "detail": f"Unknown type: {msg_type}"})
                )

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(user_id)
        await _broadcast_status(user_id, False)


async def _handle_ws_message(user_id: int, data: dict, ws: WebSocket) -> None:
    conv_id = data.get("conversation_id")
    text = (data.get("text") or "").strip()

    if not conv_id or not text:
        await ws.send_text(
            json.dumps({"type": "error", "detail": "conversation_id and text required"})
        )
        return

    conn = get_conn()

    # Check participant
    member = conn.execute(
        "SELECT 1 FROM conversation_participants WHERE conversation_id = ? AND user_id = ?",
        (conv_id, user_id),
    ).fetchone()
    if not member:
        conn.close()
        await ws.send_text(json.dumps({"type": "error", "detail": "Not a participant"}))
        return

    # Save message
    cur = conn.execute(
        "INSERT INTO messages (conversation_id, sender_id, text) VALUES (?, ?, ?)",
        (conv_id, user_id, text),
    )
    msg_id = cur.lastrowid
    conn.commit()

    # Fetch full message row
    row = conn.execute(
        """
        SELECT m.id, m.text, m.sender_id, m.created_at,
               u.name AS sender_name, u.username AS sender_username
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.id = ?
        """,
        (msg_id,),
    ).fetchone()

    # Find other participants
    other_ids = [
        r["user_id"]
        for r in conn.execute(
            "SELECT user_id FROM conversation_participants WHERE conversation_id = ? AND user_id != ?",
            (conv_id, user_id),
        ).fetchall()
    ]
    conn.close()

    base_payload = {
        "type": "message",
        "id": row["id"],
        "conversation_id": conv_id,
        "sender_id": row["sender_id"],
        "sender_name": row["sender_name"],
        "sender_username": row["sender_username"],
        "text": row["text"],
        "created_at": row["created_at"],
    }

    # Echo back to sender with is_mine=True
    await manager.send_to(user_id, {**base_payload, "is_mine": True})

    # Deliver to recipients with is_mine=False
    for other_id in other_ids:
        await manager.send_to(other_id, {**base_payload, "is_mine": False})


async def _broadcast_status(user_id: int, is_online: bool) -> None:
    """Notify all connected users about an online status change."""
    payload = {"type": "status", "user_id": user_id, "is_online": is_online}
    for uid in list(manager._active.keys()):
        await manager.send_to(uid, payload)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {"message": "ReelScholar Messaging API is running", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}
