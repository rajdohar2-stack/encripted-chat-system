from __future__ import annotations

import base64
import json
import os
import secrets
import sqlite3
import socket
import ipaddress
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv
from flask import Flask, g, jsonify, request, send_file, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash


PROJECT_DIR = Path(__file__).resolve().parent
load_dotenv(PROJECT_DIR / ".env")
IS_HOSTED = (
    os.getenv("COMMONROOM_HOSTED", "").strip().lower() == "true"
    or os.getenv("RENDER", "").strip().lower() == "true"
)
USER_DATA_DIR = Path(
    os.getenv("COMMONROOM_DATA_DIR", str(Path.home() / ".commonroom"))
).expanduser()
USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE = USER_DATA_DIR / "chat.db"
MESSAGES_DATABASE = USER_DATA_DIR / "encrypted_messages.db"
TLS_CERT_PATH = USER_DATA_DIR / "lan-server.crt"
TLS_KEY_PATH = USER_DATA_DIR / "lan-server.key"
TLS_CA_CERT_PATH = USER_DATA_DIR / "lan-root-ca.crt"
TLS_CA_KEY_PATH = USER_DATA_DIR / "lan-root-ca.key"
FIREBASE_DATABASE_URL = os.getenv("FIREBASE_DATABASE_URL", "").strip()
ALLOWED_ORIGINS = tuple(
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "COMMONROOM_ALLOWED_ORIGINS",
        "" if IS_HOSTED else "*",
    ).split(",")
    if origin.strip()
)
FIREBASE_MESSAGES = None
if FIREBASE_DATABASE_URL:
    import firebase_admin
    from firebase_admin import credentials as firebase_credentials, db as firebase_db

    cred = None
    raw_json = os.getenv("FIREBASE_CREDENTIALS_JSON", "").strip()
    if raw_json:
        try:
            cred = firebase_credentials.Certificate(json.loads(raw_json))
        except Exception as e:
            print(f"ERROR: Could not parse FIREBASE_CREDENTIALS_JSON: {e}", flush=True)

    if not cred:
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        if cred_path:
            resolved_cred = Path(cred_path).resolve()
            if resolved_cred.exists():
                try:
                    cred = firebase_credentials.Certificate(str(resolved_cred))
                except Exception as e:
                    print(f"ERROR: Could not load service account from {cred_path}: {e}", flush=True)
            else:
                print(f"WARNING: GOOGLE_APPLICATION_CREDENTIALS file not found at: {cred_path}", flush=True)

    try:
        firebase_admin.get_app()
    except ValueError:
        if cred:
            firebase_admin.initialize_app(cred, options={"databaseURL": FIREBASE_DATABASE_URL})
        else:
            firebase_admin.initialize_app(options={"databaseURL": FIREBASE_DATABASE_URL})
    FIREBASE_MESSAGES = firebase_db
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024


def lan_ip_address() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 80))
        address = probe.getsockname()[0]
        if not address.startswith("127."):
            return address
    finally:
        probe.close()
    return "127.0.0.1"


def create_lan_certificates() -> str:
    address = lan_ip_address()
    names = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    if address != "127.0.0.1":
        names.append(x509.IPAddress(ipaddress.ip_address(address)))

    ca_key = None
    ca_cert = None
    if TLS_CA_CERT_PATH.exists() and TLS_CA_KEY_PATH.exists():
        try:
            existing_ca = x509.load_pem_x509_certificate(TLS_CA_CERT_PATH.read_bytes())
            existing_ca_key = serialization.load_pem_private_key(TLS_CA_KEY_PATH.read_bytes(), password=None)
            ca_constraints = existing_ca.extensions.get_extension_for_class(x509.BasicConstraints).value
            existing_ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            if (
                isinstance(existing_ca_key, rsa.RSAPrivateKey)
                and ca_constraints.ca
                and existing_ca_key.public_key().public_numbers() == existing_ca.public_key().public_numbers()
                and existing_ca.not_valid_before_utc <= datetime.now(UTC) <= existing_ca.not_valid_after_utc
            ):
                ca_key = existing_ca_key
                ca_cert = existing_ca
        except (OSError, TypeError, ValueError, x509.ExtensionNotFound):
            pass

    now = datetime.now(UTC)
    created_ca = ca_key is None or ca_cert is None
    if created_ca:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Commonroom Local Network CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, data_encipherment=False,
                                         key_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(ca_key, hashes.SHA256())
        )

    if TLS_CERT_PATH.exists() and TLS_KEY_PATH.exists():
        try:
            existing_cert = x509.load_pem_x509_certificate(TLS_CERT_PATH.read_bytes())
            existing_key = serialization.load_pem_private_key(TLS_KEY_PATH.read_bytes(), password=None)
            existing_names = existing_cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            existing_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            ca_key.public_key().verify(
                existing_cert.signature,
                existing_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                existing_cert.signature_hash_algorithm,
            )
            if (
                isinstance(existing_key, rsa.RSAPrivateKey)
                and existing_key.public_key().public_numbers() == existing_cert.public_key().public_numbers()
                and existing_cert.issuer == ca_cert.subject
                and existing_cert.not_valid_before_utc <= now <= existing_cert.not_valid_after_utc
                and all(name in existing_names for name in names)
            ):
                return address
        except (InvalidSignature, OSError, TypeError, ValueError, x509.ExtensionNotFound):
            pass

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, address)])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    if created_ca:
        TLS_CA_KEY_PATH.write_bytes(ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        TLS_CA_CERT_PATH.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    TLS_KEY_PATH.write_bytes(server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    TLS_CERT_PATH.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    return address


LAN_ADDRESS = None if IS_HOSTED else create_lan_certificates()


@contextmanager
def connect_db(database: Path | None = None) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database or DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_db() -> None:
    with connect_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                public_key TEXT NOT NULL,
                key_backup TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS members (
                conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (conversation_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS chat_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                receiver_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (sender_id, receiver_id)
            );
            CREATE INDEX IF NOT EXISTS chat_requests_receiver ON chat_requests(receiver_id, status);
            CREATE INDEX IF NOT EXISTS chat_requests_sender ON chat_requests(sender_id, status);
            INSERT OR IGNORE INTO chat_requests (sender_id, receiver_id, status)
            SELECT m1.user_id, m2.user_id, 'accepted'
            FROM members m1
            JOIN members m2 ON m1.conversation_id = m2.conversation_id AND m1.user_id < m2.user_id
            WHERE (SELECT COUNT(*) FROM members WHERE members.conversation_id = m1.conversation_id) = 2;
            """
        )
        user_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()
        }
        if "key_backup" not in user_columns:
            db.execute("ALTER TABLE users ADD COLUMN key_backup TEXT")
    initialize_messages_db()
    sync_accounts_with_firebase()


def initialize_messages_db() -> None:
    with connect_db(MESSAGES_DATABASE) as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                sender_id TEXT NOT NULL,
                sender_name TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                iv TEXT NOT NULL,
                envelopes TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('text', 'image')),
                attachment_name TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS messages_conversation_id_id
                ON messages(conversation_id, id);
            """
        )

    with connect_db() as account_db:
        existing_table = account_db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'messages'"
        ).fetchone()
        if not existing_table:
            return
        legacy_messages = account_db.execute(
            "SELECT messages.id, messages.conversation_id, messages.sender_id, users.username, "
            "messages.ciphertext, messages.iv, messages.envelopes, messages.kind, "
            "messages.attachment_name, messages.created_at "
            "FROM messages JOIN users ON users.id = messages.sender_id ORDER BY messages.id"
        ).fetchall()

    with connect_db(MESSAGES_DATABASE) as message_db:
        message_db.executemany(
            "INSERT OR IGNORE INTO messages "
            "(id, conversation_id, sender_id, sender_name, ciphertext, iv, envelopes, kind, attachment_name, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            legacy_messages,
        )
        copied = message_db.execute(
            "SELECT COUNT(*) FROM messages WHERE id IN "
            f"({','.join('?' for _ in legacy_messages)})",
            [row[0] for row in legacy_messages],
        ).fetchone()[0] if legacy_messages else 0
        if copied != len(legacy_messages):
            raise RuntimeError("Could not safely migrate every encrypted message.")

    with connect_db() as account_db:
        account_db.execute("DROP TABLE messages")


def sync_accounts_with_firebase() -> None:
    if not FIREBASE_MESSAGES:
        return
    try:
        fb_users = FIREBASE_MESSAGES.reference("accounts/users").get() or {}
        fb_conversations = FIREBASE_MESSAGES.reference("accounts/conversations").get() or {}
        fb_members = FIREBASE_MESSAGES.reference("accounts/members").get() or {}

        with connect_db() as db:
            if isinstance(fb_users, dict):
                for uid, udata in fb_users.items():
                    if isinstance(udata, dict) and "username" in udata and "password_hash" in udata:
                        db.execute(
                            "INSERT OR IGNORE INTO users "
                            "(id, username, password_hash, public_key, key_backup, created_at) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                str(udata.get("id", uid)),
                                str(udata["username"]),
                                str(udata["password_hash"]),
                                str(udata["public_key"]) if isinstance(udata["public_key"], str) else json.dumps(udata["public_key"]),
                                (
                                    str(udata["key_backup"])
                                    if isinstance(udata.get("key_backup"), str)
                                    else json.dumps(udata["key_backup"])
                                    if isinstance(udata.get("key_backup"), dict)
                                    else None
                                ),
                                str(udata.get("created_at", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"))),
                            ),
                        )

            if isinstance(fb_conversations, dict):
                for cid, cdata in fb_conversations.items():
                    if isinstance(cdata, dict) and "id" in cdata:
                        db.execute(
                            "INSERT OR IGNORE INTO conversations (id, title, created_at) VALUES (?, ?, ?)",
                            (
                                int(cdata["id"]),
                                cdata.get("title"),
                                str(cdata.get("created_at", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"))),
                            ),
                        )

            if isinstance(fb_members, dict):
                for mdata in fb_members.values():
                    if isinstance(mdata, dict) and "conversation_id" in mdata and "user_id" in mdata:
                        db.execute(
                            "INSERT OR IGNORE INTO members (conversation_id, user_id) VALUES (?, ?)",
                            (int(mdata["conversation_id"]), str(mdata["user_id"])),
                        )

            # Two-way sync: push local users/conversations/members to Firebase if missing
            local_users = db.execute("SELECT * FROM users").fetchall()
            for u in local_users:
                if isinstance(fb_users, dict) and u["id"] not in fb_users:
                    FIREBASE_MESSAGES.reference(f"accounts/users/{u['id']}").set({
                        "id": u["id"],
                        "username": u["username"],
                        "password_hash": u["password_hash"],
                        "public_key": u["public_key"],
                        "key_backup": u["key_backup"],
                        "created_at": u["created_at"],
                    })

            local_convs = db.execute("SELECT * FROM conversations").fetchall()
            for c in local_convs:
                cid_str = str(c["id"])
                if isinstance(fb_conversations, dict) and cid_str not in fb_conversations:
                    FIREBASE_MESSAGES.reference(f"accounts/conversations/{c['id']}").set({
                        "id": c["id"],
                        "title": c["title"],
                        "created_at": c["created_at"],
                    })

            local_members = db.execute("SELECT * FROM members").fetchall()
            members_to_push = {}
            for m in local_members:
                key = f"{m['conversation_id']}_{m['user_id']}"
                if isinstance(fb_members, dict) and key not in fb_members:
                    members_to_push[key] = {
                        "conversation_id": m["conversation_id"],
                        "user_id": m["user_id"],
                    }
            if members_to_push:
                FIREBASE_MESSAGES.reference("accounts/members").update(members_to_push)

            # Sync chat requests
            fb_requests = FIREBASE_MESSAGES.reference("accounts/requests").get() or {}
            if isinstance(fb_requests, dict):
                for rid, rdata in fb_requests.items():
                    if isinstance(rdata, dict) and "sender_id" in rdata and "receiver_id" in rdata:
                        db.execute(
                            "INSERT OR IGNORE INTO chat_requests (id, sender_id, receiver_id, status, created_at, updated_at) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (
                                int(rdata.get("id", rid)),
                                str(rdata["sender_id"]),
                                str(rdata["receiver_id"]),
                                str(rdata.get("status", "pending")),
                                str(rdata.get("created_at", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"))),
                                str(rdata.get("updated_at", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"))),
                            ),
                        )
            local_requests = db.execute("SELECT * FROM chat_requests").fetchall()
            for r in local_requests:
                rid_str = str(r["id"])
                if isinstance(fb_requests, dict) and rid_str not in fb_requests:
                    FIREBASE_MESSAGES.reference(f"accounts/requests/{r['id']}").set({
                        "id": r["id"],
                        "sender_id": r["sender_id"],
                        "receiver_id": r["receiver_id"],
                        "status": r["status"],
                        "created_at": r["created_at"],
                        "updated_at": r["updated_at"],
                    })
    except Exception as e:
        print(f"WARNING: Sync with Firebase accounts failed: {e}", flush=True)


def token_digest(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def user_payload(row: sqlite3.Row) -> dict[str, Any]:
    public_key = row["public_key"]
    if isinstance(public_key, str):
        public_key = json.loads(public_key)
    return {"id": row["id"], "username": row["username"], "public_key": public_key}


def current_user() -> sqlite3.Row | None:
    if "current_user" in g:
        return g.current_user
    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        g.current_user = None
        return None
    with connect_db() as db:
        g.current_user = db.execute(
            "SELECT users.* FROM users JOIN sessions ON sessions.user_id = users.id "
            "WHERE sessions.token_hash = ?",
            (token_digest(token),),
        ).fetchone()
    return g.current_user


def require_user() -> sqlite3.Row | None:
    user = current_user()
    if user is None:
        return None
    return user


def issue_session(db: sqlite3.Connection, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions (token_hash, user_id) VALUES (?, ?)",
        (token_digest(token), user_id),
    )
    return token


@app.after_request
def add_browser_headers(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    if not request.path.startswith("/api/admin/") and (
        "*" in ALLOWED_ORIGINS or origin in ALLOWED_ORIGINS
    ):
        response.headers["Access-Control-Allow-Origin"] = "*" if "*" in ALLOWED_ORIGINS else origin
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
        if "*" not in ALLOWED_ORIGINS:
            response.vary.add("Origin")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/<path:unused>", methods=["OPTIONS"])
def preflight(unused: str):
    return "", 204


def is_loopback_request() -> bool:
    if any(
        request.headers.get(header)
        for header in ("CF-Connecting-IP", "Forwarded", "X-Forwarded-For", "True-Client-IP")
    ):
        return False
    try:
        return ipaddress.ip_address(request.remote_addr or "").is_loopback
    except ValueError:
        return False


def is_same_origin_request() -> bool:
    origin = request.headers.get("Origin")
    if origin and origin != request.host_url.rstrip("/"):
        return False
    return request.headers.get("Sec-Fetch-Site", "").casefold() != "cross-site"


@app.get("/")
@app.get("/index.html")
def chat_page():
    return send_from_directory(PROJECT_DIR, "index.html")


@app.get("/database.html")
@app.get("/encrypted-messages.html")
def database_page():
    if not is_loopback_request() or not is_same_origin_request():
        return "Encrypted records are available only on this PC. Open https://127.0.0.1:5000/encrypted-messages.html.", 403
    return send_from_directory(PROJECT_DIR, "database.html")


@app.get("/my-encrypted.html")
def my_encrypted_page():
    return send_from_directory(PROJECT_DIR, "my-encrypted.html")


@app.get("/config.js")
def frontend_config():
    return send_from_directory(PROJECT_DIR, "config.js", mimetype="application/javascript")


@app.get("/lan-root-ca.crt")
def download_lan_ca():
    return send_file(TLS_CA_CERT_PATH, mimetype="application/x-x509-ca-cert", as_attachment=True,
                     download_name="commonroom-lan-root-ca.crt")


@app.get("/api/health")
def health():
    if FIREBASE_MESSAGES:
        cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
        cred_exists = Path(cred_path).exists() if cred_path else False
        has_raw_json = bool(os.getenv("FIREBASE_CREDENTIALS_JSON", "").strip())
        return jsonify({
            "ok": True,
            "message_store": "firebase",
            "firebase_cred_path": cred_path,
            "firebase_cred_exists": cred_exists or has_raw_json,
            "firebase_cred_source": "env_json" if has_raw_json else ("file" if cred_exists else "none"),
            "firebase_db_url": FIREBASE_DATABASE_URL[:45] + "..." if len(FIREBASE_DATABASE_URL) > 45 else FIREBASE_DATABASE_URL,
        })
    return jsonify({"ok": True, "message_store": "local"})


def local_admin_error():
    if not is_loopback_request() or not is_same_origin_request():
        return jsonify(error="Encrypted records can only be viewed from this PC. Open https://127.0.0.1:5000/encrypted-messages.html."), 403
    return None


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    public_key = data.get("public_key")
    if not 3 <= len(username) <= 24 or not username.replace("_", "").isalnum():
        return jsonify(error="Use a 3-24 character username with letters, numbers, or underscores."), 400
    if len(password) < 10:
        return jsonify(error="Choose a password with at least 10 characters."), 400
    if not isinstance(public_key, dict) or public_key.get("kty") != "RSA":
        return jsonify(error="A valid RSA public key is required."), 400

    user_id = secrets.token_urlsafe(6).replace("-", "A").replace("_", "B")[:8].upper()
    password_hash = generate_password_hash(password)
    public_key_json = json.dumps(public_key)
    try:
        with connect_db() as db:
            db.execute(
                "INSERT INTO users (id, username, password_hash, public_key) VALUES (?, ?, ?, ?)",
                (user_id, username, password_hash, public_key_json),
            )
            token = issue_session(db, user_id)
        if FIREBASE_MESSAGES:
            try:
                FIREBASE_MESSAGES.reference(f"accounts/users/{user_id}").set({
                    "id": user_id,
                    "username": username,
                    "password_hash": password_hash,
                    "public_key": public_key_json,
                    "created_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception as e:
                print(f"WARNING: Failed to save user to Firebase: {e}", flush=True)
    except sqlite3.IntegrityError:
        return jsonify(error="That username is already taken."), 409
    return jsonify(token=token, user_id=user_id, username=username), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    with connect_db() as db:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None and FIREBASE_MESSAGES:
            try:
                fb_users = FIREBASE_MESSAGES.reference("accounts/users").get() or {}
                if isinstance(fb_users, dict):
                    for uid, udata in fb_users.items():
                        if isinstance(udata, dict) and str(udata.get("username", "")).casefold() == username.casefold():
                            db.execute(
                                "INSERT OR IGNORE INTO users (id, username, password_hash, public_key, created_at) "
                                "VALUES (?, ?, ?, ?, ?)",
                                (
                                    str(udata.get("id", uid)),
                                    str(udata["username"]),
                                    str(udata["password_hash"]),
                                    str(udata["public_key"]) if isinstance(udata["public_key"], str) else json.dumps(udata["public_key"]),
                                    str(udata.get("created_at", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"))),
                                ),
                            )
                user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            except Exception as e:
                print(f"WARNING: On-demand user sync failed: {e}", flush=True)
        if user is None or not check_password_hash(user["password_hash"], password):
            return jsonify(error="Username or password is incorrect."), 401
        token = issue_session(db, user["id"])
    return jsonify(token=token, user_id=user["id"], username=user["username"])


@app.get("/api/me")
def me():
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    return jsonify(user=user_payload(user))


@app.delete("/api/session")
def logout():
    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip()
    if token:
        with connect_db() as db:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
    return jsonify(ok=True)


def direct_conversation_ids(db: sqlite3.Connection, member_ids: list[str]) -> list[int]:
    return [
        row["id"]
        for row in db.execute(
            "SELECT conversations.id FROM conversations "
            "WHERE (conversations.title IS NULL OR trim(conversations.title) = '') "
            "AND (SELECT COUNT(*) FROM members WHERE members.conversation_id = conversations.id) = 2 "
            "AND EXISTS (SELECT 1 FROM members WHERE members.conversation_id = conversations.id "
            "AND members.user_id = ?) "
            "AND EXISTS (SELECT 1 FROM members WHERE members.conversation_id = conversations.id "
            "AND members.user_id = ?) ORDER BY conversations.id",
            member_ids,
        ).fetchall()
    ]


def is_request_accepted(db: sqlite3.Connection, user_a: str, user_b: str) -> bool:
    row = db.execute(
        "SELECT 1 FROM chat_requests WHERE status = 'accepted' AND "
        "((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))",
        (user_a, user_b, user_b, user_a),
    ).fetchone()
    return row is not None


@app.get("/api/users")
def find_users():
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    query = str(request.args.get("q", "")).strip()
    if len(query) < 2:
        return jsonify(users=[])
    with connect_db() as db:
        rows = db.execute(
            "SELECT id, username, public_key FROM users "
            "WHERE id != ? AND (id LIKE ? OR username LIKE ?) LIMIT 12",
            (user["id"], f"%{query}%", f"%{query}%"),
        ).fetchall()
        users = []
        for row in rows:
            u_dict = user_payload(row)
            req = db.execute(
                "SELECT id, sender_id, receiver_id, status FROM chat_requests "
                "WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)",
                (user["id"], row["id"], row["id"], user["id"]),
            ).fetchone()
            has_conv = bool(direct_conversation_ids(db, [user["id"], row["id"]]))
            if has_conv or (req and req["status"] == "accepted"):
                u_dict["relationship"] = "connected"
                u_dict["request_id"] = req["id"] if req else None
            elif req and req["status"] == "pending":
                u_dict["relationship"] = "sent_pending" if req["sender_id"] == user["id"] else "received_pending"
                u_dict["request_id"] = req["id"]
            elif req and req["status"] == "declined":
                u_dict["relationship"] = "declined"
                u_dict["request_id"] = req["id"]
            else:
                u_dict["relationship"] = "none"
                u_dict["request_id"] = None
            users.append(u_dict)
    return jsonify(users=users)


@app.get("/api/requests")
def list_requests():
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    with connect_db() as db:
        incoming_rows = db.execute(
            "SELECT r.id, r.sender_id, r.status, r.created_at, u.username, u.public_key "
            "FROM chat_requests r JOIN users u ON u.id = r.sender_id "
            "WHERE r.receiver_id = ? AND r.status = 'pending' ORDER BY r.id DESC",
            (user["id"],),
        ).fetchall()
        sent_rows = db.execute(
            "SELECT r.id, r.receiver_id, r.status, r.created_at, u.username, u.public_key "
            "FROM chat_requests r JOIN users u ON u.id = r.receiver_id "
            "WHERE r.sender_id = ? ORDER BY r.id DESC LIMIT 40",
            (user["id"],),
        ).fetchall()
        incoming = [
            {
                "id": row["id"],
                "sender": {"id": row["sender_id"], "username": row["username"]},
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in incoming_rows
        ]
        sent = [
            {
                "id": row["id"],
                "receiver": {"id": row["receiver_id"], "username": row["username"]},
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in sent_rows
        ]
    return jsonify(incoming=incoming, sent=sent, pending_count=len(incoming))


@app.post("/api/requests")
def send_chat_request():
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    data = request.get_json(silent=True) or {}
    receiver_id = str(data.get("receiver_id", "")).strip().upper()
    if not receiver_id:
        return jsonify(error="Target user ID is required."), 400
    if receiver_id == user["id"]:
        return jsonify(error="You cannot send a chat request to yourself."), 400

    with connect_db() as db:
        target = db.execute("SELECT id, username FROM users WHERE id = ?", (receiver_id,)).fetchone()
        if not target:
            return jsonify(error="User not found."), 404

        existing = db.execute(
            "SELECT * FROM chat_requests WHERE "
            "(sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)",
            (user["id"], receiver_id, receiver_id, user["id"]),
        ).fetchone()
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")

        if existing:
            if existing["status"] == "accepted":
                return jsonify(error="You are already connected with this user.", status="accepted"), 400
            if existing["sender_id"] == user["id"] and existing["status"] == "pending":
                return jsonify(error="Request already sent. Waiting for response.", status="pending"), 400
            if existing["sender_id"] == receiver_id and existing["status"] == "pending":
                # Mutual request: Auto-accept!
                db.execute(
                    "UPDATE chat_requests SET status = 'accepted', updated_at = ? WHERE id = ?",
                    (now_str, existing["id"]),
                )
                req_id = existing["id"]
                conv_ids = direct_conversation_ids(db, [user["id"], receiver_id])
                if conv_ids:
                    conv_id = conv_ids[0]
                else:
                    cursor = db.execute("INSERT INTO conversations (title) VALUES (NULL)")
                    conv_id = cursor.lastrowid
                    db.executemany(
                        "INSERT INTO members (conversation_id, user_id) VALUES (?, ?)",
                        [(conv_id, user["id"]), (conv_id, receiver_id)],
                    )
                row = db.execute("SELECT * FROM conversations WHERE id = ?", (conv_id,)).fetchone()
                conv_summary = conversation_summary(db, row, user["id"])
                if FIREBASE_MESSAGES:
                    try:
                        FIREBASE_MESSAGES.reference(f"accounts/requests/{req_id}").update({
                            "status": "accepted",
                            "updated_at": now_str,
                        })
                    except Exception as e:
                        print(f"WARNING: Firebase request update failed: {e}", flush=True)
                return jsonify(
                    message="You both sent requests! Connected automatically.",
                    status="accepted",
                    conversation=conv_summary,
                ), 200
            db.execute(
                "UPDATE chat_requests SET sender_id = ?, receiver_id = ?, status = 'pending', updated_at = ? WHERE id = ?",
                (user["id"], receiver_id, now_str, existing["id"]),
            )
            req_id = existing["id"]
        else:
            cursor = db.execute(
                "INSERT INTO chat_requests (sender_id, receiver_id, status) VALUES (?, ?, 'pending')",
                (user["id"], receiver_id),
            )
            req_id = cursor.lastrowid

        if FIREBASE_MESSAGES:
            try:
                FIREBASE_MESSAGES.reference(f"accounts/requests/{req_id}").set({
                    "id": req_id,
                    "sender_id": user["id"],
                    "receiver_id": receiver_id,
                    "status": "pending",
                    "created_at": now_str,
                    "updated_at": now_str,
                })
            except Exception as e:
                print(f"WARNING: Firebase request save failed: {e}", flush=True)

    return jsonify(message="Chat request sent successfully.", request_id=req_id, status="pending"), 201


@app.post("/api/requests/<int:request_id>/accept")
def accept_chat_request(request_id: int):
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    with connect_db() as db:
        req_row = db.execute(
            "SELECT * FROM chat_requests WHERE id = ?", (request_id,)
        ).fetchone()
        if not req_row:
            return jsonify(error="Chat request not found."), 404
        if req_row["receiver_id"] != user["id"]:
            return jsonify(error="You can only accept requests sent to you."), 403
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "UPDATE chat_requests SET status = 'accepted', updated_at = ? WHERE id = ?",
            (now_str, request_id),
        )
        sender_id = req_row["sender_id"]
        conv_ids = direct_conversation_ids(db, [user["id"], sender_id])
        if conv_ids:
            conv_id = conv_ids[0]
        else:
            cursor = db.execute("INSERT INTO conversations (title) VALUES (NULL)")
            conv_id = cursor.lastrowid
            db.executemany(
                "INSERT INTO members (conversation_id, user_id) VALUES (?, ?)",
                [(conv_id, user["id"]), (conv_id, sender_id)],
            )
            if FIREBASE_MESSAGES:
                try:
                    FIREBASE_MESSAGES.reference(f"accounts/conversations/{conv_id}").set({
                        "id": conv_id,
                        "title": None,
                        "created_at": now_str,
                    })
                    FIREBASE_MESSAGES.reference("accounts/members").update({
                        f"{conv_id}_{user['id']}": {"conversation_id": conv_id, "user_id": user["id"]},
                        f"{conv_id}_{sender_id}": {"conversation_id": conv_id, "user_id": sender_id},
                    })
                except Exception as e:
                    print(f"WARNING: Firebase conversation sync failed: {e}", flush=True)

        row = db.execute("SELECT * FROM conversations WHERE id = ?", (conv_id,)).fetchone()
        summary = conversation_summary(db, row, user["id"])

        if FIREBASE_MESSAGES:
            try:
                FIREBASE_MESSAGES.reference(f"accounts/requests/{request_id}").update({
                    "status": "accepted",
                    "updated_at": now_str,
                })
            except Exception as e:
                print(f"WARNING: Firebase request update failed: {e}", flush=True)

    return jsonify(ok=True, conversation=summary)


@app.post("/api/requests/<int:request_id>/decline")
def decline_chat_request(request_id: int):
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    with connect_db() as db:
        req_row = db.execute("SELECT * FROM chat_requests WHERE id = ?", (request_id,)).fetchone()
        if not req_row:
            return jsonify(error="Chat request not found."), 404
        if req_row["receiver_id"] != user["id"]:
            return jsonify(error="You can only decline requests sent to you."), 403
        now_str = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "UPDATE chat_requests SET status = 'declined', updated_at = ? WHERE id = ?",
            (now_str, request_id),
        )
        if FIREBASE_MESSAGES:
            try:
                FIREBASE_MESSAGES.reference(f"accounts/requests/{request_id}").update({
                    "status": "declined",
                    "updated_at": now_str,
                })
            except Exception as e:
                print(f"WARNING: Firebase request update failed: {e}", flush=True)
    return jsonify(ok=True)


@app.delete("/api/requests/<int:request_id>")
def delete_chat_request(request_id: int):
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    with connect_db() as db:
        req_row = db.execute("SELECT * FROM chat_requests WHERE id = ?", (request_id,)).fetchone()
        if not req_row:
            return jsonify(error="Chat request not found."), 404
        if user["id"] not in (req_row["sender_id"], req_row["receiver_id"]):
            return jsonify(error="Unauthorized."), 403
        db.execute("DELETE FROM chat_requests WHERE id = ?", (request_id,))
        if FIREBASE_MESSAGES:
            try:
                FIREBASE_MESSAGES.reference(f"accounts/requests/{request_id}").delete()
            except Exception as e:
                print(f"WARNING: Firebase request delete failed: {e}", flush=True)
    return jsonify(ok=True)


def conversation_for_user(db: sqlite3.Connection, conversation_id: int, user_id: str) -> bool:
    return db.execute(
        "SELECT 1 FROM members WHERE conversation_id = ? AND user_id = ?",
        (conversation_id, user_id),
    ).fetchone() is not None


def conversation_summary(db: sqlite3.Connection, conversation: sqlite3.Row, viewer_id: str) -> dict[str, Any]:
    members = db.execute(
        "SELECT users.id, users.username, users.public_key FROM users "
        "JOIN members ON members.user_id = users.id WHERE members.conversation_id = ? "
        "ORDER BY users.username COLLATE NOCASE",
        (conversation["id"],),
    ).fetchall()
    last_message = latest_message(db, conversation["id"])
    others = [member for member in members if member["id"] != viewer_id]
    title = conversation["title"]
    if not title or title.strip().casefold() in {"none", "null", "undefined"}:
        title = ", ".join(member["username"] for member in others)
    return {
        "id": conversation["id"],
        "title": title or "Saved messages",
        "members": [user_payload(member) for member in members],
        "last_message": last_message,
    }


def latest_message(db: sqlite3.Connection, conversation_id: int) -> dict[str, Any] | None:
    if FIREBASE_MESSAGES:
        records = FIREBASE_MESSAGES.reference(
            f"conversations/{conversation_id}/messages"
        ).order_by_key().limit_to_last(1).get()
        if not records:
            return None
        message_id, message = next(iter(records.items()))
        return {"id": message_id, "kind": message["kind"], "sender_id": message["sender_id"],
                "created_at": message["created_at"]}
    with connect_db(MESSAGES_DATABASE) as message_db:
        row = message_db.execute(
        "SELECT id, kind, sender_id, created_at FROM messages "
        "WHERE conversation_id = ? ORDER BY id DESC LIMIT 1",
        (conversation_id,),
        ).fetchone()
    return dict(row) if row else None


def read_stored_messages(conversation_id: int, after_id: str) -> list[dict[str, Any]]:
    if FIREBASE_MESSAGES:
        message_query = FIREBASE_MESSAGES.reference(
            f"conversations/{conversation_id}/messages"
        ).order_by_key()
        if after_id and after_id != "0":
            message_query = message_query.start_at(after_id)
        records = message_query.get() or {}
        return [
            {"id": message_id, **message}
            for message_id, message in sorted(records.items())
            if not after_id or after_id == "0" or message_id > after_id
        ][:100]

    with connect_db(MESSAGES_DATABASE) as db:
        rows = db.execute(
            "SELECT messages.* FROM messages "
            "WHERE conversation_id = ? AND messages.id > ? ORDER BY messages.id ASC LIMIT 100",
            (conversation_id, max(0, int(after_id or "0"))),
        ).fetchall()
    messages = []
    for row in rows:
        item = dict(row)
        item["envelopes"] = json.loads(item["envelopes"])
        messages.append(item)
    return messages


def save_stored_message(conversation_id: int, user: sqlite3.Row, data: dict[str, Any]) -> dict[str, Any]:
    attachment_name = str(data.get("attachment_name") or "")[:120] if data["kind"] == "image" else None
    if FIREBASE_MESSAGES:
        message = {
            "conversation_id": conversation_id,
            "sender_id": user["id"],
            "sender_name": user["username"],
            "ciphertext": data["ciphertext"],
            "iv": data["iv"],
            "envelopes": data["envelopes"],
            "kind": data["kind"],
            "attachment_name": attachment_name,
            "created_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
        }
        message_ref = FIREBASE_MESSAGES.reference(
            f"conversations/{conversation_id}/messages"
        ).push(message)
        message["id"] = message_ref.key
        return message

    with connect_db(MESSAGES_DATABASE) as db:
        cursor = db.execute(
            "INSERT INTO messages "
            "(conversation_id, sender_id, sender_name, ciphertext, iv, envelopes, kind, attachment_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (conversation_id, user["id"], user["username"], data["ciphertext"], data["iv"],
             json.dumps(data["envelopes"]), data["kind"], attachment_name),
        )
        message = db.execute(
            "SELECT messages.* FROM messages WHERE messages.id = ?",
            (cursor.lastrowid,),
        ).fetchone()
    item = dict(message)
    item["envelopes"] = json.loads(item["envelopes"])
    return item


@app.get("/api/conversations")
def list_conversations():
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    with connect_db() as db:
        rows = db.execute(
            "SELECT conversations.* FROM conversations JOIN members "
            "ON members.conversation_id = conversations.id WHERE members.user_id = ? "
            "ORDER BY conversations.id DESC",
            (user["id"],),
        ).fetchall()
        conversations = [conversation_summary(db, row, user["id"]) for row in rows]
    return jsonify(conversations=conversations)


def merge_firebase_conversations(canonical_id: int, duplicate_ids: list[int]) -> None:
    updates: dict[str, Any] = {}
    canonical_path = f"conversations/{canonical_id}/messages"
    for duplicate_id in duplicate_ids:
        duplicate_path = f"conversations/{duplicate_id}/messages"
        records = FIREBASE_MESSAGES.reference(duplicate_path).get() or {}
        for message_id, message in records.items():
            updates[f"{canonical_path}/{message_id}"] = {
                **message,
                "conversation_id": canonical_id,
            }
        updates[f"conversations/{duplicate_id}/messages"] = None
    if updates:
        FIREBASE_MESSAGES.reference().update(updates)


@app.post("/api/conversations")
def create_conversation():
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    data = request.get_json(silent=True) or {}
    member_ids = data.get("member_ids")
    title_value = data.get("title")
    title = title_value.strip()[:48] if isinstance(title_value, str) else None
    if title and title.casefold() in {"none", "null", "undefined"}:
        title = None
    title = title or None
    if not isinstance(member_ids, list):
        return jsonify(error="Choose at least one chat member."), 400
    member_ids = list(dict.fromkeys([user["id"], *[str(item).strip().upper() for item in member_ids]]))
    if len(member_ids) < 2 or len(member_ids) > 20:
        return jsonify(error="A chat needs 2 to 20 people, including you."), 400

    placeholders = ",".join("?" for _ in member_ids)
    with connect_db() as db:
        members = db.execute(
            f"SELECT id FROM users WHERE id IN ({placeholders})", member_ids
        ).fetchall()
        if len(members) != len(member_ids):
            return jsonify(error="One or more chat IDs could not be found."), 404

        if len(member_ids) == 2 and title is None:
            other_id = [m for m in member_ids if m != user["id"]][0]
            existing_ids = direct_conversation_ids(db, member_ids)
            if not existing_ids and not is_request_accepted(db, user["id"], other_id):
                return jsonify(error="A chat request must be sent and accepted before starting a direct chat."), 403
            if existing_ids:
                canonical_id = existing_ids[0]
                duplicate_ids = existing_ids[1:]
                if duplicate_ids:
                    if FIREBASE_MESSAGES:
                        merge_firebase_conversations(canonical_id, duplicate_ids)
                    else:
                        placeholders = ",".join("?" for _ in duplicate_ids)
                        with connect_db(MESSAGES_DATABASE) as message_db:
                            message_db.execute(
                                f"UPDATE messages SET conversation_id = ? "
                                f"WHERE conversation_id IN ({placeholders})",
                                [canonical_id, *duplicate_ids],
                            )
                    placeholders = ",".join("?" for _ in duplicate_ids)
                    db.execute(
                        f"DELETE FROM conversations WHERE id IN ({placeholders})",
                        duplicate_ids,
                    )
                row = db.execute("SELECT * FROM conversations WHERE id = ?", (canonical_id,)).fetchone()
                return jsonify(conversation=conversation_summary(db, row, user["id"]))

        cursor = db.execute("INSERT INTO conversations (title) VALUES (?)", (title,))
        conversation_id = cursor.lastrowid
        db.executemany(
            "INSERT INTO members (conversation_id, user_id) VALUES (?, ?)",
            [(conversation_id, member_id) for member_id in member_ids],
        )
        row = db.execute("SELECT * FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        summary = conversation_summary(db, row, user["id"])

    if FIREBASE_MESSAGES:
        try:
            FIREBASE_MESSAGES.reference(f"accounts/conversations/{conversation_id}").set({
                "id": conversation_id,
                "title": title,
                "created_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S"),
            })
            members_update = {
                f"{conversation_id}_{member_id}": {
                    "conversation_id": conversation_id,
                    "user_id": member_id,
                }
                for member_id in member_ids
            }
            FIREBASE_MESSAGES.reference("accounts/members").update(members_update)
        except Exception as e:
            print(f"WARNING: Failed to sync conversation to Firebase: {e}", flush=True)

    return jsonify(conversation=summary), 201


@app.get("/api/conversations/<int:conversation_id>/messages")
def get_messages(conversation_id: int):
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    after_id = request.args.get("after", default="0", type=str)
    with connect_db() as db:
        if not conversation_for_user(db, conversation_id, user["id"]):
            return jsonify(error="Chat not found."), 404
    return jsonify(messages=read_stored_messages(conversation_id, after_id))


@app.get("/api/admin/conversations")
def admin_conversations():
    error = local_admin_error()
    if error:
        return error
    with connect_db() as db:
        rows = db.execute("SELECT id, title FROM conversations ORDER BY id DESC").fetchall()
        conversations = []
        for row in rows:
            members = db.execute(
                "SELECT users.id, users.username FROM users "
                "JOIN members ON members.user_id = users.id "
                "WHERE members.conversation_id = ? ORDER BY users.username COLLATE NOCASE",
                (row["id"],),
            ).fetchall()
            conversations.append({
                "id": row["id"],
                "title": (
                    row["title"]
                    if row["title"] and row["title"].strip().casefold() not in {"none", "null", "undefined"}
                    else ", ".join(member["username"] for member in members)
                ),
                "members": [dict(member) for member in members],
                "last_message": latest_message(db, row["id"]),
            })
    return jsonify(conversations=conversations)


@app.get("/api/admin/status")
def admin_status():
    error = local_admin_error()
    if error:
        return error
    return jsonify({
        "message_store": "firebase" if FIREBASE_MESSAGES else "local",
        "database_file": str(MESSAGES_DATABASE) if not FIREBASE_MESSAGES else None,
    })


@app.get("/api/admin/conversations/<int:conversation_id>/messages")
def admin_messages(conversation_id: int):
    error = local_admin_error()
    if error:
        return error
    with connect_db() as db:
        exists = db.execute(
            "SELECT 1 FROM conversations WHERE id = ?", (conversation_id,)
        ).fetchone()
    if not exists:
        return jsonify(error="Conversation not found."), 404
    after_id = request.args.get("after", default="0", type=str)
    return jsonify(messages=read_stored_messages(conversation_id, after_id))


@app.post("/api/conversations/<int:conversation_id>/messages")
def send_message(conversation_id: int):
    user = require_user()
    if user is None:
        return jsonify(error="Sign in to continue."), 401
    data = request.get_json(silent=True) or {}
    ciphertext = data.get("ciphertext")
    iv = data.get("iv")
    envelopes = data.get("envelopes")
    kind = data.get("kind")
    attachment_name = data.get("attachment_name")
    if not isinstance(ciphertext, str) or not ciphertext or len(ciphertext) > 11_300_000:
        return jsonify(error="Message is empty or too large (maximum image size is 8 MB)."), 400
    if not isinstance(iv, str) or not isinstance(envelopes, dict) or kind not in ("text", "image"):
        return jsonify(error="Encrypted message is incomplete."), 400
    if len(iv) > 64 or len(envelopes) > 20 or any(not isinstance(value, str) for value in envelopes.values()):
        return jsonify(error="Encrypted message format is invalid."), 400

    with connect_db() as db:
        member_ids = {
            row[0] for row in db.execute(
                "SELECT user_id FROM members WHERE conversation_id = ?", (conversation_id,)
            ).fetchall()
        }
        if user["id"] not in member_ids or set(envelopes) != member_ids:
            return jsonify(error="Chat members do not match the encrypted key recipients."), 400
        if len(member_ids) == 2:
            other_id = [m for m in member_ids if m != user["id"]][0]
            if not is_request_accepted(db, user["id"], other_id):
                return jsonify(error="Chat request must be accepted before sending messages."), 403
    message = save_stored_message(conversation_id, user, {
        "ciphertext": ciphertext,
        "iv": iv,
        "envelopes": envelopes,
        "kind": kind,
        "attachment_name": attachment_name,
    })
    return jsonify(message=message), 201


@app.errorhandler(413)
def file_too_large(_error):
    return jsonify(error="Upload is too large. Images must be 8 MB or smaller."), 413


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    import traceback
    traceback.print_exc()
    error_msg = str(error) or error.__class__.__name__
    return jsonify(error=f"Server error: {error_msg}"), 500


initialize_db()

if __name__ == "__main__":
    if IS_HOSTED:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")), debug=False)
    else:
        print(f"Commonroom HTTPS: https://{LAN_ADDRESS}:5000/")
        print(f"Install this public CA certificate on trusted devices: {TLS_CA_CERT_PATH}")
        app.run(host="0.0.0.0", port=5000, debug=False, ssl_context=(TLS_CERT_PATH, TLS_KEY_PATH))
