import asyncio
import json
import hashlib
import os
import secrets
import time
import base64
from pathlib import Path
import ssl
import mysql.connector
from mysql.connector import Error
from bcrypt import hashpw, gensalt, checkpw

DB_RUNTIME_CONFIG = None
DB_MIGRATOR_CONFIG = None

RECOVERY_KDF_DEFAULTS = {
    "kdf": "pbkdf2_sha256",
    "iterations": 200000,
    "dklen": 32
}

RESET_MAX_ATTEMPTS = 5
RESET_LOCK_SECONDS = 60
RESET_FAIL_DELAY = 1.5

LOGIN_MAX_ATTEMPTS = 6
LOGIN_WINDOW_SECONDS = 300
LOGIN_LOCK_SECONDS = 120
LOGIN_FAIL_DELAY = 1.5

_reset_attempts = {}
_login_attempts = {}
DUMMY_PASSWORD_HASH = hashpw(b"chatpy_dummy_password", gensalt())
GROUP_E2E_V2_ENABLED = False

# ----------------- DB -----------------
def _load_env_file():
    explicit = os.getenv("CHATPY_ENV_FILE")
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())

    script_dir = Path(__file__).resolve().parent
    candidates.extend([
        Path.cwd() / ".env",
        script_dir / ".env",
        script_dir.parent / ".env",
    ])

    checked = set()
    for path in candidates:
        marker = str(path.resolve()) if path.exists() else str(path.absolute())
        if marker in checked:
            continue
        checked.add(marker)
        if not path.is_file():
            continue

        with path.open("r", encoding="utf-8") as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip().lstrip("\ufeff")
                if key.lower().startswith("export "):
                    key = key[7:].strip()
                if not key:
                    continue
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)

        print(f"[CONFIG] Loaded .env: {path}")
        return


def _require_env(name):
    value = os.getenv(name)
    if value is None or value.strip() == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _env_truthy(value):
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _parse_tls_min_version(raw):
    if not raw:
        return None
    val = str(raw).strip().lower().replace("tls", "").replace("v", "")
    if val in ("1.2", "1_2", "12"):
        return ssl.TLSVersion.TLSv1_2
    if val in ("1.3", "1_3", "13"):
        return ssl.TLSVersion.TLSv1_3
    return None


def build_server_ssl_context():
    if not _env_truthy(os.getenv("CHATPY_TLS_ENABLED", "0")):
        return None

    certfile = _require_env("CHATPY_TLS_CERTFILE")
    keyfile = _require_env("CHATPY_TLS_KEYFILE")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    min_version = _parse_tls_min_version(os.getenv("CHATPY_TLS_MIN_VERSION", "1.2"))
    if min_version:
        ctx.minimum_version = min_version
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


def init_db_configs():
    global DB_RUNTIME_CONFIG, DB_MIGRATOR_CONFIG, GROUP_E2E_V2_ENABLED
    if DB_RUNTIME_CONFIG is not None and DB_MIGRATOR_CONFIG is not None:
        return

    _load_env_file()
    GROUP_E2E_V2_ENABLED = _env_truthy(os.getenv("CHATPY_GROUP_E2E_V2", "0"))

    host = _require_env("CHATPY_DB_HOST")
    database = _require_env("CHATPY_DB_NAME")
    auth_plugin = os.getenv("CHATPY_DB_AUTH_PLUGIN", "mysql_native_password")

    runtime_user = _require_env("CHATPY_DB_RUNTIME_USER")
    runtime_password = _require_env("CHATPY_DB_RUNTIME_PASSWORD")
    migrator_user = _require_env("CHATPY_DB_MIGRATOR_USER")
    migrator_password = _require_env("CHATPY_DB_MIGRATOR_PASSWORD")

    DB_RUNTIME_CONFIG = {
        "host": host,
        "user": runtime_user,
        "password": runtime_password,
        "database": database,
        "auth_plugin": auth_plugin,
    }
    DB_MIGRATOR_CONFIG = {
        "host": host,
        "user": migrator_user,
        "password": migrator_password,
        "database": database,
        "auth_plugin": auth_plugin,
    }


def get_db():
    if DB_RUNTIME_CONFIG is None:
        raise RuntimeError("DB runtime config is not initialized")
    conn = mysql.connector.connect(**DB_RUNTIME_CONFIG)
    return conn


def get_migrator_db():
    if DB_MIGRATOR_CONFIG is None:
        raise RuntimeError("DB migrator config is not initialized")
    conn = mysql.connector.connect(**DB_MIGRATOR_CONFIG)
    return conn


def ensure_schema():
    conn = get_migrator_db()
    cur = conn.cursor()
    cur.execute("SHOW COLUMNS FROM users LIKE 'recovery_phrase_hash'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN recovery_phrase_hash VARCHAR(128) NULL")
    cur.execute("SHOW COLUMNS FROM users LIKE 'recovery_phrase_salt'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN recovery_phrase_salt VARCHAR(64) NULL")
    cur.execute("SHOW COLUMNS FROM users LIKE 'recovery_kdf_params'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE users ADD COLUMN recovery_kdf_params TEXT NULL")
    cur.execute("SHOW COLUMNS FROM messages LIKE 'deleted_by_sender'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE messages ADD COLUMN deleted_by_sender TINYINT(1) DEFAULT 0")
    cur.execute("SHOW COLUMNS FROM messages LIKE 'deleted_by_receiver'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE messages ADD COLUMN deleted_by_receiver TINYINT(1) DEFAULT 0")
    cur.execute("SHOW COLUMNS FROM messages LIKE 'payload'")
    row = cur.fetchone()
    if row:
        col_type = str(row[1]).lower()
        # Ensure payload can store encrypted files and large JSON
        if "text" not in col_type and "blob" not in col_type:
            cur.execute("ALTER TABLE messages MODIFY payload MEDIUMTEXT")
        elif col_type in ("tinytext",):
            cur.execute("ALTER TABLE messages MODIFY payload MEDIUMTEXT")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS identity_keys (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            device_id VARCHAR(64) NOT NULL,
            sign_pub TEXT NOT NULL,
            dh_pub TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uq_identity (username, device_id),
            INDEX idx_identity_user (username)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            group_uuid VARCHAR(48) NOT NULL,
            name VARCHAR(128) NOT NULL,
            owner VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_group_uuid (group_uuid),
            INDEX idx_group_owner (owner)
        )
    """)
    cur.execute("SHOW COLUMNS FROM chat_groups LIKE 'history_policy'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE chat_groups ADD COLUMN history_policy VARCHAR(16) NOT NULL DEFAULT 'since_join'")
    cur.execute("SHOW COLUMNS FROM chat_groups LIKE 'key_epoch'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE chat_groups ADD COLUMN key_epoch VARCHAR(48) NULL")
    cur.execute("SHOW COLUMNS FROM chat_groups LIKE 'group_key'")
    if not cur.fetchone():
        cur.execute("ALTER TABLE chat_groups ADD COLUMN group_key TEXT NULL")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INT NOT NULL,
            username VARCHAR(64) NOT NULL,
            role VARCHAR(16) NOT NULL DEFAULT 'member',
            added_by VARCHAR(64) NULL,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (group_id, username),
            INDEX idx_group_members_user (username)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_messages (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            group_id INT NOT NULL,
            sender VARCHAR(64) NOT NULL,
            payload MEDIUMTEXT NOT NULL,
            secure_mode TINYINT(1) DEFAULT 0,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_group_messages_group_ts (group_id, ts)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_invites (
            id INT AUTO_INCREMENT PRIMARY KEY,
            group_id INT NOT NULL,
            invited_user VARCHAR(64) NOT NULL,
            invited_by VARCHAR(64) NOT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            responded_at TIMESTAMP NULL DEFAULT NULL,
            UNIQUE KEY uq_group_invite (group_id, invited_user),
            INDEX idx_group_invites_user (invited_user, status)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS group_key_envelopes (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            group_id INT NOT NULL,
            epoch_id VARCHAR(64) NOT NULL,
            sender_username VARCHAR(64) NOT NULL,
            sender_device_id VARCHAR(64) NOT NULL,
            recipient_username VARCHAR(64) NOT NULL,
            recipient_device_id VARCHAR(64) NOT NULL,
            payload MEDIUMTEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_group_key_envelope_target (group_id, epoch_id, recipient_username, recipient_device_id),
            INDEX idx_group_key_env_recipient (recipient_username, group_id, id),
            INDEX idx_group_key_env_group_epoch (group_id, epoch_id)
        )
    """)
    cur.execute("SHOW COLUMNS FROM group_messages LIKE 'payload'")
    g_row = cur.fetchone()
    if g_row:
        g_col_type = str(g_row[1]).lower()
        if "text" not in g_col_type and "blob" not in g_col_type:
            cur.execute("ALTER TABLE group_messages MODIFY payload MEDIUMTEXT")
        elif g_col_type in ("tinytext",):
            cur.execute("ALTER TABLE group_messages MODIFY payload MEDIUMTEXT")
    if not GROUP_E2E_V2_ENABLED:
        cur.execute("""
            SELECT id
            FROM chat_groups
            WHERE key_epoch IS NULL OR key_epoch = '' OR group_key IS NULL OR group_key = ''
        """)
        missing_crypto = cur.fetchall()
        for row in missing_crypto:
            group_id = row[0]
            cur.execute(
                "UPDATE chat_groups SET key_epoch=%s, group_key=%s WHERE id=%s",
                (_new_group_epoch(), _new_group_key_b64(), group_id),
            )
    conn.commit()
    cur.close()
    conn.close()

def normalize_recovery_phrase(phrase):
    return " ".join(phrase.lower().split())

def is_valid_recovery_phrase(phrase):
    parts = phrase.split(" ")
    if len(parts) == 12 or len(parts) == 24:
        return True
    if len(parts) == 1 and len(parts[0]) == 24:
        return True
    return False

def derive_recovery_hash(phrase, salt, kdf_params=None):
    params = RECOVERY_KDF_DEFAULTS.copy()
    if kdf_params:
        params.update(kdf_params)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        phrase.encode("utf-8"),
        salt,
        int(params["iterations"]),
        dklen=int(params["dklen"])
    )
    return dk.hex(), params

def _reset_key(username, addr):
    ip = addr[0] if addr else "unknown"
    return f"{username}:{ip}"


def _login_key(username, addr):
    ip = addr[0] if addr else "unknown"
    return f"{username}:{ip}"


def _dummy_password_check(password):
    try:
        checkpw(password, DUMMY_PASSWORD_HASH)
    except Exception:
        pass


def check_login_limit(key):
    now = time.monotonic()
    entry = _login_attempts.get(key)
    if not entry:
        return True, 0
    lock_until = entry.get("lock_until", 0)
    if lock_until > now:
        return False, lock_until - now
    window_started = entry.get("window_started", now)
    if now - window_started > LOGIN_WINDOW_SECONDS:
        _login_attempts.pop(key, None)
    return True, 0


def record_login_failure(key):
    now = time.monotonic()
    entry = _login_attempts.get(key, {
        "count": 0,
        "window_started": now,
        "lock_until": 0
    })
    if now - entry.get("window_started", now) > LOGIN_WINDOW_SECONDS:
        entry = {
            "count": 0,
            "window_started": now,
            "lock_until": 0
        }
    entry["count"] += 1
    if entry["count"] >= LOGIN_MAX_ATTEMPTS:
        entry["lock_until"] = now + LOGIN_LOCK_SECONDS
        entry["count"] = 0
        entry["window_started"] = now
    _login_attempts[key] = entry


def clear_login_failures(key):
    _login_attempts.pop(key, None)

def check_reset_limit(key):
    now = time.monotonic()
    entry = _reset_attempts.get(key)
    if entry and entry.get("lock_until", 0) > now:
        return False, entry["lock_until"] - now
    return True, 0

def record_reset_failure(key):
    now = time.monotonic()
    entry = _reset_attempts.get(key, {"count": 0, "lock_until": 0})
    entry["count"] += 1
    if entry["count"] >= RESET_MAX_ATTEMPTS:
        entry["lock_until"] = now + RESET_LOCK_SECONDS
        entry["count"] = 0
    _reset_attempts[key] = entry

def clear_reset_failures(key):
    _reset_attempts.pop(key, None)

def get_all_users():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT username FROM users")
    users = [r["username"] for r in cur.fetchall()]
    cur.close()
    conn.close()
    return users

def _ensure_payload_purpose(payload, secure_mode):
    if not isinstance(payload, dict):
        return payload
    if not payload.get("purpose"):
        is_encrypted = "nonce" in payload and "ciphertext" in payload
        is_secure = payload.get("session_id") and payload.get("n")
        if is_encrypted or is_secure:
            payload["purpose"] = "secure" if secure_mode else "normal"
    return payload

def get_undelivered_messages(username):
    """Получить все неотправленные сообщения для пользователя"""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, sender, payload, ts, secure_mode 
        FROM messages 
        WHERE receiver=%s AND delivered=0 AND deleted_by_receiver=0
        ORDER BY ts ASC
    """, (username,))
    messages = cur.fetchall()
    cur.close()
    conn.close()
    return messages

def mark_message_delivered(msg_id):
    """Отметить сообщение как доставленное"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE messages SET delivered=1 WHERE id=%s", (msg_id,))
    conn.commit()
    cur.close()
    conn.close()

def delete_secure_messages(sender, receiver):
    """Удалить все защищённые сообщения между двумя пользователями"""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM messages 
        WHERE secure_mode=1 
        AND ((sender=%s AND receiver=%s AND deleted_by_sender=0) OR (sender=%s AND receiver=%s AND deleted_by_receiver=0))
    """, (sender, receiver, receiver, sender))
    deleted_count = cur.rowcount
    conn.commit()
    cur.close()
    conn.close()
    return deleted_count

def _new_group_uuid():
    return base64.urlsafe_b64encode(secrets.token_bytes(9)).decode("ascii").rstrip("=")


def _new_group_epoch():
    return base64.urlsafe_b64encode(secrets.token_bytes(9)).decode("ascii").rstrip("=")


def _new_group_key_b64():
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _normalize_history_policy(raw_policy):
    policy = str(raw_policy or "").strip().lower()
    if policy in ("since_join", "full"):
        return policy
    return "since_join"


def _normalize_group_name(raw_name):
    cleaned = " ".join(str(raw_name or "").split())
    return cleaned[:128]


def _normalize_user_list(raw_users):
    normalized = []
    seen = set()
    if not isinstance(raw_users, list):
        return normalized
    for value in raw_users:
        username = str(value or "").strip()
        if not username or username in seen:
            continue
        seen.add(username)
        normalized.append(username)
    return normalized


def _parse_group_id(raw_group_id):
    try:
        gid = int(raw_group_id)
    except (TypeError, ValueError):
        return None
    return gid if gid > 0 else None


def _normalize_epoch_id(raw_epoch_id):
    epoch_id = str(raw_epoch_id or "").strip()
    if not epoch_id:
        return None
    return epoch_id[:64]


def _row_to_group_info(row):
    if not isinstance(row, dict):
        return None
    history_policy = _normalize_history_policy(row.get("history_policy"))
    return {
        "group_id": row.get("id"),
        "group_uuid": row.get("group_uuid"),
        "name": row.get("name"),
        "owner": row.get("owner"),
        "role": row.get("role") or "member",
        "member_count": int(row.get("member_count") or 0),
        "history_policy": history_policy,
        "key_epoch": row.get("key_epoch"),
        "group_key": row.get("group_key"),
    }


def get_user_groups(username):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            g.id,
            g.group_uuid,
            g.name,
            g.owner,
            g.history_policy,
            g.key_epoch,
            g.group_key,
            gm.role,
            (
                SELECT COUNT(*)
                FROM group_members gm2
                WHERE gm2.group_id = g.id
            ) AS member_count
        FROM chat_groups g
        JOIN group_members gm ON gm.group_id = g.id
        WHERE gm.username = %s
        ORDER BY g.created_at DESC, g.id DESC
    """, (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    groups = []
    for row in rows:
        info = _row_to_group_info(row)
        if info:
            groups.append(info)
    return groups


def get_group_info_for_user(group_id, username):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            g.id,
            g.group_uuid,
            g.name,
            g.owner,
            g.history_policy,
            g.key_epoch,
            g.group_key,
            gm.role,
            (
                SELECT COUNT(*)
                FROM group_members gm2
                WHERE gm2.group_id = g.id
            ) AS member_count
        FROM chat_groups g
        JOIN group_members gm ON gm.group_id = g.id
        WHERE g.id = %s AND gm.username = %s
        LIMIT 1
    """, (group_id, username))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return _row_to_group_info(row) if row else None


def get_group_members(group_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT username
        FROM group_members
        WHERE group_id = %s
    """, (group_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [r["username"] for r in rows if r.get("username")]


def get_group_member_identity_keys(group_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            gm.username,
            ik.device_id,
            ik.sign_pub,
            ik.dh_pub
        FROM group_members gm
        LEFT JOIN identity_keys ik ON ik.username = gm.username
        WHERE gm.group_id = %s
        ORDER BY gm.username ASC, ik.device_id ASC
    """, (group_id,))
    rows = cur.fetchall() or []
    cur.close()
    conn.close()
    members = []
    for row in rows:
        username = str(row.get("username") or "").strip()
        device_id = str(row.get("device_id") or "").strip()
        sign_pub = row.get("sign_pub")
        dh_pub = row.get("dh_pub")
        if not username or not device_id or not sign_pub or not dh_pub:
            continue
        members.append({
            "username": username,
            "device_id": device_id,
            "sign_pub": sign_pub,
            "dh_pub": dh_pub,
        })
    return members


def _load_group_members_tx(cur, group_id):
    cur.execute("""
        SELECT username
        FROM group_members
        WHERE group_id = %s
    """, (group_id,))
    rows = cur.fetchall() or []
    members = set()
    for row in rows:
        if isinstance(row, dict):
            username = row.get("username")
        elif isinstance(row, (list, tuple)):
            username = row[0] if row else None
        else:
            username = row
        username = str(username or "").strip()
        if username:
            members.add(username)
    return members


def upsert_group_key_envelopes_tx(cur, group_id, epoch_id, sender_username, sender_device_id, envelopes):
    epoch = _normalize_epoch_id(epoch_id)
    sender = str(sender_username or "").strip()
    sender_device = str(sender_device_id or "").strip()[:64]
    if not epoch:
        raise ValueError("epoch_id is required")
    if not sender_device:
        raise ValueError("sender_device_id is required")
    if not isinstance(envelopes, list) or not envelopes:
        raise ValueError("envelopes must be a non-empty list")

    members = _load_group_members_tx(cur, group_id)
    if sender not in members:
        raise ValueError("You are not a member of this group")

    saved = 0
    for entry in envelopes:
        if not isinstance(entry, dict):
            continue
        recipient_username = str(
            entry.get("recipient_username")
            or entry.get("recipient")
            or ""
        ).strip()
        recipient_device_id = str(
            entry.get("recipient_device_id")
            or entry.get("recipient_device")
            or entry.get("device_id")
            or ""
        ).strip()[:64]
        payload = entry.get("payload")
        if payload is None:
            payload = {
                "envelope": {
                    k: v for k, v in entry.items()
                    if k not in {
                        "recipient_username",
                        "recipient",
                        "recipient_device_id",
                        "recipient_device",
                        "device_id",
                    }
                }
            }
        if not recipient_username or not recipient_device_id:
            continue
        if recipient_username not in members:
            raise ValueError(f"Recipient '{recipient_username}' is not a group member")
        if not isinstance(payload, dict):
            raise ValueError("Envelope payload must be a JSON object")
        payload_json = json.dumps(payload, ensure_ascii=False)
        cur.execute("""
            INSERT INTO group_key_envelopes (
                group_id,
                epoch_id,
                sender_username,
                sender_device_id,
                recipient_username,
                recipient_device_id,
                payload
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                sender_username = VALUES(sender_username),
                sender_device_id = VALUES(sender_device_id),
                payload = VALUES(payload),
                created_at = CURRENT_TIMESTAMP
        """, (
            group_id,
            epoch,
            sender,
            sender_device,
            recipient_username,
            recipient_device_id,
            payload_json,
        ))
        saved += 1

    if saved == 0:
        raise ValueError("No valid envelopes were provided")
    return saved


def get_group_key_envelopes_for_user(username, group_id, epoch_id=None, since_id=None, limit=500):
    group_id = _parse_group_id(group_id)
    if not group_id:
        return []
    epoch = _normalize_epoch_id(epoch_id) if epoch_id is not None else None
    if since_id is not None:
        try:
            since = int(since_id)
        except (TypeError, ValueError):
            since = None
    else:
        since = None
    try:
        lim = int(limit)
    except (TypeError, ValueError):
        lim = 500
    lim = max(1, min(lim, 1000))

    conn = get_db()
    cur = conn.cursor(dictionary=True)
    query = """
        SELECT
            id,
            group_id,
            epoch_id,
            sender_username,
            sender_device_id,
            recipient_username,
            recipient_device_id,
            payload
        FROM group_key_envelopes
        WHERE recipient_username = %s AND group_id = %s
    """
    params = [username, group_id]
    if epoch:
        query += " AND epoch_id = %s"
        params.append(epoch)
    if since is not None and since > 0:
        query += " AND id > %s"
        params.append(since)
    query += " ORDER BY id ASC LIMIT %s"
    params.append(lim)
    cur.execute(query, tuple(params))
    rows = cur.fetchall() or []
    cur.close()
    conn.close()

    envelopes = []
    for row in rows:
        payload_raw = row.get("payload")
        try:
            payload = json.loads(payload_raw) if isinstance(payload_raw, str) else payload_raw
        except Exception:
            payload = {"raw": payload_raw}
        envelopes.append({
            "id": row.get("id"),
            "group_id": row.get("group_id"),
            "epoch_id": row.get("epoch_id"),
            "sender_username": row.get("sender_username"),
            "sender_device_id": row.get("sender_device_id"),
            "recipient_username": row.get("recipient_username"),
            "recipient_device_id": row.get("recipient_device_id"),
            "payload": payload,
        })
    return envelopes


def delete_group_key_envelopes_for_group_tx(cur, group_id):
    cur.execute("DELETE FROM group_key_envelopes WHERE group_id = %s", (group_id,))


def delete_group_key_envelopes_for_recipient_tx(cur, group_id, username):
    cur.execute(
        "DELETE FROM group_key_envelopes WHERE group_id = %s AND recipient_username = %s",
        (group_id, username),
    )


def rotate_group_key_tx(cur, group_id):
    epoch = _new_group_epoch()
    group_key = _new_group_key_b64()
    cur.execute(
        "UPDATE chat_groups SET key_epoch = %s, group_key = %s WHERE id = %s",
        (epoch, group_key, group_id),
    )
    return epoch, group_key


def is_group_member(username, group_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT 1
        FROM group_members
        WHERE group_id = %s AND username = %s
        LIMIT 1
    """, (group_id, username))
    exists = cur.fetchone() is not None
    cur.close()
    conn.close()
    return exists


def get_pending_group_invites(username):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT
            gi.id,
            gi.group_id,
            g.group_uuid,
            g.name AS group_name,
            gi.invited_by
        FROM group_invites gi
        JOIN chat_groups g ON g.id = gi.group_id
        WHERE gi.invited_user = %s AND gi.status = 'pending'
        ORDER BY gi.created_at ASC, gi.id ASC
    """, (username,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    invites = []
    for row in rows:
        invites.append({
            "invite_id": row.get("id"),
            "group_id": row.get("group_id"),
            "group_uuid": row.get("group_uuid"),
            "group_name": row.get("group_name"),
            "invited_by": row.get("invited_by"),
        })
    return invites


async def push_group_snapshot(username, writer):
    await safe_write(writer, {
        "type": "groups",
        "groups": get_user_groups(username),
        "group_e2e_v2": GROUP_E2E_V2_ENABLED,
    })
    invites = get_pending_group_invites(username)
    if invites:
        await safe_write(writer, {
            "type": "group_invites",
            "invites": invites
        })


async def broadcast_group_rekey_required(group_id, members, reason, actor=None, epoch_id=None):
    group_id = _parse_group_id(group_id)
    if not group_id:
        return
    members = members if isinstance(members, list) else []
    reason_text = str(reason or "rekey_required").strip() or "rekey_required"
    for member in members:
        if member in clients:
            event = {
                "type": "group_rekey_required",
                "group_id": group_id,
                "reason": reason_text,
                "by": actor,
            }
            if epoch_id:
                event["key_epoch"] = epoch_id
            await safe_write(clients[member], event)


# ----------------- SERVER -----------------
clients = {}  # username -> writer

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    user = None
    print(f"[INFO] New connection from {addr}")
    
    try:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=300.0)
            except asyncio.TimeoutError:
                print(f"[TIMEOUT] Client {addr} timed out")
                break
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                print(f"[DISCONNECT] Client {addr} disconnected: {e}")
                break
                
            if not line: 
                print(f"[DISCONNECT] Client {addr} closed connection")
                break
                
            try:
                msg = json.loads(line.decode())
            except json.JSONDecodeError as e:
                print(f"[JSON ERROR] Invalid JSON from {addr}: {e}")
                continue
                
            mtype = msg.get("type")

            # ---------- REGISTER ----------
            if mtype == "register":
                username = msg["username"]
                password = msg["password"].encode()
                recovery_phrase = msg.get("recovery_phrase", "")
                recovery_phrase = normalize_recovery_phrase(recovery_phrase)
                has_recovery = bool(recovery_phrase)
                if has_recovery and not is_valid_recovery_phrase(recovery_phrase):
                    await safe_write(writer, {
                        "type": "register",
                        "status": "error",
                        "error": "Recovery phrase must be 12/24 words or 24 characters",
                        "auth_stage": "register"
                    })
                    continue
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT username FROM users WHERE username=%s", (username,))
                if cur.fetchone():
                    await safe_write(writer, {
                        "type": "register",
                        "status": "error",
                        "error": "User exists",
                        "auth_stage": "register"
                    })
                else:
                    pw_hash = hashpw(password, gensalt())
                    phrase_hash = None
                    salt_hex = None
                    kdf_params_json = None
                    if has_recovery:
                        salt = secrets.token_bytes(16)
                        phrase_hash, kdf_params = derive_recovery_hash(recovery_phrase, salt)
                        salt_hex = salt.hex()
                        kdf_params_json = json.dumps(kdf_params)
                    cur.execute(
                        "INSERT INTO users(username,password_hash,recovery_phrase_hash,recovery_phrase_salt,recovery_kdf_params) "
                        "VALUES(%s,%s,%s,%s,%s)",
                        (
                            username,
                            pw_hash,
                            phrase_hash,
                            salt_hex,
                            kdf_params_json
                        )
                    )
                    conn.commit()
                    # Auto-login the user after successful registration so messaging works immediately.
                    user = username
                    clients[user] = writer
                    reg_ok = await safe_write(writer, {
                        "type": "register",
                        "status": "ok",
                        "username": username,
                        "users": get_all_users(),
                        "is_decoy": False,
                        "recovery_set": bool(phrase_hash),
                        "auth_stage": "register"
                    })
                    if reg_ok:
                        await safe_write(writer, {
                            "type": "auth",
                            "status": "ok",
                            "username": username,
                            "users": get_all_users(),
                            "is_decoy": False,
                            "recovery_set": bool(phrase_hash)
                        })
                        await push_group_snapshot(username, writer)
                cur.close()
                conn.close()

            # ---------- LOGIN ----------
            elif mtype == "login":
                username = str(msg.get("username", ""))
                password_raw = msg.get("password", "")
                if not isinstance(password_raw, str):
                    password_raw = ""
                password = password_raw.encode()
                login_key = _login_key(username, addr)

                allowed, retry_after = check_login_limit(login_key)
                if not allowed:
                    print(f"[LOGIN LIMIT] username={username} ip={addr[0] if addr else 'unknown'} retry_after={int(retry_after)}s")
                    await asyncio.sleep(LOGIN_FAIL_DELAY)
                    await safe_write(writer, {"type": "auth", "status": "error", "error": "Invalid login"})
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                try:
                    cur.execute("SELECT password_hash, recovery_phrase_hash FROM users WHERE username=%s", (username,))
                    row = cur.fetchone()

                    valid_login = False
                    if row and row.get("password_hash"):
                        try:
                            valid_login = checkpw(password, row["password_hash"])
                        except Exception:
                            valid_login = False
                    else:
                        _dummy_password_check(password)

                    if not valid_login:
                        record_login_failure(login_key)
                        await asyncio.sleep(LOGIN_FAIL_DELAY)
                        await safe_write(writer, {"type": "auth", "status": "error", "error": "Invalid login"})
                        continue

                    clear_login_failures(login_key)
                    print(f"[DEBUG] Processing NORMAL login for {username}")
                    await safe_write(writer, {
                        "type": "auth",
                        "status": "ok",
                        "username": username,
                        "users": get_all_users(),
                        "is_decoy": False,
                        "recovery_set": bool(row.get("recovery_phrase_hash"))
                    })
                    user = username
                    clients[user] = writer
                    print(f"[LOGIN] User '{user}' logged in from {addr}")

                    # Отправка неотправленных сообщений
                    undelivered = get_undelivered_messages(user)
                    print(f"[INFO] User '{user}' has {len(undelivered)} undelivered messages")

                    for msg_data in undelivered:
                        try:
                            payload = msg_data['payload']
                            try:
                                payload = json.loads(payload)
                            except:
                                pass
                            payload = _ensure_payload_purpose(payload, msg_data.get('secure_mode', 0) == 1)

                            success = await safe_write(writer, {
                                "type": "msg",
                                "from": msg_data['sender'],
                                "payload": payload,
                                "id": msg_data['id'],
                                "secure_mode": msg_data.get('secure_mode', 0) == 1
                            })

                            if success:
                                mark_message_delivered(msg_data['id'])
                            else:
                                print(f"[FAILED] Failed to deliver message {msg_data['id']} to {user}")

                        except Exception as e:
                            print(f"[ERROR] Failed to process message {msg_data['id']}: {e}")
                    await push_group_snapshot(user, writer)
                finally:
                    cur.close()
                    conn.close()

            # ---------- RESET PASSWORD ----------
            elif mtype == "reset_password":
                username = msg.get("username", "")
                new_password = msg.get("new_password", "").encode()
                recovery_phrase = normalize_recovery_phrase(msg.get("recovery_phrase", ""))

                key = _reset_key(username, addr)
                allowed, retry_after = check_reset_limit(key)
                if not allowed:
                    await safe_write(writer, {
                        "type": "password_reset",
                        "status": "error",
                        "error": f"Too many attempts. Try again in {int(retry_after)}s."
                    })
                    continue

                if not username or not recovery_phrase or not is_valid_recovery_phrase(recovery_phrase) or not new_password:
                    await safe_write(writer, {
                        "type": "password_reset",
                        "status": "error",
                        "error": "Invalid recovery phrase"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    "SELECT recovery_phrase_hash, recovery_phrase_salt, recovery_kdf_params "
                    "FROM users WHERE username=%s",
                    (username,)
                )
                row = cur.fetchone()

                if not row or not row.get("recovery_phrase_hash"):
                    record_reset_failure(key)
                    await asyncio.sleep(RESET_FAIL_DELAY)
                    await safe_write(writer, {
                        "type": "password_reset",
                        "status": "error",
                        "error": "Recovery phrase not set"
                    })
                    cur.close()
                    conn.close()
                    continue

                try:
                    kdf_params = json.loads(row.get("recovery_kdf_params") or "{}")
                except Exception:
                    kdf_params = {}

                try:
                    salt = bytes.fromhex(row.get("recovery_phrase_salt") or "")
                except Exception:
                    salt = b""

                if not salt:
                    record_reset_failure(key)
                    await asyncio.sleep(RESET_FAIL_DELAY)
                    await safe_write(writer, {
                        "type": "password_reset",
                        "status": "error",
                        "error": "Recovery data invalid"
                    })
                    cur.close()
                    conn.close()
                    continue

                candidate_hash, _ = derive_recovery_hash(recovery_phrase, salt, kdf_params)
                if candidate_hash != row.get("recovery_phrase_hash"):
                    record_reset_failure(key)
                    await asyncio.sleep(RESET_FAIL_DELAY)
                    await safe_write(writer, {
                        "type": "password_reset",
                        "status": "error",
                        "error": "Invalid recovery phrase"
                    })
                    cur.close()
                    conn.close()
                    continue

                pw_hash = hashpw(new_password, gensalt())
                cur.execute("UPDATE users SET password_hash=%s WHERE username=%s", (pw_hash, username))
                conn.commit()
                clear_reset_failures(key)
                await safe_write(writer, {
                    "type": "password_reset",
                    "status": "ok",
                    "message": "Password updated"
                })
                cur.close()
                conn.close()

            # ---------- SET RECOVERY PHRASE ----------
            elif mtype == "set_recovery_phrase":
                username = msg.get("username", "")
                recovery_phrase = normalize_recovery_phrase(msg.get("recovery_phrase", ""))

                if not username or not is_valid_recovery_phrase(recovery_phrase):
                    await safe_write(writer, {
                        "type": "set_recovery_phrase",
                        "status": "error",
                        "error": "Recovery phrase must be 12/24 words or 24 characters"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                cur.execute(
                    "SELECT recovery_phrase_hash FROM users WHERE username=%s",
                    (username,)
                )
                row = cur.fetchone()
                if not row:
                    await safe_write(writer, {
                        "type": "set_recovery_phrase",
                        "status": "error",
                        "error": "User not found"
                    })
                    cur.close()
                    conn.close()
                    continue

                if row.get("recovery_phrase_hash"):
                    await safe_write(writer, {
                        "type": "set_recovery_phrase",
                        "status": "error",
                        "error": "Recovery phrase already set"
                    })
                    cur.close()
                    conn.close()
                    continue

                salt = secrets.token_bytes(16)
                phrase_hash, kdf_params = derive_recovery_hash(recovery_phrase, salt)
                cur.execute(
                    "UPDATE users SET recovery_phrase_hash=%s, recovery_phrase_salt=%s, recovery_kdf_params=%s WHERE username=%s",
                    (phrase_hash, salt.hex(), json.dumps(kdf_params), username)
                )
                conn.commit()
                await safe_write(writer, {
                    "type": "set_recovery_phrase",
                    "status": "ok",
                    "message": "Recovery phrase set"
                })
                cur.close()
                conn.close()

            # ---------- GET USERS ----------
            elif mtype == "get_users" and user:
                await safe_write(writer, {"type": "all_users", "users": get_all_users()})

            # ---------- GET GROUPS ----------
            elif mtype == "get_groups" and user:
                await safe_write(writer, {
                    "type": "groups",
                    "groups": get_user_groups(user),
                    "group_e2e_v2": GROUP_E2E_V2_ENABLED,
                })

            # ---------- GET GROUP INVITES ----------
            elif mtype == "get_group_invites" and user:
                await safe_write(writer, {
                    "type": "group_invites",
                    "invites": get_pending_group_invites(user)
                })

            # ---------- CREATE GROUP ----------
            elif mtype == "create_group" and user:
                group_name = _normalize_group_name(msg.get("name"))
                members = [u for u in _normalize_user_list(msg.get("members")) if u != user]
                history_policy = _normalize_history_policy(msg.get("history_policy"))

                if not group_name:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "create_group",
                        "error": "Group name is required"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                invite_events = []
                group_id = None
                group_uuid = None
                group_epoch = None if GROUP_E2E_V2_ENABLED else _new_group_epoch()
                group_key = None if GROUP_E2E_V2_ENABLED else _new_group_key_b64()
                try:
                    if members:
                        placeholders = ", ".join(["%s"] * len(members))
                        cur.execute(
                            f"SELECT username FROM users WHERE username IN ({placeholders})",
                            tuple(members)
                        )
                        found = {r["username"] for r in cur.fetchall()}
                        missing = [u for u in members if u not in found]
                        if missing:
                            await safe_write(writer, {
                                "type": "group_error",
                                "op": "create_group",
                                "error": f"Unknown users: {', '.join(missing)}"
                            })
                            continue

                    group_uuid = _new_group_uuid()
                    cur.execute("""
                        INSERT INTO chat_groups (group_uuid, name, owner, history_policy, key_epoch, group_key)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (group_uuid, group_name, user, history_policy, group_epoch, group_key))
                    group_id = cur.lastrowid

                    cur.execute("""
                        INSERT INTO group_members (group_id, username, role, added_by)
                        VALUES (%s, %s, 'owner', %s)
                    """, (group_id, user, user))

                    for invited_user in members:
                        cur.execute("""
                            INSERT INTO group_invites (group_id, invited_user, invited_by, status)
                            VALUES (%s, %s, %s, 'pending')
                        """, (group_id, invited_user, user))
                        invite_events.append({
                            "invite_id": cur.lastrowid,
                            "group_id": group_id,
                            "group_uuid": group_uuid,
                            "group_name": group_name,
                            "invited_by": user,
                            "invited_user": invited_user
                        })

                    conn.commit()
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP CREATE ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "create_group",
                        "error": "Failed to create group"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                group_info = get_group_info_for_user(group_id, user)
                if group_info:
                    await safe_write(writer, {
                        "type": "group_created",
                        "group": group_info
                    })

                for invite in invite_events:
                    invited_user = invite.get("invited_user")
                    if invited_user in clients:
                        await safe_write(clients[invited_user], {
                            "type": "group_invite",
                            "invite": {
                                "invite_id": invite.get("invite_id"),
                                "group_id": invite.get("group_id"),
                                "group_uuid": invite.get("group_uuid"),
                                "group_name": invite.get("group_name"),
                                "invited_by": invite.get("invited_by")
                            }
                        })

            # ---------- INVITE GROUP MEMBER ----------
            elif mtype == "invite_group_member" and user:
                group_id = _parse_group_id(msg.get("group_id"))
                invited_user = str(msg.get("username") or "").strip()
                if not group_id or not invited_user:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "invite_group_member",
                        "error": "group_id and username are required"
                    })
                    continue
                if invited_user == user:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "invite_group_member",
                        "error": "You are already in this group"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                invite_id = None
                group_uuid = None
                group_name = None
                try:
                    cur.execute("""
                        SELECT g.group_uuid, g.name
                        FROM chat_groups g
                        JOIN group_members gm ON gm.group_id = g.id
                        WHERE g.id = %s AND gm.username = %s
                        LIMIT 1
                    """, (group_id, user))
                    group_row = cur.fetchone()
                    if not group_row:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "invite_group_member",
                            "error": "You are not a member of this group"
                        })
                        continue
                    group_uuid = group_row.get("group_uuid")
                    group_name = group_row.get("name")

                    cur.execute("SELECT username FROM users WHERE username = %s LIMIT 1", (invited_user,))
                    if not cur.fetchone():
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "invite_group_member",
                            "error": "User does not exist"
                        })
                        continue

                    cur.execute("""
                        SELECT 1
                        FROM group_members
                        WHERE group_id = %s AND username = %s
                        LIMIT 1
                    """, (group_id, invited_user))
                    if cur.fetchone():
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "invite_group_member",
                            "error": "User is already a member"
                        })
                        continue

                    cur.execute("""
                        SELECT id, status
                        FROM group_invites
                        WHERE group_id = %s AND invited_user = %s
                        LIMIT 1
                    """, (group_id, invited_user))
                    invite_row = cur.fetchone()
                    if invite_row and invite_row.get("status") == "pending":
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "invite_group_member",
                            "error": "Invite already pending"
                        })
                        continue

                    if invite_row:
                        invite_id = int(invite_row.get("id"))
                        cur.execute("""
                            UPDATE group_invites
                            SET invited_by = %s, status = 'pending', responded_at = NULL, created_at = NOW()
                            WHERE id = %s
                        """, (user, invite_id))
                    else:
                        cur.execute("""
                            INSERT INTO group_invites (group_id, invited_user, invited_by, status)
                            VALUES (%s, %s, %s, 'pending')
                        """, (group_id, invited_user, user))
                        invite_id = cur.lastrowid

                    conn.commit()
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP INVITE ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "invite_group_member",
                        "error": "Failed to create invite"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                await safe_write(writer, {
                    "type": "group_invite_sent",
                    "group_id": group_id,
                    "username": invited_user
                })
                if invited_user in clients:
                    await safe_write(clients[invited_user], {
                        "type": "group_invite",
                        "invite": {
                            "invite_id": invite_id,
                            "group_id": group_id,
                            "group_uuid": group_uuid,
                            "group_name": group_name,
                            "invited_by": user
                        }
                    })

            # ---------- RESPOND GROUP INVITE ----------
            elif mtype == "respond_group_invite" and user:
                invite_id = _parse_group_id(msg.get("invite_id"))
                accepted = bool(msg.get("accept"))
                if not invite_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "respond_group_invite",
                        "error": "invite_id is required"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                group_id = None
                invited_by = None
                rotated_epoch = None
                rotated_key = None
                try:
                    cur.execute("""
                        SELECT
                            gi.id,
                            gi.group_id,
                            gi.invited_by
                        FROM group_invites gi
                        WHERE gi.id = %s AND gi.invited_user = %s AND gi.status = 'pending'
                        LIMIT 1
                    """, (invite_id, user))
                    invite = cur.fetchone()
                    if not invite:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "respond_group_invite",
                            "error": "Invite not found or already handled"
                        })
                        continue

                    group_id = int(invite.get("group_id"))
                    invited_by = invite.get("invited_by")

                    if accepted:
                        cur.execute("""
                            INSERT INTO group_members (group_id, username, role, added_by)
                            VALUES (%s, %s, 'member', %s)
                            ON DUPLICATE KEY UPDATE role = VALUES(role)
                        """, (group_id, user, invited_by))
                        cur.execute("""
                            UPDATE group_invites
                            SET status = 'accepted', responded_at = NOW()
                            WHERE id = %s
                        """, (invite_id,))
                        if not GROUP_E2E_V2_ENABLED:
                            rotated_epoch, rotated_key = rotate_group_key_tx(cur, group_id)
                    else:
                        cur.execute("""
                            UPDATE group_invites
                            SET status = 'declined', responded_at = NOW()
                            WHERE id = %s
                        """, (invite_id,))

                    conn.commit()
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP INVITE RESPONSE ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "respond_group_invite",
                        "error": "Failed to process invite response"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                await safe_write(writer, {
                    "type": "group_invite_response",
                    "invite_id": invite_id,
                    "group_id": group_id,
                    "accepted": accepted
                })

                if accepted:
                    group_info = get_group_info_for_user(group_id, user)
                    if group_info:
                        await safe_write(writer, {
                            "type": "group_created",
                            "group": group_info
                        })

                    members = get_group_members(group_id)
                    for member in members:
                        if member == user:
                            continue
                        if member in clients:
                            await safe_write(clients[member], {
                                "type": "group_member_added",
                                "group_id": group_id,
                                "username": user
                            })
                    if GROUP_E2E_V2_ENABLED:
                        await broadcast_group_rekey_required(
                            group_id,
                            members,
                            reason="rekey_required_member_added",
                            actor=user,
                        )
                    elif rotated_epoch and rotated_key:
                        for member in members:
                            if member in clients:
                                await safe_write(clients[member], {
                                    "type": "group_key_update",
                                    "group_id": group_id,
                                    "key_epoch": rotated_epoch,
                                    "group_key": rotated_key,
                                    "reason": "member_added",
                                })

                if invited_by in clients:
                    await safe_write(clients[invited_by], {
                        "type": "group_invite_result",
                        "invite_id": invite_id,
                        "group_id": group_id,
                        "username": user,
                        "accepted": accepted
                    })

            # ---------- LEAVE GROUP ----------
            elif mtype == "leave_group" and user:
                group_id = _parse_group_id(msg.get("group_id"))
                if not group_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "leave_group",
                        "error": "group_id is required"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                owner_before = None
                remaining_members = []
                new_owner = None
                rotated_epoch = None
                rotated_key = None
                try:
                    cur.execute("SELECT owner FROM chat_groups WHERE id = %s LIMIT 1", (group_id,))
                    group_row = cur.fetchone()
                    if not group_row:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "leave_group",
                            "error": "Group not found"
                        })
                        continue
                    owner_before = group_row.get("owner")

                    cur.execute("""
                        SELECT role
                        FROM group_members
                        WHERE group_id = %s AND username = %s
                        LIMIT 1
                    """, (group_id, user))
                    if not cur.fetchone():
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "leave_group",
                            "error": "You are not a member of this group"
                        })
                        continue

                    cur.execute("""
                        DELETE FROM group_members
                        WHERE group_id = %s AND username = %s
                    """, (group_id, user))

                    cur.execute("""
                        DELETE FROM group_invites
                        WHERE group_id = %s AND invited_user = %s AND status = 'pending'
                    """, (group_id, user))
                    delete_group_key_envelopes_for_recipient_tx(cur, group_id, user)

                    cur.execute("""
                        SELECT username
                        FROM group_members
                        WHERE group_id = %s
                        ORDER BY joined_at ASC
                    """, (group_id,))
                    remaining_rows = cur.fetchall()
                    remaining_members = [r.get("username") for r in remaining_rows if r.get("username")]

                    if not remaining_members:
                        delete_group_key_envelopes_for_group_tx(cur, group_id)
                        cur.execute("DELETE FROM group_invites WHERE group_id = %s", (group_id,))
                        cur.execute("DELETE FROM group_messages WHERE group_id = %s", (group_id,))
                        cur.execute("DELETE FROM chat_groups WHERE id = %s", (group_id,))
                    elif owner_before == user:
                        new_owner = remaining_members[0]
                        cur.execute("UPDATE chat_groups SET owner = %s WHERE id = %s", (new_owner, group_id))
                        cur.execute("""
                            UPDATE group_members
                            SET role = CASE WHEN username = %s THEN 'owner' ELSE 'member' END
                            WHERE group_id = %s
                        """, (new_owner, group_id))
                        if not GROUP_E2E_V2_ENABLED:
                            rotated_epoch, rotated_key = rotate_group_key_tx(cur, group_id)
                    else:
                        if not GROUP_E2E_V2_ENABLED:
                            rotated_epoch, rotated_key = rotate_group_key_tx(cur, group_id)

                    conn.commit()
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP LEAVE ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "leave_group",
                        "error": "Failed to leave group"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                await safe_write(writer, {
                    "type": "group_left",
                    "group_id": group_id
                })

                for member in remaining_members:
                    if member in clients:
                        await safe_write(clients[member], {
                            "type": "group_member_left",
                            "group_id": group_id,
                            "username": user,
                            "new_owner": new_owner
                        })
                if GROUP_E2E_V2_ENABLED and remaining_members:
                    await broadcast_group_rekey_required(
                        group_id,
                        remaining_members,
                        reason="rekey_required_member_left",
                        actor=user,
                    )
                elif rotated_epoch and rotated_key:
                    for member in remaining_members:
                        if member in clients:
                            await safe_write(clients[member], {
                                "type": "group_key_update",
                                "group_id": group_id,
                                "key_epoch": rotated_epoch,
                                "group_key": rotated_key,
                                "reason": "member_left",
                            })

            # ---------- DELETE GROUP ----------
            elif mtype == "delete_group" and user:
                group_id = _parse_group_id(msg.get("group_id"))
                if not group_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "delete_group",
                        "error": "group_id is required"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                members = []
                try:
                    cur.execute("""
                        SELECT owner
                        FROM chat_groups
                        WHERE id = %s
                        LIMIT 1
                    """, (group_id,))
                    group_row = cur.fetchone()
                    if not group_row:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "delete_group",
                            "error": "Group not found"
                        })
                        continue
                    owner = group_row.get("owner")
                    if owner != user:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "delete_group",
                            "error": "Only group owner can delete this group"
                        })
                        continue

                    cur.execute("""
                        SELECT username
                        FROM group_members
                        WHERE group_id = %s
                    """, (group_id,))
                    rows = cur.fetchall()
                    members = [r.get("username") for r in rows if r.get("username")]

                    delete_group_key_envelopes_for_group_tx(cur, group_id)
                    cur.execute("DELETE FROM group_invites WHERE group_id = %s", (group_id,))
                    cur.execute("DELETE FROM group_messages WHERE group_id = %s", (group_id,))
                    cur.execute("DELETE FROM group_members WHERE group_id = %s", (group_id,))
                    cur.execute("DELETE FROM chat_groups WHERE id = %s", (group_id,))
                    conn.commit()
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP DELETE ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "delete_group",
                        "error": "Failed to delete group"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                for member in members:
                    if member in clients:
                        await safe_write(clients[member], {
                            "type": "group_deleted",
                            "group_id": group_id,
                            "deleted_by": user
                        })

            # ---------- GROUP MESSAGE ----------
            elif mtype == "group_msg" and user:
                group_id = _parse_group_id(msg.get("group_id"))
                payload = msg.get("payload")
                secure_mode = bool(msg.get("secure_mode", False))
                if not group_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_msg",
                        "error": "group_id is required"
                    })
                    continue
                if not is_group_member(user, group_id):
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_msg",
                        "error": "You are not a member of this group"
                    })
                    continue

                payload = _ensure_payload_purpose(payload, secure_mode)
                payload_str = json.dumps(payload) if isinstance(payload, dict) else str(payload)

                conn = get_db()
                cur = conn.cursor()
                try:
                    cur.execute("""
                        INSERT INTO group_messages (group_id, sender, payload, secure_mode, ts)
                        VALUES (%s, %s, %s, %s, NOW())
                    """, (group_id, user, payload_str, 1 if secure_mode else 0))
                    conn.commit()
                    new_msg_id = cur.lastrowid
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP MSG ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_msg",
                        "error": "Failed to send message"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                members = get_group_members(group_id)
                for member in members:
                    if member == user:
                        continue
                    if member in clients:
                        await safe_write(clients[member], {
                            "type": "group_msg",
                            "group_id": group_id,
                            "from": user,
                            "payload": payload,
                            "id": new_msg_id,
                            "secure_mode": secure_mode
                        })

                await safe_write(writer, {
                    "type": "group_msg_sent",
                    "group_id": group_id,
                    "id": new_msg_id,
                    "payload": payload,
                    "secure_mode": secure_mode
                })

            # ---------- GROUP HISTORY ----------
            elif mtype == "get_group_history" and user:
                group_id = _parse_group_id(msg.get("group_id"))
                if not group_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "get_group_history",
                        "error": "group_id is required"
                    })
                    continue
                if not is_group_member(user, group_id):
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "get_group_history",
                        "error": "You are not a member of this group"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                cur.execute("""
                    SELECT g.history_policy, gm.joined_at
                    FROM chat_groups g
                    JOIN group_members gm ON gm.group_id = g.id
                    WHERE g.id = %s AND gm.username = %s
                    LIMIT 1
                """, (group_id, user))
                group_row = cur.fetchone() or {}
                history_policy = _normalize_history_policy(group_row.get("history_policy"))
                joined_at = group_row.get("joined_at")

                history_query = """
                    SELECT id, sender, payload, secure_mode
                    FROM group_messages
                    WHERE group_id = %s
                """
                params = [group_id]
                if history_policy == "since_join" and joined_at is not None:
                    history_query += " AND ts >= %s"
                    params.append(joined_at)
                history_query += " ORDER BY ts"
                cur.execute(history_query, tuple(params))
                rows = cur.fetchall()
                cur.close()
                conn.close()

                for row in rows:
                    try:
                        row["payload"] = json.loads(row["payload"])
                    except Exception:
                        pass
                    row["payload"] = _ensure_payload_purpose(row["payload"], row.get("secure_mode", 0) == 1)

                await safe_write(writer, {
                    "type": "group_history",
                    "group_id": group_id,
                    "messages": rows
                })

            # ---------- GROUP KEYS FOR E2E WRAP ----------
            elif mtype == "get_group_member_keys" and user:
                group_id = _parse_group_id(msg.get("group_id"))
                if not group_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "get_group_member_keys",
                        "error": "group_id is required"
                    })
                    continue
                if not is_group_member(user, group_id):
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "get_group_member_keys",
                        "error": "You are not a member of this group"
                    })
                    continue
                members = get_group_member_identity_keys(group_id)
                await safe_write(writer, {
                    "type": "group_member_keys",
                    "group_id": group_id,
                    "members": members,
                })

            # ---------- GROUP E2E: PUBLISH EPOCH ----------
            elif mtype == "group_publish_epoch" and user:
                if not GROUP_E2E_V2_ENABLED:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_publish_epoch",
                        "error": "Group E2E v2 is disabled on this server"
                    })
                    continue
                group_id = _parse_group_id(msg.get("group_id"))
                epoch_id = _normalize_epoch_id(msg.get("epoch_id"))
                sender_device_id = str(msg.get("sender_device_id") or "").strip()
                envelopes = msg.get("envelopes")
                reason = str(msg.get("reason") or "").strip() or "envelopes_published"
                if not group_id or not epoch_id or not sender_device_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_publish_epoch",
                        "error": "group_id, epoch_id and sender_device_id are required"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                envelope_count = 0
                members = []
                try:
                    cur.execute("""
                        SELECT 1
                        FROM group_members
                        WHERE group_id = %s AND username = %s
                        LIMIT 1
                    """, (group_id, user))
                    if not cur.fetchone():
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "group_publish_epoch",
                            "error": "You are not a member of this group"
                        })
                        continue

                    envelope_count = upsert_group_key_envelopes_tx(
                        cur,
                        group_id,
                        epoch_id,
                        user,
                        sender_device_id,
                        envelopes,
                    )
                    cur.execute(
                        "UPDATE chat_groups SET key_epoch = %s, group_key = NULL WHERE id = %s",
                        (epoch_id, group_id),
                    )
                    cur.execute("""
                        SELECT username
                        FROM group_members
                        WHERE group_id = %s
                    """, (group_id,))
                    members = [r.get("username") for r in cur.fetchall() if r.get("username")]
                    conn.commit()
                except ValueError as e:
                    conn.rollback()
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_publish_epoch",
                        "error": str(e)
                    })
                    continue
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP E2E PUBLISH ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_publish_epoch",
                        "error": "Failed to publish group epoch"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                await safe_write(writer, {
                    "type": "group_epoch_published",
                    "status": "ok",
                    "group_id": group_id,
                    "epoch_id": epoch_id,
                    "envelope_count": envelope_count
                })
                for member in members:
                    if member in clients:
                        await safe_write(clients[member], {
                            "type": "group_key_envelopes_available",
                            "group_id": group_id,
                            "epoch_id": epoch_id,
                            "reason": reason,
                            "from": user
                        })

            # ---------- GROUP E2E: GET ENVELOPES ----------
            elif mtype == "get_group_key_envelopes" and user:
                if not GROUP_E2E_V2_ENABLED:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "get_group_key_envelopes",
                        "error": "Group E2E v2 is disabled on this server"
                    })
                    continue
                group_id = _parse_group_id(msg.get("group_id"))
                epoch_id = _normalize_epoch_id(msg.get("epoch_id")) if msg.get("epoch_id") is not None else None
                since_id = msg.get("since_id")
                limit = msg.get("limit", 500)
                if not group_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "get_group_key_envelopes",
                        "error": "group_id is required"
                    })
                    continue
                if not is_group_member(user, group_id):
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "get_group_key_envelopes",
                        "error": "You are not a member of this group"
                    })
                    continue
                envelopes = get_group_key_envelopes_for_user(
                    user,
                    group_id,
                    epoch_id=epoch_id,
                    since_id=since_id,
                    limit=limit,
                )
                await safe_write(writer, {
                    "type": "group_key_envelopes",
                    "group_id": group_id,
                    "epoch_id": epoch_id,
                    "envelopes": envelopes
                })

            # ---------- SECURE SESSION REQUEST ----------
            elif mtype == "secure_session_request" and user:
                peer = msg.get("peer")
                if peer and peer in clients:
                    # Отправляем запрос собеседнику
                    await safe_write(clients[peer], {
                        "type": "secure_session_request",
                        "from": user
                    })
                    print(f"[SECURE] {user} requested secure session with {peer}")

            # ---------- SECURE SESSION RESPONSE ----------
            elif mtype == "secure_session_response" and user:
                peer = msg.get("peer")
                accepted = msg.get("accepted", False)
                
                if peer and peer in clients:
                    # Отправляем ответ инициатору
                    await safe_write(clients[peer], {
                        "type": "secure_session_response",
                        "from": user,
                        "accepted": accepted
                    })
                    print(f"[SECURE] {user} {'accepted' if accepted else 'declined'} secure session with {peer}")

            # ---------- SECURE KEY EXCHANGE ----------
            elif mtype == "secure_key_exchange" and user:
                peer = msg.get("peer")
                if peer and peer in clients:
                    fwd = dict(msg)
                    fwd["from"] = user
                    await safe_write(clients[peer], fwd)
                    print(f"[SECURE] Relayed key exchange from {user} to {peer}")

            # ---------- NORMAL HANDSHAKE ----------
            elif mtype == "normal_handshake" and user:
                peer = msg.get("peer")
                if peer and peer in clients:
                    fwd = dict(msg)
                    fwd["from"] = user
                    await safe_write(clients[peer], fwd)
                    print(f"[NORMAL] Relayed normal handshake from {user} to {peer}")

            # ---------- SET IDENTITY KEYS ----------
            elif mtype == "set_identity_keys" and user:
                device_id = msg.get("device_id")
                sign_pub = msg.get("sign_pub")
                dh_pub = msg.get("dh_pub")
                if not device_id or not sign_pub or not dh_pub:
                    await safe_write(writer, {
                        "type": "identity_keys_set",
                        "status": "error",
                        "error": "Missing identity key fields"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO identity_keys (username, device_id, sign_pub, dh_pub)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE sign_pub=%s, dh_pub=%s
                """, (user, device_id, sign_pub, dh_pub, sign_pub, dh_pub))
                conn.commit()
                cur.close()
                conn.close()

                await safe_write(writer, {
                    "type": "identity_keys_set",
                    "status": "ok",
                    "device_id": device_id
                })

            # ---------- GET IDENTITY KEYS ----------
            elif mtype == "get_identity_keys" and user:
                target = msg.get("username") or msg.get("peer")
                if not target:
                    await safe_write(writer, {
                        "type": "identity_keys",
                        "status": "error",
                        "error": "Username missing"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                cur.execute("""
                    SELECT device_id, sign_pub, dh_pub
                    FROM identity_keys
                    WHERE username=%s
                """, (target,))
                rows = cur.fetchall()
                cur.close()
                conn.close()

                await safe_write(writer, {
                    "type": "identity_keys",
                    "username": target,
                    "keys": rows
                })

            # ---------- SEND MESSAGE ----------
            elif mtype == "msg" and user:
                to_user = msg["to"]
                payload = msg["payload"]
                secure_mode = msg.get("secure_mode", False)
                payload = _ensure_payload_purpose(payload, secure_mode)
                
                if isinstance(payload, dict):
                    payload_str = json.dumps(payload)
                else:
                    payload_str = str(payload)
                
                conn = get_db()
                cur = conn.cursor()
                
                is_online = to_user in clients
                delivered_status = 0
                
                # Сохраняем с флагом защищённого режима
                cur.execute("""
                    INSERT INTO messages (sender, receiver, payload, delivered, secure_mode, ts) 
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (user, to_user, payload_str, delivered_status, 1 if secure_mode else 0))
                conn.commit()
                
                new_msg_id = cur.lastrowid
                cur.close()
                conn.close()

                if is_online:
                    success = await safe_write(clients[to_user], {
                        "type": "msg", 
                        "from": user, 
                        "payload": payload,
                        "id": new_msg_id,
                        "secure_mode": secure_mode
                    })
                    
                    if success:
                        mark_message_delivered(new_msg_id)
                        print(f"[DELIVERED] Message {new_msg_id} delivered to online user {to_user} (secure: {secure_mode})")
                    else:
                        print(f"[QUEUED] Message {new_msg_id} queued (delivery failed) for {to_user}")
                else:
                    print(f"[QUEUED] Message {new_msg_id} queued for offline user {to_user} (secure: {secure_mode})")
                
                await safe_write(writer, {
                    "type": "msg_sent",
                    "id": new_msg_id,
                    "to": to_user,
                    "payload": payload,
                    "delivered": is_online,
                    "secure_mode": secure_mode
                })

            # ---------- GET HISTORY ----------
            elif mtype == "get_history" and user:
                peer = msg["with"]
                secure_only = msg.get("secure_only", False)
                
                conn = get_db()
                cur = conn.cursor(dictionary=True)
                
                if secure_only:
                    # Только защищённые сообщения (не показываем в истории)
                    cur.execute("""
                        SELECT id, sender, payload, secure_mode
                        FROM messages
                        WHERE secure_mode=1 
                        AND ((sender=%s AND receiver=%s AND deleted_by_sender=0) OR (sender=%s AND receiver=%s AND deleted_by_receiver=0))
                        ORDER BY ts
                    """, (user, peer, peer, user))
                else:
                    # Обычные сообщения (без защищённых)
                    cur.execute("""
                        SELECT id, sender, payload, secure_mode
                        FROM messages
                        WHERE secure_mode=0 
                        AND ((sender=%s AND receiver=%s AND deleted_by_sender=0) OR (sender=%s AND receiver=%s AND deleted_by_receiver=0))
                        ORDER BY ts
                    """, (user, peer, peer, user))
                
                rows = cur.fetchall()
                
                for row in rows:
                    try:
                        row['payload'] = json.loads(row['payload'])
                    except:
                        pass
                    row['payload'] = _ensure_payload_purpose(row['payload'], row.get('secure_mode', 0) == 1)
                
                cur.close()
                conn.close()
                await safe_write(writer, {"type": "history", "with": peer, "messages": rows})

            # ---------- DELETE MESSAGE ----------
            elif mtype == "delete_msg" and user:
                msg_id = msg.get("id")
                for_all = msg.get("for_all", True)
                
                if msg_id:
                    conn = get_db()
                    cur = conn.cursor(dictionary=True)
                    try:
                        cur.execute("SELECT sender, receiver FROM messages WHERE id=%s", (msg_id,))
                        row = cur.fetchone()
                        
                        if row:
                            sender, receiver = row['sender'], row['receiver']
                            
                            if sender == user or receiver == user:
                                if for_all:
                                    cur.execute("DELETE FROM messages WHERE id=%s", (msg_id,))
                                    conn.commit()
                                    print(f"[INFO] Message {msg_id} deleted for all by {user}")

                                    peer = receiver if sender == user else sender
                                    if peer in clients:
                                        await safe_write(clients[peer], {
                                            "type": "delete_msg",
                                            "id": msg_id
                                        })
                                else:
                                    if sender == user:
                                        cur.execute("UPDATE messages SET deleted_by_sender=1 WHERE id=%s", (msg_id,))
                                    else:
                                        cur.execute("UPDATE messages SET deleted_by_receiver=1 WHERE id=%s", (msg_id,))
                                    conn.commit()
                                    print(f"[INFO] Message {msg_id} hidden for {user}")
                            else:
                                print(f"[WARN] User {user} tried to delete message {msg_id} without permission")
                    except Exception as e:
                        print(f"[DB DELETE ERROR] {e}")
                    finally:
                        cur.close()
                        conn.close()

            # ---------- DELETE GROUP MESSAGE ----------
            elif mtype == "group_delete_msg" and user:
                group_id = _parse_group_id(msg.get("group_id"))
                msg_id = _parse_group_id(msg.get("id"))
                if not group_id or not msg_id:
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_delete_msg",
                        "error": "group_id and id are required"
                    })
                    continue

                conn = get_db()
                cur = conn.cursor(dictionary=True)
                deleted = False
                try:
                    cur.execute("""
                        SELECT gm.sender, g.owner
                        FROM group_messages gm
                        JOIN chat_groups g ON g.id = gm.group_id
                        WHERE gm.id = %s AND gm.group_id = %s
                        LIMIT 1
                    """, (msg_id, group_id))
                    row = cur.fetchone()
                    if not row:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "group_delete_msg",
                            "error": "Group message not found"
                        })
                        continue

                    cur.execute("""
                        SELECT role
                        FROM group_members
                        WHERE group_id = %s AND username = %s
                        LIMIT 1
                    """, (group_id, user))
                    member_row = cur.fetchone()
                    if not member_row:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "group_delete_msg",
                            "error": "You are not a member of this group"
                        })
                        continue

                    sender = row.get("sender")
                    owner = row.get("owner")
                    role = str(member_row.get("role") or "").strip().lower()
                    can_delete = (sender == user) or (owner == user) or (role == "owner")
                    if not can_delete:
                        await safe_write(writer, {
                            "type": "group_error",
                            "op": "group_delete_msg",
                            "error": "You can delete only your own messages (or all messages as owner)"
                        })
                        continue

                    cur.execute("""
                        DELETE FROM group_messages
                        WHERE id = %s AND group_id = %s
                    """, (msg_id, group_id))
                    deleted = cur.rowcount > 0
                    conn.commit()
                except Error as e:
                    conn.rollback()
                    print(f"[GROUP DELETE MSG ERROR] {e}")
                    await safe_write(writer, {
                        "type": "group_error",
                        "op": "group_delete_msg",
                        "error": "Failed to delete group message"
                    })
                    continue
                finally:
                    cur.close()
                    conn.close()

                if deleted:
                    members = get_group_members(group_id)
                    for member in members:
                        if member in clients:
                            await safe_write(clients[member], {
                                "type": "group_delete_msg",
                                "group_id": group_id,
                                "id": msg_id,
                                "deleted_by": user
                            })
            
            # ---------- CLOSE SECURE CHAT ----------
            elif mtype == "close_secure_chat" and user:
                peer = msg.get("peer")
                if peer:
                    deleted = delete_secure_messages(user, peer)
                    print(f"[SECURE] Deleted {deleted} secure messages between {user} and {peer}")
                    
                    # Уведомляем собеседника если он онлайн
                    if peer in clients:
                        await safe_write(clients[peer], {
                            "type": "secure_chat_closed",
                            "peer": user,
                            "action": "delete_all"
                        })
                        print(f"[SECURE] Notified {peer} to delete secure messages with {user}")
                        
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[CONNECTION ERROR] {addr} ({user}): {type(e).__name__}")
    except Exception as e:
        print(f"[EXCEPTION] {addr} ({user}): {e}")
        import traceback
        traceback.print_exc()
    finally:
        if user and user in clients:
            del clients[user]
            print(f"[LOGOUT] User '{user}' disconnected from {addr}")
        
        try:
            if not writer.is_closing():
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as e:
            print(f"[CLOSE ERROR] {e}")

async def safe_write(writer, data):
    """Безопасная отправка данных клиенту с обработкой ошибок"""
    try:
        if writer.is_closing():
            return False
        writer.write(json.dumps(data).encode() + b"\n")
        await asyncio.wait_for(writer.drain(), timeout=5.0)
        return True
    except (ConnectionResetError, BrokenPipeError, OSError, asyncio.TimeoutError):
        return False
    except Exception as e:
        print(f"[WRITE ERROR] {e}")
        return False

async def main():
    init_db_configs()
    ensure_schema()
    ssl_ctx = build_server_ssl_context()
    server = await asyncio.start_server(
        handle_client, 
        '0.0.0.0', 
        9999, 
        limit=1024 * 1024 * 10,
        ssl=ssl_ctx,
    )
    print("=" * 50)
    print("Server running on port 9999 (Max packet: 10MB)")
    print("Transport: TLS enabled" if ssl_ctx else "Transport: plaintext (TLS disabled)")
    print("Offline message delivery: ENABLED")
    print("Secure mode (anti-forensic): ENABLED")
    print("Secure session protocol: ENABLED")
    print("Group E2E envelopes: ENABLED (v2)" if GROUP_E2E_V2_ENABLED else "Group E2E envelopes: disabled (legacy group_key mode)")
    print("=" * 50)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except RuntimeError as e:
        print(f"[FATAL] {e}")
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")    
