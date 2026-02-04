import asyncio
import json
import hashlib
import secrets
import time
import mysql.connector
from mysql.connector import Error
from bcrypt import hashpw, gensalt, checkpw

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root",
    "database": "secure_chat",
    "auth_plugin": "mysql_native_password"
}

RECOVERY_KDF_DEFAULTS = {
    "kdf": "pbkdf2_sha256",
    "iterations": 200000,
    "dklen": 32
}

RESET_MAX_ATTEMPTS = 5
RESET_LOCK_SECONDS = 60
RESET_FAIL_DELAY = 1.5

_reset_attempts = {}

# ----------------- DB -----------------
def get_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn

def ensure_schema():
    conn = get_db()
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
                cur.close()
                conn.close()

            # ---------- LOGIN ----------
            elif mtype == "login":
                username = msg["username"]
                password = msg["password"].encode()
                is_decoy = msg.get("is_decoy", False)
                
                print(f"[DEBUG] Login attempt: username={username}, is_decoy={is_decoy}")
                
                conn = get_db()
                cur = conn.cursor(dictionary=True)
                cur.execute("SELECT password_hash, recovery_phrase_hash FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
                
                if not row:
                    print(f"[DEBUG] User {username} not found in database")
                    await safe_write(writer, {"status": "error", "error": "Invalid login"})
                    cur.close()
                    conn.close()
                    
                elif is_decoy:
                    print(f"[DEBUG] Processing DECOY login for {username}")
                    # Вход с фейковым паролем - НЕ проверяем основной пароль в БД
                    await safe_write(writer, {
                        "status": "ok", 
                        "username": username, 
                        "users": [],
                        "is_decoy": True
                    })
                    user = username
                    clients[user] = writer
                    print(f"[LOGIN DECOY] User '{user}' logged in with DECOY password from {addr}")
                    cur.close()
                    conn.close()
                    
                elif not checkpw(password, row["password_hash"]):
                    print(f"[DEBUG] Wrong password for {username}")
                    await safe_write(writer, {"status": "error", "error": "Invalid login"})
                    cur.close()
                    conn.close()
                    
                else:
                    print(f"[DEBUG] Processing NORMAL login for {username}")
                    await safe_write(writer, {
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
    ensure_schema()
    server = await asyncio.start_server(
        handle_client, 
        '0.0.0.0', 
        9999, 
        limit=1024 * 1024 * 10 
    )
    print("=" * 50)
    print("Server running on port 9999 (Max packet: 10MB)")
    print("Offline message delivery: ENABLED")
    print("Secure mode (anti-forensic): ENABLED")
    print("Secure session protocol: ENABLED")
    print("=" * 50)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")    
