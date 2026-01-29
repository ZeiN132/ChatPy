import asyncio
import json
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

# ----------------- DB -----------------
def get_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn

def get_all_users():
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT username FROM users")
    users = [r["username"] for r in cur.fetchall()]
    cur.close()
    conn.close()
    return users

def get_undelivered_messages(username):
    """Получить все неотправленные сообщения для пользователя"""
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, sender, payload, ts, secure_mode 
        FROM messages 
        WHERE receiver=%s AND delivered=0
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
        AND ((sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s))
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
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT username FROM users WHERE username=%s", (username,))
                if cur.fetchone():
                    await safe_write(writer, {"status": "error", "error": "User exists"})
                else:
                    pw_hash = hashpw(password, gensalt())
                    cur.execute("INSERT INTO users(username,password_hash) VALUES(%s,%s)", (username, pw_hash))
                    conn.commit()
                    await safe_write(writer, {"status": "ok", "username": username, "users": get_all_users()})
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
                cur.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
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
                        "is_decoy": False
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

            # ---------- SEND MESSAGE ----------
            elif mtype == "msg" and user:
                to_user = msg["to"]
                payload = msg["payload"]
                secure_mode = msg.get("secure_mode", False)
                
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
                        AND ((sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s))
                        ORDER BY ts
                    """, (user, peer, peer, user))
                else:
                    # Обычные сообщения (без защищённых)
                    cur.execute("""
                        SELECT id, sender, payload, secure_mode
                        FROM messages
                        WHERE secure_mode=0 
                        AND ((sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s))
                        ORDER BY ts
                    """, (user, peer, peer, user))
                
                rows = cur.fetchall()
                
                for row in rows:
                    try:
                        row['payload'] = json.loads(row['payload'])
                    except:
                        pass
                
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
                                cur.execute("DELETE FROM messages WHERE id=%s", (msg_id,))
                                conn.commit()
                                print(f"[INFO] Message {msg_id} deleted by {user}")

                                if for_all and sender == user:
                                    peer = receiver
                                    if peer in clients:
                                        await safe_write(clients[peer], {
                                            "type": "delete_msg", 
                                            "id": msg_id
                                        })
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