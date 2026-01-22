import asyncio
import json
import mysql.connector
from mysql.connector import Error
from bcrypt import hashpw, gensalt, checkpw

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root123",
    "database": "secure_chat"
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
                conn = get_db()
                cur = conn.cursor(dictionary=True)
                cur.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
                row = cur.fetchone()
                if not row or not checkpw(password, row["password_hash"].encode()):
                    await safe_write(writer, {"status": "error", "error": "Invalid login"})
                else:
                    await safe_write(writer, {"status": "ok", "username": username, "users": get_all_users()})
                    user = username
                    clients[user] = writer
                    print(f"[LOGIN] User '{user}' logged in from {addr}")
                cur.close()
                conn.close()

            # ---------- GET USERS ----------
            elif mtype == "get_users" and user:
                await safe_write(writer, {"type": "all_users", "users": get_all_users()})

            # ---------- SEND MESSAGE ----------
            elif mtype == "msg" and user:
                to_user = msg["to"]
                payload = msg["payload"]
                
                if isinstance(payload, dict):
                    payload_str = json.dumps(payload)
                else:
                    payload_str = str(payload)
                
                conn = get_db()
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO messages (sender, receiver, payload, ts) 
                    VALUES (%s, %s, %s, NOW())
                """, (user, to_user, payload_str))
                conn.commit()
                
                new_msg_id = cur.lastrowid
                cur.close()
                conn.close()

                # Отправляем получателю
                if to_user in clients:
                    await safe_write(clients[to_user], {
                        "type": "msg", 
                        "from": user, 
                        "payload": payload,
                        "id": new_msg_id
                    })
                
                # Отправляем подтверждение отправителю
                await safe_write(writer, {
                    "type": "msg_sent",
                    "id": new_msg_id,
                    "to": to_user,
                    "payload": payload
                })

            # ---------- GET HISTORY ----------
            elif mtype == "get_history" and user:
                peer = msg["with"]
                conn = get_db()
                cur = conn.cursor(dictionary=True)
                cur.execute("""
                    SELECT id, sender, payload
                    FROM messages
                    WHERE (sender=%s AND receiver=%s) OR (sender=%s AND receiver=%s)
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
                                elif receiver == user and not for_all:
                                    pass
                            else:
                                print(f"[WARN] User {user} tried to delete message {msg_id} without permission")
                    except Exception as e:
                        print(f"[DB DELETE ERROR] {e}")
                    finally:
                        cur.close()
                        conn.close()
                        
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        print(f"[CONNECTION ERROR] {addr} ({user}): {type(e).__name__}")
    except Exception as e:
        print(f"[EXCEPTION] {addr} ({user}): {e}")
    finally:
        # Очистка при отключении
        if user and user in clients:
            del clients[user]
            print(f"[LOGOUT] User '{user}' disconnected from {addr}")
        
        # Безопасное закрытие соединения
        try:
            if not writer.is_closing():
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
            pass  # Игнорируем ошибки при закрытии
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
    print("=" * 50)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped by user")