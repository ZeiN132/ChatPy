import socket
import threading
import json
from .crypto_utils import derive_shared_key

class ClientNetwork:
    def __init__(self, signals):
        self.signals = signals
        self.connected = False
        self.sock = None
        self.file = None
        self.keys = {}
        self.username = None

    def connect(self):
        try:
            self.sock = socket.create_connection(("127.0.0.1", 9999))
            self.file = self.sock.makefile("rwb")
            self.connected = True
            threading.Thread(target=self.reader, daemon=True).start()
            return True
        except Exception as e:
            print("[NETWORK ERROR]", e)
            return False

    def get_key(self, user):
        """
        Возвращает ключ шифрования для пользователя.
        Если ключа нет - генерирует его автоматически.
        """
        if user not in self.keys:
            # Автоматическая генерация ключа на основе имен пользователей
            if self.username:
                self.keys[user] = derive_shared_key(self.username, user)
                print(f"[KEY] Generated key for {user}")
        return self.keys.get(user, b"\x00" * 32)

    def reader(self):
        for line in self.file:
            try:
                msg = json.loads(line.decode())
            except Exception as e:
                print("[JSON ERROR]", e)
                continue
            
            msg_type = msg.get("type")
            status = msg.get("status")

            if status == "ok" or status == "error":
                # Сохраняем имя пользователя при успешной авторизации
                if status == "ok" and "username" in msg:
                    self.username = msg["username"]
                self.signals.auth.emit(msg)
            
            elif msg_type == "all_users" or "users" in msg:
                users_list = msg.get("users", [])
                self.signals.users.emit(users_list)

            elif msg_type == "secure_chat_closed":
                peer = msg.get("peer")
                action = msg.get("action")
                
                if peer and action == "delete_all":
                    print(f"[SECURE] Received command to delete secure chat with {peer}")
                    self.signals.secure_chat_closed.emit(peer)
            
            elif msg_type == "secure_session_request":
                # Запрос на начало защищённой сессии
                peer = msg.get("from")
                if peer:
                    print(f"[SECURE] Received secure session request from {peer}")
                    self.signals.secure_session_request.emit(peer)
            
            elif msg_type == "secure_session_response":
                # Ответ на запрос защищённой сессии
                peer = msg.get("from")
                accepted = msg.get("accepted", False)
                if peer is not None:
                    print(f"[SECURE] Received secure session response from {peer}: {accepted}")
                    self.signals.secure_session_response.emit(peer, accepted)
            
            elif msg_type == "msg":
                # Входящее сообщение от другого пользователя
                sender = msg["from"]
                # Автоматически создаем ключ для отправителя, если его нет
                if sender not in self.keys and self.username:
                    self.keys[sender] = derive_shared_key(self.username, sender)
                    print(f"[KEY] Auto-generated key for incoming message from {sender}")
                
                self.signals.message.emit(
                    sender, 
                    msg["payload"], 
                    msg.get("id")
                )
            
            elif msg_type == "msg_sent":
                # Подтверждение отправки своего сообщения
                self.signals.msg_sent.emit(
                    msg.get("id"),
                    msg.get("to"),
                    msg.get("payload")
                )
            
            elif msg_type == "delete_msg":
                msg_id = msg.get("id")
                if msg_id is not None:
                    self.signals.delete.emit(msg_id)
            
            elif msg_type == "history":
                self.signals.history.emit(msg["with"], msg["messages"])

    def send(self, data):
        if not self.connected or self.file is None:
            print("[ERROR] Not connected to server")
            return
        try:
            self.file.write(json.dumps(data).encode() + b"\n")
            self.file.flush()
        except Exception as e:
            print("[SEND ERROR]", e)
            self.connected = False

    def register(self, username, password):
        self.send({"type": "register", "username": username, "password": password})

    def login(self, username, password, is_decoy=False):
        """
        Вход в систему.
        
        Args:
            username: Имя пользователя
            password: Пароль
            is_decoy: True если это вход с фейковым паролем
        """
        self.send({
            "type": "login", 
            "username": username, 
            "password": password,
            "is_decoy": is_decoy
        })

    def request_users(self):
        self.send({"type": "get_users"})

    def request_history(self, peer):
        self.send({"type": "get_history", "with": peer})

    def send_message(self, to, text, secure_mode=False):
        # Убеждаемся, что ключ существует перед отправкой
        if to not in self.keys and self.username:
            self.keys[to] = derive_shared_key(self.username, to)
            print(f"[KEY] Generated key before sending to {to}")
        
        self.send({
            "type": "msg", 
            "to": to, 
            "payload": text,
            "secure_mode": secure_mode
        })

    def delete_message(self, msg_id, for_all=True):
        self.send({
            "type": "delete_msg",
            "id": msg_id,
            "for_all": for_all
        })
    
    def close_secure_chat(self, peer):
        """Закрыть защищённый чат и удалить все сообщения с сервера"""
        self.send({
            "type": "close_secure_chat",
            "peer": peer
        })