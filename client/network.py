import socket
import threading
import json
import os
import base64
from .crypto_utils import (
    derive_shared_key,
    generate_ephemeral,
    ecdh_shared_secret,
    derive_session_chains,
    kdf_chain,
    encrypt_msg,
    decrypt_msg
)

class ClientNetwork:
    def __init__(self, signals):
        self.signals = signals
        self.connected = False
        self.sock = None
        self.file = None
        self.keys = {}
        self.sessions = {}
        self.username = None
        self._rekey_after = 100

    def connect(self):
        try:
            self.sock = socket.create_connection(("34.31.148.133", 9999))
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

            if msg_type == "password_reset":
                self.signals.password_reset.emit(msg)
                continue
            if msg_type == "set_recovery_phrase":
                self.signals.set_recovery_phrase.emit(msg)
                continue
            if msg_type == "register":
                self.signals.register.emit(msg)
                continue

            if status == "ok" or status == "error":
                if msg.get("auth_stage") == "register":
                    self.signals.register.emit(msg)
                    continue
                # Сохраняем имя пользователя при успешной авторизации
                if status == "ok" and "username" in msg:
                    self.username = msg["username"]
                self.signals.auth.emit(msg)
                if "users" in msg:
                    self.signals.users.emit(msg.get("users", []))
            
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

            elif msg_type == "secure_key_exchange":
                self._handle_key_exchange(msg)
            
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

    def _new_session(self, peer, initiator, session_id=None):
        priv, pub = generate_ephemeral()
        if session_id is None:
            session_id = base64.urlsafe_b64encode(os.urandom(9)).decode("ascii").rstrip("=")
        return {
            "session_id": session_id,
            "initiator": initiator,
            "my_priv": priv,
            "my_pub": pub,
            "their_pub": None,
            "send_chain": None,
            "recv_chain": None,
            "send_count": 0,
            "recv_count": 0,
            "msg_count": 0,
            "rekey_after": self._rekey_after,
            "established": False,
            "sent_response": False
        }

    def start_secure_session(self, peer, initiator=True, rekey=False):
        if not peer:
            return
        session = self._new_session(peer, initiator)
        self.sessions[peer] = session
        self._send_key_exchange(peer, session, is_response=False, rekey=rekey)

    def clear_session(self, peer):
        if peer in self.sessions:
            self.sessions.pop(peer, None)

    def _send_key_exchange(self, peer, session, is_response=False, rekey=False):
        payload = {
            "type": "secure_key_exchange",
            "peer": peer,
            "from": self.username,
            "pub": base64.b64encode(session["my_pub"]).decode("ascii"),
            "session_id": session["session_id"],
            "response": is_response,
            "rekey": rekey
        }
        self.send(payload)

    def _handle_key_exchange(self, msg):
        peer = msg.get("from") or msg.get("peer")
        pub_b64 = msg.get("pub")
        if not peer or not pub_b64:
            return

        try:
            peer_pub = base64.b64decode(pub_b64)
        except Exception:
            return

        rekey = bool(msg.get("rekey"))
        incoming_sid = msg.get("session_id")
        is_response = bool(msg.get("response"))
        session = self.sessions.get(peer)

        if session is None or rekey:
            # If we receive a response before starting, we are the initiator.
            initiator = True if is_response else False
            session = self._new_session(peer, initiator=initiator, session_id=incoming_sid)
            self.sessions[peer] = session
        elif incoming_sid:
            session["session_id"] = incoming_sid

        session["their_pub"] = peer_pub
        try:
            shared = ecdh_shared_secret(session["my_priv"], peer_pub)
        except Exception:
            return

        send_chain, recv_chain = derive_session_chains(shared, initiator=session["initiator"])
        session["send_chain"] = send_chain
        session["recv_chain"] = recv_chain
        session["established"] = True

        if not msg.get("response") and not session["initiator"] and not session["sent_response"]:
            session["sent_response"] = True
            self._send_key_exchange(peer, session, is_response=True, rekey=rekey)

        try:
            self.signals.secure_session_established.emit(peer)
        except Exception:
            pass

    def encrypt_for(self, peer, plaintext_bytes):
        session = self.sessions.get(peer)
        if not session or not session.get("established"):
            return None

        if session["msg_count"] >= session["rekey_after"]:
            self.start_secure_session(peer, initiator=True, rekey=True)
            session["msg_count"] = 0

        session["send_count"] += 1
        session["send_chain"], msg_key = kdf_chain(session["send_chain"])
        session["msg_count"] += 1
        payload = encrypt_msg(msg_key, plaintext_bytes)
        payload["n"] = session["send_count"]
        payload["session_id"] = session["session_id"]
        return payload

    def decrypt_from(self, peer, encrypted_payload):
        session = self.sessions.get(peer)
        if not session or not session.get("established"):
            raise ValueError("Secure session not established")

        msg_num = encrypted_payload.get("n")
        sess_id = encrypted_payload.get("session_id")
        if not isinstance(msg_num, int) or msg_num <= 0:
            raise ValueError("Invalid message number")
        if sess_id != session["session_id"]:
            raise ValueError("Session mismatch")
        if msg_num != session["recv_count"] + 1:
            raise ValueError("Out-of-order or replayed message")

        session["recv_chain"], msg_key = kdf_chain(session["recv_chain"])
        session["recv_count"] = msg_num
        return decrypt_msg(msg_key, encrypted_payload)

    def register(self, username, password, recovery_phrase):
        self.send({
            "type": "register",
            "username": username,
            "password": password,
            "recovery_phrase": recovery_phrase
        })

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

    def reset_password(self, username, recovery_phrase, new_password):
        self.send({
            "type": "reset_password",
            "username": username,
            "recovery_phrase": recovery_phrase,
            "new_password": new_password
        })

    def set_recovery_phrase(self, username, recovery_phrase):
        self.send({
            "type": "set_recovery_phrase",
            "username": username,
            "recovery_phrase": recovery_phrase
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
