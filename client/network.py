import socket
import threading
import json

class ClientNetwork:
    def __init__(self, signals):
        self.signals = signals
        self.connected = False
        self.sock = None
        self.file = None
        self.keys = {} 

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
        """
        if user not in self.keys:
            return b"\x00" * 32
        return self.keys.get(user)

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
                self.signals.auth.emit(msg)
            
            elif msg_type == "all_users" or "users" in msg:
                users_list = msg.get("users", [])
                self.signals.users.emit(users_list)
            
            elif msg_type == "msg":
                # Входящее сообщение от другого пользователя
                self.signals.message.emit(
                    msg["from"], 
                    msg["payload"], 
                    msg.get("id")
                )
            
            elif msg_type == "msg_sent":
                # НОВЫЙ ТИП: Подтверждение отправки своего сообщения
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

    def login(self, username, password):
        self.send({"type": "login", "username": username, "password": password})

    def request_users(self):
        self.send({"type": "get_users"})

    def request_history(self, peer):
        self.send({"type": "get_history", "with": peer})

    def send_message(self, to, text):
        self.send({"type": "msg", "to": to, "payload": text})

    def delete_message(self, msg_id, for_all=True):
        self.send({
            "type": "delete_msg",
            "id": msg_id,
            "for_all": for_all
        })