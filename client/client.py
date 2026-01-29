import asyncio, json
# Исправленный импорт: функции берутся напрямую из файла в той же директории
from crypto_utils import encrypt_msg, decrypt_msg, generate_ephemeral, derive_shared_key

class Client:
    def __init__(self, username):
        self.username = username
        self.keys = {}

    async def connect(self):
        try:
            self.reader, self.writer = await asyncio.open_connection("34.31.148.133", 9999)
            # Отправляем приветствие серверу
            self.send({"type": "hello", "user": self.username})
            return True
        except Exception as e:
            print(f"[CONN ERROR] {e}")
            return False

    def send(self, msg):
        self.writer.write((json.dumps(msg) + "\n").encode())

    async def listen(self):
        while True:
            data = await self.reader.readline()
            if not data: break
            msg = json.loads(data.decode())

            if msg.get("type") == "msg":
                sender = msg["from"]
                payload = msg["payload"]
                
                # Если сообщение зашифровано (содержит nonce)
                if isinstance(payload, dict) and "nonce" in payload:
                    try:
                        key = self.keys.get(sender)
                        if key:
                            decrypted = decrypt_msg(key, payload)
                            print(f"\n[{sender}]: {decrypted.decode()}")
                        else:
                            print(f"\n[{sender}]: (Зашифровано, нет ключа)")
                    except Exception as e:
                        print(f"Ошибка расшифровки: {e}")
                else:
                    print(f"\n[{sender}]: {payload}")
                print("> ", end="")

    async def send_loop(self, peer):
        while True:
            text = await asyncio.to_thread(input, "> ")
            if not text: continue
            
            # Шифруем сообщение перед отправкой
            key = self.keys.get(peer)
            if key:
                encrypted_payload = encrypt_msg(key, text.encode())
                self.send({
                    "type": "msg",
                    "to": peer,
                    "payload": encrypted_payload
                })
            else:
                # Если ключа нет, шлем обычным текстом (или реализуем Handshake)
                self.send({"type": "msg", "to": peer, "payload": text})

async def main():
    name = input("Username: ")
    peer = input("Send to: ")
    client = Client(name)
    if await client.connect():
        # Для теста используем статический ключ (в реале нужен Diffie-Hellman)
        client.keys[peer] = b"\x00" * 32 
        await asyncio.gather(client.listen(), client.send_loop(peer))

if __name__ == "__main__":
    asyncio.run(main())