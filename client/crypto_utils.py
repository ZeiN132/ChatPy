import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def derive_shared_key(user1, user2):
    """
    Генерирует детерминированный общий ключ для двух пользователей.
    Ключ будет одинаковым независимо от порядка пользователей.
    """
    # Сортируем имена для детерминированности
    users = sorted([user1, user2])
    # Создаем строку для хеширования
    key_material = f"{users[0]}:{users[1]}:secret_salt_12345".encode()
    # Используем SHA-256 для получения 32-байтного ключа
    return hashlib.sha256(key_material).digest()

def encrypt_msg(key, plaintext):
    """
    Шифрует сообщение с использованием ChaCha20-Poly1305.
    
    Args:
        key: 32-байтный ключ шифрования
        plaintext: bytes или str для шифрования
    
    Returns:
        dict с nonce и ciphertext (в base64 для JSON)
    """
    import base64
    
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)  # ChaCha20Poly1305 использует 12-байтный nonce
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_msg(key, encrypted_data):
    """
    Расшифровывает сообщение.
    
    Args:
        key: 32-байтный ключ шифрования
        encrypted_data: dict с nonce и ciphertext (в base64)
    
    Returns:
        bytes расшифрованных данных
    """
    import base64
    
    if not isinstance(encrypted_data, dict):
        raise ValueError("encrypted_data должен быть словарем с 'nonce' и 'ciphertext'")
    
    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    cipher = ChaCha20Poly1305(key)
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    
    return plaintext