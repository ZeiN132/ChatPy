import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

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

def generate_ephemeral():
    """Generate X25519 ephemeral keypair and return (private, public_bytes)."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return priv, pub

def load_public_key(public_bytes):
    """Load X25519 public key from raw bytes."""
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)

def load_private_key(private_bytes):
    """Load X25519 private key from raw bytes."""
    return x25519.X25519PrivateKey.from_private_bytes(private_bytes)

def load_ed25519_public_key(public_bytes):
    """Load Ed25519 public key from raw bytes."""
    return ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

def load_ed25519_private_key(private_bytes):
    """Load Ed25519 private key from raw bytes."""
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)

def ecdh_shared_secret(private_key, peer_public_bytes):
    """Compute X25519 shared secret."""
    peer_pub = load_public_key(peer_public_bytes)
    return private_key.exchange(peer_pub)

def _hkdf_expand(key_material, info, length=32):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info
    )
    return hkdf.derive(key_material)

def hkdf_derive(key_material, salt, info, length=32):
    """HKDF with explicit salt and info."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info
    )
    return hkdf.derive(key_material)

def derive_session_chains(shared_secret, initiator):
    """
    Derive send/recv chain keys from shared secret.
    initiator=True means local side sent the first key exchange.
    """
    root = _hkdf_expand(shared_secret, b"chatpy8-root", 32)
    ck1 = _hkdf_expand(root, b"chatpy8-ck1", 32)
    ck2 = _hkdf_expand(root, b"chatpy8-ck2", 32)
    if initiator:
        return ck1, ck2
    return ck2, ck1

def kdf_chain(chain_key):
    """Advance chain key and return (next_chain_key, message_key)."""
    msg_key = hmac.new(chain_key, b"msg", hashlib.sha256).digest()[:32]
    next_chain = hmac.new(chain_key, b"chain", hashlib.sha256).digest()[:32]
    return next_chain, msg_key

def encrypt_msg(key, plaintext, aad=None):
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
    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_msg(key, encrypted_data, aad=None):
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
    plaintext = cipher.decrypt(nonce, ciphertext, aad)
    
    return plaintext
