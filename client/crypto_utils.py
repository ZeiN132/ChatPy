from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_ephemeral():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_pub_bytes):
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = private_key.exchange(peer_pub)
    key = HKDF(hashes.SHA256(),32,None,b"secure-chat").derive(shared)
    return key

def encrypt_msg(key: bytes, plaintext: bytes):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return {"nonce":nonce.hex(),"ciphertext":ct.hex()}

def decrypt_msg(key: bytes, data: dict):
    aes = AESGCM(key)
    return aes.decrypt(bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]), None)
