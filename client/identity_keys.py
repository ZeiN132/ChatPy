import base64
import json
import os
import ctypes
import hashlib
import time
from ctypes import wintypes
from pathlib import Path

import keyring
from keyring.errors import NoKeyringError
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

_ALLOW_PLAINTEXT_KEYSTORE_ENV = "CHATPY_ALLOW_PLAINTEXT_KEYSTORE"


def _env_truthy(value):
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class _KeyringStore:
    def __init__(self, service="secure_chat"):
        self.service = service
        try:
            keyring.get_keyring()
        except Exception as e:
            raise RuntimeError("Keyring backend is not available") from e

    def get_json(self, key):
        try:
            raw = keyring.get_password(self.service, key)
        except NoKeyringError as e:
            raise RuntimeError("Keyring backend is not available") from e
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    def set_json(self, key, data):
        payload = json.dumps(data, ensure_ascii=True)
        try:
            keyring.set_password(self.service, key, payload)
        except NoKeyringError as e:
            raise RuntimeError("Keyring backend is not available") from e


class _DPAPIStore:
    _ENC_MARKER = "_enc"
    _ENC_TYPE = "dpapi"

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def __init__(self, path):
        self.path = Path(path)
        self._allow_plaintext = _env_truthy(os.getenv(_ALLOW_PLAINTEXT_KEYSTORE_ENV))
        self._crypt32 = None
        self._kernel32 = None
        if os.name == "nt":
            self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._crypt32.CryptProtectData.argtypes = [
                ctypes.POINTER(self._DATA_BLOB),
                wintypes.LPWSTR,
                ctypes.POINTER(self._DATA_BLOB),
                wintypes.LPVOID,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(self._DATA_BLOB),
            ]
            self._crypt32.CryptProtectData.restype = wintypes.BOOL
            self._crypt32.CryptUnprotectData.argtypes = [
                ctypes.POINTER(self._DATA_BLOB),
                ctypes.POINTER(wintypes.LPWSTR),
                ctypes.POINTER(self._DATA_BLOB),
                wintypes.LPVOID,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(self._DATA_BLOB),
            ]
            self._crypt32.CryptUnprotectData.restype = wintypes.BOOL

    def _blob_from_bytes(self, data):
        buf = ctypes.create_string_buffer(data, len(data))
        return self._DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))

    def _bytes_from_blob(self, blob):
        if not blob.pbData:
            return b""
        buf = ctypes.cast(blob.pbData, ctypes.POINTER(ctypes.c_byte * blob.cbData))
        data = bytes(buf.contents)
        self._kernel32.LocalFree(blob.pbData)
        return data

    def _dpapi_protect(self, data):
        if not self._crypt32:
            return None
        in_blob = self._blob_from_bytes(data)
        out_blob = self._DATA_BLOB()
        if not self._crypt32.CryptProtectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            return None
        return self._bytes_from_blob(out_blob)

    def _dpapi_unprotect(self, data):
        if not self._crypt32:
            return None
        in_blob = self._blob_from_bytes(data)
        out_blob = self._DATA_BLOB()
        if not self._crypt32.CryptUnprotectData(
            ctypes.byref(in_blob),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(out_blob),
        ):
            return None
        return self._bytes_from_blob(out_blob)

    def load(self):
        if not self.path.exists():
            return {}
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            return {}

        if isinstance(data, dict) and data.get(self._ENC_MARKER) == self._ENC_TYPE:
            b64 = data.get("data", "")
            try:
                protected = base64.b64decode(b64)
                decrypted = self._dpapi_unprotect(protected)
                if decrypted is None:
                    return {}
                return json.loads(decrypted.decode("utf-8"))
            except Exception:
                return {}

        if isinstance(data, dict):
            if self._allow_plaintext:
                return data
            if self._crypt32:
                # Best-effort migration of legacy plaintext JSON to DPAPI wrapper.
                self.save(data)
                return data
            raise RuntimeError(
                "Plaintext key storage is blocked. "
                f"Enable keyring/DPAPI or set {_ALLOW_PLAINTEXT_KEYSTORE_ENV}=1 for legacy mode."
            )
        return {}

    def save(self, data):
        payload = json.dumps(data, ensure_ascii=True).encode("utf-8")
        protected = self._dpapi_protect(payload)
        if protected is not None:
            wrapper = {
                self._ENC_MARKER: self._ENC_TYPE,
                "data": base64.b64encode(protected).decode("ascii"),
            }
            self.path.write_text(json.dumps(wrapper, ensure_ascii=True), encoding="utf-8")
            return
        if self._allow_plaintext:
            self.path.write_text(json.dumps(data, ensure_ascii=True), encoding="utf-8")
            return
        raise RuntimeError(
            "Secure local key storage is unavailable. "
            f"Enable keyring/DPAPI or set {_ALLOW_PLAINTEXT_KEYSTORE_ENV}=1 for legacy mode."
        )


def _b64e(data):
    return base64.b64encode(data).decode("ascii")


class IdentityKeyManager:
    def __init__(self, config_dir=".chat_config", service="secure_chat", warning_callback=None):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self._volatile = {}
        self._storage_warning_emitted = False
        self._warning_callback = warning_callback
        self._keyring = None
        try:
            self._keyring = _KeyringStore(service)
        except Exception:
            self._keyring = None
        self._dpapi = _DPAPIStore(self.config_dir / "identity_keys.json")

    def _warn_storage_issue(self, action, err):
        if self._storage_warning_emitted:
            return
        self._storage_warning_emitted = True
        message = (
            f"[IDENTITY][WARN] Secure key persistence disabled ({action} failed: {err}). "
            "Using volatile in-memory storage for this session."
        )
        print(message)
        if callable(self._warning_callback):
            try:
                self._warning_callback(message)
            except Exception:
                pass

    def _get(self, key):
        if self._keyring:
            try:
                data = self._keyring.get_json(key)
                if data is not None:
                    return data
            except Exception:
                pass
        try:
            data = self._dpapi.load()
        except RuntimeError as e:
            self._warn_storage_issue("load", e)
            data = self._volatile
        return data.get(key)

    def _set(self, key, data):
        if self._keyring:
            try:
                self._keyring.set_json(key, data)
                return
            except Exception:
                pass
        try:
            store = self._dpapi.load()
        except RuntimeError as e:
            self._warn_storage_issue("load", e)
            store = dict(self._volatile)
        store[key] = data
        self._volatile = dict(store)
        try:
            self._dpapi.save(store)
        except RuntimeError as e:
            self._warn_storage_issue("save", e)

    def get_device_id(self):
        entry = self._get("identity:device_id")
        if isinstance(entry, dict):
            device_id = entry.get("device_id")
            if device_id:
                return device_id
        device_id = base64.urlsafe_b64encode(os.urandom(12)).decode("ascii").rstrip("=")
        self._set("identity:device_id", {"device_id": device_id})
        return device_id

    def get_or_create(self, username):
        device_id = self.get_device_id()
        key = f"identity:{username}:{device_id}"
        entry = self._get(key)
        if isinstance(entry, dict) and entry.get("sign_priv") and entry.get("dh_priv"):
            entry["device_id"] = device_id
            return entry

        sign_priv = ed25519.Ed25519PrivateKey.generate()
        dh_priv = x25519.X25519PrivateKey.generate()

        entry = {
            "device_id": device_id,
            "sign_priv": _b64e(
                sign_priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
            "sign_pub": _b64e(
                sign_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
            "dh_priv": _b64e(
                dh_priv.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
            "dh_pub": _b64e(
                dh_priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
        }

        self._set(key, entry)
        return entry


def fingerprint_ed25519_pub(pub_b64):
    try:
        raw = base64.b64decode(pub_b64)
    except Exception:
        return None
    return hashlib.sha256(raw).hexdigest()


class IdentityPinStore:
    def __init__(self, config_dir=".chat_config", service="secure_chat", warning_callback=None):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self._volatile = {}
        self._storage_warning_emitted = False
        self._warning_callback = warning_callback
        self._keyring = None
        try:
            self._keyring = _KeyringStore(service)
        except Exception:
            self._keyring = None
        self._dpapi = _DPAPIStore(self.config_dir / "identity_pins.json")
        self._store_key = "identity:pins"

    def _warn_storage_issue(self, action, err):
        if self._storage_warning_emitted:
            return
        self._storage_warning_emitted = True
        message = (
            f"[IDENTITY][WARN] Secure pin persistence disabled ({action} failed: {err}). "
            "Using volatile in-memory storage for this session."
        )
        print(message)
        if callable(self._warning_callback):
            try:
                self._warning_callback(message)
            except Exception:
                pass

    def _load_all(self):
        data = None
        if self._keyring:
            try:
                data = self._keyring.get_json(self._store_key)
            except Exception:
                data = None
        if data is None:
            try:
                data = self._dpapi.load()
            except RuntimeError as e:
                self._warn_storage_issue("load", e)
                data = self._volatile
        if isinstance(data, dict):
            return data
        return {}

    def _save_all(self, data):
        if not isinstance(data, dict):
            return
        if self._keyring:
            try:
                self._keyring.set_json(self._store_key, data)
                return
            except Exception:
                pass
        self._volatile = dict(data)
        try:
            self._dpapi.save(data)
        except RuntimeError as e:
            self._warn_storage_issue("save", e)

    def get_peer(self, peer):
        data = self._load_all()
        entry = data.get(peer)
        if isinstance(entry, dict):
            return entry
        return {}

    def set_peer(self, peer, devices):
        data = self._load_all()
        data[peer] = devices
        self._save_all(data)

    def pin_device(self, peer, device_id, sign_fp, dh_pub, blocked=False, verified=False):
        devices = self.get_peer(peer)
        devices[device_id] = {
            "sign_fp": sign_fp,
            "dh_pub": dh_pub,
            "blocked": bool(blocked),
            "verified": bool(verified),
        }
        self.set_peer(peer, devices)

    def set_device_blocked(self, peer, device_id, blocked=True):
        devices = self.get_peer(peer)
        record = devices.get(device_id)
        if not isinstance(record, dict):
            return
        record["blocked"] = bool(blocked)
        devices[device_id] = record
        self.set_peer(peer, devices)

    def set_device_verified(self, peer, device_id, verified=True):
        devices = self.get_peer(peer)
        record = devices.get(device_id)
        if not isinstance(record, dict):
            return
        record["verified"] = bool(verified)
        devices[device_id] = record
        self.set_peer(peer, devices)

    def is_device_verified(self, peer, device_id):
        devices = self.get_peer(peer)
        record = devices.get(device_id)
        if not isinstance(record, dict):
            return False
        return bool(record.get("verified"))

    def is_peer_blocked(self, peer):
        devices = self.get_peer(peer)
        for record in devices.values():
            if isinstance(record, dict) and record.get("blocked"):
                return True
        return False


class NormalSessionStore:
    def __init__(self, config_dir=".chat_config", service="secure_chat", warning_callback=None):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self._volatile = {}
        self._storage_warning_emitted = False
        self._warning_callback = warning_callback
        self._keyring = None
        try:
            self._keyring = _KeyringStore(service)
        except Exception:
            self._keyring = None
        self._dpapi = _DPAPIStore(self.config_dir / "normal_sessions.json")
        self._store_key = "normal:sessions"

    def _warn_storage_issue(self, action, err):
        if self._storage_warning_emitted:
            return
        self._storage_warning_emitted = True
        message = (
            f"[SESSION][WARN] Secure session persistence disabled ({action} failed: {err}). "
            "Using volatile in-memory storage for this session."
        )
        print(message)
        if callable(self._warning_callback):
            try:
                self._warning_callback(message)
            except Exception:
                pass

    def _load_all(self):
        data = None
        if self._keyring:
            try:
                data = self._keyring.get_json(self._store_key)
            except Exception:
                data = None
        if data is None:
            try:
                data = self._dpapi.load()
            except RuntimeError as e:
                self._warn_storage_issue("load", e)
                data = self._volatile
        if isinstance(data, dict):
            return data
        return {}

    def _save_all(self, data):
        if not isinstance(data, dict):
            return
        if self._keyring:
            try:
                self._keyring.set_json(self._store_key, data)
                return
            except Exception:
                pass
        self._volatile = dict(data)
        try:
            self._dpapi.save(data)
        except RuntimeError as e:
            self._warn_storage_issue("save", e)

    def _load_user(self, username):
        data = self._load_all()
        entry = data.get(username)
        if isinstance(entry, dict):
            return entry
        return {}

    def _save_user(self, username, entry):
        if not isinstance(entry, dict):
            return
        data = self._load_all()
        data[username] = entry
        self._save_all(data)

    def get_current_epoch(self, username, peer):
        if not username or not peer:
            return None
        user_entry = self._load_user(username)
        peer_entry = user_entry.get(peer, {})
        if isinstance(peer_entry, dict):
            return peer_entry.get("current")
        return None

    def set_current_epoch(self, username, peer, epoch_id):
        if not username or not peer or not epoch_id:
            return
        user_entry = self._load_user(username)
        peer_entry = user_entry.get(peer, {})
        if not isinstance(peer_entry, dict):
            peer_entry = {}
        peer_entry["current"] = epoch_id
        user_entry[peer] = peer_entry
        self._save_user(username, user_entry)

    def set_epoch(self, username, peer, epoch_id, master_key, peer_device_id=None, created=None, set_current=False):
        if not username or not peer or not epoch_id or not master_key:
            return
        user_entry = self._load_user(username)
        peer_entry = user_entry.get(peer, {})
        if not isinstance(peer_entry, dict):
            peer_entry = {}
        epochs = peer_entry.get("epochs", {})
        if not isinstance(epochs, dict):
            epochs = {}
        epochs[epoch_id] = {
            "master": base64.b64encode(master_key).decode("ascii"),
            "created": float(created) if created is not None else time.time(),
            "peer_device_id": peer_device_id,
        }
        peer_entry["epochs"] = epochs
        if set_current:
            peer_entry["current"] = epoch_id
        user_entry[peer] = peer_entry
        self._save_user(username, user_entry)

    def get_epoch(self, username, peer, epoch_id):
        if not username or not peer or not epoch_id:
            return None
        user_entry = self._load_user(username)
        peer_entry = user_entry.get(peer, {})
        if not isinstance(peer_entry, dict):
            return None
        epochs = peer_entry.get("epochs", {})
        if not isinstance(epochs, dict):
            return None
        entry = epochs.get(epoch_id)
        if not isinstance(entry, dict):
            return None
        master_b64 = entry.get("master")
        if not master_b64:
            return None
        try:
            master = base64.b64decode(master_b64)
        except Exception:
            return None
        return {
            "master": master,
            "created": entry.get("created"),
            "peer_device_id": entry.get("peer_device_id"),
        }


class GroupSessionStore:
    def __init__(self, config_dir=".chat_config", service="secure_chat", warning_callback=None):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self._volatile = {}
        self._storage_warning_emitted = False
        self._warning_callback = warning_callback
        self._keyring = None
        try:
            self._keyring = _KeyringStore(service)
        except Exception:
            self._keyring = None
        self._dpapi = _DPAPIStore(self.config_dir / "group_sessions.json")
        self._store_key = "group:sessions"

    def _warn_storage_issue(self, action, err):
        if self._storage_warning_emitted:
            return
        self._storage_warning_emitted = True
        message = (
            f"[GROUP][WARN] Secure group key persistence disabled ({action} failed: {err}). "
            "Using volatile in-memory storage for this session."
        )
        print(message)
        if callable(self._warning_callback):
            try:
                self._warning_callback(message)
            except Exception:
                pass

    def _load_all(self):
        data = None
        if self._keyring:
            try:
                data = self._keyring.get_json(self._store_key)
            except Exception:
                data = None
        if data is None:
            try:
                data = self._dpapi.load()
            except RuntimeError as e:
                self._warn_storage_issue("load", e)
                data = self._volatile
        if isinstance(data, dict):
            return data
        return {}

    def _save_all(self, data):
        if not isinstance(data, dict):
            return
        if self._keyring:
            try:
                self._keyring.set_json(self._store_key, data)
                return
            except Exception:
                pass
        self._volatile = dict(data)
        try:
            self._dpapi.save(data)
        except RuntimeError as e:
            self._warn_storage_issue("save", e)

    def _load_user(self, username):
        data = self._load_all()
        entry = data.get(username)
        if isinstance(entry, dict):
            return entry
        return {}

    def _save_user(self, username, entry):
        if not isinstance(entry, dict):
            return
        data = self._load_all()
        data[username] = entry
        self._save_all(data)

    def _group_key(self, group_id):
        try:
            gid = int(group_id)
        except (TypeError, ValueError):
            return None
        return str(gid) if gid > 0 else None

    def get_group(self, username, group_id):
        if not username:
            return {"current": None, "epochs": {}}
        gid = self._group_key(group_id)
        if gid is None:
            return {"current": None, "epochs": {}}
        user_entry = self._load_user(username)
        group_entry = user_entry.get(gid, {})
        if not isinstance(group_entry, dict):
            return {"current": None, "epochs": {}}
        current = group_entry.get("current")
        epochs_raw = group_entry.get("epochs", {})
        epochs = {}
        if isinstance(epochs_raw, dict):
            for epoch_id, entry in epochs_raw.items():
                if not isinstance(entry, dict):
                    continue
                key_b64 = entry.get("key")
                if not key_b64:
                    continue
                try:
                    epochs[str(epoch_id)] = base64.b64decode(key_b64)
                except Exception:
                    continue
        return {"current": current, "epochs": epochs}

    def get_epoch(self, username, group_id, epoch_id):
        state = self.get_group(username, group_id)
        return state.get("epochs", {}).get(str(epoch_id))

    def set_epoch(self, username, group_id, epoch_id, key_bytes, set_current=False):
        if not username or not epoch_id or not key_bytes:
            return
        gid = self._group_key(group_id)
        if gid is None:
            return
        user_entry = self._load_user(username)
        group_entry = user_entry.get(gid, {})
        if not isinstance(group_entry, dict):
            group_entry = {}
        epochs = group_entry.get("epochs", {})
        if not isinstance(epochs, dict):
            epochs = {}
        epochs[str(epoch_id)] = {
            "key": base64.b64encode(key_bytes).decode("ascii"),
            "created": time.time(),
        }
        group_entry["epochs"] = epochs
        if set_current:
            group_entry["current"] = str(epoch_id)
        user_entry[gid] = group_entry
        self._save_user(username, user_entry)

    def set_current_epoch(self, username, group_id, epoch_id):
        if not username or not epoch_id:
            return
        gid = self._group_key(group_id)
        if gid is None:
            return
        user_entry = self._load_user(username)
        group_entry = user_entry.get(gid, {})
        if not isinstance(group_entry, dict):
            group_entry = {}
        group_entry["current"] = str(epoch_id)
        user_entry[gid] = group_entry
        self._save_user(username, user_entry)

    def remove_group(self, username, group_id):
        if not username:
            return
        gid = self._group_key(group_id)
        if gid is None:
            return
        user_entry = self._load_user(username)
        if gid in user_entry:
            user_entry.pop(gid, None)
            self._save_user(username, user_entry)
