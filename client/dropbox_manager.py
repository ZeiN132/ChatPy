import dropbox
from dropbox import DropboxOAuth2FlowNoRedirect
import webbrowser
import json
import os
import re
import ctypes
from ctypes import wintypes
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import keyring
from keyring.errors import NoKeyringError


class _KeyringStore:
    """Keyring-backed JSON storage."""

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
        payload = json.dumps(data, ensure_ascii=False)
        try:
            keyring.set_password(self.service, key, payload)
        except NoKeyringError as e:
            raise RuntimeError("Keyring backend is not available") from e

    def delete(self, key):
        try:
            keyring.delete_password(self.service, key)
        except Exception:
            pass


class _LegacyFileStore:
    """Legacy JSON loader (plaintext or DPAPI-wrapped)."""

    _ENC_MARKER = "_enc"
    _ENC_TYPE = "dpapi"

    class _DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def __init__(self):
        self._crypt32 = None
        self._kernel32 = None
        if os.name == "nt":
            self._crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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

    def load_json(self, path):
        if not path.exists():
            return None
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except Exception:
            return None

        if isinstance(data, dict) and data.get(self._ENC_MARKER) == self._ENC_TYPE:
            b64 = data.get("data", "")
            try:
                protected = base64.b64decode(b64)
                decrypted = self._dpapi_unprotect(protected)
                if decrypted is None:
                    return None
                return json.loads(decrypted.decode("utf-8"))
            except Exception:
                return None

        if isinstance(data, dict):
            return data
        return None

    def scrub(self, path):
        try:
            path.write_text(json.dumps({"migrated": True}), encoding="utf-8")
        except Exception:
            pass


class DropboxManager:
    def __init__(self, config_dir=".chat_config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)

        self.token_file = self.config_dir / "dropbox_token.json"
        self.keys_file = self.config_dir / "file_keys.json"
        self.app_keys_file = self.config_dir / "dropbox_app.json"

        # Insert your App Key and App Secret from Dropbox App Console
        # https://www.dropbox.com/developers/apps
        self.APP_KEY = "Your key here"
        self.APP_SECRET = "Your secret here"

        self.dbx = None
        self.username = None
        self.file_keys = {}
        self._store = _KeyringStore()
        self._legacy = _LegacyFileStore()

        self._load_app_keys()

    def _load_app_keys(self):
        data = self._store.get_json("dropbox:app_keys")
        if isinstance(data, dict):
            app_key = data.get("app_key")
            app_secret = data.get("app_secret")
            if app_key and app_secret:
                self.APP_KEY = app_key
                self.APP_SECRET = app_secret

    def _save_app_keys(self):
        try:
            self._store.set_json(
                "dropbox:app_keys",
                {"app_key": self.APP_KEY, "app_secret": self.APP_SECRET},
            )
        except Exception:
            pass

    def set_app_keys(self, app_key, app_secret, persist=True):
        self.APP_KEY = app_key
        self.APP_SECRET = app_secret
        if persist:
            self._save_app_keys()

    def set_user(self, username):
        """Bind Dropbox storage to a chat user."""
        self.username = username
        self.dbx = None
        self.file_keys = {}

        if not self.username:
            return

        self._migrate_legacy_for_user()
        self._load_token()
        self.file_keys = self._load_file_keys()

    def clear_user(self):
        """Drop current user context."""
        self.username = None
        self.dbx = None
        self.file_keys = {}

    def _sanitize_username(self, username):
        return re.sub(r"[^A-Za-z0-9._-]+", "_", username or "user").strip("_") or "user"

    def _user_root(self):
        safe = self._sanitize_username(self.username)
        return f"/SecureChat/{safe}"

    def _migrate_legacy_for_user(self):
        if not self.username:
            return

        if self._store.get_json("dropbox:app_keys") is None:
            data = self._legacy.load_json(self.app_keys_file)
            if isinstance(data, dict) and data.get("app_key") and data.get("app_secret"):
                self._store.set_json("dropbox:app_keys", data)
                self._legacy.scrub(self.app_keys_file)

        token_key = f"dropbox:{self.username}:tokens"
        if self._store.get_json(token_key) is None:
            data = self._legacy.load_json(self.token_file)
            if isinstance(data, dict):
                refresh_token = data.get("refresh_token")
                access_token = data.get("access_token")
                # Prefer refresh token to avoid keyring size limits
                if refresh_token:
                    to_store = {"refresh_token": refresh_token}
                elif access_token and len(access_token) < 4000:
                    to_store = {"access_token": access_token}
                else:
                    to_store = None
                if to_store:
                    try:
                        self._store.set_json(token_key, to_store)
                        self._legacy.scrub(self.token_file)
                    except Exception:
                        # Leave legacy file intact if keyring write fails
                        pass

        keys_key = f"dropbox:{self.username}:file_keys"
        if self._store.get_json(keys_key) is None:
            data = self._legacy.load_json(self.keys_file)
            if isinstance(data, dict):
                try:
                    self._store.set_json(keys_key, data)
                    self._legacy.scrub(self.keys_file)
                except Exception:
                    pass

    def _load_token(self):
        if not self.username:
            return False
        data = self._store.get_json(f"dropbox:{self.username}:tokens")
        if isinstance(data, dict):
            refresh_token = data.get("refresh_token")
            access_token = data.get("access_token")

            if refresh_token:
                self.dbx = dropbox.Dropbox(
                    oauth2_refresh_token=refresh_token,
                    app_key=self.APP_KEY,
                    app_secret=self.APP_SECRET,
                )
            elif access_token:
                self.dbx = dropbox.Dropbox(oauth2_access_token=access_token)

            if self.dbx is not None:
                try:
                    self.dbx.users_get_current_account()
                    return True
                except Exception:
                    self.dbx = None
        return False

    def _save_token(self, access_token, refresh_token=None):
        if not self.username:
            return
        # Store only refresh token when available to avoid keyring size limits
        if refresh_token:
            data = {"refresh_token": refresh_token}
        elif access_token and len(access_token) < 4000:
            data = {"access_token": access_token}
        else:
            raise ValueError("Access token is too large for keyring; refresh token required.")
        self._store.set_json(f"dropbox:{self.username}:tokens", data)

    def _load_file_keys(self):
        if not self.username:
            return {}
        data = self._store.get_json(f"dropbox:{self.username}:file_keys")
        if isinstance(data, dict):
            try:
                return {k: base64.b64decode(v) for k, v in data.items()}
            except Exception:
                return {}
        return {}

    def _save_file_keys(self):
        if not self.username:
            return
        data = {k: base64.b64encode(v).decode() for k, v in self.file_keys.items()}
        self._store.set_json(f"dropbox:{self.username}:file_keys", data)

    def is_authenticated(self):
        return self.dbx is not None

    def start_auth_flow(self):
        if not self.username:
            raise ValueError("User is not set")
        auth_flow = DropboxOAuth2FlowNoRedirect(
            self.APP_KEY,
            self.APP_SECRET,
            token_access_type="offline",
        )

        authorize_url = auth_flow.start()
        self.auth_flow = auth_flow
        webbrowser.open(authorize_url)
        return authorize_url

    def finish_auth_flow(self, auth_code):
        try:
            if not self.username:
                return False, "User is not set"
            oauth_result = self.auth_flow.finish(auth_code)
            access_token = oauth_result.access_token
            refresh_token = getattr(oauth_result, "refresh_token", None)

            try:
                self._save_token(access_token, refresh_token=refresh_token)
            except Exception as e:
                return False, f"Authorization failed: {str(e)}"

            if refresh_token:
                self.dbx = dropbox.Dropbox(
                    oauth2_refresh_token=refresh_token,
                    app_key=self.APP_KEY,
                    app_secret=self.APP_SECRET,
                )
            else:
                self.dbx = dropbox.Dropbox(oauth2_access_token=access_token)

            return True, "Authorization successful!"
        except Exception as e:
            return False, f"Authorization failed: {str(e)}"

    def generate_file_key(self):
        return os.urandom(32)

    def encrypt_file(self, file_data, key):
        aes = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, file_data, None)
        return nonce + ciphertext

    def decrypt_file(self, encrypted_data, key):
        aes = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aes.decrypt(nonce, ciphertext, None)

    def upload_file(self, file_name, file_data):
        if not self.is_authenticated():
            return False, "Not authenticated with Dropbox", None

        try:
            file_key = self.generate_file_key()
            encrypted_data = self.encrypt_file(file_data, file_key)
            dropbox_path = f"{self._user_root()}/{file_name}.encrypted"

            self.dbx.files_upload(
                encrypted_data,
                dropbox_path,
                mode=dropbox.files.WriteMode.overwrite,
            )

            self.file_keys[dropbox_path] = file_key
            self._save_file_keys()

            return True, dropbox_path, file_key
        except Exception as e:
            return False, str(e), None

    def list_files(self):
        if not self.is_authenticated():
            return []

        try:
            root = self._user_root()
            result = self.dbx.files_list_folder(root)
            files = []

            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    display_name = entry.name.replace(".encrypted", "")
                    files.append(
                        {
                            "name": display_name,
                            "path": entry.path_display,
                            "size": entry.size,
                            "modified": entry.server_modified,
                            "has_key": entry.path_display in self.file_keys,
                        }
                    )

            return files

        except dropbox.exceptions.AuthError as e:
            err_text = str(e)
            if "missing_scope" in err_text or "required_scope" in err_text:
                raise ValueError(
                    "Dropbox app is missing required permissions. Open Dropbox App Console -> Permissions -> Files and folders, enable all scopes, then reconnect."
                )
            raise

        except dropbox.exceptions.ApiError as e:
            err_text = str(e)
            if "missing_scope" in err_text or "required_scope" in err_text:
                raise ValueError(
                    "Dropbox app is missing required permissions. Open Dropbox App Console -> Permissions -> Files and folders, enable all scopes, then reconnect."
                )
            if isinstance(e.error, dropbox.files.ListFolderError):
                try:
                    self.dbx.files_create_folder_v2(self._user_root())
                    return []
                except Exception:
                    pass
            return []

    def download_file(self, dropbox_path):
        if not self.is_authenticated():
            return False, None, "Not authenticated with Dropbox"

        if dropbox_path not in self.file_keys:
            return False, None, "Decryption key not found. You can only decrypt files you uploaded."

        try:
            metadata, response = self.dbx.files_download(dropbox_path)
            encrypted_data = response.content

            file_key = self.file_keys[dropbox_path]
            decrypted_data = self.decrypt_file(encrypted_data, file_key)

            return True, decrypted_data, "Success"

        except Exception as e:
            return False, None, str(e)

    def delete_file(self, dropbox_path):
        if not self.is_authenticated():
            return False, "Not authenticated"

        try:
            self.dbx.files_delete_v2(dropbox_path)

            if dropbox_path in self.file_keys:
                del self.file_keys[dropbox_path]
                self._save_file_keys()

            return True, "File deleted successfully"
        except Exception as e:
            return False, str(e)

    def get_account_info(self):
        if not self.is_authenticated():
            return None

        try:
            account = self.dbx.users_get_current_account()
            space_usage = self.dbx.users_get_space_usage()

            return {
                "name": account.name.display_name,
                "email": account.email,
                "used_space": space_usage.used,
                "allocated_space": space_usage.allocation.get_individual().allocated,
            }
        except Exception:
            return None

    def disconnect(self):
        if self.username:
            self._store.delete(f"dropbox:{self.username}:tokens")
        self.dbx = None

