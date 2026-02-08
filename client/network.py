import socket
import threading
import json
import os
import base64
import time
import ssl
from collections import deque
from cryptography.hazmat.primitives import serialization
from .crypto_utils import (
    generate_ephemeral,
    ecdh_shared_secret,
    derive_session_chains,
    kdf_chain,
    encrypt_msg,
    decrypt_msg,
    load_private_key,
    load_public_key,
    load_ed25519_public_key,
    load_ed25519_private_key,
    hkdf_derive
)
from .identity_keys import (
    IdentityKeyManager,
    IdentityPinStore,
    NormalSessionStore,
    GroupSessionStore,
    fingerprint_ed25519_pub,
)

def _env_truthy(value):
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _parse_tls_min_version(raw):
    if not raw:
        return None
    val = str(raw).strip().lower().replace("tls", "").replace("v", "")
    if val in ("1.2", "1_2", "12"):
        return ssl.TLSVersion.TLSv1_2
    if val in ("1.3", "1_3", "13"):
        return ssl.TLSVersion.TLSv1_3
    return None


class ClientNetwork:
    def __init__(self, signals, config_dir=".chat_config"):
        self.signals = signals
        self.connected = False
        self.sock = None
        self.file = None
        self.server_host = os.getenv("CHATPY_SERVER_HOST", "34.46.154.216")
        try:
            self.server_port = int(os.getenv("CHATPY_SERVER_PORT", "9999"))
        except ValueError:
            self.server_port = 9999
        self.tls_enabled = _env_truthy(os.getenv("CHATPY_TLS_ENABLED", "0"))
        self.tls_ca_file = os.getenv("CHATPY_TLS_CA_FILE")
        self.tls_server_name = os.getenv("CHATPY_TLS_SERVER_NAME") or self.server_host
        self.tls_min_version = _parse_tls_min_version(os.getenv("CHATPY_TLS_MIN_VERSION", "1.2"))
        self.sessions = {}
        self.pending_exchanges = {}
        self.approved_peers = set()
        self.normal_sessions = {}
        self._normal_replay = {}
        self._normal_replay_max_epochs = 8
        self._normal_replay_max_ids = 4096
        self.config_dir = config_dir or ".chat_config"
        self.identity_mgr = IdentityKeyManager(
            config_dir=self.config_dir,
            warning_callback=self._notify_storage_warning,
        )
        self.identity = None
        self.peer_identities = {}
        self.identity_pins = IdentityPinStore(
            config_dir=self.config_dir,
            warning_callback=self._notify_storage_warning,
        )
        self.normal_store = NormalSessionStore(
            config_dir=self.config_dir,
            warning_callback=self._notify_storage_warning,
        )
        self.group_store = GroupSessionStore(
            config_dir=self.config_dir,
            warning_callback=self._notify_storage_warning,
        )
        self.username = None
        self.group_sessions = {}
        self.group_key_envelopes = {}
        self.group_meta = {}
        self.group_member_keys = {}
        self._group_publish_pending = {}
        self._group_rekey_required = set()
        self.group_e2e_v2_enabled = False
        self._rekey_after = 100

    def _notify_storage_warning(self, message):
        if not message:
            return
        try:
            self.signals.storage_warning.emit(str(message))
        except Exception:
            pass

    def connect(self):
        if self.connected and self.sock is not None and self.file is not None:
            return True
        try:
            raw_sock = socket.create_connection((self.server_host, self.server_port))
            sock = raw_sock
            if self.tls_enabled:
                if not self.tls_ca_file:
                    print("[TLS ERROR] CHATPY_TLS_CA_FILE is required when TLS is enabled")
                    raw_sock.close()
                    return False
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.tls_ca_file)
                if self.tls_min_version:
                    ctx.minimum_version = self.tls_min_version
                sock = ctx.wrap_socket(raw_sock, server_hostname=self.tls_server_name)
            self.sock = sock
            self.file = sock.makefile("rwb")
            self.connected = True
            threading.Thread(target=self.reader, daemon=True).start()
            return True
        except Exception as e:
            print("[NETWORK ERROR]", e)
            self.disconnect()
            return False

    def disconnect(self):
        self.connected = False
        if self.file is not None:
            try:
                self.file.close()
            except Exception:
                pass
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
        self.file = None
        self.sock = None

    def reader(self):
        if self.file is None:
            self.connected = False
            return
        try:
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
                if msg_type == "identity_keys":
                    peer = msg.get("username")
                    if peer:
                        self.peer_identities[peer] = msg.get("keys", [])
                        try:
                            self.signals.identity_keys.emit(peer, msg.get("keys", []))
                        except Exception:
                            pass
                    continue
                if msg_type == "identity_keys_set":
                    continue
                if msg_type == "group_epoch_published":
                    try:
                        gid = self._normalize_group_id(msg.get("group_id"))
                        epoch_id = str(msg.get("epoch_id") or "").strip()
                        if gid is not None:
                            pending = self._group_publish_pending.get(gid)
                            if isinstance(pending, dict) and pending.get("epoch_id") == epoch_id:
                                pending["state"] = "confirmed"
                                pending["confirmed_at"] = time.time()
                                self._group_publish_pending[gid] = pending
                            self._group_rekey_required.discard(gid)
                            self.request_group_key_envelopes(gid, epoch_id=epoch_id)
                    except Exception:
                        pass
                    continue
                if msg_type == "group_member_keys":
                    try:
                        self._handle_group_member_keys(msg)
                    except Exception:
                        pass
                    continue

                if (status == "ok" or status == "error") and msg_type in ("auth", "register", "login"):
                    if msg.get("auth_stage") == "register":
                        self.signals.register.emit(msg)
                        continue
                    # Сохраняем имя пользователя при успешной авторизации
                    if status == "ok" and "username" in msg:
                        new_user = msg["username"]
                        if self.username != new_user:
                            self.group_sessions = {}
                            self.group_meta = {}
                            self.group_member_keys = {}
                            self.group_key_envelopes = {}
                            self._group_publish_pending = {}
                            self._group_rekey_required = set()
                        self.username = new_user
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

                elif msg_type == "normal_handshake":
                    self._handle_normal_handshake(msg)
                
                elif msg_type == "msg":
                    # Входящее сообщение от другого пользователя
                    sender = msg["from"]
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

                elif msg_type == "groups":
                    try:
                        self.group_e2e_v2_enabled = bool(msg.get("group_e2e_v2", False))
                        groups = msg.get("groups", [])
                        if isinstance(groups, list):
                            for group_obj in groups:
                                self._update_group_meta(group_obj)
                                self.ingest_group_crypto(group_obj)
                        self.signals.groups.emit(groups if isinstance(groups, list) else [])
                    except Exception:
                        pass

                elif msg_type == "group_created":
                    try:
                        group_obj = msg.get("group", {})
                        self._update_group_meta(group_obj)
                        self.ingest_group_crypto(group_obj)
                        if self.group_e2e_v2_enabled:
                            gid = self._normalize_group_id(group_obj.get("group_id") if isinstance(group_obj, dict) else None)
                            if gid is not None and self._is_group_owner(gid):
                                self.ensure_group_epoch_published(
                                    gid,
                                    reason="group_created",
                                    force_new=True,
                                )
                        self.signals.group_created.emit(group_obj if isinstance(group_obj, dict) else {})
                    except Exception:
                        pass

                elif msg_type == "group_invites":
                    invites = msg.get("invites", [])
                    try:
                        self.signals.group_invites.emit(invites if isinstance(invites, list) else [])
                    except Exception:
                        pass

                elif msg_type == "group_invite":
                    try:
                        self.signals.group_invite.emit(msg.get("invite", {}))
                    except Exception:
                        pass

                elif msg_type == "group_invite_sent":
                    try:
                        self.signals.group_invite_sent.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_invite_response":
                    try:
                        self.signals.group_invite_response.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_invite_result":
                    try:
                        self.signals.group_invite_result.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_member_added":
                    try:
                        self.signals.group_member_added.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_member_left":
                    try:
                        self.signals.group_member_left.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_msg":
                    try:
                        self.signals.group_message.emit(
                            msg.get("group_id"),
                            msg.get("from"),
                            msg.get("payload"),
                            msg.get("id")
                        )
                    except Exception:
                        pass

                elif msg_type == "group_msg_sent":
                    try:
                        self.signals.group_msg_sent.emit(
                            msg.get("id"),
                            msg.get("group_id"),
                            msg.get("payload")
                        )
                    except Exception:
                        pass

                elif msg_type == "group_delete_msg":
                    try:
                        self.signals.group_message_deleted.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_history":
                    try:
                        self.signals.group_history.emit(
                            msg.get("group_id"),
                            msg.get("messages", [])
                        )
                    except Exception:
                        pass

                elif msg_type == "group_left":
                    try:
                        group_id = msg.get("group_id")
                        gid = self._normalize_group_id(group_id)
                        self.clear_group_session(gid)
                        if gid is not None:
                            self.group_meta.pop(gid, None)
                            self.group_member_keys.pop(gid, None)
                            self._group_publish_pending.pop(gid, None)
                            self._group_rekey_required.discard(gid)
                        self.signals.group_left.emit(group_id)
                    except Exception:
                        pass

                elif msg_type == "group_deleted":
                    try:
                        group_id = msg.get("group_id")
                        gid = self._normalize_group_id(group_id)
                        self.clear_group_session(gid)
                        if gid is not None:
                            self.group_meta.pop(gid, None)
                            self.group_member_keys.pop(gid, None)
                            self._group_publish_pending.pop(gid, None)
                            self._group_rekey_required.discard(gid)
                        self.signals.group_deleted.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_key_update":
                    try:
                        self.set_group_key(
                            msg.get("group_id"),
                            msg.get("key_epoch"),
                            msg.get("group_key"),
                            set_current=True,
                        )
                        gid = self._normalize_group_id(msg.get("group_id"))
                        if gid is not None:
                            self._group_rekey_required.discard(gid)
                            self._update_group_meta({
                                "group_id": gid,
                                "key_epoch": msg.get("key_epoch"),
                                "group_key": msg.get("group_key"),
                            })
                        self.signals.group_key_update.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_rekey_required":
                    try:
                        gid = self._normalize_group_id(msg.get("group_id"))
                        if gid is not None:
                            self._group_rekey_required.add(gid)
                            if self.group_e2e_v2_enabled and self._is_group_owner(gid):
                                self.ensure_group_epoch_published(
                                    gid,
                                    reason=msg.get("reason") or "rekey_required",
                                    force_new=True,
                                )
                            else:
                                self.request_group_key_envelopes(gid, epoch_id=msg.get("key_epoch"))
                        self.signals.group_key_update.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_key_envelopes_available":
                    try:
                        gid = self._normalize_group_id(msg.get("group_id"))
                        if gid is not None:
                            self.request_group_key_envelopes(gid, epoch_id=msg.get("epoch_id"))
                        self.signals.group_key_update.emit(msg)
                    except Exception:
                        pass

                elif msg_type == "group_key_envelopes":
                    try:
                        gid = self._normalize_group_id(msg.get("group_id"))
                        if gid is not None:
                            envelopes = msg.get("envelopes", [])
                            if isinstance(envelopes, list):
                                self.group_key_envelopes[gid] = envelopes
                                self._ingest_group_key_envelopes(gid, envelopes)
                    except Exception:
                        pass

                elif msg_type == "group_error":
                    try:
                        self.signals.group_error.emit(msg)
                    except Exception:
                        pass
        except Exception as e:
            print("[READER ERROR]", e)
        finally:
            self.disconnect()

    def send(self, data):
        if not self.connected or self.file is None:
            print("[ERROR] Not connected to server")
            return
        try:
            self.file.write(json.dumps(data).encode() + b"\n")
            self.file.flush()
        except Exception as e:
            print("[SEND ERROR]", e)
            self.disconnect()

    def _normalize_group_id(self, value):
        try:
            gid = int(value)
        except (TypeError, ValueError):
            return None
        return gid if gid > 0 else None

    def _group_aad(self, group_id, epoch_id):
        gid = self._normalize_group_id(group_id)
        if gid is None or not epoch_id:
            return None
        return f"chatpy-group-v1|{gid}|{epoch_id}".encode("utf-8")

    def _new_group_epoch_id(self):
        return base64.urlsafe_b64encode(os.urandom(12)).decode("ascii").rstrip("=")

    def _group_wrap_info(self, group_id, epoch_id, sender_username, sender_device_id, recipient_username, recipient_device_id):
        parts = [
            b"chatpy-group-wrap-v1",
            str(group_id).encode("utf-8"),
            str(epoch_id).encode("utf-8"),
            str(sender_username).encode("utf-8"),
            str(sender_device_id).encode("utf-8"),
            str(recipient_username).encode("utf-8"),
            str(recipient_device_id).encode("utf-8"),
        ]
        return b"|".join(parts)

    def _group_wrap_aad(self, group_id, epoch_id, sender_username, sender_device_id, recipient_username, recipient_device_id):
        parts = [
            b"chatpy-group-wrap-v1-aad",
            str(group_id).encode("utf-8"),
            str(epoch_id).encode("utf-8"),
            str(sender_username).encode("utf-8"),
            str(sender_device_id).encode("utf-8"),
            str(recipient_username).encode("utf-8"),
            str(recipient_device_id).encode("utf-8"),
        ]
        return b"|".join(parts)

    def _group_wrap_sig_data(
        self,
        group_id,
        epoch_id,
        sender_username,
        sender_device_id,
        recipient_username,
        recipient_device_id,
        eph_pub_raw,
        salt_raw,
        nonce_raw,
        ciphertext_raw,
    ):
        parts = [
            b"chatpy-group-wrap-v1-sig",
            str(group_id).encode("utf-8"),
            str(epoch_id).encode("utf-8"),
            str(sender_username).encode("utf-8"),
            str(sender_device_id).encode("utf-8"),
            str(recipient_username).encode("utf-8"),
            str(recipient_device_id).encode("utf-8"),
            eph_pub_raw,
            salt_raw,
            nonce_raw,
            ciphertext_raw,
        ]
        return b"|".join(parts)

    def _canonical_group_payload_bytes(self, payload_obj):
        try:
            return json.dumps(
                payload_obj,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except Exception:
            fallback = {"type": "text", "text": str(payload_obj)}
            return json.dumps(
                fallback,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

    def _group_msg_sig_data(self, group_id, epoch_id, sender_username, sender_device_id, payload_bytes):
        parts = [
            b"chatpy-group-msg-v1",
            str(group_id).encode("utf-8"),
            str(epoch_id).encode("utf-8"),
            str(sender_username).encode("utf-8"),
            str(sender_device_id).encode("utf-8"),
        ]
        return b"|".join(parts) + b"|" + payload_bytes

    def _update_group_meta(self, group_obj):
        if not isinstance(group_obj, dict):
            return
        gid = self._normalize_group_id(group_obj.get("group_id"))
        if gid is None:
            return
        meta = dict(self.group_meta.get(gid) or {})
        for key in ("group_uuid", "name", "owner", "role", "member_count", "history_policy", "key_epoch", "group_key"):
            if key in group_obj:
                meta[key] = group_obj.get(key)
        meta["group_id"] = gid
        self.group_meta[gid] = meta

    def _is_group_owner(self, group_id):
        gid = self._normalize_group_id(group_id)
        if gid is None or not self.username:
            return False
        meta = self.group_meta.get(gid)
        if not isinstance(meta, dict):
            return False
        if str(meta.get("owner") or "").strip() == self.username:
            return True
        return str(meta.get("role") or "").strip().lower() == "owner"

    def _remember_peer_identity(self, peer, device_id, sign_pub=None, dh_pub=None):
        if not peer or not device_id:
            return
        entries = self.peer_identities.get(peer, [])
        if not isinstance(entries, list):
            entries = []
        found = None
        for entry in entries:
            if isinstance(entry, dict) and entry.get("device_id") == device_id:
                found = entry
                break
        if found is None:
            found = {"device_id": device_id}
            entries.append(found)
        if sign_pub:
            found["sign_pub"] = sign_pub
        if dh_pub:
            found["dh_pub"] = dh_pub
        self.peer_identities[peer] = entries

    def _resolve_group_sender_sign_pub(self, sender_username, sender_device_id, sender_sign_pub, sender_dh_pub):
        if not sender_username or not sender_device_id:
            return None

        if sender_username == self.username:
            identity = self.ensure_identity_keys()
            if not identity:
                return None
            return identity.get("sign_pub")

        pinned = self.identity_pins.get_peer(sender_username)
        record = pinned.get(sender_device_id, {}) if isinstance(pinned, dict) else {}
        if isinstance(record, dict) and record.get("blocked"):
            return None

        peer_entry = self._find_peer_identity(sender_username, sender_device_id)
        known_sign = peer_entry.get("sign_pub") if isinstance(peer_entry, dict) else None
        known_dh = peer_entry.get("dh_pub") if isinstance(peer_entry, dict) else None

        sign_pub = sender_sign_pub or known_sign
        dh_pub = sender_dh_pub or known_dh
        if not sign_pub:
            self.request_identity_keys(sender_username)
            return None

        fp = fingerprint_ed25519_pub(sign_pub)
        if not fp:
            return None

        if known_sign and sign_pub != known_sign:
            self.identity_pins.set_device_blocked(sender_username, sender_device_id, True)
            self._emit_identity_key_notice(sender_username, sender_device_id, sign_pub, dh_pub)
            return None
        if known_dh and dh_pub and known_dh != dh_pub:
            self.identity_pins.set_device_blocked(sender_username, sender_device_id, True)
            self._emit_identity_key_notice(sender_username, sender_device_id, sign_pub, dh_pub)
            return None

        if isinstance(record, dict) and record:
            if record.get("sign_fp") and record.get("sign_fp") != fp:
                self.identity_pins.set_device_blocked(sender_username, sender_device_id, True)
                self._emit_identity_key_notice(sender_username, sender_device_id, sign_pub, dh_pub)
                return None
            if dh_pub and record.get("dh_pub") and record.get("dh_pub") != dh_pub:
                self.identity_pins.set_device_blocked(sender_username, sender_device_id, True)
                self._emit_identity_key_notice(sender_username, sender_device_id, sign_pub, dh_pub)
                return None
        else:
            self.identity_pins.pin_device(sender_username, sender_device_id, fp, dh_pub)
            self._emit_identity_key_notice(sender_username, sender_device_id, sign_pub, dh_pub)

        self._remember_peer_identity(sender_username, sender_device_id, sign_pub=sign_pub, dh_pub=dh_pub)
        return sign_pub

    def _wrap_group_key_for_device(self, group_id, epoch_id, group_key_bytes, recipient_username, recipient_device_id, recipient_dh_pub_b64):
        gid = self._normalize_group_id(group_id)
        epoch = str(epoch_id or "").strip()
        if gid is None or not epoch or not recipient_username or not recipient_device_id:
            return None
        if not isinstance(group_key_bytes, (bytes, bytearray)) or len(group_key_bytes) != 32:
            return None
        if not recipient_dh_pub_b64:
            return None

        identity = self.ensure_identity_keys()
        privs = self._load_identity_private()
        if not identity or not privs:
            return None
        sign_priv, _ = privs
        if not sign_priv:
            return None

        sender_username = self.username or ""
        sender_device_id = identity.get("device_id")
        sender_sign_pub = identity.get("sign_pub")
        sender_dh_pub = identity.get("dh_pub")
        if not sender_device_id or not sender_sign_pub or not sender_dh_pub:
            return None

        try:
            peer_pub = load_public_key(base64.b64decode(recipient_dh_pub_b64))
        except Exception:
            return None

        from cryptography.hazmat.primitives.asymmetric import x25519
        eph_priv = x25519.X25519PrivateKey.generate()
        eph_pub_raw = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        salt_raw = os.urandom(32)
        try:
            shared = eph_priv.exchange(peer_pub)
        except Exception:
            return None

        info = self._group_wrap_info(
            gid,
            epoch,
            sender_username,
            sender_device_id,
            recipient_username,
            recipient_device_id,
        )
        wrap_key = hkdf_derive(shared, salt_raw, info, length=32)
        aad = self._group_wrap_aad(
            gid,
            epoch,
            sender_username,
            sender_device_id,
            recipient_username,
            recipient_device_id,
        )
        enc = encrypt_msg(wrap_key, bytes(group_key_bytes), aad=aad)
        if not isinstance(enc, dict):
            return None

        try:
            nonce_raw = base64.b64decode(enc.get("nonce", ""))
            ciphertext_raw = base64.b64decode(enc.get("ciphertext", ""))
        except Exception:
            return None

        sig_data = self._group_wrap_sig_data(
            gid,
            epoch,
            sender_username,
            sender_device_id,
            recipient_username,
            recipient_device_id,
            eph_pub_raw,
            salt_raw,
            nonce_raw,
            ciphertext_raw,
        )
        sig_raw = sign_priv.sign(sig_data)
        payload = {
            "version": "group_key_wrap_v1",
            "group_id": gid,
            "epoch_id": epoch,
            "sender_username": sender_username,
            "sender_device_id": sender_device_id,
            "sender_sign_pub": sender_sign_pub,
            "sender_dh_pub": sender_dh_pub,
            "recipient_username": recipient_username,
            "recipient_device_id": recipient_device_id,
            "eph_pub": base64.b64encode(eph_pub_raw).decode("ascii"),
            "salt": base64.b64encode(salt_raw).decode("ascii"),
            "enc": enc,
            "sig": base64.b64encode(sig_raw).decode("ascii"),
        }
        return {
            "recipient_username": recipient_username,
            "recipient_device_id": recipient_device_id,
            "payload": payload,
        }

    def _unwrap_group_key_envelope(self, group_id, envelope):
        gid = self._normalize_group_id(group_id)
        if gid is None or not isinstance(envelope, dict):
            return False

        payload = envelope.get("payload")
        if isinstance(payload, dict) and isinstance(payload.get("envelope"), dict):
            payload = payload.get("envelope")
        if not isinstance(payload, dict):
            return False
        if str(payload.get("version") or "").strip() != "group_key_wrap_v1":
            return False

        epoch_id = str(payload.get("epoch_id") or envelope.get("epoch_id") or "").strip()
        sender_username = str(payload.get("sender_username") or envelope.get("sender_username") or "").strip()
        sender_device_id = str(payload.get("sender_device_id") or envelope.get("sender_device_id") or "").strip()
        sender_sign_pub = payload.get("sender_sign_pub")
        sender_dh_pub = payload.get("sender_dh_pub")
        recipient_username = str(payload.get("recipient_username") or envelope.get("recipient_username") or "").strip()
        recipient_device_id = str(payload.get("recipient_device_id") or envelope.get("recipient_device_id") or "").strip()

        if not epoch_id or not sender_username or not sender_device_id:
            return False
        if recipient_username and self.username and recipient_username != self.username:
            return False

        my_device_id = self.identity_mgr.get_device_id()
        if recipient_device_id and recipient_device_id != my_device_id:
            return False

        enc = payload.get("enc")
        eph_pub_b64 = payload.get("eph_pub")
        salt_b64 = payload.get("salt")
        sig_b64 = payload.get("sig")
        if not isinstance(enc, dict) or not eph_pub_b64 or not salt_b64 or not sig_b64:
            return False

        trusted_sign_pub = self._resolve_group_sender_sign_pub(
            sender_username,
            sender_device_id,
            sender_sign_pub,
            sender_dh_pub,
        )
        if not trusted_sign_pub:
            return False

        try:
            eph_pub_raw = base64.b64decode(eph_pub_b64)
            salt_raw = base64.b64decode(salt_b64)
            sig_raw = base64.b64decode(sig_b64)
            nonce_raw = base64.b64decode(enc.get("nonce", ""))
            ciphertext_raw = base64.b64decode(enc.get("ciphertext", ""))
        except Exception:
            return False

        sig_data = self._group_wrap_sig_data(
            gid,
            epoch_id,
            sender_username,
            sender_device_id,
            recipient_username or (self.username or ""),
            recipient_device_id or my_device_id,
            eph_pub_raw,
            salt_raw,
            nonce_raw,
            ciphertext_raw,
        )
        try:
            pub = load_ed25519_public_key(base64.b64decode(trusted_sign_pub))
            pub.verify(sig_raw, sig_data)
        except Exception:
            self.identity_pins.set_device_blocked(sender_username, sender_device_id, True)
            self._emit_identity_key_notice(sender_username, sender_device_id, trusted_sign_pub, sender_dh_pub)
            return False

        privs = self._load_identity_private()
        if not privs:
            return False
        _, dh_priv = privs

        try:
            eph_pub_key = load_public_key(eph_pub_raw)
            shared = dh_priv.exchange(eph_pub_key)
        except Exception:
            return False

        info = self._group_wrap_info(
            gid,
            epoch_id,
            sender_username,
            sender_device_id,
            recipient_username or (self.username or ""),
            recipient_device_id or my_device_id,
        )
        wrap_key = hkdf_derive(shared, salt_raw, info, length=32)
        aad = self._group_wrap_aad(
            gid,
            epoch_id,
            sender_username,
            sender_device_id,
            recipient_username or (self.username or ""),
            recipient_device_id or my_device_id,
        )
        try:
            group_key = decrypt_msg(wrap_key, enc, aad=aad)
        except Exception:
            return False
        if not isinstance(group_key, (bytes, bytearray)) or len(group_key) != 32:
            return False

        key_b64 = base64.b64encode(bytes(group_key)).decode("ascii")
        return self.set_group_key(gid, epoch_id, key_b64, set_current=True)

    def _ingest_group_key_envelopes(self, group_id, envelopes):
        gid = self._normalize_group_id(group_id)
        if gid is None or not isinstance(envelopes, list):
            return False
        changed = False
        for envelope in envelopes:
            try:
                if self._unwrap_group_key_envelope(gid, envelope):
                    changed = True
            except Exception:
                continue
        if changed:
            self._group_rekey_required.discard(gid)
        return changed

    def _publish_pending_group_epoch(self, group_id, member_keys):
        gid = self._normalize_group_id(group_id)
        if gid is None:
            return False
        pending = self._group_publish_pending.get(gid)
        if not isinstance(pending, dict):
            return False

        epoch_id = str(pending.get("epoch_id") or "").strip()
        group_key = pending.get("group_key")
        reason = str(pending.get("reason") or "group_rekey").strip()
        if not epoch_id or not isinstance(group_key, (bytes, bytearray)) or len(group_key) != 32:
            return False

        identity = self.ensure_identity_keys()
        if not identity:
            return False

        envelopes = []
        seen = set()
        members = member_keys if isinstance(member_keys, list) else []
        for item in members:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username") or "").strip()
            device_id = str(item.get("device_id") or "").strip()
            sign_pub = item.get("sign_pub")
            dh_pub = item.get("dh_pub")
            if not username or not device_id or not dh_pub:
                continue
            if (username, device_id) in seen:
                continue
            seen.add((username, device_id))
            self._remember_peer_identity(username, device_id, sign_pub=sign_pub, dh_pub=dh_pub)
            envelope = self._wrap_group_key_for_device(
                gid,
                epoch_id,
                bytes(group_key),
                username,
                device_id,
                dh_pub,
            )
            if envelope:
                envelopes.append(envelope)

        me = self.username or ""
        my_device = identity.get("device_id")
        my_dh_pub = identity.get("dh_pub")
        if me and my_device and my_dh_pub and (me, my_device) not in seen:
            envelope = self._wrap_group_key_for_device(
                gid,
                epoch_id,
                bytes(group_key),
                me,
                my_device,
                my_dh_pub,
            )
            if envelope:
                envelopes.append(envelope)

        if not envelopes:
            pending["state"] = "waiting_member_keys"
            pending["updated_at"] = time.time()
            self._group_publish_pending[gid] = pending
            return False

        pending["state"] = "publishing"
        pending["updated_at"] = time.time()
        pending["envelope_count"] = len(envelopes)
        self._group_publish_pending[gid] = pending
        self.publish_group_epoch(
            gid,
            epoch_id,
            envelopes,
            sender_device_id=identity.get("device_id"),
            reason=reason,
        )
        return True

    def _handle_group_member_keys(self, msg):
        gid = self._normalize_group_id(msg.get("group_id"))
        if gid is None:
            return
        members = msg.get("members", [])
        if not isinstance(members, list):
            members = []
        self.group_member_keys[gid] = members
        self._publish_pending_group_epoch(gid, members)

    def ensure_group_epoch_published(self, group_id, reason="group_rekey", force_new=False):
        if not self.group_e2e_v2_enabled:
            return False
        gid, session = self._ensure_group_session(group_id)
        if gid is None or not session:
            return False

        existing = self._group_publish_pending.get(gid)
        if isinstance(existing, dict) and not force_new:
            state = str(existing.get("state") or "")
            updated_at = float(existing.get("updated_at") or 0.0)
            if state in ("requested", "waiting_member_keys", "publishing") and (time.time() - updated_at) < 15:
                return True

        epoch_id = None
        key_bytes = None
        if not force_new:
            current = session.get("current")
            epochs = session.get("epochs", {})
            candidate = epochs.get(current) if isinstance(epochs, dict) and current else None
            if isinstance(candidate, (bytes, bytearray)) and len(candidate) == 32:
                epoch_id = str(current)
                key_bytes = bytes(candidate)

        if key_bytes is None:
            epoch_id = self._new_group_epoch_id()
            key_bytes = os.urandom(32)
            self.set_group_key(gid, epoch_id, base64.b64encode(key_bytes).decode("ascii"), set_current=True)

        pending = {
            "epoch_id": epoch_id,
            "group_key": bytes(key_bytes),
            "reason": str(reason or "group_rekey"),
            "state": "requested",
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        self._group_publish_pending[gid] = pending
        self.request_group_member_keys(gid)
        return True

    def _ensure_group_session(self, group_id):
        gid = self._normalize_group_id(group_id)
        if gid is None:
            return None, None
        session = self.group_sessions.get(gid)
        if isinstance(session, dict):
            return gid, session
        session = {"current": None, "epochs": {}}
        if self.username:
            try:
                stored = self.group_store.get_group(self.username, gid)
            except Exception:
                stored = {"current": None, "epochs": {}}
            if isinstance(stored, dict):
                session["current"] = stored.get("current")
                epochs = stored.get("epochs", {})
                if isinstance(epochs, dict):
                    session["epochs"] = dict(epochs)
        self.group_sessions[gid] = session
        return gid, session

    def set_group_key(self, group_id, epoch_id, group_key_b64, set_current=True):
        gid = self._normalize_group_id(group_id)
        epoch = str(epoch_id or "").strip()
        if gid is None or not epoch or not group_key_b64:
            return False
        try:
            key_bytes = base64.b64decode(group_key_b64)
        except Exception:
            return False
        if len(key_bytes) != 32:
            return False
        _, session = self._ensure_group_session(gid)
        if not session:
            return False
        epochs = session.get("epochs")
        if not isinstance(epochs, dict):
            epochs = {}
        epochs[epoch] = key_bytes
        session["epochs"] = epochs
        if set_current:
            session["current"] = epoch
        self.group_sessions[gid] = session
        self._group_rekey_required.discard(gid)
        meta = self.group_meta.get(gid)
        if isinstance(meta, dict):
            meta["key_epoch"] = epoch
            self.group_meta[gid] = meta
        if self.username:
            try:
                self.group_store.set_epoch(self.username, gid, epoch, key_bytes, set_current=set_current)
            except Exception:
                pass
        return True

    def clear_group_session(self, group_id):
        gid = self._normalize_group_id(group_id)
        if gid is None:
            return
        self.group_sessions.pop(gid, None)
        self.group_key_envelopes.pop(gid, None)
        self.group_member_keys.pop(gid, None)
        self._group_publish_pending.pop(gid, None)
        self._group_rekey_required.discard(gid)
        if self.username:
            try:
                self.group_store.remove_group(self.username, gid)
            except Exception:
                pass

    def ingest_group_crypto(self, group_obj):
        if not isinstance(group_obj, dict):
            return False
        applied = self.set_group_key(
            group_obj.get("group_id"),
            group_obj.get("key_epoch"),
            group_obj.get("group_key"),
            set_current=True,
        )
        if not applied and self.group_e2e_v2_enabled:
            gid = self._normalize_group_id(group_obj.get("group_id"))
            if gid is not None:
                self.request_group_key_envelopes(gid, epoch_id=group_obj.get("key_epoch"))
        return applied

    def encrypt_group_payload(self, group_id, payload_obj):
        gid, session = self._ensure_group_session(group_id)
        if gid is None or not session:
            return None
        if self.group_e2e_v2_enabled and gid in self._group_rekey_required:
            if self._is_group_owner(gid):
                self.ensure_group_epoch_published(
                    gid,
                    reason="rekey_required",
                    force_new=True,
                )
            self.request_group_key_envelopes(gid)
            return None
        epoch = session.get("current")
        epochs = session.get("epochs", {})
        if not epoch and isinstance(epochs, dict) and epochs:
            epoch = list(epochs.keys())[-1]
            session["current"] = epoch
        key_bytes = epochs.get(epoch) if isinstance(epochs, dict) else None
        if not epoch or not key_bytes:
            if self.group_e2e_v2_enabled:
                if self._is_group_owner(gid):
                    self.ensure_group_epoch_published(
                        gid,
                        reason="send_missing_key",
                        force_new=False,
                    )
                self.request_group_key_envelopes(gid, epoch_id=epoch)
            return None
        aad = self._group_aad(gid, epoch)
        if not isinstance(payload_obj, dict):
            payload_obj = {"type": "text", "text": str(payload_obj)}
        payload_base = dict(payload_obj)
        payload_base.pop("_sig", None)

        identity = self.ensure_identity_keys()
        privs = self._load_identity_private()
        if not identity or not privs or not privs[0]:
            return None
        sign_priv, _ = privs

        sender_username = self.username or ""
        sender_device_id = identity.get("device_id")
        sender_sign_pub = identity.get("sign_pub")
        sender_dh_pub = identity.get("dh_pub")
        if not sender_device_id or not sender_sign_pub:
            return None

        payload_bytes = self._canonical_group_payload_bytes(payload_base)
        sig_data = self._group_msg_sig_data(
            gid,
            epoch,
            sender_username,
            sender_device_id,
            payload_bytes,
        )
        sig_raw = sign_priv.sign(sig_data)
        payload_signed = dict(payload_base)
        payload_signed["_sig"] = {
            "v": "group_msg_sig_v1",
            "sender_username": sender_username,
            "sender_device_id": sender_device_id,
            "sender_sign_pub": sender_sign_pub,
            "sender_dh_pub": sender_dh_pub,
            "sig": base64.b64encode(sig_raw).decode("ascii"),
        }

        plaintext = json.dumps(payload_signed, ensure_ascii=False).encode("utf-8")
        enc = encrypt_msg(key_bytes, plaintext, aad=aad)
        return {
            "purpose": "group_v1",
            "epoch_id": epoch,
            "enc": enc,
        }

    def decrypt_group_payload(self, group_id, payload_obj, sender_username=None, require_sig=False):
        if not isinstance(payload_obj, dict) or payload_obj.get("purpose") != "group_v1":
            return payload_obj
        gid, session = self._ensure_group_session(group_id)
        if gid is None or not session:
            raise RuntimeError("Group key is unavailable")
        epoch = str(payload_obj.get("epoch_id") or "").strip()
        enc = payload_obj.get("enc")
        if not isinstance(enc, dict):
            raise RuntimeError("Invalid group payload")

        epochs = session.get("epochs", {})
        if not isinstance(epochs, dict):
            epochs = {}

        key_bytes = epochs.get(epoch) if epoch else None
        if key_bytes is None and self.username and epoch:
            try:
                key_bytes = self.group_store.get_epoch(self.username, gid, epoch)
            except Exception:
                key_bytes = None
            if key_bytes:
                epochs[epoch] = key_bytes
                session["epochs"] = epochs
                self.group_sessions[gid] = session

        if key_bytes is None:
            cached = self.group_key_envelopes.get(gid, [])
            if isinstance(cached, list) and cached:
                self._ingest_group_key_envelopes(gid, cached)
                epochs = session.get("epochs", {})
                if isinstance(epochs, dict):
                    key_bytes = epochs.get(epoch) if epoch else None

        if key_bytes is None:
            current = session.get("current")
            key_bytes = epochs.get(current) if current else None
            if key_bytes is not None:
                epoch = current
        if key_bytes is None or not epoch:
            if self.group_e2e_v2_enabled:
                self.request_group_key_envelopes(gid, epoch_id=payload_obj.get("epoch_id"))
            raise RuntimeError("Group key is unavailable")

        aad = self._group_aad(gid, epoch)
        plaintext = decrypt_msg(key_bytes, enc, aad=aad)
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
        except Exception:
            return plaintext.decode("utf-8", errors="replace")

        if not isinstance(decoded, dict):
            return decoded

        sig_meta = decoded.get("_sig")
        if sig_meta is None:
            if require_sig:
                raise RuntimeError("Missing group message signature")
            return decoded
        if not isinstance(sig_meta, dict):
            raise RuntimeError("Invalid group message signature")

        sig_ver = str(sig_meta.get("v") or "").strip()
        if sig_ver != "group_msg_sig_v1":
            raise RuntimeError("Unsupported group signature version")

        sig_b64 = sig_meta.get("sig")
        sender_device_id = str(sig_meta.get("sender_device_id") or "").strip()
        sender_sign_pub = sig_meta.get("sender_sign_pub")
        sender_dh_pub = sig_meta.get("sender_dh_pub")
        sender_from_sig = str(sig_meta.get("sender_username") or "").strip()

        resolved_sender = sender_from_sig or (sender_username or "")
        if sender_username and sender_from_sig and sender_username != sender_from_sig:
            raise RuntimeError("Group sender mismatch")
        if not resolved_sender or not sender_device_id or not sig_b64:
            raise RuntimeError("Invalid group message signature")

        trusted_sign_pub = self._resolve_group_sender_sign_pub(
            resolved_sender,
            sender_device_id,
            sender_sign_pub,
            sender_dh_pub,
        )
        if not trusted_sign_pub:
            raise RuntimeError("Untrusted group sender key")

        payload_base = dict(decoded)
        payload_base.pop("_sig", None)
        payload_bytes = self._canonical_group_payload_bytes(payload_base)
        sig_data = self._group_msg_sig_data(
            gid,
            epoch,
            resolved_sender,
            sender_device_id,
            payload_bytes,
        )
        try:
            sig_raw = base64.b64decode(sig_b64)
            pub = load_ed25519_public_key(base64.b64decode(trusted_sign_pub))
            pub.verify(sig_raw, sig_data)
        except Exception:
            self.identity_pins.set_device_blocked(resolved_sender, sender_device_id, True)
            self._emit_identity_key_notice(resolved_sender, sender_device_id, trusted_sign_pub, sender_dh_pub)
            raise RuntimeError("Invalid group message signature")

        return payload_base

    def ensure_identity_keys(self):
        if not self.username:
            return None
        try:
            identity = self.identity_mgr.get_or_create(self.username)
        except Exception as e:
            print(f"[IDENTITY] Failed to load identity keys: {e}")
            return None
        self.identity = identity
        self.send({
            "type": "set_identity_keys",
            "device_id": identity.get("device_id"),
            "sign_pub": identity.get("sign_pub"),
            "dh_pub": identity.get("dh_pub")
        })
        return identity

    def clear_normal_session(self, peer):
        if peer in self.normal_sessions:
            self.normal_sessions.pop(peer, None)
        self._normal_replay.pop(peer, None)

    def _normal_info(self, a_user, b_user, a_device_id, b_device_id):
        parts = [
            b"chatpy-normal-v1",
            str(a_user).encode("utf-8"),
            str(b_user).encode("utf-8"),
            str(a_device_id).encode("utf-8"),
            str(b_device_id).encode("utf-8")
        ]
        return b"|".join(parts)

    def _normal_sig_data(self, a_device_id, b_user, a_dh_pub, a_eph_pub, salt_session, b_device_id):
        parts = [
            b"chatpy-normal-v1",
            str(a_device_id).encode("utf-8"),
            str(b_user).encode("utf-8"),
            str(b_device_id).encode("utf-8"),
            a_dh_pub,
            a_eph_pub,
            salt_session
        ]
        return b"|".join(parts)

    def _normal_ack_sig_data(self, a_user, b_user, a_device_id, b_device_id, epoch_id):
        parts = [
            b"chatpy-normal-v1-ack",
            str(a_user).encode("utf-8"),
            str(b_user).encode("utf-8"),
            str(a_device_id).encode("utf-8"),
            str(b_device_id).encode("utf-8"),
            str(epoch_id).encode("utf-8"),
        ]
        return b"|".join(parts)

    def _secure_sig_data(self, a_user, b_user, a_device_id, b_device_id, session_id, a_eph_pub, response, rekey):
        parts = [
            b"chatpy-secure-v1",
            str(a_user).encode("utf-8"),
            str(b_user).encode("utf-8"),
            str(a_device_id).encode("utf-8"),
            str(b_device_id or "").encode("utf-8"),
            str(session_id).encode("utf-8"),
            a_eph_pub,
            b"1" if response else b"0",
            b"1" if rekey else b"0",
        ]
        return b"|".join(parts)

    def _b64u_encode(self, data):
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def _b64u_decode(self, data):
        if not isinstance(data, str):
            return None
        padding = "=" * (-len(data) % 4)
        try:
            return base64.urlsafe_b64decode((data + padding).encode("ascii"))
        except Exception:
            return None

    def _normal_epoch_id(self, salt_session):
        return self._b64u_encode(salt_session)

    def _normal_msg_id(self):
        raw = os.urandom(16)
        return self._b64u_encode(raw), raw

    def _normal_msg_key(self, master_key, msg_id_raw):
        return hkdf_derive(master_key, msg_id_raw, b"chatpy-normal-msg-v1", length=32)

    def _normal_aad(self, sender, receiver, epoch_id, msg_id):
        parts = [
            b"chatpy-normal-v1",
            str(sender).encode("utf-8"),
            str(receiver).encode("utf-8"),
            str(epoch_id).encode("utf-8"),
            str(msg_id).encode("utf-8"),
        ]
        return b"|".join(parts)

    def _load_normal_current(self, peer):
        if not self.username or not peer:
            return None
        epoch_id = self.normal_store.get_current_epoch(self.username, peer)
        if not epoch_id:
            return None
        stored = self.normal_store.get_epoch(self.username, peer, epoch_id)
        if not stored or not stored.get("master"):
            return None
        entry = self.normal_sessions.get(peer, {})
        entry.update({
            "current_epoch": epoch_id,
            "master": stored["master"],
            "peer_device_id": stored.get("peer_device_id"),
            "ready": True,
        })
        self.normal_sessions[peer] = entry
        return entry

    def _get_normal_epoch_key(self, peer, epoch_id):
        session = self.normal_sessions.get(peer, {})
        if session.get("current_epoch") == epoch_id and session.get("master"):
            return session.get("master")
        if session.get("pending_epoch") == epoch_id and session.get("pending_master"):
            return session.get("pending_master")
        if not self.username:
            return None
        stored = self.normal_store.get_epoch(self.username, peer, epoch_id)
        if stored and stored.get("master"):
            return stored["master"]
        return None

    def _normal_replay_bucket(self, peer, epoch_id):
        peer_cache = self._normal_replay.setdefault(peer, {})
        bucket = peer_cache.get(epoch_id)
        if bucket is None:
            bucket = {"seen": set(), "order": deque()}
            peer_cache[epoch_id] = bucket
            while len(peer_cache) > self._normal_replay_max_epochs:
                oldest_epoch = next(iter(peer_cache))
                peer_cache.pop(oldest_epoch, None)
        return bucket

    def _normal_replay_seen(self, peer, epoch_id, msg_id):
        peer_cache = self._normal_replay.get(peer)
        if not isinstance(peer_cache, dict):
            return False
        bucket = peer_cache.get(epoch_id)
        if not isinstance(bucket, dict):
            return False
        seen = bucket.get("seen")
        return msg_id in seen if isinstance(seen, set) else False

    def _normal_replay_mark(self, peer, epoch_id, msg_id):
        bucket = self._normal_replay_bucket(peer, epoch_id)
        seen = bucket["seen"]
        order = bucket["order"]
        if msg_id in seen:
            return
        seen.add(msg_id)
        order.append(msg_id)
        while len(order) > self._normal_replay_max_ids:
            old_id = order.popleft()
            seen.discard(old_id)

    def _select_peer_device(self, peer):
        devices = self.identity_pins.get_peer(peer)
        if not isinstance(devices, dict):
            return None, None
        fallback = (None, None)
        for device_id, record in devices.items():
            if not isinstance(record, dict):
                continue
            if record.get("blocked"):
                continue
            dh_pub = record.get("dh_pub")
            if not dh_pub:
                continue
            if record.get("verified"):
                return device_id, dh_pub
            if fallback[0] is None:
                fallback = (device_id, dh_pub)
        return fallback

    def _find_peer_identity(self, peer, device_id):
        if not peer or not device_id:
            return None
        entries = self.peer_identities.get(peer, [])
        if not isinstance(entries, list):
            return None
        for entry in entries:
            if isinstance(entry, dict) and entry.get("device_id") == device_id:
                return entry
        return None

    def _emit_identity_key_notice(self, peer, device_id, sign_pub, dh_pub):
        try:
            self.signals.identity_keys.emit(peer, [{
                "device_id": device_id,
                "sign_pub": sign_pub,
                "dh_pub": dh_pub
            }])
        except Exception:
            pass

    def _load_identity_private(self):
        if not self.username:
            return None
        if not self.identity:
            try:
                self.identity = self.identity_mgr.get_or_create(self.username)
            except Exception:
                return None
        try:
            sign_priv = load_ed25519_private_key(base64.b64decode(self.identity.get("sign_priv", "")))
            dh_priv = load_private_key(base64.b64decode(self.identity.get("dh_priv", "")))
        except Exception:
            return None
        return sign_priv, dh_priv

    def ensure_normal_session(self, peer):
        if not peer or not self.username:
            return None

        session = self.normal_sessions.get(peer, {})
        if session.get("ready") and session.get("current_epoch") and session.get("master"):
            return session.get("master"), session.get("current_epoch")

        loaded = self._load_normal_current(peer)
        if loaded and loaded.get("master") and loaded.get("current_epoch"):
            return loaded.get("master"), loaded.get("current_epoch")

        if session.get("pending_epoch"):
            return None

        return self._start_normal_handshake(peer)

    def _start_normal_handshake(self, peer):
        if not peer or not self.username:
            return None

        identity = self.ensure_identity_keys()
        if not identity:
            return None

        peer_device_id, peer_dh_pub = self._select_peer_device(peer)
        if not peer_device_id or not peer_dh_pub:
            self.request_identity_keys(peer)
            return None

        sign_priv, _ = self._load_identity_private() or (None, None)
        if not sign_priv:
            return None

        from cryptography.hazmat.primitives.asymmetric import x25519
        eph_priv = x25519.X25519PrivateKey.generate()

        eph_pub = eph_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        try:
            peer_pub = load_public_key(base64.b64decode(peer_dh_pub))
        except Exception:
            return None

        salt_session = os.urandom(32)
        epoch_id = self._normal_epoch_id(salt_session)
        shared = eph_priv.exchange(peer_pub)
        info = self._normal_info(self.username, peer, identity.get("device_id"), peer_device_id)
        master_key = hkdf_derive(shared, salt_session, info, length=32)

        sig_data = self._normal_sig_data(
            identity.get("device_id"),
            peer,
            base64.b64decode(identity.get("dh_pub", "")),
            eph_pub,
            salt_session,
            peer_device_id
        )
        sig = sign_priv.sign(sig_data)

        payload = {
            "type": "normal_handshake",
            "stage": "init",
            "peer": peer,
            "from": self.username,
            "epoch_id": epoch_id,
            "a_device_id": identity.get("device_id"),
            "a_ed25519_pub": identity.get("sign_pub"),
            "a_x25519_pub": identity.get("dh_pub"),
            "a_eph_x25519_pub": base64.b64encode(eph_pub).decode("ascii"),
            "salt_session": base64.b64encode(salt_session).decode("ascii"),
            "sig": base64.b64encode(sig).decode("ascii"),
            "b_device_id": peer_device_id
        }

        entry = self.normal_sessions.get(peer, {})
        entry.update({
            "pending_epoch": epoch_id,
            "pending_master": master_key,
            "pending_created": time.time(),
            "peer_device_id": peer_device_id,
            "ready": False,
        })
        self.normal_sessions[peer] = entry
        self.normal_store.set_epoch(
            self.username,
            peer,
            epoch_id,
            master_key,
            peer_device_id=peer_device_id,
            created=time.time(),
            set_current=False,
        )
        self.send(payload)
        return None

    def encrypt_normal(self, peer, plaintext_bytes):
        if not peer or not self.username:
            return None
        session = self.ensure_normal_session(peer)
        if not session:
            return None
        master_key, epoch_id = session
        msg_id, msg_id_raw = self._normal_msg_id()
        msg_key = self._normal_msg_key(master_key, msg_id_raw)
        aad = self._normal_aad(self.username, peer, epoch_id, msg_id)
        payload = encrypt_msg(msg_key, plaintext_bytes, aad=aad)
        if isinstance(payload, dict):
            payload["purpose"] = "normal_v1"
            payload["epoch_id"] = epoch_id
            payload["msg_id"] = msg_id
        return payload

    def _handle_normal_handshake(self, msg):
        peer = msg.get("from") or msg.get("peer")
        if not peer:
            return
        if not self.username:
            return
        stage = msg.get("stage") or "init"
        if stage == "ack":
            self._handle_normal_handshake_ack(msg)
            return
        a_device_id = msg.get("a_device_id")
        a_ed_pub = msg.get("a_ed25519_pub")
        a_dh_pub = msg.get("a_x25519_pub")
        a_eph_pub_b64 = msg.get("a_eph_x25519_pub")
        salt_b64 = msg.get("salt_session")
        sig_b64 = msg.get("sig")
        b_device_id = msg.get("b_device_id")
        epoch_id = msg.get("epoch_id")

        if not a_device_id or not a_ed_pub or not a_dh_pub:
            return
        if not a_eph_pub_b64 or not salt_b64 or not sig_b64:
            return

        my_device_id = self.identity_mgr.get_device_id()
        if b_device_id and b_device_id != my_device_id:
            return

        if self.identity_pins.is_peer_blocked(peer):
            return

        fp = fingerprint_ed25519_pub(a_ed_pub)
        if not fp:
            return

        pinned = self.identity_pins.get_peer(peer)
        if isinstance(pinned, dict) and a_device_id in pinned:
            record = pinned.get(a_device_id, {})
            if record.get("sign_fp") and record.get("sign_fp") != fp:
                self.identity_pins.set_device_blocked(peer, a_device_id, True)
                try:
                    self.signals.identity_keys.emit(peer, [{
                        "device_id": a_device_id,
                        "sign_pub": a_ed_pub,
                        "dh_pub": a_dh_pub
                    }])
                except Exception:
                    pass
                return
            if record.get("dh_pub") and record.get("dh_pub") != a_dh_pub:
                self.identity_pins.set_device_blocked(peer, a_device_id, True)
                try:
                    self.signals.identity_keys.emit(peer, [{
                        "device_id": a_device_id,
                        "sign_pub": a_ed_pub,
                        "dh_pub": a_dh_pub
                    }])
                except Exception:
                    pass
                return

        try:
            a_eph_pub = base64.b64decode(a_eph_pub_b64)
            a_dh_pub_raw = base64.b64decode(a_dh_pub)
            salt_session = base64.b64decode(salt_b64)
            sig = base64.b64decode(sig_b64)
        except Exception:
            return
        derived_epoch = self._normal_epoch_id(salt_session)
        if epoch_id and epoch_id != derived_epoch:
            return
        epoch_id = derived_epoch

        sig_data = self._normal_sig_data(
            a_device_id,
            self.username or "",
            a_dh_pub_raw,
            a_eph_pub,
            salt_session,
            my_device_id
        )
        try:
            pub = load_ed25519_public_key(base64.b64decode(a_ed_pub))
            pub.verify(sig, sig_data)
        except Exception:
            return

        privs = self._load_identity_private()
        if not privs:
            return
        _, dh_priv = privs

        try:
            eph_pub_key = load_public_key(a_eph_pub)
            shared = dh_priv.exchange(eph_pub_key)
        except Exception:
            return

        info = self._normal_info(peer, self.username or "", a_device_id, my_device_id)
        master_key = hkdf_derive(shared, salt_session, info, length=32)
        entry = self.normal_sessions.get(peer, {})
        entry.update({
            "current_epoch": epoch_id,
            "master": master_key,
            "peer_device_id": a_device_id,
            "ready": True,
        })
        self.normal_sessions[peer] = entry
        self.normal_store.set_epoch(
            self.username,
            peer,
            epoch_id,
            master_key,
            peer_device_id=a_device_id,
            created=time.time(),
            set_current=True,
        )

        try:
            self.signals.identity_keys.emit(peer, [{
                "device_id": a_device_id,
                "sign_pub": a_ed_pub,
                "dh_pub": a_dh_pub
            }])
        except Exception:
            pass

        identity = self.ensure_identity_keys()
        if not identity:
            return
        sign_priv, _ = self._load_identity_private() or (None, None)
        if not sign_priv:
            return
        ack_sig_data = self._normal_ack_sig_data(
            peer,
            self.username,
            a_device_id,
            identity.get("device_id"),
            epoch_id,
        )
        ack_sig = sign_priv.sign(ack_sig_data)
        ack_payload = {
            "type": "normal_handshake",
            "stage": "ack",
            "peer": peer,
            "from": self.username,
            "epoch_id": epoch_id,
            "a_device_id": a_device_id,
            "b_device_id": identity.get("device_id"),
            "b_ed25519_pub": identity.get("sign_pub"),
            "b_x25519_pub": identity.get("dh_pub"),
            "sig": base64.b64encode(ack_sig).decode("ascii"),
        }
        self.send(ack_payload)

    def _handle_normal_handshake_ack(self, msg):
        peer = msg.get("from") or msg.get("peer")
        if not peer or not self.username:
            return
        epoch_id = msg.get("epoch_id")
        a_device_id = msg.get("a_device_id")
        b_device_id = msg.get("b_device_id")
        b_ed_pub = msg.get("b_ed25519_pub")
        b_dh_pub = msg.get("b_x25519_pub")
        sig_b64 = msg.get("sig")
        if not epoch_id or not a_device_id or not b_device_id or not b_ed_pub or not b_dh_pub or not sig_b64:
            return
        if self.identity_pins.is_peer_blocked(peer):
            return
        my_device_id = self.identity_mgr.get_device_id()
        if a_device_id != my_device_id:
            return

        fp = fingerprint_ed25519_pub(b_ed_pub)
        if not fp:
            return

        pinned = self.identity_pins.get_peer(peer)
        if isinstance(pinned, dict) and b_device_id in pinned:
            record = pinned.get(b_device_id, {})
            if record.get("sign_fp") and record.get("sign_fp") != fp:
                self.identity_pins.set_device_blocked(peer, b_device_id, True)
                try:
                    self.signals.identity_keys.emit(peer, [{
                        "device_id": b_device_id,
                        "sign_pub": b_ed_pub,
                        "dh_pub": b_dh_pub
                    }])
                except Exception:
                    pass
                return
            if record.get("dh_pub") and record.get("dh_pub") != b_dh_pub:
                self.identity_pins.set_device_blocked(peer, b_device_id, True)
                try:
                    self.signals.identity_keys.emit(peer, [{
                        "device_id": b_device_id,
                        "sign_pub": b_ed_pub,
                        "dh_pub": b_dh_pub
                    }])
                except Exception:
                    pass
                return

        try:
            sig = base64.b64decode(sig_b64)
        except Exception:
            return

        sig_data = self._normal_ack_sig_data(
            self.username,
            peer,
            a_device_id,
            b_device_id,
            epoch_id,
        )
        try:
            pub = load_ed25519_public_key(base64.b64decode(b_ed_pub))
            pub.verify(sig, sig_data)
        except Exception:
            return

        pending = self.normal_sessions.get(peer, {})
        expected_device = pending.get("peer_device_id")
        if expected_device and expected_device != b_device_id:
            return
        master_key = None
        if pending.get("pending_epoch") == epoch_id:
            master_key = pending.get("pending_master")
        if not master_key and self.username:
            stored = self.normal_store.get_epoch(self.username, peer, epoch_id)
            if stored:
                master_key = stored.get("master")
        if not master_key:
            return

        pending.update({
            "current_epoch": epoch_id,
            "master": master_key,
            "peer_device_id": b_device_id,
            "ready": True,
        })
        pending.pop("pending_epoch", None)
        pending.pop("pending_master", None)
        pending.pop("pending_created", None)
        self.normal_sessions[peer] = pending
        self.normal_store.set_epoch(
            self.username,
            peer,
            epoch_id,
            master_key,
            peer_device_id=b_device_id,
            created=time.time(),
            set_current=True,
        )

        try:
            self.signals.identity_keys.emit(peer, [{
                "device_id": b_device_id,
                "sign_pub": b_ed_pub,
                "dh_pub": b_dh_pub
            }])
        except Exception:
            pass

    def decrypt_normal_v1(self, peer, payload, sender=None, receiver=None, replay_protect=False):
        if not isinstance(payload, dict):
            raise ValueError("Invalid payload")
        epoch_id = payload.get("epoch_id")
        msg_id = payload.get("msg_id")
        if not epoch_id or not msg_id:
            raise ValueError("Missing normal session data")
        if sender is None:
            sender = peer
        if receiver is None:
            receiver = self.username or ""
        local_user = self.username or ""
        if replay_protect and sender != local_user and self._normal_replay_seen(peer, epoch_id, msg_id):
            raise ValueError("Replayed normal message")
        master_key = self._get_normal_epoch_key(peer, epoch_id)
        if not master_key:
            raise ValueError("Normal session not established")
        msg_id_raw = self._b64u_decode(msg_id)
        if not msg_id_raw:
            raise ValueError("Invalid message id")
        msg_key = self._normal_msg_key(master_key, msg_id_raw)
        aad = self._normal_aad(sender, receiver, epoch_id, msg_id)
        plaintext = decrypt_msg(msg_key, payload, aad=aad)
        if replay_protect and sender != local_user:
            self._normal_replay_mark(peer, epoch_id, msg_id)
        return plaintext

    def request_identity_keys(self, username):
        if not username:
            return
        self.send({
            "type": "get_identity_keys",
            "username": username
        })

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
            "sent_response": False,
            "peer_device_id": None,
        }

    def start_secure_session(self, peer, initiator=True, rekey=False):
        if not peer:
            return
        session = self._new_session(peer, initiator)
        self.sessions[peer] = session
        self._send_key_exchange(peer, session, is_response=False, rekey=rekey)



    def clear_session(self, peer, keep_pending=False):
        if peer in self.sessions:
            self.sessions.pop(peer, None)
        if not keep_pending:
            self.pending_exchanges.pop(peer, None)
        self.approved_peers.discard(peer)

    def approve_secure_session(self, peer):
        if not peer:
            return
        self.approved_peers.add(peer)
        pending = self.pending_exchanges.pop(peer, None)
        if pending:
            self._handle_key_exchange(pending, allow_unapproved=True)
            return True
        return False

    def has_pending_exchange(self, peer):
        return peer in self.pending_exchanges

    def _send_key_exchange(self, peer, session, is_response=False, rekey=False, target_device_id=None):
        identity = self.ensure_identity_keys()
        if not identity:
            return
        sign_priv, _ = self._load_identity_private() or (None, None)
        if not sign_priv:
            return

        peer_device_id = target_device_id
        if not peer_device_id and is_response and isinstance(session, dict):
            peer_device_id = session.get("peer_device_id")
        sig_data = self._secure_sig_data(
            self.username or "",
            peer,
            identity.get("device_id"),
            peer_device_id,
            session["session_id"],
            session["my_pub"],
            is_response,
            rekey,
        )
        sig = sign_priv.sign(sig_data)

        payload = {
            "type": "secure_key_exchange",
            "peer": peer,
            "from": self.username,
            "pub": base64.b64encode(session["my_pub"]).decode("ascii"),
            "session_id": session["session_id"],
            "response": is_response,
            "rekey": rekey,
            "version": "secure_v1",
            "device_id": identity.get("device_id"),
            "sign_pub": identity.get("sign_pub"),
            "dh_pub": identity.get("dh_pub"),
            "sig": base64.b64encode(sig).decode("ascii"),
        }
        if peer_device_id:
            payload["b_device_id"] = peer_device_id
        self.send(payload)

    def _handle_key_exchange(self, msg, allow_unapproved=False):
        peer = msg.get("from") or msg.get("peer")
        pub_b64 = msg.get("pub")
        if not peer or not pub_b64:
            return

        version = msg.get("version")
        if version != "secure_v1":
            return

        rekey = bool(msg.get("rekey"))
        incoming_sid = msg.get("session_id")
        is_response = bool(msg.get("response"))

        if not allow_unapproved and not is_response and peer not in self.approved_peers:
            # Wait for user acceptance before processing.
            self.pending_exchanges[peer] = msg
            return

        device_id = msg.get("device_id")
        sign_pub = msg.get("sign_pub")
        dh_pub = msg.get("dh_pub")
        sig_b64 = msg.get("sig")
        b_device_id = msg.get("b_device_id")
        if not incoming_sid or not device_id or not sign_pub or not sig_b64:
            return

        if self.identity_pins.is_peer_blocked(peer):
            return

        my_device_id = self.identity_mgr.get_device_id()
        if b_device_id and b_device_id != my_device_id:
            return

        fp = fingerprint_ed25519_pub(sign_pub)
        if not fp:
            return

        pinned = self.identity_pins.get_peer(peer)
        record = pinned.get(device_id, {}) if isinstance(pinned, dict) else {}
        if record.get("blocked"):
            return

        peer_entry = self._find_peer_identity(peer, device_id)
        if isinstance(peer_entry, dict):
            if peer_entry.get("sign_pub") and peer_entry.get("sign_pub") != sign_pub:
                self.identity_pins.set_device_blocked(peer, device_id, True)
                self._emit_identity_key_notice(peer, device_id, sign_pub, dh_pub)
                return
            if dh_pub and peer_entry.get("dh_pub") and peer_entry.get("dh_pub") != dh_pub:
                self.identity_pins.set_device_blocked(peer, device_id, True)
                self._emit_identity_key_notice(peer, device_id, sign_pub, dh_pub)
                return

        if record:
            if record.get("sign_fp") and record.get("sign_fp") != fp:
                self.identity_pins.set_device_blocked(peer, device_id, True)
                self._emit_identity_key_notice(peer, device_id, sign_pub, dh_pub)
                return
            if dh_pub and record.get("dh_pub") and record.get("dh_pub") != dh_pub:
                self.identity_pins.set_device_blocked(peer, device_id, True)
                self._emit_identity_key_notice(peer, device_id, sign_pub, dh_pub)
                return

        try:
            peer_pub = base64.b64decode(pub_b64)
            sig = base64.b64decode(sig_b64)
        except Exception:
            return

        sig_data = self._secure_sig_data(
            peer,
            self.username or "",
            device_id,
            b_device_id,
            incoming_sid,
            peer_pub,
            is_response,
            rekey,
        )
        try:
            pub = load_ed25519_public_key(base64.b64decode(sign_pub))
            pub.verify(sig, sig_data)
        except Exception:
            self.identity_pins.set_device_blocked(peer, device_id, True)
            self._emit_identity_key_notice(peer, device_id, sign_pub, dh_pub)
            return

        if not record:
            self.identity_pins.pin_device(peer, device_id, fp, dh_pub)
            self._emit_identity_key_notice(peer, device_id, sign_pub, dh_pub)

        session = self.sessions.get(peer)

        if session is None or rekey:
            # If we receive a response before starting, we are the initiator.
            initiator = True if is_response else False
            session = self._new_session(peer, initiator=initiator, session_id=incoming_sid)
            self.sessions[peer] = session
        else:
            if session is not None and incoming_sid:
                session["session_id"] = incoming_sid

        session["peer_device_id"] = device_id

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
            self._send_key_exchange(
                peer,
                session,
                is_response=True,
                rekey=rekey,
                target_device_id=device_id,
            )

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
        payload["purpose"] = "secure"
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
            is_decoy: deprecated, reserved for backward compatibility
        """
        self.send({
            "type": "login", 
            "username": username, 
            "password": password
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

    def request_groups(self):
        self.send({"type": "get_groups"})

    def request_group_invites(self):
        self.send({"type": "get_group_invites"})

    def create_group(self, name, members):
        self.send({
            "type": "create_group",
            "name": name,
            "members": members if isinstance(members, list) else []
        })

    def invite_group_member(self, group_id, username):
        self.send({
            "type": "invite_group_member",
            "group_id": group_id,
            "username": username
        })

    def respond_group_invite(self, invite_id, accept):
        self.send({
            "type": "respond_group_invite",
            "invite_id": invite_id,
            "accept": bool(accept)
        })

    def leave_group(self, group_id):
        self.send({
            "type": "leave_group",
            "group_id": group_id
        })

    def delete_group(self, group_id):
        self.send({
            "type": "delete_group",
            "group_id": group_id
        })

    def request_group_history(self, group_id):
        self.send({
            "type": "get_group_history",
            "group_id": group_id
        })

    def request_group_member_keys(self, group_id):
        self.send({
            "type": "get_group_member_keys",
            "group_id": group_id
        })

    def publish_group_epoch(self, group_id, epoch_id, envelopes, sender_device_id=None, reason=None):
        gid = self._normalize_group_id(group_id)
        identity = self.identity if isinstance(self.identity, dict) else None
        if not sender_device_id:
            if identity is None:
                identity = self.ensure_identity_keys()
            if isinstance(identity, dict):
                sender_device_id = identity.get("device_id")
        payload = {
            "type": "group_publish_epoch",
            "group_id": gid if gid is not None else group_id,
            "epoch_id": epoch_id,
            "sender_device_id": sender_device_id,
            "envelopes": envelopes if isinstance(envelopes, list) else []
        }
        if reason:
            payload["reason"] = str(reason)
        self.send(payload)
        if gid is not None:
            pending = self._group_publish_pending.get(gid)
            if isinstance(pending, dict):
                pending["state"] = "publishing"
                pending["updated_at"] = time.time()
                self._group_publish_pending[gid] = pending

    def request_group_key_envelopes(self, group_id, epoch_id=None, since_id=None, limit=None):
        gid = self._normalize_group_id(group_id)
        payload = {
            "type": "get_group_key_envelopes",
            "group_id": gid if gid is not None else group_id
        }
        if epoch_id:
            payload["epoch_id"] = epoch_id
        if since_id is not None:
            payload["since_id"] = since_id
        if limit is not None:
            payload["limit"] = limit
        self.send(payload)

    def send_group_message(self, group_id, payload, secure_mode=False):
        self.send({
            "type": "group_msg",
            "group_id": group_id,
            "payload": payload,
            "secure_mode": bool(secure_mode)
        })

    def delete_group_message(self, group_id, msg_id):
        self.send({
            "type": "group_delete_msg",
            "group_id": group_id,
            "id": msg_id
        })

    def request_history(self, peer):
        self.send({"type": "get_history", "with": peer})

    def send_message(self, to, text, secure_mode=False):
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
