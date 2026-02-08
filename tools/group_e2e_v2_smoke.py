#!/usr/bin/env python3
"""
Smoke test for ChatPy group E2E v2 server endpoints.

What it checks:
1) Authentication (login/register fallback).
2) Group creation.
3) group_publish_epoch.
4) get_group_key_envelopes.
5) Basic validation path (invalid publish should return group_error).

Environment defaults:
- CHATPY_SERVER_HOST (default: 127.0.0.1)
- CHATPY_SERVER_PORT (default: 9999)
- CHATPY_TLS_ENABLED (default: 0)
- CHATPY_TLS_CA_FILE
- CHATPY_TLS_SERVER_NAME
"""

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import time
import uuid
from typing import Any, Callable, Dict, Optional


def _env_truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _b64_random(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode("ascii")


class JsonLineClient:
    def __init__(self, host: str, port: int, tls: bool, ca_file: Optional[str], server_name: Optional[str]):
        self.host = host
        self.port = port
        self.tls = tls
        self.ca_file = ca_file
        self.server_name = server_name or host
        self.sock: Optional[socket.socket] = None
        self.file = None

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=10.0)
        sock: socket.socket = raw
        if self.tls:
            if self.ca_file:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_file)
            else:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            sock = ctx.wrap_socket(raw, server_hostname=self.server_name)
        self.sock = sock
        self.file = sock.makefile("rwb")

    def close(self) -> None:
        try:
            if self.file is not None:
                self.file.close()
        finally:
            self.file = None
            if self.sock is not None:
                try:
                    self.sock.close()
                finally:
                    self.sock = None

    def send(self, data: Dict[str, Any]) -> None:
        if self.file is None:
            raise RuntimeError("Not connected")
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8") + b"\n"
        self.file.write(payload)
        self.file.flush()

    def recv(self, timeout_s: float = 10.0) -> Dict[str, Any]:
        if self.sock is None or self.file is None:
            raise RuntimeError("Not connected")
        self.sock.settimeout(timeout_s)
        raw = self.file.readline()
        if not raw:
            raise RuntimeError("Connection closed by server")
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON from server: {raw!r}") from exc

    def wait_for(self, predicate: Callable[[Dict[str, Any]], bool], timeout_s: float = 12.0) -> Dict[str, Any]:
        deadline = time.time() + timeout_s
        last: Optional[Dict[str, Any]] = None
        while time.time() < deadline:
            msg = self.recv(timeout_s=max(0.1, deadline - time.time()))
            last = msg
            if predicate(msg):
                return msg
        raise RuntimeError(f"Timeout waiting for expected message; last={last}")


def wait_auth_ok(client: JsonLineClient, timeout_s: float = 15.0) -> Dict[str, Any]:
    def _match(msg: Dict[str, Any]) -> bool:
        if msg.get("status") != "ok":
            return False
        mtype = msg.get("type")
        return mtype in ("auth", "register") or ("username" in msg and "users" in msg)

    return client.wait_for(_match, timeout_s=timeout_s)


def login_or_register(client: JsonLineClient, username: str, password: str) -> None:
    client.send({
        "type": "login",
        "username": username,
        "password": password,
    })
    auth = client.wait_for(lambda m: m.get("type") in ("auth", "register"), timeout_s=15.0)
    if auth.get("status") == "ok":
        return

    # Fallback to register when login fails.
    client.send({
        "type": "register",
        "username": username,
        "password": password,
        "recovery_phrase": "",
    })
    reg = client.wait_for(lambda m: m.get("type") == "register", timeout_s=15.0)
    if reg.get("status") != "ok":
        raise RuntimeError(f"Register failed: {reg}")
    wait_auth_ok(client, timeout_s=10.0)


def set_identity_keys(client: JsonLineClient, device_id: str) -> None:
    client.send({
        "type": "set_identity_keys",
        "device_id": device_id,
        "sign_pub": _b64_random(32),
        "dh_pub": _b64_random(32),
    })
    resp = client.wait_for(lambda m: m.get("type") == "identity_keys_set", timeout_s=10.0)
    if resp.get("status") != "ok":
        raise RuntimeError(f"set_identity_keys failed: {resp}")


def create_group(client: JsonLineClient, name: str) -> int:
    client.send({
        "type": "create_group",
        "name": name,
        "members": [],
    })
    resp = client.wait_for(lambda m: m.get("type") == "group_created", timeout_s=15.0)
    group = resp.get("group") if isinstance(resp.get("group"), dict) else {}
    group_id = group.get("group_id")
    if not isinstance(group_id, int) or group_id <= 0:
        raise RuntimeError(f"Invalid group_created payload: {resp}")
    return group_id


def publish_epoch(client: JsonLineClient, group_id: int, username: str, sender_device_id: str, epoch_id: str) -> None:
    envelope = {
        "recipient_username": username,
        "recipient_device_id": sender_device_id,
        "payload": {
            "scheme": "group_key_wrap_v1",
            "wrapped_key": _b64_random(48),
            "eph_pub": _b64_random(32),
            "salt": _b64_random(16),
        },
    }
    client.send({
        "type": "group_publish_epoch",
        "group_id": group_id,
        "epoch_id": epoch_id,
        "sender_device_id": sender_device_id,
        "reason": "smoke_test",
        "envelopes": [envelope],
    })
    resp = client.wait_for(lambda m: m.get("type") == "group_epoch_published", timeout_s=15.0)
    if resp.get("status") != "ok":
        raise RuntimeError(f"group_publish_epoch failed: {resp}")
    if resp.get("group_id") != group_id or resp.get("epoch_id") != epoch_id:
        raise RuntimeError(f"Unexpected publish response: {resp}")


def fetch_envelopes(client: JsonLineClient, group_id: int, epoch_id: str) -> Dict[str, Any]:
    client.send({
        "type": "get_group_key_envelopes",
        "group_id": group_id,
        "epoch_id": epoch_id,
        "limit": 50,
    })
    resp = client.wait_for(lambda m: m.get("type") == "group_key_envelopes", timeout_s=12.0)
    if resp.get("group_id") != group_id:
        raise RuntimeError(f"Unexpected group_id in envelopes response: {resp}")
    return resp


def negative_invalid_publish(client: JsonLineClient, group_id: int, sender_device_id: str, epoch_id: str) -> None:
    client.send({
        "type": "group_publish_epoch",
        "group_id": group_id,
        "epoch_id": epoch_id + "-bad",
        "sender_device_id": sender_device_id,
        "envelopes": [],
    })
    err = client.wait_for(
        lambda m: m.get("type") == "group_error" and m.get("op") == "group_publish_epoch",
        timeout_s=10.0,
    )
    if not err.get("error"):
        raise RuntimeError(f"Expected validation error for invalid publish, got: {err}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke test for group E2E v2 endpoints")
    parser.add_argument("--host", default=os.getenv("CHATPY_SERVER_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CHATPY_SERVER_PORT", "9999")))
    parser.add_argument("--username", default="smoke_e2e_v2")
    parser.add_argument("--password", default="smoke_e2e_v2_password")
    parser.add_argument("--tls", action="store_true", default=_env_truthy(os.getenv("CHATPY_TLS_ENABLED", "0")))
    parser.add_argument("--ca-file", default=os.getenv("CHATPY_TLS_CA_FILE"))
    parser.add_argument("--server-name", default=os.getenv("CHATPY_TLS_SERVER_NAME"))
    parser.add_argument("--skip-negative", action="store_true", help="Skip invalid publish validation case")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = JsonLineClient(
        host=args.host,
        port=args.port,
        tls=args.tls,
        ca_file=args.ca_file,
        server_name=args.server_name,
    )
    group_id = None
    epoch_id = None
    try:
        print(f"[1/6] Connecting to {args.host}:{args.port} tls={args.tls}")
        client.connect()

        print("[2/6] Login/register")
        login_or_register(client, args.username, args.password)

        device_id = f"smoke-{uuid.uuid4().hex[:16]}"
        print(f"[3/6] Set identity keys (device_id={device_id})")
        set_identity_keys(client, device_id=device_id)

        group_name = f"smoke-{uuid.uuid4().hex[:10]}"
        print(f"[4/6] Create group ({group_name})")
        group_id = create_group(client, group_name)
        print(f"      group_id={group_id}")

        epoch_id = f"epoch-{uuid.uuid4().hex[:12]}"
        print(f"[5/6] Publish epoch envelopes ({epoch_id})")
        publish_epoch(client, group_id, args.username, device_id, epoch_id)

        print("[6/6] Fetch envelopes")
        env_resp = fetch_envelopes(client, group_id, epoch_id)
        envelopes = env_resp.get("envelopes")
        if not isinstance(envelopes, list) or not envelopes:
            raise RuntimeError(f"Envelope list is empty: {env_resp}")
        first = envelopes[0] if isinstance(envelopes[0], dict) else {}
        if first.get("epoch_id") != epoch_id:
            raise RuntimeError(f"Unexpected epoch in envelope: {first}")

        if not args.skip_negative:
            print("[extra] Validate invalid publish path")
            negative_invalid_publish(client, group_id, device_id, epoch_id)

        print("PASS: group E2E v2 smoke checks completed")
        return 0
    except Exception as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
