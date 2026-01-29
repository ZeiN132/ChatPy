import base64
import hashlib
import json
import os
import shutil
from pathlib import Path


class GraphicPasswordManager:
    def __init__(self, config_dir=None):
        self.config_dir = Path(config_dir) if config_dir else Path.home() / ".secure_chat"
        self.config_dir.mkdir(exist_ok=True)
        self.config_file = self.config_dir / "graphic_password.json"
        self.data = self._load()
        self._migrate_legacy_if_needed()

    def _load(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return None

    def _save(self):
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(self.data, f)

    def _get_image_hash(self, image_path):
        try:
            raw = Path(image_path).read_bytes()
        except Exception:
            return None
        return hashlib.sha256(raw).hexdigest()

    def _points_to_bytes(self, points_norm, tolerance=None):
        # Stable encoding for PBKDF2 with optional tolerance quantization
        tol = float(tolerance) if tolerance else 0.0
        parts = []
        for x, y in points_norm:
            fx = float(x)
            fy = float(y)
            if tol > 0:
                fx = round(fx / tol) * tol
                fy = round(fy / tol) * tol
            parts.append(f"{fx:.8f},{fy:.8f}")
        return "|".join(parts).encode("utf-8")

    def _derive_hash(self, points_norm, salt, iterations=200_000, dklen=32, tolerance=None):
        return hashlib.pbkdf2_hmac(
            "sha256",
            self._points_to_bytes(points_norm, tolerance=tolerance),
            salt,
            int(iterations),
            dklen=int(dklen),
        ).hex()

    def _migrate_legacy_if_needed(self):
        if not isinstance(self.data, dict):
            return
        if "points" not in self.data:
            return
        if "image" not in self.data:
            return

        points = self.data.get("points", [])
        image_name = self.data.get("image")
        tolerance = float(self.data.get("tolerance", 0.06))
        image_path = self.config_dir / image_name if image_name else None
        if not image_path or not image_path.exists():
            return

        salt = os.urandom(16)
        image_hash = self._get_image_hash(image_path)
        if image_hash is None:
            return

        pwd_hash = self._derive_hash(points, salt, tolerance=tolerance)
        self.data = {
            "image": image_name,
            "tolerance": tolerance,
            "point_count": len(points),
            "salt": base64.b64encode(salt).decode("ascii"),
            "hash": pwd_hash,
            "image_hash": image_hash,
            "kdf": "pbkdf2_sha256",
            "iterations": 200_000,
            "dklen": 32,
        }
        self._save()

    def has_password(self):
        if not self.data:
            return False
        image_path = self.get_image_path()
        return image_path is not None and image_path.exists()

    def get_image_path(self):
        if not self.data:
            return None
        image_name = self.data.get("image")
        if not image_name:
            return None
        return self.config_dir / image_name

    def get_points(self):
        if not self.data:
            return []
        return self.data.get("points", [])

    def get_point_count(self):
        if not self.data:
            return 0
        count = self.data.get("point_count")
        if isinstance(count, int) and count > 0:
            return count
        # Legacy fallback
        return len(self.data.get("points", []))

    def get_tolerance(self):
        if not self.data:
            return 0.06
        return float(self.data.get("tolerance", 0.06))

    def set_password(self, image_path, points_norm, tolerance=0.06):
        src = Path(image_path)
        if not src.exists():
            raise FileNotFoundError("Image not found")

        image_name = f"graphic_password{src.suffix.lower()}"
        dst = self.config_dir / image_name
        shutil.copy2(src, dst)

        salt = os.urandom(16)
        image_hash = self._get_image_hash(dst)
        if image_hash is None:
            raise ValueError("Unable to read image data")

        pwd_hash = self._derive_hash(points_norm, salt, tolerance=tolerance)
        self.data = {
            "image": image_name,
            "tolerance": tolerance,
            "point_count": len(points_norm),
            "salt": base64.b64encode(salt).decode("ascii"),
            "hash": pwd_hash,
            "image_hash": image_hash,
            "kdf": "pbkdf2_sha256",
            "iterations": 200_000,
            "dklen": 32,
        }
        self._save()

    def verify(self, points_norm):
        if not self.data:
            return False

        image_path = self.get_image_path()
        if image_path is None or not image_path.exists():
            return False
        image_hash = self._get_image_hash(image_path)
        if image_hash is None:
            return False
        stored_image_hash = self.data.get("image_hash")
        if stored_image_hash and stored_image_hash != image_hash:
            return False

        salt_b64 = self.data.get("salt")
        stored_hash = self.data.get("hash")
        if not salt_b64 or not stored_hash:
            return False

        try:
            salt = base64.b64decode(salt_b64)
        except Exception:
            return False

        iterations = int(self.data.get("iterations", 200_000))
        dklen = int(self.data.get("dklen", 32))
        tolerance = float(self.data.get("tolerance", 0.06))
        candidate = self._derive_hash(points_norm, salt, iterations, dklen, tolerance=tolerance)
        return candidate == stored_hash
