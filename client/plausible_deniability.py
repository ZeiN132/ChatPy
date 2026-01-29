# plausible_deniability.py - Модуль правдоподобного отрицания

import os
import json
import hashlib
import bcrypt
from pathlib import Path

class PlausibleDeniability:
    """
    Система правдоподобного отрицания.
    Позволяет создать фейковый чат с невинными сообщениями,
    доступный по альтернативному паролю.
    """
    
    def __init__(self):
        self.config_dir = Path.home() / ".secure_chat"
        self.config_dir.mkdir(exist_ok=True)
        self.decoy_config_file = self.config_dir / "decoy_passwords.json"
        self.fake_messages_file = self.config_dir / "fake_messages.json"
        
        # Загружаем конфигурацию
        self.decoy_passwords = self._load_decoy_passwords()
        self.fake_messages = self._load_fake_messages()
    
    def _load_decoy_passwords(self):
        """Загрузить сохранённые фейковые пароли"""
        if self.decoy_config_file.exists():
            try:
                with open(self.decoy_config_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_decoy_passwords(self):
        """Сохранить фейковые пароли"""
        with open(self.decoy_config_file, 'w') as f:
            json.dump(self.decoy_passwords, f)
    
    def _load_fake_messages(self):
        """Загрузить фейковые сообщения"""
        if self.fake_messages_file.exists():
            try:
                with open(self.fake_messages_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return self._get_default_fake_messages()
        return self._get_default_fake_messages()
    
    def _save_fake_messages(self):
        """Сохранить фейковые сообщения"""
        with open(self.fake_messages_file, 'w', encoding='utf-8') as f:
            json.dump(self.fake_messages, f, ensure_ascii=False, indent=2)
    
    def _hash_password(self, password):
        """Хешировать пароль для безопасного хранения"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def _verify_password(self, password, stored_hash):
        if not stored_hash:
            return False
        if (
            isinstance(stored_hash, str)
            and len(stored_hash) == 64
            and all(c in "0123456789abcdef" for c in stored_hash.lower())
        ):
            return hashlib.sha256(password.encode()).hexdigest() == stored_hash
        try:
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False
    
    def _get_default_fake_messages(self):
        """Получить набор невинных сообщений по умолчанию"""
        return {
            "Alice": [
                {"text": "Hey! How are you?", "mine": False},
                {"text": "I'm good, thanks! How about you?", "mine": True},
                {"text": "Great! Did you see the game yesterday?", "mine": False},
                {"text": "Yeah, it was amazing!", "mine": True},
                {"text": "I know right! That last goal was incredible", "mine": False},
            ],
            "Bob": [
                {"text": "Hi! Are we still meeting tomorrow?", "mine": False},
                {"text": "Yes, 3 PM at the café", "mine": True},
                {"text": "Perfect! See you then", "mine": False},
                {"text": "👍", "mine": True},
            ],
            "Charlie": [
                {"text": "Did you finish the homework?", "mine": False},
                {"text": "Almost done, just need to finish the last question", "mine": True},
                {"text": "Same here, it's pretty difficult", "mine": False},
                {"text": "Yeah, especially problem 5", "mine": True},
                {"text": "Want to study together this weekend?", "mine": False},
                {"text": "Sure, that would be helpful!", "mine": True},
            ]
        }
    
    def setup_decoy_password(self, username, decoy_password):
        """
        Настроить фейковый пароль для пользователя.
        
        Args:
            username: Основной никнейм пользователя
            decoy_password: Альтернативный пароль для фейкового чата
        
        Returns:
            username (тот же самый)
        """
        # Хешируем и сохраняем фейковый пароль
        password_hash = self._hash_password(decoy_password)
        self.decoy_passwords[username] = password_hash
        self._save_decoy_passwords()
        
        print(f"[PLAUSIBLE] Decoy password set for user: {username}")
        return username
    
    def is_decoy_password(self, username, password):
        """
        Проверить, является ли введённый пароль фейковым.
        
        Args:
            username: Никнейм пользователя
            password: Введённый пароль
        
        Returns:
            True если это фейковый пароль, False иначе
        """
        if username not in self.decoy_passwords:
            return False
        
        stored = self.decoy_passwords[username]
        if self._verify_password(password, stored):
            # Upgrade legacy SHA-256 hash to bcrypt on successful login
            if (
                isinstance(stored, str)
                and len(stored) == 64
                and all(c in "0123456789abcdef" for c in stored.lower())
            ):
                self.decoy_passwords[username] = self._hash_password(password)
                self._save_decoy_passwords()
            return True
        return False
    
    def get_fake_messages(self, peer):
        """
        Получить фейковые сообщения для конкретного собеседника.
        
        Args:
            peer: Имя собеседника
        
        Returns:
            Список фейковых сообщений
        """
        if peer in self.fake_messages:
            return self.fake_messages[peer]
        
        # Возвращаем пустой список если нет готовых сообщений
        return []
    
    def get_fake_contacts(self):
        """
        Получить список фейковых контактов.
        
        Returns:
            Список имён фейковых собеседников
        """
        return list(self.fake_messages.keys())
    
    def add_fake_contact(self, contact_name, messages=None):
        """
        Добавить нового фейкового собеседника.
        
        Args:
            contact_name: Имя контакта
            messages: Список сообщений (необязательно)
        """
        if messages is None:
            messages = [
                {"text": "Hello!", "mine": False},
                {"text": "Hi there!", "mine": True},
            ]
        
        self.fake_messages[contact_name] = messages
        self._save_fake_messages()
    
    def has_decoy_password(self, username):
        """
        Проверить, установлен ли фейковый пароль для пользователя.
        
        Args:
            username: Никнейм пользователя
        
        Returns:
            True если установлен, False иначе
        """
        return username in self.decoy_passwords
    
    def remove_decoy_password(self, username):
        """
        Удалить фейковый пароль для пользователя.
        
        Args:
            username: Никнейм пользователя
        """
        if username in self.decoy_passwords:
            del self.decoy_passwords[username]
            self._save_decoy_passwords()
            print(f"[PLAUSIBLE] Decoy password removed for user: {username}")


# Глобальный экземпляр
_plausible_deniability = PlausibleDeniability()

def get_plausible_deniability():
    """Получить глобальный экземпляр системы правдоподобного отрицания"""
    return _plausible_deniability
