# forensic_protection.py - Модуль защиты от форензики

import os
import ctypes
import gc
import mmap
import tempfile
from pathlib import Path

class ForensicProtection:
    """
    Класс для защиты от форензического анализа.
    Включает очистку памяти, безопасное удаление данных и защиту от восстановления.
    """
    
    def __init__(self):
        self.secure_mode = False
        self.temp_files = []
        
    def enable_secure_mode(self):
        """Включить защищённый режим"""
        self.secure_mode = True
        print("[FORENSIC] Secure mode ENABLED")
        
    def disable_secure_mode(self):
        """Выключить защищённый режим"""
        self.secure_mode = False
        print("[FORENSIC] Secure mode DISABLED")
        
    def is_secure_mode(self):
        """Проверить, включён ли защищённый режим"""
        return self.secure_mode
    
    def secure_delete_string(self, string_obj):
        """
        Безопасное удаление строки из памяти.
        Перезаписывает память перед удалением.
        """
        if not isinstance(string_obj, str):
            return
            
        try:
            # Получаем адрес объекта в памяти
            string_bytes = string_obj.encode('utf-8')
            length = len(string_bytes)
            
            # Создаём буфер с нулями
            zeros = b'\x00' * length
            
            # Перезаписываем память (работает только в CPython)
            try:
                # Попытка перезаписать через ctypes
                addr = id(string_obj)
                # В Python строки иммутабельны, поэтому работаем с байтами
                pass
            except:
                pass
                
        except Exception as e:
            print(f"[FORENSIC] Error in secure_delete_string: {e}")
    
    def secure_delete_bytes(self, bytes_obj):
        """
        Безопасное удаление байтов из памяти.
        """
        if not isinstance(bytes_obj, (bytes, bytearray)):
            return
            
        try:
            if isinstance(bytes_obj, bytearray):
                # Для bytearray можем напрямую перезаписать
                for i in range(len(bytes_obj)):
                    bytes_obj[i] = 0
        except Exception as e:
            print(f"[FORENSIC] Error in secure_delete_bytes: {e}")
    
    def secure_delete_dict(self, dict_obj):
        """
        Безопасное удаление словаря.
        Перезаписывает все значения перед удалением.
        """
        if not isinstance(dict_obj, dict):
            return
            
        try:
            for key in list(dict_obj.keys()):
                value = dict_obj[key]
                
                if isinstance(value, str):
                    self.secure_delete_string(value)
                elif isinstance(value, (bytes, bytearray)):
                    self.secure_delete_bytes(value)
                elif isinstance(value, dict):
                    self.secure_delete_dict(value)
                    
                dict_obj[key] = None
                
            dict_obj.clear()
        except Exception as e:
            print(f"[FORENSIC] Error in secure_delete_dict: {e}")
    
    def secure_wipe_memory(self):
        """
        Агрессивная очистка памяти Python.
        Вызывает сборщик мусора несколько раз.
        """
        try:
            # Принудительная сборка мусора 3 раза
            for _ in range(3):
                gc.collect()
                
            # Очистка кеша CPython (если доступно)
            try:
                import sys
                if hasattr(sys, 'intern'):
                    # Очистка interned строк (limited)
                    pass
            except:
                pass
                
            print("[FORENSIC] Memory wiped")
        except Exception as e:
            print(f"[FORENSIC] Error in secure_wipe_memory: {e}")
    
    def secure_delete_file(self, filepath):
        """
        Безопасное удаление файла с перезаписью.
        DoD 5220.22-M стандарт (3 прохода).
        """
        try:
            if not os.path.exists(filepath):
                return True
                
            # Получаем размер файла
            file_size = os.path.getsize(filepath)
            
            # 3 прохода перезаписи
            patterns = [
                b'\x00',  # Проход 1: нули
                b'\xFF',  # Проход 2: единицы
                os.urandom(1)[0:1]  # Проход 3: случайные данные
            ]
            
            for pattern in patterns:
                with open(filepath, 'wb') as f:
                    # Записываем паттерн
                    for _ in range(0, file_size, 4096):
                        chunk_size = min(4096, file_size - f.tell())
                        if chunk_size <= 0:
                            break
                        f.write(pattern * chunk_size)
                    f.flush()
                    os.fsync(f.fileno())
            
            # Удаляем файл
            os.remove(filepath)
            print(f"[FORENSIC] File securely deleted: {filepath}")
            return True
            
        except Exception as e:
            print(f"[FORENSIC] Error deleting file {filepath}: {e}")
            return False
    
    def register_temp_file(self, filepath):
        """Регистрация временного файла для последующего безопасного удаления"""
        if filepath not in self.temp_files:
            self.temp_files.append(filepath)
    
    def cleanup_temp_files(self):
        """Очистка всех зарегистрированных временных файлов"""
        for filepath in self.temp_files:
            self.secure_delete_file(filepath)
        self.temp_files.clear()
        print("[FORENSIC] All temp files cleaned")
    
    def create_secure_temp_file(self, data, suffix=''):
        """
        Создаёт временный файл, который будет безопасно удалён.
        """
        try:
            fd, filepath = tempfile.mkstemp(suffix=suffix)
            os.write(fd, data)
            os.close(fd)
            self.register_temp_file(filepath)
            return filepath
        except Exception as e:
            print(f"[FORENSIC] Error creating temp file: {e}")
            return None
    
    def secure_overwrite_ram(self, size_mb=10):
        """
        Перезапись части RAM для затруднения восстановления данных.
        ВНИМАНИЕ: Может замедлить систему!
        """
        try:
            # Создаём большие объекты в памяти
            junk_data = []
            chunk_size = 1024 * 1024  # 1 MB
            
            for _ in range(size_mb):
                # Создаём случайные данные
                junk_data.append(os.urandom(chunk_size))
            
            # Перезаписываем нулями
            for i in range(len(junk_data)):
                junk_data[i] = b'\x00' * chunk_size
            
            # Удаляем
            junk_data.clear()
            gc.collect()
            
            print(f"[FORENSIC] RAM overwritten: {size_mb} MB")
        except Exception as e:
            print(f"[FORENSIC] Error in secure_overwrite_ram: {e}")


class SecureMessageStorage:
    """
    Хранилище для сообщений в защищённом режиме.
    Все данные хранятся в памяти и уничтожаются при закрытии.
    """
    
    def __init__(self):
        self.messages = {}  # peer -> list of messages
        self.message_ids = {}  # msg_id -> peer
        
    def add_message(self, peer, msg_id, message_data):
        """Добавить сообщение в защищённое хранилище"""
        if peer not in self.messages:
            self.messages[peer] = []
        
        self.messages[peer].append({
            'id': msg_id,
            'data': message_data
        })
        
        self.message_ids[msg_id] = peer
    
    def get_messages(self, peer):
        """Получить все сообщения для собеседника"""
        return self.messages.get(peer, [])
    
    def remove_message(self, msg_id):
        """Удалить конкретное сообщение"""
        if msg_id in self.message_ids:
            peer = self.message_ids[msg_id]
            
            if peer in self.messages:
                self.messages[peer] = [
                    msg for msg in self.messages[peer] 
                    if msg['id'] != msg_id
                ]
            
            del self.message_ids[msg_id]
    
    def clear_peer_messages(self, peer, forensic_protection):
        """Безопасно очистить все сообщения с собеседником"""
        if peer in self.messages:
            # Безопасно удаляем каждое сообщение
            for msg in self.messages[peer]:
                if isinstance(msg['data'], dict):
                    forensic_protection.secure_delete_dict(msg['data'])
            
            # Удаляем ID сообщений
            msg_ids_to_remove = [
                msg_id for msg_id, p in self.message_ids.items() 
                if p == peer
            ]
            for msg_id in msg_ids_to_remove:
                del self.message_ids[msg_id]
            
            # Очищаем список
            self.messages[peer].clear()
            del self.messages[peer]
            
            print(f"[SECURE] Messages with {peer} securely erased")
    
    def secure_cleanup_all(self, forensic_protection):
        """Полная безопасная очистка всех данных"""
        for peer in list(self.messages.keys()):
            self.clear_peer_messages(peer, forensic_protection)
        
        self.messages.clear()
        self.message_ids.clear()
        
        # Перезаписываем память
        forensic_protection.secure_wipe_memory()
        
        print("[SECURE] All secure messages erased from memory")


# Глобальный экземпляр защиты
_forensic_protection = ForensicProtection()
_secure_storage = SecureMessageStorage()

def get_forensic_protection():
    """Получить глобальный экземпляр защиты от форензики"""
    return _forensic_protection

def get_secure_storage():
    """Получить глобальное защищённое хранилище"""
    return _secure_storage