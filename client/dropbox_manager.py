import dropbox
from dropbox import DropboxOAuth2FlowNoRedirect
import webbrowser
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

class DropboxManager:
    def __init__(self, config_dir=".chat_config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        self.token_file = self.config_dir / "dropbox_token.json"
        self.keys_file = self.config_dir / "file_keys.json"
        
        # Вставьте сюда свои App Key и App Secret из Dropbox App Console
        # https://www.dropbox.com/developers/apps
        self.APP_KEY = "ulm2r3wvq4k0rsg"
        self.APP_SECRET = "czgm1fd04gt2y8z"
        
        self.dbx = None
        self.file_keys = self._load_file_keys()
        
        # Попытка загрузить существующий токен
        self._load_token()
    
    def _load_token(self):
        """Загрузка сохраненного токена доступа"""
        if self.token_file.exists():
            try:
                with open(self.token_file, 'r') as f:
                    data = json.load(f)
                    access_token = data.get('access_token')
                    if access_token:
                        self.dbx = dropbox.Dropbox(access_token)
                        # Проверка валидности токена
                        try:
                            self.dbx.users_get_current_account()
                            return True
                        except:
                            self.dbx = None
            except:
                pass
        return False
    
    def _save_token(self, access_token):
        """Сохранение токена доступа"""
        with open(self.token_file, 'w') as f:
            json.dump({'access_token': access_token}, f)
    
    def _load_file_keys(self):
        """Загрузка ключей шифрования файлов"""
        if self.keys_file.exists():
            try:
                with open(self.keys_file, 'r') as f:
                    data = json.load(f)
                    # Декодируем ключи из base64
                    return {k: base64.b64decode(v) for k, v in data.items()}
            except:
                pass
        return {}
    
    def _save_file_keys(self):
        """Сохранение ключей шифрования файлов"""
        # Кодируем ключи в base64 для JSON
        data = {k: base64.b64encode(v).decode() for k, v in self.file_keys.items()}
        with open(self.keys_file, 'w') as f:
            json.dump(data, f)
    
    def is_authenticated(self):
        """Проверка авторизации"""
        return self.dbx is not None
    
    def start_auth_flow(self):
        """
        Начало процесса OAuth авторизации.
        Возвращает URL для открытия в браузере.
        """
        auth_flow = DropboxOAuth2FlowNoRedirect(
            self.APP_KEY,
            self.APP_SECRET,
            token_access_type='offline'
        )
        
        authorize_url = auth_flow.start()
        self.auth_flow = auth_flow
        
        # Открываем браузер
        webbrowser.open(authorize_url)
        
        return authorize_url
    
    def finish_auth_flow(self, auth_code):
        """
        Завершение авторизации с кодом из браузера.
        """
        try:
            oauth_result = self.auth_flow.finish(auth_code)
            access_token = oauth_result.access_token
            
            self._save_token(access_token)
            self.dbx = dropbox.Dropbox(access_token)
            
            return True, "Authorization successful!"
        except Exception as e:
            return False, f"Authorization failed: {str(e)}"
    
    def generate_file_key(self):
        """Генерация нового ключа шифрования для файла"""
        return os.urandom(32)  # 256-bit ключ для AES-GCM
    
    def encrypt_file(self, file_data, key):
        """Шифрование файла"""
        aes = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, file_data, None)
        
        # Возвращаем nonce + ciphertext
        return nonce + ciphertext
    
    def decrypt_file(self, encrypted_data, key):
        """Расшифровка файла"""
        aes = AESGCM(key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        return aes.decrypt(nonce, ciphertext, None)
    
    def upload_file(self, file_name, file_data):
        """
        Загрузка зашифрованного файла в Dropbox.
        Возвращает (успех, путь_в_dropbox, ключ_шифрования)
        """
        if not self.is_authenticated():
            return False, "Not authenticated with Dropbox", None
        
        try:
            # Генерируем уникальный ключ для этого файла
            file_key = self.generate_file_key()
            
            # Шифруем файл
            encrypted_data = self.encrypt_file(file_data, file_key)
            
            # Путь в Dropbox
            dropbox_path = f"/SecureChat/{file_name}.encrypted"
            
            # Загружаем в Dropbox
            self.dbx.files_upload(
                encrypted_data,
                dropbox_path,
                mode=dropbox.files.WriteMode.overwrite
            )
            
            # Сохраняем ключ локально
            self.file_keys[dropbox_path] = file_key
            self._save_file_keys()
            
            return True, dropbox_path, file_key
        
        except Exception as e:
            return False, str(e), None
    
    def list_files(self):
        """
        Получение списка файлов из Dropbox.
        Возвращает список словарей с информацией о файлах.
        """
        if not self.is_authenticated():
            return []
        
        try:
            result = self.dbx.files_list_folder("/SecureChat")
            files = []
            
            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    # Убираем .encrypted из имени
                    display_name = entry.name.replace('.encrypted', '')
                    
                    files.append({
                        'name': display_name,
                        'path': entry.path_display,
                        'size': entry.size,
                        'modified': entry.server_modified,
                        'has_key': entry.path_display in self.file_keys
                    })
            
            return files
        
        except dropbox.exceptions.ApiError as e:
            if isinstance(e.error, dropbox.files.ListFolderError):
                # Папка не существует - создаем
                try:
                    self.dbx.files_create_folder_v2("/SecureChat")
                    return []
                except:
                    pass
            return []
    
    def download_file(self, dropbox_path):
        """
        Скачивание и расшифровка файла из Dropbox.
        Возвращает (успех, данные_файла, сообщение)
        """
        if not self.is_authenticated():
            return False, None, "Not authenticated with Dropbox"
        
        # Проверяем наличие ключа
        if dropbox_path not in self.file_keys:
            return False, None, "Decryption key not found. You can only decrypt files you uploaded."
        
        try:
            # Скачиваем из Dropbox
            metadata, response = self.dbx.files_download(dropbox_path)
            encrypted_data = response.content
            
            # Расшифровываем
            file_key = self.file_keys[dropbox_path]
            decrypted_data = self.decrypt_file(encrypted_data, file_key)
            
            return True, decrypted_data, "Success"
        
        except Exception as e:
            return False, None, str(e)
    
    def delete_file(self, dropbox_path):
        """
        Удаление файла из Dropbox и локального ключа.
        """
        if not self.is_authenticated():
            return False, "Not authenticated"
        
        try:
            # Удаляем из Dropbox
            self.dbx.files_delete_v2(dropbox_path)
            
            # Удаляем ключ локально
            if dropbox_path in self.file_keys:
                del self.file_keys[dropbox_path]
                self._save_file_keys()
            
            return True, "File deleted successfully"
        
        except Exception as e:
            return False, str(e)
    
    def get_account_info(self):
        """Получение информации об аккаунте"""
        if not self.is_authenticated():
            return None
        
        try:
            account = self.dbx.users_get_current_account()
            space_usage = self.dbx.users_get_space_usage()
            
            return {
                'name': account.name.display_name,
                'email': account.email,
                'used_space': space_usage.used,
                'allocated_space': space_usage.allocation.get_individual().allocated
            }
        except:
            return None
    
    def disconnect(self):
        """Отключение от Dropbox (удаление токена)"""
        if self.token_file.exists():
            self.token_file.unlink()
        self.dbx = None