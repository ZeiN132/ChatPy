import mysql.connector
import json
from crypto_utils import encrypt_msg, decrypt_msg

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root123",
    "database": "secure_chat"
}

def check_encryption_in_db():
    """
    Проверяет, действительно ли сообщения зашифрованы в БД
    """
    print("=" * 70)
    print("ПРОВЕРКА ШИФРОВАНИЯ В БАЗЕ ДАННЫХ")
    print("=" * 70)
    
    conn = mysql.connector.connect(**DB_CONFIG)
    cur = conn.cursor(dictionary=True)
    
    # Получаем все сообщения
    cur.execute("SELECT id, sender, receiver, payload, ts FROM messages ORDER BY ts DESC LIMIT 20")
    messages = cur.fetchall()
    
    if not messages:
        print("\n❌ Нет сообщений в базе данных")
        cur.close()
        conn.close()
        return
    
    print(f"\n📊 Найдено сообщений: {len(messages)}\n")
    
    encrypted_count = 0
    plain_text_count = 0
    file_count = 0
    
    for msg in messages:
        msg_id = msg['id']
        sender = msg['sender']
        receiver = msg['receiver']
        payload = msg['payload']
        timestamp = msg['ts']
        
        print(f"\n{'='*70}")
        print(f"📩 Message ID: {msg_id}")
        print(f"👤 From: {sender} → To: {receiver}")
        print(f"🕒 Time: {timestamp}")
        print(f"{'='*70}")
        
        # Проверяем тип payload
        try:
            parsed = json.loads(payload)
            
            # Проверка на зашифрованное сообщение
            if isinstance(parsed, dict) and 'nonce' in parsed and 'ciphertext' in parsed:
                print("✅ ЗАШИФРОВАНО (AES-GCM)")
                print(f"   Nonce: {parsed['nonce'][:20]}...")
                print(f"   Ciphertext: {parsed['ciphertext'][:40]}...")
                encrypted_count += 1
                
            # Проверка на файл
            elif isinstance(parsed, str) and parsed.startswith("FILE:"):
                parts = parsed.split(":", 2)
                if len(parts) >= 3:
                    file_name = parts[1]
                    try:
                        file_data = json.loads(parts[2])
                        if 'nonce' in file_data and 'ciphertext' in file_data:
                            print(f"✅ ФАЙЛ ЗАШИФРОВАН: {file_name}")
                            print(f"   Nonce: {file_data['nonce'][:20]}...")
                            print(f"   Ciphertext: {file_data['ciphertext'][:40]}...")
                            file_count += 1
                        else:
                            print(f"⚠️  ФАЙЛ НЕ ЗАШИФРОВАН: {file_name}")
                    except:
                        print(f"⚠️  ФАЙЛ (формат неизвестен): {file_name}")
            else:
                print("❌ ОТКРЫТЫЙ ТЕКСТ (НЕ ЗАШИФРОВАН):")
                print(f"   Content: {str(parsed)[:100]}")
                plain_text_count += 1
                
        except json.JSONDecodeError:
            # Это обычный текст (не JSON)
            print("❌ ОТКРЫТЫЙ ТЕКСТ (НЕ ЗАШИФРОВАН):")
            print(f"   Content: {payload[:100]}")
            plain_text_count += 1
    
    print(f"\n{'='*70}")
    print("📈 СТАТИСТИКА:")
    print(f"{'='*70}")
    print(f"✅ Зашифрованных сообщений: {encrypted_count}")
    print(f"📎 Зашифрованных файлов: {file_count}")
    print(f"❌ Открытых текстов: {plain_text_count}")
    print(f"📊 Всего: {len(messages)}")
    
    security_level = ((encrypted_count + file_count) / len(messages) * 100) if messages else 0
    print(f"\n🔒 Уровень безопасности: {security_level:.1f}%")
    
    if security_level == 100:
        print("✅ ВСЕ СООБЩЕНИЯ ЗАШИФРОВАНЫ!")
    elif security_level > 0:
        print("⚠️  ЧАСТЬ СООБЩЕНИЙ НЕ ЗАШИФРОВАНА!")
    else:
        print("❌ ШИФРОВАНИЕ НЕ РАБОТАЕТ!")
    
    cur.close()
    conn.close()

def test_encryption_manually():
    """
    Тестирует шифрование вручную
    """
    print("\n" + "="*70)
    print("РУЧНОЙ ТЕСТ ШИФРОВАНИЯ")
    print("="*70)
    
    
    
    # Генерируем тестовый ключ
    test_key = b"\x00" * 32
    
    # Тестовое сообщение
    test_message = "Hello, this is a secret message! 🔒"
    
    print(f"\n📝 Исходное сообщение: {test_message}")
    
    # Шифруем
    encrypted = encrypt_msg(test_key, test_message.encode())
    print(f"\n🔐 Зашифрованное:")
    print(f"   Type: {type(encrypted)}")
    print(f"   Nonce: {encrypted['nonce']}")
    print(f"   Ciphertext: {encrypted['ciphertext'][:50]}...")
    
    # Расшифровываем
    decrypted = decrypt_msg(test_key, encrypted)
    print(f"\n🔓 Расшифрованное: {decrypted.decode()}")
    
    # Проверяем
    if decrypted.decode() == test_message:
        print("\n✅ Шифрование работает корректно!")
    else:
        print("\n❌ ОШИБКА ШИФРОВАНИЯ!")
    
    # Пробуем расшифровать неправильным ключом
    print("\n🔍 Попытка расшифровать неправильным ключом...")
    wrong_key = b"\xFF" * 32
    try:
        wrong_decrypt = decrypt_msg(wrong_key, encrypted)
        print("❌ ОПАСНО! Расшифровка прошла с неправильным ключом!")
    except Exception as e:
        print(f"✅ Правильно! Ошибка: {type(e).__name__}")

def show_recommendations():
    """
    Показывает рекомендации по безопасности
    """
    print("\n" + "="*70)
    print("🔒 РЕКОМЕНДАЦИИ ПО БЕЗОПАСНОСТИ")
    print("="*70)
    
    print("""
1. ✅ End-to-End шифрование (E2EE):
   - Сообщения шифруются на клиенте ПЕРЕД отправкой
   - Сервер видит только зашифрованные данные
   - Только получатель может расшифровать (имеет ключ)

2. ⚠️  ТЕКУЩИЕ ПРОБЛЕМЫ:
   - Используется тестовый ключ (b"\\x00" * 32)
   - Все пары пользователей используют ОДИН ключ
   - Нет обмена ключами (Diffie-Hellman)

3. 🔧 ЧТО НУЖНО УЛУЧШИТЬ:
   - Реализовать Diffie-Hellman для обмена ключами
   - Каждая пара пользователей = уникальный ключ
   - Добавить Perfect Forward Secrecy (PFS)
   - Хранить ключи безопасно (не в коде!)

4. 📋 КАК ПРОВЕРИТЬ БЕЗОПАСНОСТЬ:
   - Запустите этот скрипт: python verify_encryption.py
   - Откройте БД напрямую: mysql -u root -p
   - Проверьте: SELECT * FROM messages;
   - Вы должны видеть только hex-строки, не текст!

5. 🚨 RED FLAGS (если видите):
   - Читаемый текст в поле payload
   - JSON без полей nonce/ciphertext
   - Одинаковые ciphertext для одинаковых сообщений
    """)

if __name__ == "__main__":
    # Запускаем все проверки
    test_encryption_manually()
    check_encryption_in_db()
    show_recommendations()
    
    print("\n" + "="*70)
    print("ПРОВЕРКА ЗАВЕРШЕНА")
    print("="*70)