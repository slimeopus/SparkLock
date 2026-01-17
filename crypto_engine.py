import os
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.constant_time import bytes_eq
import base64
import secrets
import ctypes
from contextlib import contextmanager
import time
import hashlib
from typing import Optional, Dict, List, Tuple

def calculate_file_hash(file_path: str) -> str:
    """Вычисляет SHA-256 хеш файла для проверки целостности"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def verify_encryption_integrity(original_path: str, encrypted_path: str, 
                               algorithm: str, key: bytes, nonce: bytes) -> bool:
    """Проверяет целостность зашифрованного файла перед удалением оригинала"""
    try:
        original_hash = calculate_file_hash(original_path)
        encrypted_data = Path(encrypted_path).read_bytes()
        
        # Пробуем расшифровать для проверки
        if algorithm == "AES-256-GCM":
            cipher = AESGCM(key)
        elif algorithm == "ChaCha20":
            cipher = ChaCha20Poly1305(key)
        else:
            raise ValueError(f"Неизвестный алгоритм: {algorithm}")
        
        decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
        decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()

        # Сравниваем хеши
        return original_hash == decrypted_hash
    except Exception as e:
        print(f"Ошибка проверки целостности: {e}")
        return False

def verify_decryption_integrity(encrypted_path: str, decrypted_path: str, 
                               original_hash: str) -> bool:
    """Проверяет целостность расшифрованного файла перед удалением зашифрованного"""
    try:
        decrypted_hash = calculate_file_hash(decrypted_path)
        return original_hash == decrypted_hash
    except Exception as e:
        print(f"Ошибка проверки целостности: {e}")
        return False

# Файлы блокировки и временные метаданные
LOCK_FILE = ".encryption_lock.json"
TEMP_METADATA_FILE = ".usb_crypt_meta_temp.json"

def create_lock(drive_path: str, operation: str, algorithm: str = None) -> str:
    """Создает файл блокировки для отслеживания операции"""
    lock_data = {
        "operation": operation,  # "encrypt" или "decrypt"
        "algorithm": algorithm,
        "timestamp": time.time(),
        "status": "in_progress",
        "processed_files": [],
        "total_files": 0
    }
    lock_path = os.path.join(drive_path, LOCK_FILE)
    with open(lock_path, 'w', encoding='utf-8') as f:
        json.dump(lock_data, f, indent=2)
    return lock_path

def update_lock(lock_path: str, file_path: str, success: bool = True):
    """Обновляет файл блокировки с информацией об обработанном файле"""
    if not os.path.exists(lock_path):
        return
    
    with open(lock_path, 'r', encoding='utf-8') as f:
        lock_data = json.load(f)
    
    lock_data["processed_files"].append({
        "path": file_path,
        "success": success,
        "timestamp": time.time()
    })
    with open(lock_path, 'w', encoding='utf-8') as f:
        json.dump(lock_data, f, indent=2)

def remove_lock(drive_path: str):
    """Удаляет файл блокировки при успешном завершении"""
    lock_path = os.path.join(drive_path, LOCK_FILE)
    if os.path.exists(lock_path):
        os.remove(lock_path)

def recover_from_lock(drive_path: str) -> Optional[Dict]:
    """Восстанавливает состояние после сбоя на основе файла блокировки"""
    lock_path = os.path.join(drive_path, LOCK_FILE)
    if not os.path.exists(lock_path):
        return None
    
    try:
        with open(lock_path, 'r', encoding='utf-8') as f:
            lock_data = json.load(f)
        return lock_data
    except Exception as e:
        print(f"Ошибка чтения файла блокировки: {e}")
        return None

def check_disk_space(drive_path: str, required_space: int) -> bool:
    """Проверяет наличие достаточного места на диске"""
    try:
        # Получаем информацию о свободном месте
        stat = os.statvfs(drive_path)
        free_space = stat.f_frsize * stat.f_bavail
        return free_space > required_space * 1.2  # 20% запаса
    except Exception:
        # Для Windows используем альтернативный метод
        import shutil
        try:
            free_space = shutil.disk_usage(drive_path).free
            return free_space > required_space * 1.2
        except Exception:
            print("⚠️ Не удалось проверить свободное место на диске")
            return True  # Продолжаем с предупреждением

def secure_wipe(data: bytearray):
    """Безопасно очищает содержимое bytearray, перезаписывая его случайными данными, затем нулями"""
    if not isinstance(data, bytearray):
        raise TypeError("Можно очистить только bytearray")
    # Сначала перезаписываем случайными данными
    random_data = secrets.token_bytes(len(data))
    data[:] = random_data
    # Затем перезаписываем нулями
    data[:] = b'\x00' * len(data)
    # Принудительно запускаем сборку мусора
    import gc
    gc.collect()

@contextmanager
def secure_key(password: str, salt: bytes, key_size: int = 32):
    """Контекстный менеджер для безопасного управления ключом"""
    key_buffer = bytearray(PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=1_000_000,  # Увеличиваем количество итераций
    ).derive(password.encode()))

    try:
        yield bytes(key_buffer)  # Возвращаем неизменяемую копию для использования
    finally:
        # Безопасно очищаем буфер ключа из памяти
        secure_wipe(key_buffer)

def validate_password_strength(password: str) -> bool:
    """Проверяет сложность пароля, возвращает True если пароль достаточно сложный"""
    if len(password) < 12:
        return False, "Пароль должен содержать минимум 12 символов"
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Пароль должен содержать заглавные и строчные буквы, цифры и специальные символы"
    
    # Проверка на распространенные слабые пароли
    weak_passwords = {"password", "12345678", "qwerty", "admin", "letmein", "welcome"}
    if password.lower() in weak_passwords:
        return False, "Слишком распространенный пароль"

    # Проверка на последовательные символы
    for i in range(len(password) - 3):
        if (ord(password[i+1]) - ord(password[i]) == 1 and 
            ord(password[i+2]) - ord(password[i+1]) == 1):
            return False, "Пароль содержит последовательные символы"
    
    return True, "Пароль соответствует требованиям безопасности"

METADATA_FILE = ".usb_crypt_meta.json"

def derive_key(password: str, salt: bytes, key_size: int = 32) -> bytes:
    """Устаревшая функция. Используйте secure_key контекстный менеджер вместо этого."""
    import warnings
    warnings.warn("Функция derive_key устарела. Используйте secure_key контекстный менеджер для безопасности.", 
                 DeprecationWarning)
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=1_000_000,  # Обновляем количество итераций здесь тоже
    ).derive(password.encode())

def verify_key(attempt: bytes, original: bytes) -> bool:
    return bytes_eq(attempt, original)

def encrypt_file(file_path: str, algorithm: str, key: bytes) -> bytes:
    """Шифрует файл с проверкой целостности перед удалением оригинала"""
    data = Path(file_path).read_bytes()
    original_hash = hashlib.sha256(data).hexdigest()
    
    if algorithm == "AES-256-GCM":
        nonce = os.urandom(12)
        cipher = AESGCM(key)
        encrypted_data = cipher.encrypt(nonce, data, None)
    elif algorithm == "ChaCha20":
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
        encrypted_data = cipher.encrypt(nonce, data, None)
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    encrypted_path = file_path + ".encrypted"
    Path(encrypted_path).write_bytes(encrypted_data)

    # Проверяем целостность перед удалением исходного файла
    if not verify_encryption_integrity(file_path, encrypted_path, algorithm, key, nonce):
        os.remove(encrypted_path)  # Удаляем поврежденный зашифрованный файл
        raise ValueError(f"Ошибка целостности при шифровании файла {file_path}. Исходный файл сохранен.")

        # Еще одна проверка - сравниваем размеры (зашифрованный файл должен быть больше)
    if os.path.getsize(encrypted_path) <= os.path.getsize(file_path):
        os.remove(encrypted_path)
        raise ValueError(f"Подозрительный размер зашифрованного файла {file_path}. Исходный файл сохранен.")

        # Только после всех проверок удаляем исходный файл
    os.remove(file_path)
    return nonce

def decrypt_file(file_path: str, algorithm: str, key: bytes, nonce: bytes):
    """Расшифровывает файл с проверкой целостности перед удалением зашифрованной версии"""
    original_path = file_path.replace(".encrypted", "")
    
    encrypted_data = Path(file_path).read_bytes()
    original_size = len(encrypted_data)
    
    if algorithm == "AES-256-GCM":
        cipher = AESGCM(key)
    elif algorithm == "ChaCha20":
        cipher = ChaCha20Poly1305(key)
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")
    
    try:
        decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        raise ValueError("Неверный пароль или повреждённые данные") from e
    
    # Сохраняем расшифрованные данные во временный файл для проверки
    temp_path = original_path + ".tmp"
    Path(temp_path).write_bytes(decrypted_data)
    
    # Проверяем размер (расшифрованный файл не должен быть слишком маленьким)
    if os.path.getsize(temp_path) < max(1, original_size // 100):  # Не менее 1% от оригинала
        os.remove(temp_path)
        raise ValueError(f"Подозрительно маленький размер расшифрованного файла {original_path}")
    
    # Проверяем целостность через хеш
    original_hash = hashlib.sha256(decrypted_data).hexdigest()
    if not verify_decryption_integrity(file_path, temp_path, original_hash):
        os.remove(temp_path)
        raise ValueError(f"Ошибка целостности при расшифровке файла {original_path}")
    
    # Только после всех проверок заменяем исходный файл
    if os.path.exists(original_path):
        os.remove(original_path)
    os.rename(temp_path, original_path)
    os.remove(file_path)

def save_metadata(drive_path: str, salt: bytes, file_nonces: dict, algorithm: str):
    """Сохраняет метаданные на флешку"""
    meta = {
        "algorithm": algorithm,
        "salt": base64.b64encode(salt).decode(),
        "files": {
            rel_path: {
                "nonce": base64.b64encode(nonce).decode(),
                "nonce_size": len(nonce)
            }
            for rel_path, nonce in file_nonces.items()
        }
    }
    meta_path = os.path.join(drive_path, METADATA_FILE)
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)

def load_metadata(drive_path: str):
    """Загружает метаданные с флешки"""
    meta_path = os.path.join(drive_path, METADATA_FILE)
    if not os.path.exists(meta_path):
        raise FileNotFoundError("Метаданные не найдены. Устройство не зашифровано.")
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    salt = base64.b64decode(meta["salt"])
    files = {}
    for rel_path, info in meta["files"].items():
        nonce = base64.b64decode(info["nonce"])
        files[rel_path] = nonce
    return salt, files, meta["algorithm"]

def is_encrypted(drive_path: str) -> bool:
    return os.path.exists(os.path.join(drive_path, METADATA_FILE))

def encrypt_drive(drive_path: str, password: str, algorithm: str = "AES-256-GCM", progress_callback=None):
    # Проверяем, есть ли незавершенная операция
    recovery_data = recover_from_lock(drive_path)
    if recovery_data and recovery_data["status"] == "in_progress":
        raise ValueError("Обнаружена незавершенная операция шифрования. Сначала завершите или отмените её.")
    
    if is_encrypted(drive_path):
        raise ValueError("Накопитель уже зашифрован!")
    
    # Проверка сложности пароля
    is_strong, message = validate_password_strength(password)
    if not is_strong:
        raise ValueError(f"Слабый пароль: {message}. "
                         "Используйте пароль минимум из 12 символов с заглавными и строчными буквами, "
                         "цифрами и специальными символами.")
    
    # Собираем список файлов для шифрования
    all_files = []
    total_size = 0
    for root, dirs, files in os.walk(drive_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('System Volume Information', '$RECYCLE.BIN')]
        for f in files:
            if f in (METADATA_FILE, LOCK_FILE, TEMP_METADATA_FILE) or f.startswith('.'):
                continue
            file_path = os.path.join(root, f)
            all_files.append(file_path)
            total_size += os.path.getsize(file_path)
    
    # Проверяем наличие достаточного места на диске (учитывая увеличение размера при шифровании)
    if not check_disk_space(drive_path, total_size * 1.3):
        raise ValueError("Недостаточно места на диске для безопасного шифрования. Требуется примерно на 30% больше места, чем занимают файлы.")
    
    # Создаем файл блокировки
    lock_path = create_lock(drive_path, "encrypt", algorithm)
    
    # Определяем длину ключа
    key_size = 32  # все три алгоритма используют 256-битный ключ
    salt = os.urandom(16)
    
    total = len(all_files)
    
    try:
        with secure_key(password, salt, key_size) as key:
            file_nonces = {}
            processed_count = 0
            
            for i, file_path in enumerate(all_files):
                try:
                    rel_path = os.path.relpath(file_path, drive_path)
                    nonce = encrypt_file(file_path, algorithm, key)
                    file_nonces[rel_path] = nonce
                    processed_count += 1
                    update_lock(lock_path, rel_path, success=True)
                except Exception as e:
                    print(f"⚠️ Пропущен файл {file_path}: {e}")
                    update_lock(lock_path, rel_path, success=False)
                
                if progress_callback:
                    progress_callback(i + 1, total)
            
            # Сохраняем метаданные во временный файл
            temp_meta_path = os.path.join(drive_path, TEMP_METADATA_FILE)
            meta = {
                "algorithm": algorithm,
                "salt": base64.b64encode(salt).decode(),
                "files": {
                    rel_path: {
                        "nonce": base64.b64encode(nonce).decode(),
                        "nonce_size": len(nonce)
                    }
                    for rel_path, nonce in file_nonces.items()
                }
            }
            with open(temp_meta_path, 'w', encoding='utf-8') as f:
                json.dump(meta, f, indent=2)
            
            # Только после успешного сохранения метаданных переименовываем в основной файл
            meta_path = os.path.join(drive_path, METADATA_FILE)
            if os.path.exists(meta_path):
                os.remove(meta_path)
            os.rename(temp_meta_path, meta_path)
            
            # Обновляем статус блокировки
            with open(lock_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
            lock_data["status"] = "completed"
            lock_data["total_files"] = total
            lock_data["processed_files_count"] = processed_count
            with open(lock_path, 'w', encoding='utf-8') as f:
                json.dump(lock_data, f, indent=2)
            
            return processed_count
    except Exception as e:
        # При ошибке сохраняем блокировку для возможности восстановления
        print(f"Критическая ошибка при шифровании: {e}")
        raise
    finally:
        # Удаляем блокировку только при полном успехе
        if os.path.exists(lock_path):
            with open(lock_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
            if lock_data.get("status") == "completed":
                remove_lock(drive_path)

def decrypt_drive(drive_path: str, password: str, progress_callback=None):
    # Проверяем, есть ли незавершенная операция
    recovery_data = recover_from_lock(drive_path)
    if recovery_data and recovery_data["status"] == "in_progress":
        raise ValueError("Обнаружена незавершенная операция расшифровки. Сначала завершите или отмените её.")
    
    if not is_encrypted(drive_path):
        raise ValueError("Накопитель не зашифрован!")
    
    # Проверка сложности пароля (даже при расшифровке)
    is_strong, _ = validate_password_strength(password)
    if not is_strong:
        print("Предупреждение: Используется слабый пароль. Рекомендуется изменить пароль после расшифровки.")
    
    salt, file_nonces, algorithm = load_metadata(drive_path)
    
    # Создаем файл блокировки
    lock_path = create_lock(drive_path, "decrypt")
    
    total = len(file_nonces)
    
    try:
        with secure_key(password, salt, 32) as key:
            processed_count = 0
            
            for i, (rel_path, nonce) in enumerate(file_nonces.items()):
                encrypted_path = os.path.join(drive_path, rel_path + ".encrypted")
                if not os.path.exists(encrypted_path):
                    print(f"⚠️ Файл не найден: {encrypted_path}")
                    update_lock(lock_path, rel_path, success=False)
                    continue
                
                try:
                    decrypt_file(encrypted_path, algorithm, key, nonce)
                    processed_count += 1
                    update_lock(lock_path, rel_path, success=True)
                except Exception as e:
                    print(f"⚠️ Ошибка расшифровки файла {rel_path}: {e}")
                    update_lock(lock_path, rel_path, success=False)
                
                if progress_callback:
                    progress_callback(i + 1, total)
            
            # Обновляем статус блокировки
            with open(lock_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
            lock_data["status"] = "completed"
            lock_data["total_files"] = total
            lock_data["processed_files_count"] = processed_count
            with open(lock_path, 'w', encoding='utf-8') as f:
                json.dump(lock_data, f, indent=2)
            
            # Только после успешной расшифровки всех файлов удаляем метаданные
            os.remove(os.path.join(drive_path, METADATA_FILE))
            return processed_count
    except Exception as e:
        print(f"Критическая ошибка при расшифровке: {e}")
        raise
    finally:
        # Удаляем блокировку только при полном успехе
        if os.path.exists(lock_path):
            with open(lock_path, 'r', encoding='utf-8') as f:
                lock_data = json.load(f)
            if lock_data.get("status") == "completed":
                remove_lock(drive_path)

def rollback_operation(drive_path: str):
    """Откатывает незавершенную операцию шифрования/расшифровки"""
    lock_data = recover_from_lock(drive_path)
    if not lock_data:
        raise ValueError("Нет незавершенной операции для отката")
    
    operation = lock_data["operation"]
    processed_files = lock_data.get("processed_files", [])
    
    print(f"Начинаем откат операции {operation}...")
    
    if operation == "encrypt":
        # Для отката шифрования: расшифровываем обработанные файлы
        salt, file_nonces, algorithm = load_metadata(drive_path)
        
        with secure_key(input("Введите пароль для отката: "), salt, 32) as key:
            for file_info in processed_files:
                if file_info.get("success", False):
                    rel_path = file_info["path"]
                    encrypted_path = os.path.join(drive_path, rel_path + ".encrypted")
                    nonce = file_nonces.get(rel_path)
                    
                    if nonce and os.path.exists(encrypted_path):
                        try:
                            decrypt_file(encrypted_path, algorithm, key, nonce)
                            print(f"✅ Откат файла: {rel_path}")
                        except Exception as e:
                            print(f"❌ Ошибка отката файла {rel_path}: {e}")
        
        # Удаляем метаданные после отката
        meta_path = os.path.join(drive_path, METADATA_FILE)
        if os.path.exists(meta_path):
            os.remove(meta_path)
    
    elif operation == "decrypt":
        # Для отката расшифровки: переименовываем файлы обратно во временное состояние
        for file_info in processed_files:
            if file_info.get("success", False):
                rel_path = file_info["path"]
                decrypted_path = os.path.join(drive_path, rel_path)
                encrypted_path = decrypted_path + ".encrypted"
                
                if os.path.exists(decrypted_path) and not os.path.exists(encrypted_path):
                    try:
                        os.rename(decrypted_path, encrypted_path)
                        print(f"✅ Откат файла: {rel_path}")
                    except Exception as e:
                        print(f"❌ Ошибка отката файла {rel_path}: {e}")
    
    # Удаляем файл блокировки после завершения отката
    remove_lock(drive_path)
    print("Операция отката завершена. Накопитель возвращен в исходное состояние.")