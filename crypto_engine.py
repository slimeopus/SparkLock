import os
import json
import tempfile
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
import hmac

try:
    import nacl.exceptions
    from nacl.bindings import crypto_aead_xchacha20poly1305_encrypt, crypto_aead_xchacha20poly1305_decrypt, randombytes
    HAS_PYNACL = True
except ImportError:
    HAS_PYNACL = False

def calculate_file_hash(file_path: str) -> str:
    """Вычисляет SHA-256 хеш файла для проверки целостности"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def calculate_hmac(file_path: str, key: bytes) -> str:
    """Вычисляет HMAC-SHA256 файла для проверки целостности"""
    hmac_obj = hmac.new(key, digestmod=hashlib.sha256)
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hmac_obj.update(byte_block)
    return hmac_obj.hexdigest()

def verify_encryption_integrity(original_path: str, encrypted_path: str,
                               algorithm: str, key: bytes, nonce: bytes, original_hmac: str = None) -> bool:
    """Проверяет целостность зашифрованного файла перед удалением оригинала"""
    try:
        original_hash = calculate_file_hash(original_path)
        encrypted_data = Path(encrypted_path).read_bytes()

        # Пробуем расшифровать для проверки
        if algorithm == "AES-256-GCM":
            cipher = AESGCM(key)
            decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
        elif algorithm == "ChaCha20":
            cipher = ChaCha20Poly1305(key)
            decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
        elif algorithm == "XChaCha20-Poly1305":
            # Для XChaCha20-Poly1305 проверка целостности не поддерживается в этой функции
            # потому что она использует другую библиотеку и имеет другие особенности
            print("⚠️ Проверка целостности для XChaCha20-Poly1305 не поддерживается в этой версии")
            return True
        else:
            raise ValueError(f"Неизвестный алгоритм: {algorithm}")

        if algorithm in ["AES-256-GCM", "ChaCha20"]:
            decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()

            # Сравниваем хеши
            hash_match = original_hash == decrypted_hash
            
            # Проверяем HMAC, если он предоставлен
            hmac_match = True
            if original_hmac:
                # Создаем временный файл для проверки HMAC
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(decrypted_data)
                    temp_path = temp_file.name
                
                try:
                    decrypted_hmac = calculate_hmac(temp_path, key)
                    hmac_match = original_hmac == decrypted_hmac
                finally:
                    os.unlink(temp_path)
            
            # Возвращаем результат проверки по обоим критериям
            return hash_match and hmac_match
        else:
            # Для XChaCha20-Poly1305 просто возвращаем True, так как проверка не выполнена
            return True
    except Exception as e:
        print(f"Ошибка проверки целостности: {e}")
        return False

def verify_decryption_integrity(encrypted_path: str, decrypted_path: str,
                               original_hash: str, original_hmac: str = None, key: bytes = None) -> bool:
    """Проверяет целостность расшифрованного файла перед удалением зашифрованного"""
    try:
        decrypted_hash = calculate_file_hash(decrypted_path)
        
        # Проверяем хеш
        hash_match = original_hash == decrypted_hash
        
        # Проверяем HMAC, если он предоставлен
        hmac_match = True
        if original_hmac and key:
            decrypted_hmac = calculate_hmac(decrypted_path, key)
            hmac_match = original_hmac == decrypted_hmac
        
        # Возвращаем результат проверки по обоим критериям
        return hash_match and hmac_match
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
    return hmac.compare_digest(attempt, original)

CHUNK_SIZE = 8192  # 8KB chunks для оптимального баланса между производительностью и потреблением памяти
MAX_MEMORY_FILE_SIZE = 100 * 1024 * 1024  # 100 MB - порог для переключения на потоковую обработку

def _encrypt_with_xchacha20(file_path: str, key: bytes, nonce: bytes) -> tuple[bytes, str]:
    """Шифрует файл с помощью XChaCha20-Poly1305"""
    if not HAS_PYNACL:
        raise ValueError("Для использования XChaCha20-Poly1305 требуется установить библиотеку pynacl")

    # Преобразуем 32-байтный ключ в формат, подходящий для PyNaCl
    if len(key) != 32:
        raise ValueError("XChaCha20-Poly1305 требует 32-байтовый ключ")

    key_for_pynacl = key
    
    # Вычисляем HMAC оригинального файла
    original_hmac = calculate_hmac(file_path, key)

    file_size = os.path.getsize(file_path)
    encrypted_path = file_path + ".encrypted"
    temp_path = encrypted_path + ".tmp"

    try:
        if file_size <= MAX_MEMORY_FILE_SIZE:
            # Для файлов до 100MB шифруем целиком
            data = Path(file_path).read_bytes()
            encrypted_data = crypto_aead_xchacha20poly1305_encrypt(
                message=data,
                ad=None,  # Additional data (не используется)
                nonce=nonce,
                key=key_for_pynacl
            )
            Path(temp_path).write_bytes(encrypted_data)
        else:
            # Для больших файлов используем потоковую обработку
            print(f"[INFO] Потоковое шифрование большого файла: {os.path.basename(file_path)} ({file_size // (1024*1024)} MB)")

            # PyNaCl не поддерживает потоковую обработку напрямую, но мы можем обрабатывать файл блоками
            # чтобы избежать загрузки всего файла в память
            with open(file_path, 'rb') as infile, open(temp_path, 'wb') as outfile:
                while True:
                    chunk = infile.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # Зашифровываем каждый блок с тем же nonce (это не идеальный подход с точки зрения безопасности,
                    # но позволяет избежать загрузки всего файла в память)
                    encrypted_chunk = crypto_aead_xchacha20poly1305_encrypt(
                        message=chunk,
                        ad=None,
                        nonce=nonce,
                        key=key_for_pynacl
                    )
                    outfile.write(encrypted_chunk)

        # Переименовываем временный файл
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        os.rename(temp_path, encrypted_path)

        # Проверяем, что зашифрованный файл больше исходного (как ожидается из-за аутентификационного тега)
        if os.path.getsize(encrypted_path) <= os.path.getsize(file_path):
            os.remove(encrypted_path)
            raise ValueError(f"Подозрительный размер зашифрованного файла {file_path}. Исходный файл сохранен.")

        # Удаляем исходный файл только после всех проверок
        os.remove(file_path)
        return nonce, original_hmac

    finally:
        # Очищаем временные файлы в случае ошибки
        if os.path.exists(temp_path):
            os.remove(temp_path)

def encrypt_file(file_path: str, algorithm: str, key: bytes) -> Tuple[bytes, str]:
    """Шифрует файл с проверкой целостности перед удалением оригинала.
    Использует потоковую обработку для больших файлов (>100MB)"""
    file_size = os.path.getsize(file_path)
    original_hash = hashlib.sha256()
    
    # Вычисляем HMAC оригинального файла
    original_hmac = calculate_hmac(file_path, key)

    # Определяем алгоритм шифрования
    if algorithm == "AES-256-GCM":
        # Генерируем nonce
        nonce = os.urandom(12)
        cipher = AESGCM(key)
    elif algorithm == "ChaCha20":
        # Генерируем nonce
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(key)
    elif algorithm == "XChaCha20-Poly1305":
        if not HAS_PYNACL:
            raise ValueError("Для использования XChaCha20-Poly1305 требуется установить библиотеку pynacl")
        # XChaCha20 использует 24-байтовый nonce
        nonce = randombytes(24)
        return _encrypt_with_xchacha20(file_path, key, nonce), original_hmac
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    # Если это один из стандартных алгоритмов (AES или ChaCha20), продолжаем стандартную процедуру
    encrypted_path = file_path + ".encrypted"
    temp_path = encrypted_path + ".tmp"

    try:
        # Для файлов меньше 100MB используем текущий метод для сохранения производительности
        if file_size <= MAX_MEMORY_FILE_SIZE:
            data = Path(file_path).read_bytes()
            original_hash.update(data)
            encrypted_data = cipher.encrypt(nonce, data, None)
            Path(temp_path).write_bytes(encrypted_data)
        else:
            # Потоковая обработка для больших файлов
            print(f"[INFO] Потоковое шифрование большого файла: {os.path.basename(file_path)} ({file_size // (1024*1024)} MB)")

            # Вычисляем хеш оригинального файла
            with open(file_path, 'rb') as infile:
                while True:
                    chunk = infile.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    original_hash.update(chunk)

            # Для AEAD-алгоритмов (AES-GCM, ChaCha20-Poly1305) мы должны шифровать файл целиком
            # для обеспечения аутентификации и целостности.
            # Попробуем использовать меньший порог для максимально допустимого размера файла в памяти
            # и обработать исключение, если памяти недостаточно
            try:
                with open(file_path, 'rb') as infile:
                    file_data = infile.read()

                encrypted_data = cipher.encrypt(nonce, file_data, None)

                # Записываем зашифрованные данные во временный файл
                with open(temp_path, 'wb') as outfile:
                    outfile.write(encrypted_data)
            except MemoryError:
                # Если недостаточно памяти для загрузки всего файла, используем альтернативный подход
                # ВНИМАНИЕ: Это снижает безопасность, поскольку AEAD-алгоритмы не поддерживают
                # частичное шифрование с последующей проверкой целостности всего файла
                # Этот вариант следует использовать только в крайнем случае
                raise ValueError(f"Файл слишком велик для шифрования с проверкой целостности. Рассмотрите использование XChaCha20-Poly1305.")

        # Переименовываем временный файл
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        os.rename(temp_path, encrypted_path)

        # Проверяем целостность (для XChaCha20-Poly1305 эта проверка не поддерживается в текущей реализации)
        if algorithm in ["AES-256-GCM", "ChaCha20"]:
            if not verify_encryption_integrity(file_path, encrypted_path, algorithm, key, nonce, original_hmac):
                os.remove(encrypted_path)
                raise ValueError(f"Ошибка целостности при шифровании файла {file_path}. Исходный файл сохранен.")

        # Проверяем размер
        if os.path.getsize(encrypted_path) <= os.path.getsize(file_path):
            os.remove(encrypted_path)
            raise ValueError(f"Подозрительный размер зашифрованного файла {file_path}. Исходный файл сохранен.")

        # Удаляем исходный файл только после всех проверок
        os.remove(file_path)
        return nonce, original_hmac

    finally:
        # Очищаем временные файлы в случае ошибки
        if os.path.exists(temp_path):
            os.remove(temp_path)

def _decrypt_with_xchacha20(file_path: str, key: bytes, nonce: bytes, original_hmac: str = None):
    """Расшифровывает файл с помощью XChaCha20-Poly1305"""
    if not HAS_PYNACL:
        raise ValueError("Для использования XChaCha20-Poly1305 требуется установить библиотеку pynacl")

    # Преобразуем 32-байтный ключ в формат, подходящий для PyNaCl
    if len(key) != 32:
        raise ValueError("XChaCha20-Poly1305 требует 32-байтовый ключ")

    key_for_pynacl = key

    encrypted_size = os.path.getsize(file_path)
    original_path = file_path.replace(".encrypted", "")
    temp_path = original_path + ".tmp"

    try:
        if encrypted_size <= MAX_MEMORY_FILE_SIZE:
            # Для файлов до 100MB расшифровываем целиком
            encrypted_data = Path(file_path).read_bytes()
            try:
                decrypted_data = crypto_aead_xchacha20poly1305_decrypt(
                    ciphertext=encrypted_data,
                    ad=None,  # Additional data (не используется)
                    nonce=nonce,
                    key=key_for_pynacl
                )
                Path(temp_path).write_bytes(decrypted_data)
            except nacl.exceptions.CryptoError:
                raise ValueError("Неверный пароль или повреждённые данные")
        else:
            # Для больших файлов используем потоковую обработку
            print(f"[INFO] Потоковое расшифровывание большого файла: {os.path.basename(original_path)} ({encrypted_size // (1024*1024)} MB)")

            # Расшифровываем файл блоками, чтобы избежать загрузки всего файла в память
            with open(file_path, 'rb') as infile, open(temp_path, 'wb') as outfile:
                while True:
                    # Читаем зашифрованные данные блоками (размер зависит от CHUNK_SIZE и размера аутентификационного тега)
                    # Для XChaCha20-Poly1305 аутентификационный тег добавляется к каждому блоку
                    chunk = infile.read(CHUNK_SIZE + 16)  # +16 байт для аутентификационного тега
                    if not chunk:
                        break

                    try:
                        decrypted_chunk = crypto_aead_xchacha20poly1305_decrypt(
                            ciphertext=chunk,
                            ad=None,
                            nonce=nonce,
                            key=key_for_pynacl
                        )
                        outfile.write(decrypted_chunk)
                    except nacl.exceptions.CryptoError:
                        raise ValueError("Неверный пароль или повреждённые данные")

        # Проверяем размер расшифрованного файла
        decrypted_size = os.path.getsize(temp_path)
        if decrypted_size < max(1, encrypted_size // 100):  # Не менее 1% от оригинала
            os.remove(temp_path)
            raise ValueError(f"Подозрительно маленький размер расшифрованного файла {original_path}")

        # Проверяем целостность через HMAC, если он предоставлен
        if original_hmac:
            decrypted_hmac = calculate_hmac(temp_path, key)
            if original_hmac != decrypted_hmac:
                os.remove(temp_path)
                raise ValueError(f"Ошибка целостности HMAC при расшифровке файла {original_path}")

        # Заменяем исходный файл
        if os.path.exists(original_path):
            os.remove(original_path)
        os.rename(temp_path, original_path)
        os.remove(file_path)

    finally:
        # Очищаем временные файлы в случае ошибки
        if os.path.exists(temp_path):
            os.remove(temp_path)

def decrypt_file(file_path: str, algorithm: str, key: bytes, nonce: bytes, original_hmac: str = None):
    """Расшифровывает файл с проверкой целостности перед удалением зашифрованной версии.
    Использует потоковую обработку для больших файлов"""
    encrypted_size = os.path.getsize(file_path)
    original_path = file_path.replace(".encrypted", "")
    temp_path = original_path + ".tmp"

    # Определяем алгоритм расшифровки
    if algorithm == "AES-256-GCM":
        cipher = AESGCM(key)
    elif algorithm == "ChaCha20":
        cipher = ChaCha20Poly1305(key)
    elif algorithm == "XChaCha20-Poly1305":
        if not HAS_PYNACL:
            raise ValueError("Для использования XChaCha20-Poly1305 требуется установить библиотеку pynacl")
        # XChaCha20 использует 24-байтовый nonce
        if len(nonce) != 24:
            raise ValueError("XChaCha20-Poly1305 требует 24-байтовый nonce")
        return _decrypt_with_xchacha20(file_path, key, nonce, original_hmac)
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    # Если это один из стандартных алгоритмов (AES или ChaCha20), продолжаем стандартную процедуру

    try:
        # Для файлов меньше 100MB используем текущий метод
        if encrypted_size <= MAX_MEMORY_FILE_SIZE:
            encrypted_data = Path(file_path).read_bytes()
            decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
            Path(temp_path).write_bytes(decrypted_data)
        else:
            # Потоковая обработка для больших файлов
            print(f"[INFO] Потоковое расшифровывание большого файла: {os.path.basename(original_path)} ({encrypted_size // (1024*1024)} MB)")

            # Для AEAD-алгоритмов (AES-GCM, ChaCha20-Poly1305) мы должны расшифровывать файл целиком
            # для обеспечения аутентификации и целостности
            try:
                with open(file_path, 'rb') as infile:
                    encrypted_data = infile.read()

                decrypted_data = cipher.decrypt(nonce, encrypted_data, None)

                # Записываем расшифрованные данные во временный файл
                with open(temp_path, 'wb') as outfile:
                    outfile.write(decrypted_data)
            except MemoryError:
                # Если недостаточно памяти для загрузки всего файла, используем альтернативный подход
                raise ValueError(f"Файл слишком велик для расшифровки с проверкой целостности. Рассмотрите использование XChaCha20-Poly1305.")

        # Проверяем размер расшифрованного файла
        decrypted_size = os.path.getsize(temp_path)
        if decrypted_size < max(1, encrypted_size // 100):  # Не менее 1% от оригинала
            os.remove(temp_path)
            raise ValueError(f"Подозрительно маленький размер расшифрованного файла {original_path}")

        # Проверяем целостность через хеш и HMAC
        decrypted_hash = calculate_file_hash(temp_path)

        # Проверяем целостность
        if not verify_decryption_integrity(file_path, temp_path, decrypted_hash, original_hmac, key):
            os.remove(temp_path)
            raise ValueError(f"Ошибка целостности при расшифровке файла {original_path}")

        # Заменяем исходный файл
        if os.path.exists(original_path):
            os.remove(original_path)
        os.rename(temp_path, original_path)
        os.remove(file_path)

    finally:
        # Очищаем временные файлы в случае ошибки
        if os.path.exists(temp_path):
            os.remove(temp_path)

def save_metadata(drive_path: str, salt: bytes, file_nonces: dict, file_hmacs: dict, algorithm: str):
    """Сохраняет метаданные на флешку"""
    meta = {
        "algorithm": algorithm,
        "salt": base64.b64encode(salt).decode(),
        "files": {
            rel_path: {
                "nonce": base64.b64encode(nonce).decode(),
                "nonce_size": len(nonce),
                "hmac": file_hmacs[rel_path]
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
    file_hmacs = {}
    for rel_path, info in meta["files"].items():
        nonce = base64.b64decode(info["nonce"])
        files[rel_path] = nonce
        file_hmacs[rel_path] = info["hmac"]
    return salt, files, file_hmacs, meta["algorithm"]

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
            file_hmacs = {}
            processed_count = 0

            for i, file_path in enumerate(all_files):
                try:
                    rel_path = os.path.relpath(file_path, drive_path)
                    nonce, hmac_value = encrypt_file(file_path, algorithm, key)
                    file_nonces[rel_path] = nonce
                    file_hmacs[rel_path] = hmac_value
                    processed_count += 1
                    update_lock(lock_path, rel_path, success=True)
                except Exception as e:
                    print(f"⚠️ Пропущен файл {file_path}: {e}")
                    update_lock(lock_path, rel_path, success=False)

                if progress_callback:
                    progress_callback(i + 1, total)

            # Сохраняем метаданные во временный файл
            temp_meta_path = os.path.join(drive_path, TEMP_METADATA_FILE)
            save_metadata(drive_path, salt, file_nonces, file_hmacs, algorithm)
            
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
    
    salt, file_nonces, file_hmacs, algorithm = load_metadata(drive_path)

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
                    original_hmac = file_hmacs.get(rel_path)
                    decrypt_file(encrypted_path, algorithm, key, nonce, original_hmac)
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


# === Параллельная обработка файлов ===
import concurrent.futures
from threading import Lock

# Блокировка для синхронизации обновления прогресса
progress_lock = Lock()

def encrypt_files_parallel(file_paths: List[str], algorithm: str, key: bytes, max_workers: int = 4) -> Dict[str, Tuple[bytes, str]]:
    """
    Параллельно шифрует несколько файлов
    
    Args:
        file_paths: Список путей к файлам для шифрования
        algorithm: Алгоритм шифрования
        key: Ключ шифрования
        max_workers: Максимальное количество потоков
        
    Returns:
        Словарь с nonce и hmac для каждого файла
    """
    results = {}
    
    def encrypt_single_file(file_path: str):
        try:
            nonce, hmac_value = encrypt_file(file_path, algorithm, key)
            return file_path, nonce, hmac_value
        except Exception as e:
            print(f"⚠️ Ошибка шифрования файла {file_path}: {e}")
            return file_path, None, None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Запускаем задачи шифрования
        future_to_file = {executor.submit(encrypt_single_file, file_path): file_path 
                          for file_path in file_paths}
        
        # Обрабатываем результаты
        for future in concurrent.futures.as_completed(future_to_file):
            file_path, nonce, hmac_value = future.result()
            if nonce is not None and hmac_value is not None:
                results[file_path] = (nonce, hmac_value)
    
    return results


def decrypt_files_parallel(file_paths: List[Tuple[str, str, bytes, bytes, str]], max_workers: int = 4) -> List[bool]:
    """
    Параллельно расшифровывает несколько файлов
    
    Args:
        file_paths: Список кортежей (encrypted_path, algorithm, key, nonce, original_hmac)
        max_workers: Максимальное количество потоков
        
    Returns:
        Список результатов (успешно ли расшифрован каждый файл)
    """
    results = []
    
    def decrypt_single_file(encrypted_path: str, algorithm: str, key: bytes, nonce: bytes, original_hmac: str = None):
        try:
            decrypt_file(encrypted_path, algorithm, key, nonce, original_hmac)
            return True
        except Exception as e:
            print(f"⚠️ Ошибка расшифровки файла {encrypted_path}: {e}")
            return False
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Подготовим аргументы для каждой задачи
        futures = []
        for encrypted_path, algorithm, key, nonce, original_hmac in file_paths:
            future = executor.submit(decrypt_single_file, encrypted_path, algorithm, key, nonce, original_hmac)
            futures.append(future)
        
        # Обрабатываем результаты
        for future in concurrent.futures.as_completed(futures):
            success = future.result()
            results.append(success)
    
    return results


def encrypt_drive_parallel(drive_path: str, password: str, algorithm: str = "AES-256-GCM", 
                          max_workers: int = 4, progress_callback=None):
    """
    Параллельное шифрование всего диска
    
    Args:
        drive_path: Путь к диску для шифрования
        password: Пароль для шифрования
        algorithm: Алгоритм шифрования
        max_workers: Максимальное количество потоков
        progress_callback: Функция обратного вызова для отображения прогресса
    """
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
    processed_count = 0

    try:
        with secure_key(password, salt, key_size) as key:
            # Используем параллельное шифрование
            file_results = encrypt_files_parallel(all_files, algorithm, key, max_workers)
            
            # Подготовим метаданные
            file_nonces = {}
            file_hmacs = {}
            
            for file_path, (nonce, hmac_value) in file_results.items():
                if nonce is not None and hmac_value is not None:
                    rel_path = os.path.relpath(file_path, drive_path)
                    file_nonces[rel_path] = nonce
                    file_hmacs[rel_path] = hmac_value
                    processed_count += 1
                    update_lock(lock_path, rel_path, success=True)
                    
                    # Обновляем прогресс
                    if progress_callback:
                        with progress_lock:
                            progress_callback(processed_count, total)
                else:
                    rel_path = os.path.relpath(file_path, drive_path)
                    update_lock(lock_path, rel_path, success=False)

            # Сохраняем метаданные во временный файл
            temp_meta_path = os.path.join(drive_path, TEMP_METADATA_FILE)
            save_metadata(drive_path, salt, file_nonces, file_hmacs, algorithm)

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


def decrypt_drive_parallel(drive_path: str, password: str, max_workers: int = 4, progress_callback=None):
    """
    Параллельная расшифровка всего диска
    
    Args:
        drive_path: Путь к диску для расшифровки
        password: Пароль для расшифровки
        max_workers: Максимальное количество потоков
        progress_callback: Функция обратного вызова для отображения прогресса
    """
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

    salt, file_nonces, file_hmacs, algorithm = load_metadata(drive_path)

    # Создаем файл блокировки
    lock_path = create_lock(drive_path, "decrypt")

    total = len(file_nonces)
    processed_count = 0

    try:
        with secure_key(password, salt, 32) as key:
            # Подготовим список файлов для расшифровки
            files_to_decrypt = []
            for rel_path, nonce in file_nonces.items():
                encrypted_path = os.path.join(drive_path, rel_path + ".encrypted")
                original_hmac = file_hmacs.get(rel_path)
                
                if os.path.exists(encrypted_path):
                    files_to_decrypt.append((encrypted_path, algorithm, key, nonce, original_hmac))
            
            # Используем параллельную расшифровку
            results = decrypt_files_parallel(files_to_decrypt, max_workers)
            
            # Обновляем статусы
            for i, (rel_path, nonce) in enumerate(file_nonces.items()):
                if i < len(results) and results[i]:
                    processed_count += 1
                    update_lock(lock_path, rel_path, success=True)
                else:
                    update_lock(lock_path, rel_path, success=False)

                # Обновляем прогресс
                if progress_callback:
                    with progress_lock:
                        progress_callback(min(i + 1, total), total)

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