import os
import json
import tempfile
import gc
import mmap
import weakref
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
from typing import Optional, Dict, List, Tuple, Union
import hmac
import psutil

try:
    import nacl.exceptions
    from nacl.bindings import crypto_aead_xchacha20poly1305_encrypt, crypto_aead_xchacha20poly1305_decrypt, randombytes
    HAS_PYNACL = True
except ImportError:
    HAS_PYNACL = False


# === Улучшенное управление памятью ===

class SecureBytes:
    """
    Класс для безопасного хранения чувствительных данных (ключей, паролей) в памяти.
    Автоматически очищает данные при удалении объекта.
    """
    
    def __init__(self, data: Union[bytes, bytearray, int]):
        """
        Инициализирует безопасный буфер.
        
        Args:
            data: Начальные данные (bytes, bytearray) или размер буфера (int)
        """
        if isinstance(data, int):
            self._buffer = bytearray(data)
        else:
            self._buffer = bytearray(data)
        self._finalized = False
        # Регистрируем слабый финализатор для очистки при сборке мусора
        self._weak_ref = weakref.ref(self, self._cleanup_callback)
    
    @staticmethod
    def _cleanup_callback(weak_ref):
        """Вызывается при удалении объекта сборщиком мусора"""
        # Не можем здесь очистить, объект уже уничтожен
        # Но можем принудительно запустить gc
        gc.collect()
    
    @property
    def data(self) -> bytes:
        """Возвращает неизменяемую копию данных"""
        if self._finalized:
            raise ValueError("Данные уже были очищены")
        return bytes(self._buffer)
    
    @property
    def buffer(self) -> bytearray:
        """Возвращает прямой доступ к буферу (только для внутреннего использования)"""
        if self._finalized:
            raise ValueError("Данные уже были очищены")
        return self._buffer
    
    def wipe(self, passes: int = 3):
        """
        Безопасно перезаписывает данные несколькими проходами.
        
        Args:
            passes: Количество проходов перезаписи (1 случайный, остальные нули)
        """
        if self._finalized or len(self._buffer) == 0:
            return
        
        # Проход 1: случайные данные
        self._buffer[:] = secrets.token_bytes(len(self._buffer))
        
        # Дополнительные проходы: нули и единицы
        for i in range(passes - 1):
            if i % 2 == 0:
                self._buffer[:] = b'\x00' * len(self._buffer)
            else:
                self._buffer[:] = b'\xFF' * len(self._buffer)
        
        # Финальный проход: нули
        self._buffer[:] = b'\x00' * len(self._buffer)
        self._finalized = True
        
        # Принудительная сборка мусора
        gc.collect()
    
    def __len__(self) -> int:
        return len(self._buffer)
    
    def __del__(self):
        """Автоматическая очистка при уничтожении объекта"""
        if not self._finalized:
            self.wipe()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        return False


class MemoryMonitor:
    """
    Мониторинг использования памяти для предотвращения переполнения.
    """
    
    def __init__(self, max_memory_percent: float = 80.0):
        """
        Args:
            max_memory_percent: Максимальный процент использования памяти перед предупреждением
        """
        self.max_memory_percent = max_memory_percent
        self.process = psutil.Process()
    
    def get_memory_usage(self) -> Tuple[float, float]:
        """
        Возвращает текущее использование памяти.
        
        Returns:
            Кортеж (процент_использования, мегабайты_используется)
        """
        mem_info = self.process.memory_info()
        mem_percent = self.process.memory_percent()
        mb_used = mem_info.rss / (1024 * 1024)
        return mem_percent, mb_used
    
    def check_memory_available(self, required_bytes: int) -> bool:
        """
        Проверяет, достаточно ли доступно памяти.
        
        Args:
            required_bytes: Требуемое количество байт
            
        Returns:
            True если памяти достаточно, False иначе
        """
        mem_percent, _ = self.get_memory_usage()
        if mem_percent > self.max_memory_percent:
            print(f"⚠️ Предупреждение: использование памяти {mem_percent:.1f}% (порог: {self.max_memory_percent}%)")
            # Принудительная сборка мусора
            gc.collect()
            return False
        return True
    
    @contextmanager
    def memory_limit(self, required_bytes: int):
        """
        Контекстный менеджер для операций с выделением памяти.
        
        Args:
            required_bytes: Требуемое количество байт
        """
        if not self.check_memory_available(required_bytes):
            raise MemoryError(f"Недостаточно доступной памяти для операции ({required_bytes} байт)")
        try:
            yield
        finally:
            # Освобождаем память после операции
            gc.collect()


def secure_wipe(data: bytearray, passes: int = 3):
    """
    Безопасно очищает содержимое bytearray множественными проходами перезаписи.
    Соответствует рекомендациям NIST SP 800-88 для очистки памяти.
    
    Args:
        data: bytearray для очистки
        passes: Количество проходов перезаписи (по умолчанию 3)
    """
    if not isinstance(data, bytearray):
        raise TypeError("Можно очистить только bytearray")
    
    if len(data) == 0:
        return
    
    # Проход 1: случайные данные
    random_data = secrets.token_bytes(len(data))
    data[:] = random_data
    
    # Проход 2: нули
    data[:] = b'\x00' * len(data)
    
    # Проход 3: единицы (если указано)
    if passes > 2:
        data[:] = b'\xFF' * len(data)
    
    # Финальный проход: нули
    data[:] = b'\x00' * len(data)
    
    # Принудительно запускаем сборку мусора
    gc.collect()


def get_memory_stats() -> Dict[str, Union[float, int]]:
    """
    Возвращает статистику использования памяти процессом.
    
    Returns:
        Словарь с ключами:
        - percent: процент использования памяти
        - rss_mb: резидентная память в МБ
        - vms_mb: виртуальная память в МБ
        - available_mb: доступно памяти в системе в МБ
    """
    process = psutil.Process()
    mem_info = process.memory_info()
    virtual_memory = psutil.virtual_memory()
    
    return {
        "percent": process.memory_percent(),
        "rss_mb": mem_info.rss / (1024 * 1024),
        "vms_mb": mem_info.vms / (1024 * 1024),
        "available_mb": virtual_memory.available / (1024 * 1024)
    }


def log_memory_usage(operation: str = ""):
    """
    Выводит в лог текущее использование памяти (для отладки).
    
    Args:
        operation: Описание операции для логирования
    """
    stats = get_memory_stats()
    print(f"[MEMORY] {operation}: {stats['rss_mb']:.1f} MB ({stats['percent']:.1f}%)")


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
            if not HAS_PYNACL:
                raise ValueError("Для использования XChaCha20-Poly1305 требуется установить библиотеку pynacl")
            
            # Для XChaCha20-Poly1305 расшифровываем и проверяем хеш
            try:
                decrypted_data = crypto_aead_xchacha20poly1305_decrypt(
                    ciphertext=encrypted_data,
                    ad=None,
                    nonce=nonce,
                    key=key
                )
            except nacl.exceptions.CryptoError:
                print("❌ Ошибка расшифровки при проверке целостности XChaCha20-Poly1305")
                return False
        else:
            raise ValueError(f"Неизвестный алгоритм: {algorithm}")

        if algorithm in ["AES-256-GCM", "ChaCha20", "XChaCha20-Poly1305"]:
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


@contextmanager
def secure_key(password: str, salt: bytes, key_size: int = 32):
    """Контекстный менеджер для безопасного управления ключом с использованием SecureBytes"""
    key_buffer = SecureBytes(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=1_000_000,  # Увеличиваем количество итераций
        ).derive(password.encode())
    )

    try:
        yield key_buffer.data  # Возвращаем неизменяемую копию для использования
    finally:
        # Безопасно очищаем буфер ключа из памяти (автоматически через SecureBytes.wipe())
        key_buffer.wipe()

@contextmanager
def secure_key_buffer(password: str, salt: bytes, key_size: int = 32):
    """
    Контекстный менеджер для безопасного управления ключом с прямым доступом к буферу.
    Используйте только когда нужен прямой доступ к bytearray для модификации.
    """
    key_buffer = SecureBytes(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_size,
            salt=salt,
            iterations=1_000_000,
        ).derive(password.encode())
    )

    try:
        yield key_buffer.buffer  # Возвращаем прямой доступ к буферу
    finally:
        key_buffer.wipe()

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

# Глобальный монитор памяти для всех операций
_memory_monitor = MemoryMonitor(max_memory_percent=80.0)


class MemorySensitiveReader:
    """
    Контекстный менеджер для чтения файлов с контролем использования памяти.
    Автоматически переключается на потоковое чтение для больших файлов.
    """
    
    def __init__(self, file_path: str, memory_threshold: int = MAX_MEMORY_FILE_SIZE):
        """
        Args:
            file_path: Путь к файлу для чтения
            memory_threshold: Порог размера файла для переключения на потоковый режим
        """
        self.file_path = file_path
        self.memory_threshold = memory_threshold
        self.file_size = os.path.getsize(file_path)
        self.use_streaming = self.file_size > memory_threshold
        self._file = None
        self._data = None
    
    def __enter__(self):
        if not _memory_monitor.check_memory_available(self.file_size):
            # Принудительно включаем потоковый режим если мало памяти
            self.use_streaming = True
        
        if self.use_streaming:
            self._file = open(self.file_path, 'rb')
        else:
            with _memory_monitor.memory_limit(self.file_size):
                self._data = Path(self.file_path).read_bytes()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._file:
            self._file.close()
        self._data = None
        gc.collect()
    
    def read_all(self) -> bytes:
        """Читает весь файл в память (только если use_streaming=False)"""
        if self.use_streaming:
            raise RuntimeError("read_all() недоступен в потоковом режиме")
        return self._data
    
    def iter_chunks(self, chunk_size: int = CHUNK_SIZE):
        """Итератор для потокового чтения файла блоками"""
        if not self.use_streaming and self._data:
            # Если файл в памяти, всё равно используем итератор для совместимости
            for i in range(0, len(self._data), chunk_size):
                yield self._data[i:i + chunk_size]
        elif self._file:
            while True:
                chunk = self._file.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        else:
            raise RuntimeError("Файл не открыт")
    
    @property
    def size(self) -> int:
        return self.file_size


def _derive_block_nonce(base_nonce: bytes, block_index: int) -> bytes:
    """
    Генерирует уникальный 24-байтный nonce для каждого блока на основе базового nonce и индекса блока.
    
    Args:
        base_nonce: Базовый 16-байтный nonce (24 - 8 байт под счётчик)
        block_index: Индекс блока (0, 1, 2, ...)
    
    Returns:
        24-байтный уникальный nonce для блока
    """
    # Используем первые 16 байт как префикс, последние 8 байт — как счётчик блока
    if len(base_nonce) != 16:
        # Если передан полный 24-байтный nonce, используем первые 16 байт
        prefix = base_nonce[:16]
    else:
        prefix = base_nonce
    
    # Добавляем 8-байтный счётчик (little-endian)
    block_counter = block_index.to_bytes(8, byteorder='little')
    return prefix + block_counter


def _encrypt_with_xchacha20(file_path: str, key: bytes, nonce: bytes) -> tuple[bytes, str]:
    """Шифрует файл с помощью XChaCha20-Poly1305 с улучшенным управлением памятью.
    
    Для потокового режима каждый блок шифруется с уникальным nonce (base_nonce + счётчик блока).
    """
    if not HAS_PYNACL:
        raise ValueError("Для использования XChaCha20-Poly1305 требуется установить библиотеку pynacl")

    # Преобразуем 32-байтный ключ в формат, подходящий для PyNaCl
    if len(key) != 32:
        raise ValueError("XChaCha20-Poly1305 требует 32-байтовый ключ")

    key_for_pynacl = key

    # Вычисляем HMAC оригинального файла
    original_hmac = calculate_hmac(file_path, key)
    
    # Вычисляем SHA-256 хеш оригинального файла
    original_hash = calculate_file_hash(file_path)

    file_size = os.path.getsize(file_path)
    encrypted_path = file_path + ".encrypted"
    temp_path = encrypted_path + ".tmp"

    try:
        # Используем MemorySensitiveReader для автоматического управления памятью
        with MemorySensitiveReader(file_path) as reader:
            if not reader.use_streaming:
                # Для файлов до порога шифруем целиком в памяти
                data = reader.read_all()
                encrypted_data = crypto_aead_xchacha20poly1305_encrypt(
                    message=data,
                    ad=None,
                    nonce=nonce,
                    key=key_for_pynacl
                )
                Path(temp_path).write_bytes(encrypted_data)
            else:
                # Для больших файлов используем потоковую обработку с уникальным nonce для каждого блока
                print(f"[INFO] Потоковое шифрование большого файла: {os.path.basename(file_path)} ({file_size // (1024*1024)} MB)")

                # Сохраняем базовый nonce (16 байт) для генерации уникальных nonce блоков
                base_nonce = nonce[:16]
                
                with open(temp_path, 'wb') as outfile:
                    block_index = 0
                    for chunk in reader.iter_chunks():
                        # Генерируем уникальный nonce для каждого блока
                        block_nonce = _derive_block_nonce(base_nonce, block_index)
                        
                        # Зашифровываем каждый блок с уникальным nonce
                        encrypted_chunk = crypto_aead_xchacha20poly1305_encrypt(
                            message=chunk,
                            ad=None,
                            nonce=block_nonce,
                            key=key_for_pynacl
                        )
                        outfile.write(encrypted_chunk)
                        block_index += 1

        # Переименовываем временный файл
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)
        os.rename(temp_path, encrypted_path)

        # Проверяем, что зашифрованный файл больше исходного (как ожидается из-за аутентификационного тега)
        if os.path.getsize(encrypted_path) <= os.path.getsize(file_path):
            os.remove(encrypted_path)
            raise ValueError(f"Подозрительный размер зашифрованного файла {file_path}. Исходный файл сохранен.")

        # === ПРОВЕРКА ЦЕЛОСТНОСТИ: расшифровываем и сравниваем хеш ===
        try:
            with MemorySensitiveReader(encrypted_path) as reader:
                if not reader.use_streaming:
                    # Для файлов до порога расшифровываем целиком и проверяем хеш
                    encrypted_data = reader.read_all()
                    try:
                        decrypted_data = crypto_aead_xchacha20poly1305_decrypt(
                            ciphertext=encrypted_data,
                            ad=None,
                            nonce=nonce,
                            key=key_for_pynacl
                        )
                    except nacl.exceptions.CryptoError:
                        raise ValueError("Ошибка шифрования: данные не могут быть расшифрованы")
                    
                    # Сравниваем хеш расшифрованных данных с оригинальным
                    decrypted_hash = hashlib.sha256(decrypted_data).hexdigest()
                    if decrypted_hash != original_hash:
                        raise ValueError("Ошибка целостности: хеш расшифрованных данных не совпадает")
                    
                    # Сравниваем HMAC
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(decrypted_data)
                        temp_path_hmac = temp_file.name
                    try:
                        decrypted_hmac = calculate_hmac(temp_path_hmac, key)
                        if decrypted_hmac != original_hmac:
                            raise ValueError("Ошибка целостности: HMAC не совпадает")
                    finally:
                        os.unlink(temp_path_hmac)
                    
                    # Очищаем decrypted_data из памяти
                    del decrypted_data
                    gc.collect()
                else:
                    # Для больших файлов проверяем каждый блок потоково
                    print(f"[INFO] Проверка целостности зашифрованного файла: {os.path.basename(file_path)}")
                    
                    base_nonce = nonce[:16]
                    temp_verify_path = temp_path + ".verify"
                    
                    with open(temp_verify_path, 'wb') as verify_file:
                        block_index = 0
                        for chunk in reader.iter_chunks(chunk_size=CHUNK_SIZE + 16):
                            try:
                                block_nonce = _derive_block_nonce(base_nonce, block_index)
                                decrypted_chunk = crypto_aead_xchacha20poly1305_decrypt(
                                    ciphertext=chunk,
                                    ad=None,
                                    nonce=block_nonce,
                                    key=key_for_pynacl
                                )
                                verify_file.write(decrypted_chunk)
                                block_index += 1
                            except nacl.exceptions.CryptoError:
                                raise ValueError("Ошибка шифрования: данные не могут быть расшифрованы")
                    
                    # Проверяем хеш и HMAC расшифрованного файла
                    decrypted_hash = calculate_file_hash(temp_verify_path)
                    if decrypted_hash != original_hash:
                        os.remove(temp_verify_path)
                        raise ValueError("Ошибка целостности: хеш расшифрованных данных не совпадает")
                    
                    decrypted_hmac = calculate_hmac(temp_verify_path, key)
                    if decrypted_hmac != original_hmac:
                        os.remove(temp_verify_path)
                        raise ValueError("Ошибка целостности: HMAC не совпадает")
                    
                    os.remove(temp_verify_path)
        except Exception as e:
            # Если проверка не прошла, удаляем зашифрованный файл и оставляем оригинал
            os.remove(encrypted_path)
            raise ValueError(f"Ошибка проверки целостности при шифровании {file_path}: {e}. Исходный файл сохранен.")
        # === КОНЕЦ ПРОВЕРКИ ЦЕЛОСТНОСТИ ===

        # Удаляем исходный файл только после успешной проверки целостности
        os.remove(file_path)
        return nonce, original_hmac, original_hash

    finally:
        # Очищаем временные файлы в случае ошибки
        if os.path.exists(temp_path):
            os.remove(temp_path)

def encrypt_file(file_path: str, algorithm: str, key: bytes) -> Tuple[bytes, str, str]:
    """Шифрует файл с проверкой целостности перед удалением оригинала.
    Использует MemorySensitiveReader для улучшенного управления памятью"""
    file_size = os.path.getsize(file_path)

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
        nonce, hmac_from_func, original_hash_from_func = _encrypt_with_xchacha20(file_path, key, nonce)
        return nonce, original_hmac, original_hash_from_func
    else:
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    # Если это один из стандартных алгоритмов (AES или ChaCha20), продолжаем стандартную процедуру
    encrypted_path = file_path + ".encrypted"
    temp_path = encrypted_path + ".tmp"
    original_hash = hashlib.sha256()

    try:
        # Используем MemorySensitiveReader для автоматического управления памятью
        with MemorySensitiveReader(file_path) as reader:
            if not reader.use_streaming:
                # Для файлов до порога шифруем целиком в памяти
                data = reader.read_all()
                original_hash.update(data)
                encrypted_data = cipher.encrypt(nonce, data, None)
                Path(temp_path).write_bytes(encrypted_data)
            else:
                # Потоковая обработка для больших файлов
                print(f"[INFO] Потоковое шифрование большого файла: {os.path.basename(file_path)} ({file_size // (1024*1024)} MB)")

                # Вычисляем хеш оригинального файла потоково
                for chunk in reader.iter_chunks():
                    original_hash.update(chunk)

                # Для AEAD-алгоритмов мы должны шифровать файл целиком для целостности
                # Используем SecureBytes для временного хранения данных
                with SecureBytes(reader.size) as data_buffer:
                    # Читаем файл в безопасный буфер
                    with open(file_path, 'rb') as f:
                        f.seek(0)
                        data_buffer.buffer[:] = f.read()
                    
                    try:
                        encrypted_data = cipher.encrypt(nonce, data_buffer.data, None)
                        Path(temp_path).write_bytes(encrypted_data)
                    except MemoryError:
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
        # Возвращаем nonce, original_hmac и original_hash (hex) для метаданных
        return nonce, original_hmac, original_hash.hexdigest()

    finally:
        # Очищаем временные файлы в случае ошибки
        if os.path.exists(temp_path):
            os.remove(temp_path)

def _decrypt_with_xchacha20(file_path: str, key: bytes, nonce: bytes, original_hmac: str = None):
    """Расшифровывает файл с помощью XChaCha20-Poly1305 с улучшенным управлением памятью.
    
    Для потокового режима каждый блок расшифровывается с уникальным nonce (base_nonce + счётчик блока).
    """
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
        # Используем MemorySensitiveReader для автоматического управления памятью
        with MemorySensitiveReader(file_path) as reader:
            if not reader.use_streaming:
                # Для файлов до порога расшифровываем целиком
                encrypted_data = reader.read_all()
                try:
                    decrypted_data = crypto_aead_xchacha20poly1305_decrypt(
                        ciphertext=encrypted_data,
                        ad=None,
                        nonce=nonce,
                        key=key_for_pynacl
                    )
                    Path(temp_path).write_bytes(decrypted_data)
                except nacl.exceptions.CryptoError:
                    raise ValueError("Неверный пароль или повреждённые данные")
            else:
                # Для больших файлов используем потоковую обработку с уникальным nonce для каждого блока
                print(f"[INFO] Потоковое расшифровывание большого файла: {os.path.basename(original_path)} ({encrypted_size // (1024*1024)} MB)")

                # Сохраняем базовый nonce (16 байт) для генерации уникальных nonce блоков
                base_nonce = nonce[:16]
                
                with open(temp_path, 'wb') as outfile:
                    block_index = 0
                    for chunk in reader.iter_chunks(chunk_size=CHUNK_SIZE + 16):
                        try:
                            # Генерируем уникальный nonce для каждого блока (тот же, что при шифровании)
                            block_nonce = _derive_block_nonce(base_nonce, block_index)
                            
                            decrypted_chunk = crypto_aead_xchacha20poly1305_decrypt(
                                ciphertext=chunk,
                                ad=None,
                                nonce=block_nonce,
                                key=key_for_pynacl
                            )
                            outfile.write(decrypted_chunk)
                            block_index += 1
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

def decrypt_file(file_path: str, algorithm: str, key: bytes, nonce: bytes, original_hmac: str = None, original_hash: str = None):
    """Расшифровывает файл с проверкой целостности перед удалением зашифрованной версии.
    Использует MemorySensitiveReader для улучшенного управления памятью"""
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
        # Используем MemorySensitiveReader для автоматического управления памятью
        with MemorySensitiveReader(file_path) as reader:
            if not reader.use_streaming:
                # Для файлов до порога расшифровываем целиком
                encrypted_data = reader.read_all()
                decrypted_data = cipher.decrypt(nonce, encrypted_data, None)
                Path(temp_path).write_bytes(decrypted_data)
            else:
                # Потоковая обработка для больших файлов
                print(f"[INFO] Потоковое расшифровывание большого файла: {os.path.basename(original_path)} ({encrypted_size // (1024*1024)} MB)")

                # Для AEAD-алгоритмов мы должны расшифровывать файл целиком для целостности
                # Используем SecureBytes для временного хранения зашифрованных данных
                with SecureBytes(reader.size) as enc_buffer:
                    with open(file_path, 'rb') as f:
                        f.seek(0)
                        enc_buffer.buffer[:] = f.read()
                    
                    try:
                        decrypted_data = cipher.decrypt(nonce, enc_buffer.data, None)
                        Path(temp_path).write_bytes(decrypted_data)
                    except MemoryError:
                        raise ValueError(f"Файл слишком велик для расшифровки с проверкой целостности. Рассмотрите использование XChaCha20-Poly1305.")

        # Проверяем размер расшифрованного файла
        decrypted_size = os.path.getsize(temp_path)
        if decrypted_size < max(1, encrypted_size // 100):  # Не менее 1% от оригинала
            os.remove(temp_path)
            raise ValueError(f"Подозрительно маленький размер расшифрованного файла {original_path}")

        # Проверяем целостность через HMAC (хеш-проверка удалена как бессмысленная)
        # Основная проверка целостности происходит через HMAC
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

def save_metadata(drive_path: str, salt: bytes, file_nonces: dict, file_hmacs: dict, 
                  file_hashes: dict, algorithm: str):
    """Сохраняет метаданные на флешку"""
    meta = {
        "algorithm": algorithm,
        "salt": base64.b64encode(salt).decode(),
        "files": {
            rel_path: {
                "nonce": base64.b64encode(nonce).decode(),
                "nonce_size": len(nonce),
                "hmac": file_hmacs[rel_path],
                "original_hash": file_hashes[rel_path]
            }
            for rel_path, nonce in file_nonces.items()
        }
    }
    meta_path = os.path.join(drive_path, METADATA_FILE)
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)

# Максимальный размер файла метаданных (10 MB - защита от DoS-атак)
MAX_METADATA_SIZE = 10 * 1024 * 1024


def load_metadata(drive_path: str):
    """
    Загружает метаданные с флешки с проверкой на переполнение памяти.
    
    Перед загрузкой проверяется размер файла метаданных для предотвращения
    атак типа "отказ в обслуживании" через подмену метаданных на очень большой файл.
    """
    meta_path = os.path.join(drive_path, METADATA_FILE)
    if not os.path.exists(meta_path):
        raise FileNotFoundError("Метаданные не найдены. Устройство не зашифровано.")
    
    # Проверяем размер файла перед загрузкой
    file_size = os.path.getsize(meta_path)
    if file_size > MAX_METADATA_SIZE:
        raise MemoryError(
            f"Файл метаданных слишком большой ({file_size / (1024*1024):.2f} MB). "
            f"Максимальный размер: {MAX_METADATA_SIZE / (1024*1024):.2f} MB. "
            "Возможна атака на переполнение памяти."
        )
    
    # Проверяем доступность памяти перед загрузкой
    if not _memory_monitor.check_memory_available(file_size):
        raise MemoryError(
            f"Недостаточно доступной памяти для загрузки метаданных ({file_size / (1024*1024):.2f} MB)"
        )
    
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    
    # Валидируем структуру метаданных
    if not isinstance(meta, dict):
        raise ValueError("Неверная структура метаданных: ожидается объект")
    if "salt" not in meta or "files" not in meta or "algorithm" not in meta:
        raise ValueError("Неверная структура метаданных: отсутствуют обязательные поля")
    if not isinstance(meta["files"], dict):
        raise ValueError("Неверная структура метаданных: поле 'files' должно быть объектом")
    
    # Ограничиваем количество файлов для предотвращения атак
    max_files = 100000  # Максимум 100,000 файлов
    if len(meta["files"]) > max_files:
        raise ValueError(
            f"Слишком много файлов в метаданных: {len(meta['files'])}. "
            f"Максимум: {max_files}"
        )
    
    salt = base64.b64decode(meta["salt"])
    files = {}
    file_hmacs = {}
    file_hashes = {}
    for rel_path, info in meta["files"].items():
        # Валидируем структуру каждого элемента
        if not all(key in info for key in ("nonce", "hmac", "original_hash")):
            raise ValueError(f"Неверная структура метаданных для файла: {rel_path}")
        
        nonce = base64.b64decode(info["nonce"])
        files[rel_path] = nonce
        file_hmacs[rel_path] = info["hmac"]
        file_hashes[rel_path] = info["original_hash"]
    return salt, files, file_hmacs, file_hashes, meta["algorithm"]

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
            file_hashes = {}
            processed_count = 0

            for i, file_path in enumerate(all_files):
                try:
                    rel_path = os.path.relpath(file_path, drive_path)
                    nonce, hmac_value, original_hash = encrypt_file(file_path, algorithm, key)
                    file_nonces[rel_path] = nonce
                    file_hmacs[rel_path] = hmac_value
                    file_hashes[rel_path] = original_hash
                    processed_count += 1
                    update_lock(lock_path, rel_path, success=True)
                except Exception as e:
                    print(f"⚠️ Пропущен файл {file_path}: {e}")
                    update_lock(lock_path, rel_path, success=False)

                if progress_callback:
                    progress_callback(i + 1, total)

            # Сохраняем метаданные во временный файл
            temp_meta_path = os.path.join(drive_path, TEMP_METADATA_FILE)
            save_metadata(drive_path, salt, file_nonces, file_hmacs, file_hashes, algorithm)
            
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
    
    salt, file_nonces, file_hmacs, file_hashes, algorithm = load_metadata(drive_path)

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
                    original_hash = file_hashes.get(rel_path)
                    decrypt_file(encrypted_path, algorithm, key, nonce, original_hmac, original_hash)
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
        salt, file_nonces, file_hmacs, file_hashes, algorithm = load_metadata(drive_path)

        with secure_key(input("Введите пароль для отката: "), salt, 32) as key:
            for file_info in processed_files:
                if file_info.get("success", False):
                    rel_path = file_info["path"]
                    encrypted_path = os.path.join(drive_path, rel_path + ".encrypted")
                    nonce = file_nonces.get(rel_path)
                    original_hmac = file_hmacs.get(rel_path)
                    original_hash_val = file_hashes.get(rel_path)

                    if nonce and os.path.exists(encrypted_path):
                        try:
                            decrypt_file(encrypted_path, algorithm, key, nonce, original_hmac, original_hash_val)
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

def encrypt_files_parallel(file_paths: List[str], algorithm: str, key: bytes, max_workers: int = 4) -> Dict[str, Tuple[bytes, str, str]]:
    """
    Параллельно шифрует несколько файлов

    Args:
        file_paths: Список путей к файлам для шифрования
        algorithm: Алгоритм шифрования
        key: Ключ шифрования
        max_workers: Максимальное количество потоков

    Returns:
        Словарь с nonce, hmac и original_hash для каждого файла
    """
    results = {}

    def encrypt_single_file(file_path: str):
        try:
            nonce, hmac_value, original_hash = encrypt_file(file_path, algorithm, key)
            return file_path, nonce, hmac_value, original_hash
        except Exception as e:
            print(f"⚠️ Ошибка шифрования файла {file_path}: {e}")
            return file_path, None, None, None

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Запускаем задачи шифрования
        future_to_file = {executor.submit(encrypt_single_file, file_path): file_path
                          for file_path in file_paths}

        # Обрабатываем результаты
        for future in concurrent.futures.as_completed(future_to_file):
            file_path, nonce, hmac_value, original_hash = future.result()
            if nonce is not None and hmac_value is not None and original_hash is not None:
                results[file_path] = (nonce, hmac_value, original_hash)

    return results


def decrypt_files_parallel(file_paths: List[Tuple[str, str, bytes, bytes, str, str]], max_workers: int = 4) -> List[bool]:
    """
    Параллельно расшифровывает несколько файлов

    Args:
        file_paths: Список кортежей (encrypted_path, algorithm, key, nonce, original_hmac, original_hash)
        max_workers: Максимальное количество потоков

    Returns:
        Список результатов (успешно ли расшифрован каждый файл)
    """
    results = []

    def decrypt_single_file(encrypted_path: str, algorithm: str, key: bytes, nonce: bytes, original_hmac: str = None, original_hash: str = None):
        try:
            decrypt_file(encrypted_path, algorithm, key, nonce, original_hmac, original_hash)
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
            file_hashes = {}

            for file_path, (nonce, hmac_value, original_hash) in file_results.items():
                if nonce is not None and hmac_value is not None and original_hash is not None:
                    rel_path = os.path.relpath(file_path, drive_path)
                    file_nonces[rel_path] = nonce
                    file_hmacs[rel_path] = hmac_value
                    file_hashes[rel_path] = original_hash
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
            save_metadata(drive_path, salt, file_nonces, file_hmacs, file_hashes, algorithm)

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

    salt, file_nonces, file_hmacs, file_hashes, algorithm = load_metadata(drive_path)

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
                original_hash_val = file_hashes.get(rel_path)

                if os.path.exists(encrypted_path):
                    files_to_decrypt.append((encrypted_path, algorithm, key, nonce, original_hmac, original_hash_val))

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