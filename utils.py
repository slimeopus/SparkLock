import platform
import winsound
import json
import os
from resources import resource_path

class LanguageManager:
    """Class to manage multilingual support for the application"""
    def __init__(self, default_language="ru"):
        self.current_language = default_language
        self.translations = {}
        self.observers = []  # Список наблюдателей для обновления интерфейса
        self.load_translations(default_language)

    def load_translations(self, language_code):
        """Load translations for the specified language"""
        try:
            lang_file = resource_path(f"locales/{language_code}.json")
            if os.path.exists(lang_file):
                with open(lang_file, 'r', encoding='utf-8') as f:
                    self.translations = json.load(f)
                self.current_language = language_code
            else:
                # Fallback to default language if requested language doesn't exist
                fallback_file = resource_path(f"locales/{default_language}.json")
                if os.path.exists(fallback_file):
                    with open(fallback_file, 'r', encoding='utf-8') as f:
                        self.translations = json.load(f)
                    self.current_language = default_language
        except Exception as e:
            print(f"Error loading translations: {e}")
            # Load default language as fallback
            try:
                with open(resource_path(f"locales/{default_language}.json"), 'r', encoding='utf-8') as f:
                    self.translations = json.load(f)
            except:
                self.translations = {}  # Empty fallback

    def set_language(self, language_code):
        """Set the current language and load its translations"""
        if self.current_language != language_code:
            self.load_translations(language_code)
            self.notify_observers()  # Уведомляем наблюдателей об изменении языка

    def t(self, key, **kwargs):
        """Translate a key and optionally format with provided values"""
        # Navigate nested keys using dot notation
        keys = key.split('.')
        value = self.translations

        for k in keys:
            try:
                value = value[k]
            except (KeyError, TypeError):
                # Return the key itself if translation is not found
                return key.replace('.', '_')

        # Format the string with provided kwargs if it's a string
        if isinstance(value, str) and kwargs:
            try:
                return value.format(**kwargs)
            except KeyError:
                return value
        elif isinstance(value, str):
            return value
        else:
            # If the result is not a string, return it as is
            return str(value)

    def add_observer(self, callback):
        """Добавить наблюдатель для обновления интерфейса при смене языка"""
        self.observers.append(callback)

    def remove_observer(self, callback):
        """Удалить наблюдатель"""
        if callback in self.observers:
            self.observers.remove(callback)

    def notify_observers(self):
        """Уведомить всех наблюдателей об изменении языка"""
        for callback in self.observers:
            try:
                callback(self.current_language)
            except Exception as e:
                print(f"Error notifying observer: {e}")

# Global instance of LanguageManager
lang_manager = LanguageManager()

def play_completion_sound():
    """Воспроизводит звук завершения операции (Windows-style)"""
    if platform.system() == "Windows":
        try:
            # Используем системный звук завершения
            winsound.PlaySound("SystemAsterisk", winsound.SND_ALIAS)
        except:
            # Резервный вариант, если SystemAsterisk недоступен
            winsound.Beep(500, 100)

def center_window(window, width, height):
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - width) // 2
    y = (screen_height - height) // 2
    window.geometry(f"{width}x{height}+{x}+{y}")

def load_settings():
    """Загружает настройки из файла config.json"""
    config_file = "config.json"
    default_settings = {
        "theme": "light",
        "default_algorithm": "AES-256",
        "notify_sound": True,
        "notify_popup": True,
        "notify_log": False,
        "log_path": "./encryption_log.txt",
        "language": "ru"  # Default language
    }
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                loaded_settings = json.load(f)
                # Merge with defaults to ensure all settings exist
                for key, value in default_settings.items():
                    if key not in loaded_settings:
                        loaded_settings[key] = value
                return loaded_settings
        except (json.JSONDecodeError, IOError):
            pass
    return default_settings

def get_files_word(count, language="ru"):
    """Возвращает правильную форму слова "файл" в зависимости от числа и языка"""
    if language == "ru":
        if count % 10 == 1 and count % 100 != 11:
            return "файл"
        elif 2 <= count % 10 <= 4 and (count % 100 < 10 or count % 100 >= 20):
            return "файла"
        else:
            return "файлов"
    else:  # Для английского и других языков
        if count == 1:
            return "file"
        else:
            return "files"

def get_lang_manager():
    """Returns the global language manager instance"""
    return lang_manager

# Initialize language manager with language from settings
def initialize_language_from_settings():
    """Initializes the language manager with the language from settings file"""
    settings = load_settings()
    language = settings.get("language", "ru")
    lang_manager.set_language(language)

# Initialize language from settings on module load
initialize_language_from_settings()