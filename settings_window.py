from utils import center_window, get_lang_manager
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os

class SettingsWindow:
    def __init__(self, parent):
        self.parent = parent
        self.config_file = "config.json"
        self.settings = self.load_settings()
        self.lang_manager = get_lang_manager()

        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        self.win.title(self.lang_manager.t("settings_window.title"))
        center_window(self.win, 500, 550)  # Increased height to accommodate new language selector
        self.win.resizable(False, False)
        self.win.transient(parent.root)
        self.win.grab_set()

        # Сохраняем ссылки на элементы управления для последующего обновления
        self.window_title_label = None
        self.language_label = None
        self.english_radio = None
        self.russian_radio = None
        self.theme_label = None
        self.light_theme_radio = None
        self.dark_theme_radio = None
        self.default_algo_label = None
        self.algo_radios = []
        self.notification_label = None
        self.show_popup_check = None
        self.log_to_file_check = None
        self.log_path_label = None
        self.browse_button = None

        # --- Заголовок ---
        self.window_title_label = tk.Label(self.win, text=self.lang_manager.t("settings_window.window_title"), font=("Arial", 16, "bold"))
        self.window_title_label.pack(pady=(10, 5))

        # --- Язык интерфейса ---
        self.language_label = tk.Label(self.win, text=self.lang_manager.t("settings_window.language"), font=("Arial", 12))
        self.language_label.pack(anchor="w", padx=20, pady=(10, 5))
        self.language_var = tk.StringVar(master=self.win, value=self.settings.get("language", "ru"))
        self.language_var.trace_add("write", lambda *args: self.auto_save())
        language_frame = tk.Frame(self.win)
        language_frame.pack(anchor="w", padx=30, pady=5)
        self.english_radio = ttk.Radiobutton(language_frame, text=self.lang_manager.t("settings_window.english"), variable=self.language_var, value="en")
        self.english_radio.pack(anchor="w", pady=2)
        self.russian_radio = ttk.Radiobutton(language_frame, text=self.lang_manager.t("settings_window.russian"), variable=self.language_var, value="ru")
        self.russian_radio.pack(anchor="w", pady=2)

        # --- Тема интерфейса ---
        self.theme_label = tk.Label(self.win, text=self.lang_manager.t("settings_window.interface_theme"), font=("Arial", 12))
        self.theme_label.pack(anchor="w", padx=20, pady=(10, 5))
        self.theme_var = tk.StringVar(master=self.win, value=self.settings.get("theme", "light"))
        self.theme_var.trace_add("write", lambda *args: self.auto_save())
        theme_frame = tk.Frame(self.win)
        theme_frame.pack(anchor="w", padx=30, pady=5)
        self.light_theme_radio = ttk.Radiobutton(theme_frame, text=self.lang_manager.t("settings_window.light_theme"), variable=self.theme_var, value="light")
        self.light_theme_radio.pack(anchor="w", pady=2)
        self.dark_theme_radio = ttk.Radiobutton(theme_frame, text=self.lang_manager.t("settings_window.dark_theme"), variable=self.theme_var, value="dark")
        self.dark_theme_radio.pack(anchor="w", pady=2)

        # --- Алгоритм по умолчанию ---
        self.default_algo_label = tk.Label(self.win, text=self.lang_manager.t("settings_window.default_algorithm"), font=("Arial", 12))
        self.default_algo_label.pack(anchor="w", padx=20, pady=(10, 5))
        self.default_algo_var = tk.StringVar(master=self.win, value=self.settings.get("default_algorithm", "AES-256"))
        self.default_algo_var.trace_add("write", lambda *args: self.auto_save())
        self.algorithm_frame = tk.Frame(self.win)
        self.algorithm_frame.pack(anchor="w", padx=30, pady=5)

        # Use language manager for algorithm descriptions
        self.update_algorithms_display()

        # --- Уведомления ---
        self.notification_label = tk.Label(self.win, text=self.lang_manager.t("settings_window.notification_settings"), font=("Arial", 12))
        self.notification_label.pack(anchor="w", padx=20, pady=(15, 5))

        # Галочки
        self.notify_sound_var = tk.BooleanVar(master=self.win, value=self.settings.get("notify_sound", True))
        self.notify_sound_var.trace_add("write", lambda *args: self.auto_save())
        self.notify_popup_var = tk.BooleanVar(master=self.win, value=self.settings.get("notify_popup", True))
        self.notify_popup_var.trace_add("write", lambda *args: self.auto_save())
        self.notify_log_var = tk.BooleanVar(master=self.win, value=self.settings.get("notify_log", False))
        self.notify_log_var.trace_add("write", lambda *args: self.auto_save())

        self.show_popup_check = tk.Checkbutton(self.win, text=self.lang_manager.t("settings_window.show_popup"), variable=self.notify_popup_var)
        self.show_popup_check.pack(anchor="w", padx=30, pady=2)
        self.log_to_file_check = tk.Checkbutton(self.win, text=self.lang_manager.t("settings_window.log_to_file"), variable=self.notify_log_var)
        self.log_to_file_check.pack(anchor="w", padx=30, pady=2)

        # --- Путь к лог-файлу (если включено) ---
        log_frame = tk.Frame(self.win)
        log_frame.pack(anchor="w", padx=30, pady=10)

        self.log_path_label = tk.Label(log_frame, text=self.lang_manager.t("settings_window.log_path"))
        self.log_path_label.grid(row=0, column=0, sticky="w")
        self.log_path_entry = ttk.Entry(log_frame, width=30)
        self.log_path_entry.grid(row=0, column=1, padx=5)
        self.log_path_entry.insert(0, self.settings.get("log_path", "./encryption_log.txt"))

        self.browse_button = tk.Button(log_frame, text=self.lang_manager.t("settings_window.browse"), command=self.browse_log_path)
        self.browse_button.grid(row=0, column=2, padx=5)

        # Подписываемся на изменения языка
        self.lang_manager.add_observer(self.update_ui_language)
        
        # Привязываем удаление наблюдателя к событию закрытия окна
        self.win.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Удаляем наблюдатель при закрытии окна"""
        try:
            self.lang_manager.remove_observer(self.update_ui_language)
        except ValueError:
            # Наблюдатель уже удален
            pass
        self.win.destroy()

    def update_algorithms_display(self):
        """Обновляет отображение алгоритмов с учетом текущего языка"""
        # Удаляем старые радиокнопки
        for widget in self.algorithm_frame.winfo_children():
            widget.destroy()
            
        # Use language manager for algorithm descriptions
        algorithms = [
            ("AES-256", self.lang_manager.t("algorithms.aes256_desc")),
            ("ChaCha20", self.lang_manager.t("algorithms.chacha20_desc")),
            ("XChaCha20-Poly1305", self.lang_manager.t("algorithms.xchacha20_desc"))
        ]

        for algo, desc in algorithms:
            rb = ttk.Radiobutton(self.algorithm_frame, text=f"{algo} — {desc}", variable=self.default_algo_var, value=algo)
            rb.pack(anchor="w", pady=2)

    def update_ui_language(self, language_code):
        """Обновляет текст всех элементов интерфейса при смене языка"""
        # Обновляем заголовок окна
        self.win.title(self.lang_manager.t("settings_window.title"))
        
        # Обновляем текст меток
        self.window_title_label.config(text=self.lang_manager.t("settings_window.window_title"))
        self.language_label.config(text=self.lang_manager.t("settings_window.language"))
        self.english_radio.config(text=self.lang_manager.t("settings_window.english"))
        self.russian_radio.config(text=self.lang_manager.t("settings_window.russian"))
        self.theme_label.config(text=self.lang_manager.t("settings_window.interface_theme"))
        self.light_theme_radio.config(text=self.lang_manager.t("settings_window.light_theme"))
        self.dark_theme_radio.config(text=self.lang_manager.t("settings_window.dark_theme"))
        self.default_algo_label.config(text=self.lang_manager.t("settings_window.default_algorithm"))
        
        # Обновляем алгоритмы
        self.update_algorithms_display()
        
        self.notification_label.config(text=self.lang_manager.t("settings_window.notification_settings"))
        self.show_popup_check.config(text=self.lang_manager.t("settings_window.show_popup"))
        self.log_to_file_check.config(text=self.lang_manager.t("settings_window.log_to_file"))
        self.log_path_label.config(text=self.lang_manager.t("settings_window.log_path"))
        self.browse_button.config(text=self.lang_manager.t("settings_window.browse"))

    def load_settings(self):
        """Загружает настройки из файла config.json"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r', encoding='utf-8') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    pass
        # Возвращаем настройки по умолчанию
        return {
            "theme": "light",
            "default_algorithm": "AES-256",
            "notify_sound": True,
            "notify_popup": True,
            "notify_log": False,
            "log_path": "./encryption_log.txt",
            "language": "ru"  # Default language
        }

    def auto_save(self):
        """Автоматически сохраняет настройки и применяет их"""
        settings = {
            "theme": self.theme_var.get(),
            "default_algorithm": self.default_algo_var.get(),
            "notify_popup": self.notify_popup_var.get(),
            "notify_log": self.notify_log_var.get(),
            "log_path": self.log_path_entry.get().strip(),
            "language": self.language_var.get()  # Add language to settings
        }
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=4, ensure_ascii=False)
            print(f"Настройки сохранены: {settings}")

            # Update language if changed
            if hasattr(self.parent, 'lang_manager'):
                current_lang = self.parent.lang_manager.current_language
                new_lang = settings["language"]
                if current_lang != new_lang:
                    self.parent.lang_manager.set_language(new_lang)

            # Применяем тему мгновенно
            if hasattr(self.parent, 'apply_theme'):
                self.parent.apply_theme()
        except Exception as e:
            print(f"Не удалось сохранить настройки: {e}")

    def browse_log_path(self):
        """Выбор пути к лог-файлу"""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
            title=self.lang_manager.t("settings_window.browse") + " " + self.lang_manager.t("settings_window.log_path")
        )
        if path:
            self.log_path_entry.delete(0, tk.END)
            self.log_path_entry.insert(0, path)
            self.auto_save()