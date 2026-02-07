from utils import center_window
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os

class SettingsWindow:
    def __init__(self, parent):
        self.parent = parent
        self.config_file = "config.json"
        self.settings = self.load_settings()

        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        self.win.title("Настройки")
        center_window(self.win, 500, 500)
        self.win.resizable(False, False)
        self.win.transient(parent.root)
        self.win.grab_set()

        # --- Заголовок ---
        tk.Label(self.win, text="Настройки программы", font=("Arial", 16, "bold")).pack(pady=(10, 5))

        # --- Тема интерфейса ---
        tk.Label(self.win, text="Тема интерфейса:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 5))
        self.theme_var = tk.StringVar(master=self.win, value=self.settings.get("theme", "light"))
        self.theme_var.trace_add("write", lambda *args: self.auto_save())
        theme_frame = tk.Frame(self.win)
        theme_frame.pack(anchor="w", padx=30, pady=5)
        ttk.Radiobutton(theme_frame, text="Светлая", variable=self.theme_var, value="light").pack(anchor="w", pady=2)
        ttk.Radiobutton(theme_frame, text="Тёмная", variable=self.theme_var, value="dark").pack(anchor="w", pady=2)

        # --- Алгоритм по умолчанию ---
        tk.Label(self.win, text="Алгоритм шифрования по умолчанию:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(10, 5))
        self.default_algo_var = tk.StringVar(master=self.win, value=self.settings.get("default_algorithm", "AES-256"))
        self.default_algo_var.trace_add("write", lambda *args: self.auto_save())
        algorithm_frame = tk.Frame(self.win)
        algorithm_frame.pack(anchor="w", padx=30, pady=5)

        algorithms = [
            ("AES-256", "Высокая безопасность, стандарт де-факто"),
            ("ChaCha20", "Быстрый, хорош для мобильных устройств"),
            ("XChaCha20-Poly1305", "Расширенная версия ChaCha с более длинным nonce, обеспечивает дополнительную безопасность")
        ]

        for algo, desc in algorithms:
            rb = ttk.Radiobutton(algorithm_frame, text=f"{algo} — {desc}", variable=self.default_algo_var, value=algo)
            rb.pack(anchor="w", pady=2)

        # --- Уведомления ---
        tk.Label(self.win, text="Уведомления о завершении операции:", font=("Arial", 12)).pack(anchor="w", padx=20, pady=(15, 5))

        # Галочки
        self.notify_sound_var = tk.BooleanVar(master=self.win, value=self.settings.get("notify_sound", True))
        self.notify_sound_var.trace_add("write", lambda *args: self.auto_save())
        self.notify_popup_var = tk.BooleanVar(master=self.win, value=self.settings.get("notify_popup", True))
        self.notify_popup_var.trace_add("write", lambda *args: self.auto_save())
        self.notify_log_var = tk.BooleanVar(master=self.win, value=self.settings.get("notify_log", False))
        self.notify_log_var.trace_add("write", lambda *args: self.auto_save())

        tk.Checkbutton(self.win, text="Показывать всплывающее окно", variable=self.notify_popup_var).pack(anchor="w", padx=30, pady=2)
        tk.Checkbutton(self.win, text="Записывать в лог-файл", variable=self.notify_log_var).pack(anchor="w", padx=30, pady=2)

        # --- Путь к лог-файлу (если включено) ---
        log_frame = tk.Frame(self.win)
        log_frame.pack(anchor="w", padx=30, pady=10)

        tk.Label(log_frame, text="Путь к лог-файлу:").grid(row=0, column=0, sticky="w")
        self.log_path_entry = ttk.Entry(log_frame, width=30)
        self.log_path_entry.grid(row=0, column=1, padx=5)
        self.log_path_entry.insert(0, self.settings.get("log_path", "./encryption_log.txt"))

        tk.Button(log_frame, text="Обзор", command=self.browse_log_path).grid(row=0, column=2, padx=5)

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
            "log_path": "./encryption_log.txt"
        }

    def auto_save(self):
        """Автоматически сохраняет настройки и применяет их"""
        settings = {
            "theme": self.theme_var.get(),
            "default_algorithm": self.default_algo_var.get(),
            "notify_popup": self.notify_popup_var.get(),
            "notify_log": self.notify_log_var.get(),
            "log_path": self.log_path_entry.get().strip()
        }
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=4, ensure_ascii=False)
            print(f"Настройки сохранены: {settings}")
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
            title="Выберите путь для лог-файла"
        )
        if path:
            self.log_path_entry.delete(0, tk.END)
            self.log_path_entry.insert(0, path)
            self.auto_save()