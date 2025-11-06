from utils import center_window
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import os
import shutil
from crypto_engine import encrypt_drive, decrypt_drive
from utils import load_settings, play_completion_sound, get_files_word

class EncryptionWindow:
    def __init__(self, parent, drive_path, mode="encrypt"):
        self.parent = parent
        self.drive_path = drive_path
        self.mode = mode
        self.is_running = False
        self.settings = load_settings()

        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        style = ttk.Style()
        style.theme_use('default')  # гарантирует, что стиль можно переопределить
        style.configure("Green.Horizontal.TProgressbar", foreground='green', background='green')
        self.win.title(f"{'Шифрование' if mode == 'encrypt' else 'Расшифровка'} накопителя")
        center_window(self.win, 500, 500)
        self.win.resizable(False, False)
        self.win.transient(parent.root)  # делаем модальным
        self.win.grab_set()  # блокируем родительское окно

        # --- Заголовок ---
        title = f"{'Шифрование' if mode == 'encrypt' else 'Расшифровка'} накопителя"
        tk.Label(self.win, text=title, font=("Arial", 16, "bold")).pack(pady=(10, 5))

        # --- Устройство ---
        tk.Label(self.win, text=f"Выбрано устройство: {drive_path}", font=("Arial", 10), fg="blue").pack(pady=5)

        # --- Пароль ---
        tk.Label(self.win, text="Пароль:", font=("Arial", 12)).pack(pady=(10, 0))
        self.password_entry = ttk.Entry(self.win, show="*", width=40)
        self.password_entry.pack(pady=5)

        tk.Label(self.win, text="Подтвердите пароль:", font=("Arial", 12)).pack(pady=(5, 0))
        self.confirm_entry = ttk.Entry(self.win, show="*", width=40)
        self.confirm_entry.pack(pady=5)

        # --- Кнопка генерации пароля ---
        gen_frame = tk.Frame(self.win)
        gen_frame.pack(pady=5)
        ttk.Button(gen_frame, text="Сгенерировать надёжный пароль", command=self.generate_password).pack()

        # --- Алгоритм ---
        tk.Label(self.win, text="Алгоритм шифрования:", font=("Arial", 12)).pack(pady=(10, 0))
        self.algorithm_var = tk.StringVar(value="AES-256")
        algorithm_frame = tk.Frame(self.win)
        algorithm_frame.pack(pady=5)

        algorithms = [
            ("AES-256", "Высокая безопасность, стандарт де-факто"),
            ("ChaCha20", "Быстрый, хорош для мобильных устройств")
        ]

        for algo, desc in algorithms:
            rb = ttk.Radiobutton(algorithm_frame, text=f"{algo} — {desc}", variable=self.algorithm_var, value=algo)
            rb.pack(anchor="w", pady=2)

        # --- Кнопки ---
        button_frame = tk.Frame(self.win)
        button_frame.pack(pady=20)

        self.start_button = ttk.Button(button_frame, text="Начать", command=self.start_operation, width=15)
        self.start_button.pack(side="left", padx=10)

        self.cancel_button = ttk.Button(button_frame, text="Отмена", command=self.cancel_operation, width=15)
        self.cancel_button.pack(side="right", padx=10)

        # --- Прогресс и таймер ---
        progress_frame = tk.Frame(self.win)
        progress_frame.pack(fill="x", padx=20, pady=(10, 0))

        tk.Label(progress_frame, text="Прогресс:").pack(anchor="w")
        self.progress = ttk.Progressbar(
            progress_frame,
            mode="determinate",
            length=400,
            style="Green.Horizontal.TProgressbar"
        )
        self.progress.pack(fill="x", pady=5)

        self.time_label = tk.Label(progress_frame, text="Осталось: --:--", font=("Arial", 10))
        self.time_label.pack(anchor="e", pady=5)

        # --- Статус ---
        self.status_label = tk.Label(self.win, text="Готов к началу...", fg="gray")
        self.status_label.pack(pady=10)

    def generate_password(self):
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.confirm_entry.delete(0, tk.END)
        self.confirm_entry.insert(0, password)
        self.status_label.config(text="✅ Пароль сгенерирован", fg="green")

    def validate_inputs(self):
        """Проверяет корректность введённых данных"""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not password or not confirm:
            messagebox.showerror("Ошибка", "Введите пароль и подтвердите его.")
            return False

        if password != confirm:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return False

        if len(password) < 8:
            messagebox.showwarning("Предупреждение", "Пароль должен быть не менее 8 символов.")
            return False
            # Можно продолжить, но предупредили

        return True

    def start_operation(self):
        """Запускает процесс шифрования/расшифровки"""
        if not self.validate_inputs():
            return

        if self.is_running:
            messagebox.showinfo("Информация", "Операция уже выполняется.")
            return

        # === Пункт 3: Проверка свободного места (только при шифровании) ===
        if self.mode == "encrypt":
            try:
                total, used, free = shutil.disk_usage(self.drive_path)
                # Оценка: нужно минимум 1.2 × объёма занятого места (на время шифрования)
                needed = int(used * 1.2)
                if free < needed:
                    messagebox.showwarning(
                        "Недостаточно места",
                        f"На устройстве недостаточно свободного места для безопасного шифрования.\n"
                        f"Занято: {used // (1024**2)} МБ\n"
                        f"Свободно: {free // (1024**2)} МБ\n"
                        f"Рекомендуется: минимум {needed // (1024**2)} МБ свободного места."
                    )
                    return
            except Exception as e:
                messagebox.showwarning("Предупреждение", f"Не удалось проверить место: {e}")

        self.is_running = True
        self.start_button.config(state="disabled")
        self.cancel_button.config(text="Прервать")

        # Сбрасываем прогресс
        self.progress["value"] = 0
        self.time_label.config(text="Осталось: --:--")
        self.status_label.config(text="Начинаем операцию...")

        # Имитация длительной операции в отдельном потоке
        if self.mode == "encrypt":
            thread = threading.Thread(target=self.real_encrypt)
        else:
            thread = threading.Thread(target=self.real_decrypt)
        thread.daemon = True
        thread.start()

    def load_settings(self):
        """Загружает настройки из config.json"""
        try:
            from utils import load_settings
            return load_settings()
        except:
            return {
                "notify_sound": True,
                "notify_popup": True,
                "notify_log": False,
                "log_path": "./encryption_log.txt"
            }

    def finish_operation(self, message=None):
        self.is_running = False
        self.progress["value"] = 100
        text = message if message else "✅ Операция завершена успешно!"
        self.status_label.config(text=text)
        self.start_button.config(state="disabled")
        self.cancel_button.config(text="Закрыть", command=self.close_window)
        
        # === Обновить статус в главном окне ===
        try:
            self.parent.scan_usb_drives()
        except Exception as e:
            print(f"Не удалось обновить список устройств: {e}")
        
        # === Проверяем настройки и показываем уведомление ===
        settings = self.load_settings()
        
        # Если включено уведомление — показываем окно и воспроизводим звук
        if settings.get("notify_popup", True):
            messagebox.showinfo("Готово", message or f"{'Шифрование' if self.mode == 'encrypt' else 'Расшифровка'} успешно завершено!")

    def cancelled_operation(self):
        """Операция прервана пользователем"""
        self.is_running = False
        self.status_label.config(text="❌ Операция прервана.")
        self.start_button.config(state="normal")
        self.cancel_button.config(text="Закрыть", command=self.close_window)

    def cancel_operation(self):
        """Пользователь нажал «Отмена»"""
        if self.is_running:
            if messagebox.askyesno("Подтверждение", "Вы уверены, что хотите прервать операцию?"):
                self.is_running = False
        else:
            self.close_window()

    def close_window(self):
        """Закрытие окна"""
        self.win.destroy()

    def real_encrypt(self):
        password = self.password_entry.get()
        algorithm = self.algorithm_var.get()
        drive = self.drive_path
        
        def progress(current, total):
            # Обновляем прогресс по количеству файлов
            self.parent.root.after(0, lambda: self.update_progress_simple(current, total))
        
        try:
            total_files = encrypt_drive(drive, password, progress_callback=progress)
            files_word = get_files_word(total_files)
            self.parent.root.after(0, lambda: self.finish_operation(f"Зашифровано {total_files} {files_word}."))
        except Exception as e:
            self.parent.root.after(0, lambda: self.handle_error(str(e)))

    def real_decrypt(self):
        password = self.password_entry.get()
        drive = self.drive_path
        
        def progress(current, total):
            self.parent.root.after(0, lambda: self.update_progress_simple(current, total))
        
        try:
            total_files = decrypt_drive(drive, password, progress_callback=progress)
            files_word = get_files_word(total_files)
            self.parent.root.after(0, lambda: self.finish_operation(f"Расшифровано {total_files} {files_word}."))
        except Exception as e:
            self.parent.root.after(0, lambda: self.handle_error(str(e)))

    def update_progress_simple(self, current, total):
        """Обновляет прогресс без оценки времени (т.к. неизвестно время на файл)"""
        if total == 0:
            percent = 0
        else:
            percent = int((current / total) * 100)
            self.progress["value"] = percent
        self.status_label.config(text=f"Обработано {current} из {total} файлов...")

    def handle_error(self, message):
        """Обработка ошибок шифрования/расшифровки"""
        self.is_running = False
        self.status_label.config(text=f"❌ Ошибка: {message}", fg="red")
        self.start_button.config(state="normal")
        self.cancel_button.config(text="Закрыть", command=self.close_window)
        messagebox.showerror("Ошибка", message)