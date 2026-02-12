from utils import center_window, get_lang_manager
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
        self.lang_manager = get_lang_manager()

        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        style = ttk.Style()
        style.theme_use('default')  # гарантирует, что стиль можно переопределить
        style.configure("Green.Horizontal.TProgressbar", foreground='green', background='green')
        self.win.title(self.lang_manager.t(f"encryption_window.title_{mode}"))
        center_window(self.win, 500, 500)
        self.win.resizable(False, False)
        self.win.transient(parent.root)  # делаем модальным
        self.win.grab_set()  # блокируем родительское окно

        # Сохраняем ссылки на элементы управления для последующего обновления
        self.title_label = None
        self.device_label = None
        self.password_label = None
        self.confirm_label = None
        self.generate_password_btn = None
        self.algorithm_label = None
        self.algorithm_frame = None
        self.start_button = None
        self.cancel_button = None
        self.progress_label = None
        self.time_label = None
        self.status_label = None

        # --- Заголовок ---
        title = self.lang_manager.t(f"encryption_window.title_{mode}")
        self.title_label = tk.Label(self.win, text=title, font=("Arial", 16, "bold"))
        self.title_label.pack(pady=(10, 5))

        # --- Устройство ---
        self.device_label = tk.Label(self.win, text=f"{self.lang_manager.t('encryption_window.selected_device')} {drive_path}", font=("Arial", 10), fg="blue")
        self.device_label.pack(pady=5)

        # --- Пароль с кнопкой показа/скрытия ---
        password_frame = tk.Frame(self.win)
        password_frame.pack(pady=(10, 5), fill="x", padx=40)
        self.password_label = tk.Label(password_frame, text=self.lang_manager.t("encryption_window.password"), font=("Arial", 12))
        self.password_label.pack(anchor="w")
        self.password_visible = False
        self.password_entry = ttk.Entry(password_frame, show="*", width=40)
        self.password_entry.pack(side="left", fill="x", expand=True)
        self.toggle_password_btn = ttk.Button(password_frame, text=" 👁 ", width=4, command=self.toggle_password_visibility)
        self.toggle_password_btn.pack(side="right", padx=(5, 0))

        confirm_frame = tk.Frame(self.win)
        confirm_frame.pack(pady=(5, 10), fill="x", padx=40)
        self.confirm_label = tk.Label(confirm_frame, text=self.lang_manager.t("encryption_window.confirm_password"), font=("Arial", 12))
        self.confirm_label.pack(anchor="w")
        self.confirm_visible = False
        self.confirm_entry = ttk.Entry(confirm_frame, show="*", width=40)
        self.confirm_entry.pack(side="left", fill="x", expand=True)
        self.toggle_confirm_btn = ttk.Button(confirm_frame, text=" 👁 ", width=4, command=self.toggle_confirm_visibility)
        self.toggle_confirm_btn.pack(side="right", padx=(5, 0))

        self.password_entry.bind('<Return>', lambda event: self.confirm_entry.focus_set())
        self.confirm_entry.bind('<Return>', lambda event: self.start_operation())

        # --- Кнопка генерации пароля ---
        gen_frame = tk.Frame(self.win)
        gen_frame.pack(pady=5)
        self.generate_password_btn = ttk.Button(gen_frame, text=self.lang_manager.t("encryption_window.generate_password"), command=self.generate_password)
        self.generate_password_btn.pack()

        # --- Алгоритм ---
        self.algorithm_label = tk.Label(self.win, text=self.lang_manager.t("encryption_window.encryption_algorithm"), font=("Arial", 12))
        self.algorithm_label.pack(pady=(10, 0))
        self.algorithm_var = tk.StringVar(value="AES-256")
        self.algorithm_frame = tk.Frame(self.win)
        self.algorithm_frame.pack(pady=5)

        self.update_algorithms_display()

        # --- Кнопки ---
        button_frame = tk.Frame(self.win)
        button_frame.pack(pady=20)

        self.start_button = ttk.Button(button_frame, text=self.lang_manager.t("encryption_window.start"), command=self.start_operation, width=15)
        self.start_button.pack(side="left", padx=10)

        self.cancel_button = ttk.Button(button_frame, text=self.lang_manager.t("encryption_window.cancel"), command=self.cancel_operation, width=15)
        self.cancel_button.pack(side="right", padx=10)

        # --- Прогресс и таймер ---
        progress_frame = tk.Frame(self.win)
        progress_frame.pack(fill="x", padx=20, pady=(10, 0))

        self.progress_label = tk.Label(progress_frame, text=self.lang_manager.t("encryption_window.progress"))
        self.progress_label.pack(anchor="w")
        self.progress = ttk.Progressbar(
            progress_frame,
            mode="determinate",
            length=400,
            style="Green.Horizontal.TProgressbar"
        )
        self.progress.pack(fill="x", pady=5)

        self.time_label = tk.Label(progress_frame, text=self.lang_manager.t("encryption_window.time_remaining") + " --:--", font=("Arial", 10))
        self.time_label.pack(anchor="e", pady=5)

        # --- Статус ---
        self.status_label = tk.Label(self.win, text=self.lang_manager.t("encryption_window.ready_to_start"), fg="gray")
        self.status_label.pack(pady=10)

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
            
        algorithms = [
            ("AES-256", self.lang_manager.t("algorithms.aes256_desc")),
            ("ChaCha20", self.lang_manager.t("algorithms.chacha20_desc")),
            ("XChaCha20-Poly1305", self.lang_manager.t("algorithms.xchacha20_desc"))
        ]

        for algo, desc in algorithms:
            rb = ttk.Radiobutton(self.algorithm_frame, text=f"{algo} — {desc}", variable=self.algorithm_var, value=algo)
            rb.pack(anchor="w", pady=2)

    def update_ui_language(self, language_code):
        """Обновляет текст всех элементов интерфейса при смене языка"""
        # Обновляем заголовок окна
        self.win.title(self.lang_manager.t(f"encryption_window.title_{self.mode}"))
        
        # Обновляем текст меток
        self.title_label.config(text=self.lang_manager.t(f"encryption_window.title_{self.mode}"))
        self.device_label.config(text=f"{self.lang_manager.t('encryption_window.selected_device')} {self.drive_path}")
        self.password_label.config(text=self.lang_manager.t("encryption_window.password"))
        self.confirm_label.config(text=self.lang_manager.t("encryption_window.confirm_password"))
        self.generate_password_btn.config(text=self.lang_manager.t("encryption_window.generate_password"))
        self.algorithm_label.config(text=self.lang_manager.t("encryption_window.encryption_algorithm"))
        
        # Обновляем алгоритмы
        self.update_algorithms_display()
        
        self.start_button.config(text=self.lang_manager.t("encryption_window.start"))
        self.cancel_button.config(text=self.lang_manager.t("encryption_window.cancel"))
        self.progress_label.config(text=self.lang_manager.t("encryption_window.progress"))
        self.time_label.config(text=self.lang_manager.t("encryption_window.time_remaining") + " --:--")
        self.status_label.config(text=self.lang_manager.t("encryption_window.ready_to_start"))

    def generate_password(self):
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.confirm_entry.delete(0, tk.END)
        self.confirm_entry.insert(0, password)
        # Скрываем пароль после генерации
        self.password_visible = False
        self.confirm_visible = False
        self.password_entry.config(show="*")
        self.confirm_entry.config(show="*")
        self.toggle_password_btn.config(text=" 👁 ")
        self.toggle_confirm_btn.config(text=" 👁 ")
        self.status_label.config(text=self.lang_manager.t("encryption_window.password_generated"), fg="green")
        # Устанавливаем фокус на кнопку начала операции
        self.start_button.focus_set()

    def toggle_password_visibility(self):
        """Переключает видимость основного пароля"""
        self.password_visible = not self.password_visible
        if self.password_visible:
            self.password_entry.config(show="")
            self.toggle_password_btn.config(text=" 🙈 ")
        else:
            self.password_entry.config(show="*")
            self.toggle_password_btn.config(text=" 👁 ")
        # Автоматически скрываем пароль через 5 секунд для безопасности
        if self.password_visible:
            self.win.after(5000, lambda: self.hide_password_after_delay("password"))

    def toggle_confirm_visibility(self):
        """Переключает видимость пароля подтверждения"""
        self.confirm_visible = not self.confirm_visible
        if self.confirm_visible:
            self.confirm_entry.config(show="")
            self.toggle_confirm_btn.config(text=" 🙈 ")
        else:
            self.confirm_entry.config(show="*")
            self.toggle_confirm_btn.config(text=" 👁 ")
        # Автоматически скрываем пароль через 5 секунд для безопасности
        if self.confirm_visible:
            self.win.after(5000, lambda: self.hide_password_after_delay("confirm"))

    def hide_password_after_delay(self, field_type):
        """Автоматически скрывает пароль после задержки для безопасности"""
        if field_type == "password" and self.password_visible:
            self.password_visible = False
            self.password_entry.config(show="*")
            self.toggle_password_btn.config(text=" 👁 ")
            self.status_label.config(text=self.lang_manager.t("encryption_window.password_hidden"), fg="gray")
        elif field_type == "confirm" and self.confirm_visible:
            self.confirm_visible = False
            self.confirm_entry.config(show="*")
            self.toggle_confirm_btn.config(text=" 👁 ")
            self.status_label.config(text=self.lang_manager.t("encryption_window.password_hidden"), fg="gray")

    def validate_inputs(self):
        """Проверяет корректность введённых данных"""
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not password or not confirm:
            messagebox.showerror("Ошибка", self.lang_manager.t("encryption_window.enter_password_error"))
            return False

        if password != confirm:
            messagebox.showerror("Ошибка", self.lang_manager.t("encryption_window.password_mismatch_error"))
            return False

        if len(password) < 8:
            messagebox.showwarning("Предупреждение", self.lang_manager.t("encryption_window.password_length_warning"))
            return False
            # Можно продолжить, но предупредили

        return True

    def start_operation(self):
        """Запускает процесс шифрования/расшифровки"""
        if not self.validate_inputs():
            return

        if self.is_running:
            messagebox.showinfo("Информация", self.lang_manager.t("encryption_window.operation_in_progress"))
            return

        # === Пункт 3: Проверка свободного места (только при шифровании) ===
        if self.mode == "encrypt":
            try:
                total, used, free = shutil.disk_usage(self.drive_path)
                # Оценка: нужно минимум 1.2 × объёма занятого места (на время шифрования)
                needed = int(used * 1.2)
                if free < needed:
                    messagebox.showwarning(
                        self.lang_manager.t("warnings.insufficient_space"),
                        self.lang_manager.t("encryption_window.insufficient_space_warning") + "\n" +
                        f"Занято: {used // (1024**2)} МБ\n" +
                        f"Свободно: {free // (1024**2)} МБ\n" +
                        f"Рекомендуется: минимум {needed // (1024**2)} МБ свободного места."
                    )
                    return
            except Exception as e:
                messagebox.showwarning(self.lang_manager.t("warnings.warning"), self.lang_manager.t("warnings.cannot_check_space", error=str(e)))

        self.is_running = True
        self.start_button.config(state="disabled")
        self.cancel_button.config(text=self.lang_manager.t("encryption_window.cancel"))

        # Сбрасываем прогресс
        self.progress["value"] = 0
        self.time_label.config(text=self.lang_manager.t("encryption_window.time_remaining") + " --:--")
        self.status_label.config(text=self.lang_manager.t("encryption_window.starting_operation"))

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
        text = message if message else self.lang_manager.t("encryption_window.operation_completed")
        self.status_label.config(text=text)
        self.start_button.config(state="disabled")
        self.cancel_button.config(text=self.lang_manager.t("encryption_window.cancel"), command=self.close_window)

        # === Обновить статус в главном окне ===
        try:
            self.parent.scan_usb_drives()
        except Exception as e:
            print(f"Не удалось обновить список устройств: {e}")

        # === Проверяем настройки и показываем уведомление ===
        settings = self.load_settings()

        # Если включено уведомление — показываем окно и воспроизводим звук
        if settings.get("notify_popup", True):
            popup_message = message or self.lang_manager.t(f"encryption_window.{self.mode}_completed")
            messagebox.showinfo(self.lang_manager.t("encryption_window.operation_completed"), popup_message)

    def cancelled_operation(self):
        """Операция прервана пользователем"""
        self.is_running = False
        self.status_label.config(text=self.lang_manager.t("encryption_window.operation_cancelled"))
        self.start_button.config(state="normal")
        self.cancel_button.config(text=self.lang_manager.t("encryption_window.cancel"), command=self.close_window)

    def cancel_operation(self):
        """Пользователь нажал «Отмена»"""
        if self.is_running:
            if messagebox.askyesno("Подтверждение", self.lang_manager.t("encryption_window.confirmation")):
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
            files_word = get_files_word(total_files, self.lang_manager.current_language)
            message = self.lang_manager.t("encryption_window.encrypted_count", count=total_files, files_word=files_word)
            self.parent.root.after(0, lambda: self.finish_operation(message))
        except Exception as e:
            self.parent.root.after(0, lambda: self.handle_error(str(e)))

    def real_decrypt(self):
        password = self.password_entry.get()
        drive = self.drive_path

        def progress(current, total):
            self.parent.root.after(0, lambda: self.update_progress_simple(current, total))

        try:
            total_files = decrypt_drive(drive, password, progress_callback=progress)
            files_word = get_files_word(total_files, self.lang_manager.current_language)
            message = self.lang_manager.t("encryption_window.decrypted_count", count=total_files, files_word=files_word)
            self.parent.root.after(0, lambda: self.finish_operation(message))
        except Exception as e:
            self.parent.root.after(0, lambda: self.handle_error(str(e)))

    def update_progress_simple(self, current, total):
        """Обновляет прогресс без оценки времени (т.к. неизвестно время на файл)"""
        if total == 0:
            percent = 0
        else:
            percent = int((current / total) * 100)
            self.progress["value"] = percent
        self.status_label.config(text=self.lang_manager.t("encryption_window.files_processed", current=current, total=total))

    def handle_error(self, message):
        """Обработка ошибок шифрования/расшифровки"""
        self.is_running = False
        self.status_label.config(text=self.lang_manager.t("encryption_window.error") + f" {message}", fg="red")
        self.start_button.config(state="normal")
        self.cancel_button.config(text=self.lang_manager.t("encryption_window.cancel"), command=self.close_window)
        messagebox.showerror(self.lang_manager.t("errors.error_title"), self.lang_manager.t("errors.operation_error", message=message))