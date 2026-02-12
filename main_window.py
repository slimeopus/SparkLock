from utils import center_window, get_lang_manager
import json
import tkinter as tk
from tkinter import ttk, messagebox, Menu
import os
import platform
import subprocess
import threading
from encryption_window import EncryptionWindow

class MainWindow:
    def __init__(self, root):
        self.active_encryption_window = None
        self.root = root
        self.lang_manager = get_lang_manager()
        # Подписываемся на изменения языка
        self.lang_manager.add_observer(self.update_ui_language)
        
        self.root.title(self.lang_manager.t("app_title"))
        self.root.geometry("1000x600")
        center_window(self.root, 1000, 600)
        self.root.configure(bg="#f0f0f0")
        self.last_known_drives = []

        # Сохраняем ссылки на элементы управления для последующего обновления
        self.btn_encrypt = None
        self.btn_decrypt = None
        self.btn_settings = None
        self.btn_help = None
        self.btn_about = None
        self.usb_drives_label = None
        self.detailed_info_label = None
        self.status_label = None

        # Верхнее меню
        self.top_button_frame = tk.Frame(root, bg="#e0e0e0", height=40)
        self.top_button_frame.pack(side="top", fill="x", padx=5, pady=5)
        self.top_button_frame.pack_propagate(False)

        self.btn_encrypt = tk.Button(self.top_button_frame, text=self.lang_manager.t("menu.encrypt"), command=self.encrypt_selected, width=12,
                       bg="#e0e0e0", fg="black", relief="flat", padx=5, pady=2,
                       activebackground="#d0d0d0", activeforeground="black")
        self.btn_encrypt.pack(side="left", padx=5, pady=5)

        self.btn_decrypt = tk.Button(self.top_button_frame, text=self.lang_manager.t("menu.decrypt"), command=self.decrypt_selected, width=14,
                               bg="#e0e0e0", fg="black", relief="flat", padx=5, pady=2,
                               activebackground="#d0d0d0", activeforeground="black")
        self.btn_decrypt.pack(side="left", padx=5, pady=5)

        self.btn_settings = tk.Button(self.top_button_frame, text=self.lang_manager.t("menu.settings"), command=self.open_settings, width=12,
                                bg="#e0e0e0", fg="black", relief="flat", padx=5, pady=2,
                                activebackground="#d0d0d0", activeforeground="black")
        self.btn_settings.pack(side="left", padx=5, pady=5)

        self.btn_help = tk.Button(self.top_button_frame, text=self.lang_manager.t("menu.help"), command=self.open_help, width=12,
                            bg="#e0e0e0", fg="black", relief="flat", padx=5, pady=2,
                            activebackground="#d0d0d0", activeforeground="black")
        self.btn_help.pack(side="left", padx=5, pady=5)

        self.btn_about = tk.Button(self.top_button_frame, text=self.lang_manager.t("menu.about"), command=self.show_about, width=13,
                             bg="#e0e0e0", fg="black", relief="flat", padx=5, pady=2,
                             activebackground="#d0d0d0", activeforeground="black")
        self.btn_about.pack(side="left", padx=5, pady=5)

        # --- Левая боковая панель (USB-устройства) ---
        self.left_frame = tk.Frame(root, bg="#e0e0e0", width=300)
        self.left_frame.pack(side="left", fill="y", padx=5, pady=5)
        self.left_frame.pack_propagate(False)
        self.usb_drives_label = tk.Label(self.left_frame, text=self.lang_manager.t("main_window.usb_drives_title"), font=("Arial", 12, "bold"), bg="#e0e0e0")
        self.usb_drives_label.pack(pady=(10, 5))

        # Список устройств
        self.usb_listbox = tk.Listbox(self.left_frame, selectmode="single", height=20, bg="white", relief="flat")
        self.usb_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.usb_listbox.bind("<<ListboxSelect>>", self.on_usb_select)

        # --- Центральная область (информация) ---
        self.center_frame = tk.Frame(root, bg="white", padx=10, pady=10)
        self.center_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        self.detailed_info_label = tk.Label(self.center_frame, text=self.lang_manager.t("main_window.detailed_info"), font=("Arial", 14, "bold"), bg="#e0e0e0")
        self.detailed_info_label.pack(anchor="w", pady=(0, 10))
        self.info_text = tk.Text(self.center_frame, wrap="word", state="disabled", bg="white", relief="flat", height=20)
        self.info_text.pack(fill="both", expand=True)

        # --- Нижняя панель (статус и прогресс) ---
        self.bottom_frame = tk.Frame(root, bg="#d0d0d0", height=40)
        self.bottom_frame.pack(side="bottom", fill="x", padx=5, pady=5)
        self.bottom_frame.pack_propagate(False)
        self.status_label = tk.Label(self.bottom_frame, text=self.lang_manager.t("main_window.ready_status"), anchor="w", bg="#d0d0d0")
        self.status_label.pack(side="left", padx=10)
        self.progress = ttk.Progressbar(self.bottom_frame, mode="indeterminate")
        self.progress.pack(side="right", padx=10, fill="x", expand=True)

        # Загрузка устройств при запуске
        self.scan_usb_drives()
        self.apply_theme()

        # Запускаем мониторинг USB-устройств
        self.start_usb_monitoring()
        
        # Привязываем удаление наблюдателя к событию закрытия окна
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """Удаляем наблюдатель при закрытии окна"""
        try:
            self.lang_manager.remove_observer(self.update_ui_language)
        except ValueError:
            # Наблюдатель уже удален
            pass
        self.root.destroy()

    def update_ui_language(self, language_code):
        """Обновляет текст всех элементов интерфейса при смене языка"""
        # Обновляем заголовок окна
        self.root.title(self.lang_manager.t("app_title"))
        
        # Обновляем текст кнопок меню
        self.btn_encrypt.config(text=self.lang_manager.t("menu.encrypt"))
        self.btn_decrypt.config(text=self.lang_manager.t("menu.decrypt"))
        self.btn_settings.config(text=self.lang_manager.t("menu.settings"))
        self.btn_help.config(text=self.lang_manager.t("menu.help"))
        self.btn_about.config(text=self.lang_manager.t("menu.about"))
        
        # Обновляем метки
        self.usb_drives_label.config(text=self.lang_manager.t("main_window.usb_drives_title"))
        self.detailed_info_label.config(text=self.lang_manager.t("main_window.detailed_info"))
        self.status_label.config(text=self.lang_manager.t("main_window.ready_status"))
        
        # Пересканируем устройства, чтобы обновить их статусы
        self.scan_usb_drives()
        
        # Если есть выбранный элемент, обновим информацию о нем
        selection = self.usb_listbox.curselection()
        if selection:
            self.on_usb_select(None)

    def start_usb_monitoring(self):
        """Запускает мониторинг подключенных устройств"""
        self.root.after(3000, self.check_for_new_devices)

    def check_for_new_devices(self):
        """Проверяет, появились ли новые USB-устройства"""
        current_drives = self.get_usb_drives()
        if set(current_drives) != set(self.last_known_drives):
            self.scan_usb_drives()
            self.last_known_drives = current_drives
        self.root.after(3000, self.check_for_new_devices)

    def scan_usb_drives(self):
        """Сканирует и заполняет список USB-устройств"""
        drives = self.get_usb_drives()  # ← Этот метод должен быть отдельно!
        self.usb_listbox.delete(0, tk.END)
        for drive in drives:
            info = self.get_drive_info(drive)
            status = self.lang_manager.t("main_window.encrypted_status") if info.get("encrypted", False) else self.lang_manager.t("main_window.not_encrypted_status")
            display = f"{info['name']} ({info['size']}) — {status}"
            self.usb_listbox.insert(tk.END, display)
            self.usb_listbox.itemconfig(tk.END, {'fg': 'red' if info.get("encrypted") else 'black'})

    def get_usb_drives(self):
        """Возвращает список USB-дисков (Windows/Linux/Mac)"""
        drives = []
        system = platform.system()
        if system == "Windows":
            import string
            from ctypes import windll
            for letter in string.ascii_uppercase:
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    try:
                        if windll.kernel32.GetDriveTypeW(drive) == 2:  # DRIVE_REMOVABLE
                            drives.append(drive)
                    except Exception:
                        continue
        elif system == "Linux":
            base = "/media/"
            if os.path.exists(base):
                for user in os.listdir(base):
                    user_path = os.path.join(base, user)
                    if os.path.isdir(user_path):
                        for device in os.listdir(user_path):
                            drives.append(os.path.join(user_path, device))
        elif system == "Darwin":  # macOS
            base = "/Volumes/"
            if os.path.exists(base):
                for volume in os.listdir(base):
                    if not volume.startswith('.'):
                        drives.append(os.path.join(base, volume))
        return drives

    def get_drive_name(self, path):
        """Возвращает понятное имя устройства (метку тома или букву диска)"""
        system = platform.system()
        try:
            if system == "Windows":
                import subprocess
                # Получаем метку тома через vol
                result = subprocess.run(
                    ["vol", path[0] + ":"],
                    capture_output=True, text=True, shell=True
                )
                for line in result.stdout.splitlines():
                    if "тома" in line or "Volume" in line:
                        parts = line.split(" ")
                        # Пример: "Том в устройстве E имеет метку USB_DRIVE"
                        if "метку" in line:
                            return line.split("метку")[-1].strip()
                        elif "is" in line:
                            # Английский: "Volume in drive E is USB_DRIVE"
                            return line.split("is")[-1].strip()
                # Если метки нет — возвращаем букву диска
                return f"{path[0]}:"
            elif system == "Linux":
                return os.path.basename(path)
            elif system == "Darwin":
                return os.path.basename(path)
        except Exception as e:
            print(f"Не удалось получить имя устройства: {e}")
            return os.path.basename(path) or path

    def get_drive_info(self, path):
        name = self.get_drive_name(path)  # ← Используем новую функцию
        total, used, free = shutil.disk_usage(path) if os.path.exists(path) else (0, 0, 0)
        size_gb = total // (1024**3)
        free_gb = free // (1024**3)
        fs_type = self.get_filesystem_type(path)
        meta_path = os.path.join(path, ".usb_crypt_meta.json")
        encrypted = os.path.exists(meta_path)

        if encrypted:
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                algorithm = meta.get("algorithm", "AES-256-GCM")
            except:
                algorithm = self.lang_manager.t("main_window.unknown")
        else:
            algorithm = "—"

        return {
            "name": name,
            "size": f"{size_gb} {self.lang_manager.t('main_window.gb')}",
            "free": f"{free_gb} {self.lang_manager.t('main_window.gb_free')}",
            "fs": fs_type,
            "encrypted": encrypted,
            "algorithm": algorithm
        }

    def get_filesystem_type(self, path):
        """Определяет тип файловой системы"""
        system = platform.system()
        try:
            if system == "Windows":
                import subprocess

                # Попробуем через wmic (более надёжно)
                try:
                    result = subprocess.run(
                        ["wmic", "volume", "where", f"DriveLetter='{path[0]}:'", "get", "FileSystem"],
                        capture_output=True, text=True, check=True
                    )
                    for line in result.stdout.splitlines():
                        if line.strip() and not line.startswith("FileSystem"):
                            return line.strip()
                except Exception:
                    pass

                # Если wmic не сработал — пробуем fsutil
                try:
                    output = subprocess.check_output(f'fsutil fsinfo volumeinfo {path}', shell=True, text=True)
                    for line in output.splitlines():
                        if "File System Name" in line:
                            return line.split(":")[1].strip()
                except Exception:
                    pass

                return "FAT32/NTFS/exFAT"

            elif system == "Linux":
                result = subprocess.run(
                    ["df", "-T", path],
                    capture_output=True, text=True, check=True
                )
                lines = result.stdout.strip().splitlines()
                if len(lines) >= 2:
                    return lines[1].split()[1]
                return "ext4/FAT32/exFAT"

            elif system == "Darwin":  # macOS
                result = subprocess.run(
                    ["diskutil", "info", path],
                    capture_output=True, text=True, check=True
                )
                for line in result.stdout.splitlines():
                    if "File System Personality" in line:
                        return line.split(":")[1].strip()
                return "APFS/HFS+"

        except Exception as e:
            print(f"Ошибка определения ФС: {e}")
            return "Неизвестная ФС"

    def on_usb_select(self, event):
        """Обновляет информацию при выборе устройства"""
        selection = self.usb_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        drive = self.get_usb_drives()[index]
        info = self.get_drive_info(drive)

        text = f"{self.lang_manager.t('main_window.device_info.name')} {info['name']}\n"
        text += f"{self.lang_manager.t('main_window.device_info.size')} {info['size']}\n"
        text += f"{self.lang_manager.t('main_window.device_info.free_space')} {info['free']}\n"
        text += f"{self.lang_manager.t('main_window.device_info.filesystem')} {info['fs']}\n"
        text += f"{self.lang_manager.t('main_window.device_info.encryption_algorithm')} {info['algorithm']}\n"
        text += f"{self.lang_manager.t('main_window.device_info.status')} {self.lang_manager.t('main_window.device_info.encrypted_yes') if info['encrypted'] else self.lang_manager.t('main_window.device_info.encrypted_no')}"

        self.info_text.config(state="normal")
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, text)
        self.info_text.config(state="disabled")

    def encrypt_selected(self):
        """Открывает окно шифрования"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning(self.lang_manager.t("errors.error_title"), self.lang_manager.t("main_window.select_device_error"))
            return

        drive = self.get_usb_drives()[selection[0]]
        if self.active_encryption_window is None or not self.active_encryption_window.winfo_exists():
            from encryption_window import EncryptionWindow
            self.active_encryption_window = EncryptionWindow(self, drive, mode="encrypt").win
        else:
            messagebox.showinfo(self.lang_manager.t("info.info_title"), self.lang_manager.t("main_window.encryption_window_open"))

    def decrypt_selected(self):
        """Открывает окно расшифровки"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning(self.lang_manager.t("errors.error_title"), self.lang_manager.t("main_window.select_device_error"))
            return

        drive = self.get_usb_drives()[selection[0]]
        if self.active_encryption_window is None or not self.active_encryption_window.winfo_exists():
            from encryption_window import EncryptionWindow
            self.active_encryption_window = EncryptionWindow(self, drive, mode="decrypt").win
        else:
            messagebox.showinfo(self.lang_manager.t("info.info_title"), self.lang_manager.t("main_window.encryption_window_open"))

    def start_operation(self, message, success_msg):
        """Запускает операцию в отдельном потоке с анимацией прогресса"""
        self.status_label.config(text=message)
        self.progress.start()

        def simulate_work():
            import time
            time.sleep(3)  # Имитация работы
            self.root.after(0, lambda: self.finish_operation(success_msg))

        thread = threading.Thread(target=simulate_work)
        thread.daemon = True
        thread.start()

    def finish_operation(self, msg):
        """Завершение операции"""
        self.progress.stop()
        self.status_label.config(text=msg)
        self.scan_usb_drives()

    def open_settings(self):
        """Открывает окно настроек"""
        try:
            from settings_window import SettingsWindow
            SettingsWindow(self)
        except ImportError as e:
            messagebox.showerror("Ошибка", self.lang_manager.t("errors.settings_load_error", error=str(e)))

    def show_about(self):
        """Открывает окно 'О программе'"""
        try:
            from about_window import AboutWindow
            AboutWindow(self)
        except ImportError as e:
            messagebox.showerror("Ошибка", self.lang_manager.t("errors.about_load_error", error=str(e)))

    def open_help(self):
        """Открывает окно помощи"""
        try:
            from help_window import HelpWindow
            HelpWindow(self)
        except ImportError as e:
            messagebox.showerror("Ошибка", self.lang_manager.t("errors.help_load_error", error=str(e)))

    def apply_theme(self):
        """Применяет выбранную тему из настроек"""
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                config = json.load(f)
            theme = config.get("theme", "light")
            # Update language if it's in config
            if "language" in config:
                current_lang = self.lang_manager.current_language
                new_lang = config["language"]
                if current_lang != new_lang:
                    self.lang_manager.set_language(new_lang)
        except:
            theme = "light"

        style = ttk.Style()

        if theme == "dark":
            style.configure("TButton", background="#4a4a4a", foreground="white")
            style.map("TButton", background=[("active", "#5a5a5a")])
            bg_main = "#2e2e2e"
            bg_panel = "#3c3c3c"
            fg_text = "white"
            listbox_bg = "#4a4a4a"
            listbox_fg = "white"
            status_bg = "#252525"
        else:  # light
            style.configure("TButton", background="#e0e0e0", foreground="black")
            style.map("TButton", background=[("active", "#d0d0d0")])
            bg_main = "#f0f0f0"
            bg_panel = "#e0e0e0"
            fg_text = "black"
            listbox_bg = "white"
            listbox_fg = "black"
            status_bg = "#d0d0d0"

        # Применяем цвета
        self.root.configure(bg=bg_main)

        # Все панели
        for frame in [self.top_button_frame, self.left_frame, self.center_frame, self.bottom_frame]:
            frame.configure(bg=bg_panel)

        # Метки в панелях
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Label):
                if widget in [self.status_label]:
                    widget.configure(bg=status_bg, fg=fg_text)
                elif widget.master in [self.left_frame, self.top_button_frame, self.bottom_frame]:
                    widget.configure(bg=bg_panel, fg=fg_text)
                elif widget.master == self.center_frame:
                    widget.configure(bg="white", fg="black")

        # Список USB
        self.usb_listbox.configure(bg=listbox_bg, fg=listbox_fg)

        # Текстовое поле
        self.info_text.configure(bg="white" if theme == "light" else "#333333", fg=fg_text, insertbackground=fg_text)

# Добавим импорт для disk_usage
try:
    import shutil
except ImportError:
    shutil = None