from utils import center_window, get_lang_manager
import tkinter as tk
from tkinter import ttk

class AboutWindow:
    def __init__(self, parent):
        self.parent = parent
        self.lang_manager = get_lang_manager()
        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        self.win.title(self.lang_manager.t("about_window.title"))
        center_window(self.win, 400, 250)
        self.win.resizable(False, False)
        self.win.transient(parent.root)  # делаем модальным
        self.win.grab_set()  # блокируем родительское окно

        # Сохраняем ссылки на элементы управления для последующего обновления
        self.app_title_label = None
        self.program_title_label = None
        self.version_label = None
        self.version_value_label = None
        self.developer_label = None
        self.developer_value_label = None

        # --- Заголовок ---
        self.app_title_label = tk.Label(self.win, text=self.lang_manager.t("app_title"), font=("Arial", 18, "bold"))
        self.app_title_label.pack(pady=(15, 5))
        self.program_title_label = tk.Label(self.win, text=self.lang_manager.t("program_title"), font=("Arial", 12))
        self.program_title_label.pack(pady=5)

        # --- Информация ---
        info_frame = tk.Frame(self.win)
        info_frame.pack(pady=10, padx=20, fill="x")

        self.version_label = tk.Label(info_frame, text=self.lang_manager.t("about_window.version"), font=("Arial", 10, "bold"), anchor="w")
        self.version_label.grid(row=0, column=0, sticky="w", pady=2)
        self.version_value_label = tk.Label(info_frame, text="3.5.1", font=("Arial", 10), anchor="w")
        self.version_value_label.grid(row=0, column=1, sticky="w", padx=10, pady=2)

        self.developer_label = tk.Label(info_frame, text=self.lang_manager.t("about_window.developer"), font=("Arial", 10, "bold"), anchor="w")
        self.developer_label.grid(row=1, column=0, sticky="w", pady=2)
        self.developer_value_label = tk.Label(info_frame, text="SlimeOpus", font=("Arial", 10), anchor="w")
        self.developer_value_label.grid(row=1, column=1, sticky="w", padx=10, pady=2)

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

    def update_ui_language(self, language_code):
        """Обновляет текст всех элементов интерфейса при смене языка"""
        # Обновляем заголовок окна
        self.win.title(self.lang_manager.t("about_window.title"))

        # Обновляем текст меток
        self.app_title_label.config(text=self.lang_manager.t("app_title"))
        self.program_title_label.config(text=self.lang_manager.t("program_title"))
        self.version_label.config(text=self.lang_manager.t("about_window.version"))
        self.developer_label.config(text=self.lang_manager.t("about_window.developer"))

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    win = AboutWindow(root)
    root.mainloop()
