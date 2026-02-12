import tkinter as tk
from main_window import MainWindow
import utils
import os
import sys
import json
from resources import resource_path

def main():
    # Уничтожаем любое существующее окно перед созданием нового
    if tk._default_root is not None:
        tk._default_root.destroy()

    root = tk.Tk()
    
    # Устанавливаем заголовок окна с учетом локализации
    from utils import get_lang_manager
    lang_manager = get_lang_manager()
    root.title(lang_manager.t("app_title"))

    # Центрируем окно ДО создания приложения
    from utils import center_window
    center_window(root, 1000, 600)

    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
