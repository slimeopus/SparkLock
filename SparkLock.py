import tkinter as tk
from main_window import MainWindow
import utils
import os
import sys
import json
from resources import resource_path

default_language = 'ru'

locales_path = resource_path("locales")
print(f"DEBUG: Путь к локалям: {locales_path}")
print(f"DEBUG: Содержимое папки: {os.listdir(locales_path) if os.path.exists(locales_path) else 'Папка не найдена'}")

def main():
    # Уничтожаем любое существующее окно перед созданием нового
    if tk._default_root is not None:
        tk._default_root.destroy()

    root = tk.Tk()
    root.title("SparkLock")

    # Центрируем окно ДО создания приложения
    from utils import center_window
    center_window(root, 1000, 600)

    app = MainWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
