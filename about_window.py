from utils import center_window
import tkinter as tk
from tkinter import ttk

class AboutWindow:
    def __init__(self, parent):
        self.parent = parent
        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        self.win.title("О программе")
        center_window(self.win, 400, 250)
        self.win.resizable(False, False)
        self.win.transient(parent.root)  # делаем модальным
        self.win.grab_set()  # блокируем родительское окно

        # --- Заголовок ---
        tk.Label(self.win, text="SparkLock", font=("Arial", 18, "bold")).pack(pady=(15, 5))
        tk.Label(self.win, text="Шифровальщик USB-накопителей", font=("Arial", 12)).pack(pady=5)

        # --- Информация ---
        info_frame = tk.Frame(self.win)
        info_frame.pack(pady=10, padx=20, fill="x")

        tk.Label(info_frame, text="Версия:", font=("Arial", 10, "bold"), anchor="w").grid(row=0, column=0, sticky="w", pady=2)
        tk.Label(info_frame, text="3.4.0", font=("Arial", 10), anchor="w").grid(row=0, column=1, sticky="w", padx=10, pady=2)

        tk.Label(info_frame, text="Разработчик:", font=("Arial", 10, "bold"), anchor="w").grid(row=1, column=0, sticky="w", pady=2)
        tk.Label(info_frame, text="SlimeOpus", font=("Arial", 10), anchor="w").grid(row=1, column=1, sticky="w", padx=10, pady=2)

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  
    win = AboutWindow(root)
    root.mainloop()