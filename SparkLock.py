import tkinter as tk
from main_window import MainWindow
import utils

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