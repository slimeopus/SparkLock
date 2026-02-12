from utils import center_window, get_lang_manager
import tkinter as tk
from tkinter import ttk, messagebox

class HelpWindow:
    def __init__(self, parent):
        self.parent = parent
        self.lang_manager = get_lang_manager()

        # Создаём модальное окно
        self.win = tk.Toplevel(parent.root)
        self.win.title(self.lang_manager.t("help_window.title"))
        center_window(self.win, 700, 500)
        self.win.resizable(True, True)
        self.win.transient(parent.root)
        self.win.grab_set()

        # Сохраняем ссылки на элементы управления для последующего обновления
        self.window_title_label = None
        self.notebook = None
        self.instructions_tab = None
        self.faq_tab = None
        self.support_tab = None
        self.close_button = None

        # --- Заголовок ---
        self.window_title_label = tk.Label(self.win, text=self.lang_manager.t("help_window.title"), font=("Arial", 16, "bold"))
        self.window_title_label.pack(pady=(10, 5))

        # --- Вкладки ---
        self.notebook = ttk.Notebook(self.win)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Вкладка: Инструкции
        instructions_frame = tk.Frame(self.notebook)
        self.notebook.add(instructions_frame, text=self.lang_manager.t("help_window.instructions_tab"))
        self.instructions_tab = instructions_frame

        self.instructions_text = tk.Text(instructions_frame, wrap="word", bg="white", relief="flat", font=("Arial", 11))
        self.instructions_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.update_instructions_content()

        # Вкладка: FAQ
        faq_frame = tk.Frame(self.notebook)
        self.notebook.add(faq_frame, text=self.lang_manager.t("help_window.faq_tab"))
        self.faq_tab = faq_frame

        self.faq_text = tk.Text(faq_frame, wrap="word", bg="white", relief="flat", font=("Arial", 11))
        self.faq_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.update_faq_content()

        # Вкладка: Поддержка
        support_frame = tk.Frame(self.notebook)
        self.notebook.add(support_frame, text=self.lang_manager.t("help_window.support_tab"))
        self.support_tab = support_frame

        self.support_text = tk.Text(support_frame, wrap="word", bg="white", relief="flat", font=("Arial", 11))
        self.support_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.update_support_content()

        # Кнопка закрытия
        self.close_button = tk.Button(self.win, text=self.lang_manager.t("help_window.close"), command=self.win.destroy, width=15)
        self.close_button.pack(pady=10)

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

    def update_instructions_content(self):
        """Обновляет содержимое вкладки инструкций"""
        # Очищаем текстовое поле
        self.instructions_text.config(state="normal")
        self.instructions_text.delete(1.0, tk.END)
        
        instructions_content = f"""
=== {self.lang_manager.t("help_window.instructions.header")} ===

{self.lang_manager.t("help_window.instructions.step1")}
{self.lang_manager.t("help_window.instructions.step2")}
{self.lang_manager.t("help_window.instructions.step3")}
{self.lang_manager.t("help_window.instructions.step4")}
{self.lang_manager.t("help_window.instructions.step4_details")}
{self.lang_manager.t("help_window.instructions.step4_details2")}
{self.lang_manager.t("help_window.instructions.step4_details3")}
{self.lang_manager.t("help_window.instructions.step5")}
{self.lang_manager.t("help_window.instructions.step6")}

{self.lang_manager.t("help_window.instructions.important")}
{self.lang_manager.t("help_window.instructions.important1")}
{self.lang_manager.t("help_window.instructions.important2")}
{self.lang_manager.t("help_window.instructions.important3")}
"""

        self.instructions_text.insert(tk.END, instructions_content)
        self.instructions_text.config(state="disabled")  # только для чтения

    def update_faq_content(self):
        """Обновляет содержимое вкладки FAQ"""
        # Очищаем текстовое поле
        self.faq_text.config(state="normal")
        self.faq_text.delete(1.0, tk.END)
        
        faq_content = f"""
=== {self.lang_manager.t("help_window.faq.header")} ===

{self.lang_manager.t("help_window.faq.q1")}
{self.lang_manager.t("help_window.faq.a1")}

{self.lang_manager.t("help_window.faq.q2")}
{self.lang_manager.t("help_window.faq.a2")}

{self.lang_manager.t("help_window.faq.q3")}
{self.lang_manager.t("help_window.faq.a3")}

{self.lang_manager.t("help_window.faq.q4")}
{self.lang_manager.t("help_window.faq.a4")}
"""

        self.faq_text.insert(tk.END, faq_content)
        self.faq_text.config(state="disabled")

    def update_support_content(self):
        """Обновляет содержимое вкладки поддержки"""
        # Очищаем текстовое поле
        self.support_text.config(state="normal")
        self.support_text.delete(1.0, tk.END)
        
        support_content = f"""
=== {self.lang_manager.t("help_window.support.header")} ===

{self.lang_manager.t("help_window.support.contact_info")}

{self.lang_manager.t("help_window.support.email")}
{self.lang_manager.t("help_window.support.website")}
"""

        self.support_text.insert(tk.END, support_content)
        self.support_text.config(state="disabled")

    def update_ui_language(self, language_code):
        """Обновляет текст всех элементов интерфейса при смене языка"""
        # Обновляем заголовок окна
        self.win.title(self.lang_manager.t("help_window.title"))
        
        # Обновляем текст метки заголовка
        self.window_title_label.config(text=self.lang_manager.t("help_window.title"))
        
        # Обновляем текст вкладок (используя индексы вместо имен)
        self.notebook.tab(0, text=self.lang_manager.t("help_window.instructions_tab"))
        self.notebook.tab(1, text=self.lang_manager.t("help_window.faq_tab"))
        self.notebook.tab(2, text=self.lang_manager.t("help_window.support_tab"))
        
        # Обновляем содержимое вкладок
        self.update_instructions_content()
        self.update_faq_content()
        self.update_support_content()
        
        # Обновляем кнопку закрытия
        self.close_button.config(text=self.lang_manager.t("help_window.close"))

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()  
    win = HelpWindow(root)
    root.mainloop()