"""Module for managing application resources and paths."""
import os
import sys


def resource_path(relative_path):
    """ Получает абсолютный путь к ресурсу, работает для разработки и для PyInstaller """
    try:
        # PyInstaller создает временную папку и сохраняет путь в _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)