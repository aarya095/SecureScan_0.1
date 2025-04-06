from PyQt6 import QtWidgets, QtGui, QtCore

class ThemeSwitcher(QtWidgets.QPushButton):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.dark_mode = True  
        self.setIcon(QtGui.QIcon("icons/dark_mode_icon.png")) 
        self.setIconSize(QtCore.QSize(32, 32))

        self.apply_stylesheet("GUI/theme_switch/dark_style.qss") 

        self.clicked.connect(self.toggle_theme)

    def apply_stylesheet(self, file_path):
        """Loads and applies the QSS stylesheet from the given file."""
        try:
            with open(file_path, "r") as file:
                style = file.read()
                QtWidgets.QApplication.instance().setStyleSheet(style)
        except Exception as e:
            print(f"Error loading stylesheet: {e}")

    def toggle_theme(self):
        """Switches between light and dark themes dynamically."""
        if self.dark_mode:
            self.apply_stylesheet("GUI/theme_switch/light_style.qss")
            self.setIcon(QtGui.QIcon("icons/light_mode_icon.png"))
        else:
            self.apply_stylesheet("GUI/theme_switch/dark_style.qss")
            self.setIcon(QtGui.QIcon("icons/dark_mode_icon.png"))

        self.dark_mode = not self.dark_mode
        self.update()
