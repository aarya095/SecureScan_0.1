from PyQt6 import QtCore, QtGui, QtWidgets
from GUI.main_window_ui.tabs.home_quick_scan import QuickScanTab
from GUI.main_window_ui.tabs.custom_scan_tab import CustomScanTab
from GUI.main_window_ui.tabs.history_tab import HistoryTab
from GUI.main_window_ui.tabs.profile_tab import ProfileTab
from GUI.main_window_ui.tabs.about_tab import AboutTab

from GUI.theme_switch.theme_manager import ThemeSwitcher

class Ui_MainWindow(QtWidgets.QMainWindow):

    @staticmethod
    def load_stylesheet(file_path):
        
        try:
            with open(file_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            print(f"Warning: Stylesheet '{file_path}' not found.")
            return ""

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setObjectName("MainWindow")
        self.resize(1099, 693)
    
        self.setWindowIcon(QtGui.QIcon("icons/S_logo.png"))

        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.sizePolicy().hasHeightForWidth())
        self.setSizePolicy(sizePolicy)
        self.setStyleSheet("QMainWindow{\n"
"    background-color:black\n"
"}")
        self.centralwidget = QtWidgets.QWidget(parent=self)
        self.centralwidget.setObjectName("centralwidget")
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.centralwidget.sizePolicy().hasHeightForWidth())
        self.centralwidget.setSizePolicy(sizePolicy)

        self.tabWidget = QtWidgets.QTabWidget(parent=self.centralwidget)
        layout = QtWidgets.QVBoxLayout(self.centralwidget)  # Use vertical layout
        layout.addWidget(self.tabWidget)
        self.setCentralWidget(self.centralwidget)  
        self.tabWidget.setObjectName("tabWidget")

        self.home_tab = QuickScanTab(parent=self.tabWidget)
        self.custom_scan_tab = CustomScanTab(parent=self.tabWidget)
        self.history_tab = HistoryTab(parent=self.tabWidget)
        self.profile_tab = ProfileTab(parent=self.tabWidget)
        self.about_tab = AboutTab(parent=self.tabWidget)

        # Add them to the tab widget
        self.tabWidget.addTab(self.home_tab, "Home")
        self.tabWidget.addTab(self.custom_scan_tab, "Custom Scan")
        self.tabWidget.addTab(self.history_tab, "History")
        self.tabWidget.addTab(self.profile_tab, "Profile")
        self.tabWidget.addTab(self.about_tab, "About")

        self.setCentralWidget(self.centralwidget)

        self.tabWidget.setCurrentIndex(0)
        print("Total Tabs:", self.tabWidget.count())
        
        QtCore.QMetaObject.connectSlotsByName(self)

def center_window(self):
    """Centers the MainWindow on the screen."""
    screen = QtWidgets.QApplication.primaryScreen().geometry()  # Get screen size
    window = self.frameGeometry()  # Get window size

    center_x = (screen.width() - window.width()) // 2
    center_y = (screen.height() - window.height()) // 2
    self.move(center_x, center_y)

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)

    stylesheet = Ui_MainWindow.load_stylesheet("GUI/theme_switch/light_style.qss")
    app.setStyleSheet(stylesheet)

    # 🔹 Initialize Main Window
    MainWindow = QtWidgets.QMainWindow()
    window = Ui_MainWindow()
    window.show()
    center_window(window)

    sys.exit(app.exec())