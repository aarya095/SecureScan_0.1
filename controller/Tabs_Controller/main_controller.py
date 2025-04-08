from GUI.main_window_ui.user_interface import Ui_MainWindow
from PyQt6.QtWidgets import QMainWindow
from controller.Tabs_Controller.home_tab_controller import QuickScanController
from controller.Tabs_Controller.custom_scan_controller import CustomScanController


class MainWindowController:
    def __init__(self):
        self.window = QMainWindow()
        self.ui = Ui_MainWindow()
        self.ui.init_ui(self.window)

        self.quick_scan_controller = QuickScanController(self.ui.home_tab)
        self.custom_scan_controller = CustomScanController(self.ui.custom_scan_tab)

        self.setup_inter_tab_communication()
        self.window.show()

    def setup_inter_tab_communication(self):
        """If you need tabs to talk to each other, wire their signals here."""
        pass  # Implement shared logic or event forwarding here if necessary

    def get_window(self):
        """Returns the main UI window (used by login controller if needed)."""
        return self.main_window
