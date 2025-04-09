from GUI.main_window_ui.user_interface import Ui_MainWindow
from PyQt6.QtWidgets import QMainWindow
from controller.Tabs_Controller.home_tab_controller import QuickScanController
from controller.Tabs_Controller.custom_scan_controller import CustomScanController


class MainWindowController:
    def __init__(self):
        self.window = Ui_MainWindow()
        
        self.quick_scan_controller = QuickScanController(self.window.home_tab)
        self.custom_scan_controller = CustomScanController(self.window.custom_scan_tab)

        self.setup_inter_tab_communication()
        self.window.show()

    def setup_inter_tab_communication(self):
        """If you need tabs to talk to each other, wire their signals here."""
        pass 

    def get_window(self):
        """Returns the main UI window (used by login controller if needed)."""
        if hasattr(self, "window"):
            return self.window
        else:
            print("❌ MainWindowController has no window attribute!")
            return None
