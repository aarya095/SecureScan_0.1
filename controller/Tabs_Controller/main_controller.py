# controller/main_controller.py

from GUI.main_window_ui.user_interface import Ui_MainWindow

from controller.Tabs_Controller.home_tab_controller import QuickScanController


class MainWindowController:
    def __init__(self):
        # Initialize the main UI window
        self.main_window = Ui_MainWindow()

        # Initialize individual controllers for each tab
        self.quick_scan_controller = QuickScanController(self.main_window.home_tab)

        # Optional: Connect inter-tab events here if needed
        self.setup_inter_tab_communication()

        self.main_window.show()

    def setup_inter_tab_communication(self):
        """If you need tabs to talk to each other, wire their signals here."""
        pass  # Implement shared logic or event forwarding here if necessary

    def get_window(self):
        """Returns the main UI window (used by login controller if needed)."""
        return self.main_window
