import sys
from PyQt6.QtWidgets import QApplication, QMainWindow
from GUI.main_window_ui.tabs.home_quick_scan import QuickScanTab
from controller.Tabs_Controller.home_tab_controller import QuickScanController

app = QApplication(sys.argv)

# Initialize main window
main_window = QMainWindow()
main_window.setWindowTitle("Quick Scan Test")
main_window.resize(800, 600)

# Initialize tab
quick_scan_tab = QuickScanTab()
QuickScanController(quick_scan_tab)

main_window.setCentralWidget(quick_scan_tab)
main_window.show()

sys.exit(app.exec())
