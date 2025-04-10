from PyQt6.QtCore import QThread
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox
from Worker.UI_tab_workers.history_tab_worker import VulnerabilityDistributionWorker

from GUI.main_window_ui.tabs.history_tab import HistoryTab
import traceback

from Database.db_connection import DatabaseConnection

class HistoryTabController:

    """
    Controller class to manage interaction between QuickScanTab UI and scan logic.
    """
    def __init__(self, view: HistoryTab):
        self.view = view
        self.db_connection = DatabaseConnection()
        self.connect_signals()
        
    def connect_signals(self):
        try:
            self.view.view_full_scan_history_pushButton.clicked.disconnect()
        except TypeError:
            pass
        self.view.view_full_scan_history_pushButton.clicked.connect(self.open_full_scan_history_window)

        try:
            self.view.view_custom_scan_history_pushButton.clicked.disconnect()
        except TypeError:
            pass
        self.view.view_custom_scan_history_pushButton.clicked.connect(self.open_custom_scan_history_window)
            
    def load_pie_chart_async(self):
        self.worker_thread = QThread()
        self.worker = VulnerabilityDistributionWorker(include_custom=True)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.result_ready.connect(self.view.display_pie_chart)
        self.worker.error.connect(lambda msg: QMessageBox.critical(self.view, "Error", msg))
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)

        self.worker_thread.start()

    def open_full_scan_history_window(self):
        from GUI.main_window_ui.full_scan_history import FullScanHistoryWindow
        from controller.Tabs_Controller.history_windows_controller import FullScanHistoryWindowController
        
        self.full_scan_history_view = FullScanHistoryWindow()
        self.full_scan_history_controller = FullScanHistoryWindowController(self.full_scan_history_view, self.db_connection)
        traceback.print_stack()
        self.full_scan_history_view.show()

    def open_custom_scan_history_window(self):
        from GUI.main_window_ui.custom_scan_history import CustomScanHistoryWindow
        from controller.Tabs_Controller.history_windows_controller import CustomScanHistoryWindowController
        
        self.custom_scan_history_view = CustomScanHistoryWindow()
        self.custom_scan_history_controller = CustomScanHistoryWindowController(self.custom_scan_history_view, self.db_connection)
        traceback.print_stack()
        self.custom_scan_history_view.show()
        