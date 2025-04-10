from PyQt6.QtCore import QThread
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox
from Worker.UI_tab_workers.history_tab_worker import VulnerabilityDistributionWorker
from Worker.UI_tab_workers.history_tab_worker import GetTotalScanCountWorker
from Worker.UI_tab_workers.history_tab_worker import TotalNumberOfVulnerabilityDetectedWorker
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

        self.get_total_num_scans()
        self.get_total_num_vulnerabilities_detected()
        
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

    def get_total_num_scans(self):
        self.scan_count_thread = QThread()
        self.scan_count_worker = GetTotalScanCountWorker()
        self.scan_count_worker.moveToThread(self.scan_count_thread)

        self.scan_count_thread.started.connect(self.scan_count_worker.run)
        self.scan_count_worker.finished.connect(self.update_total_scan_count_label)
        self.scan_count_worker.finished.connect(self.scan_count_thread.quit)
        self.scan_count_worker.finished.connect(self.scan_count_worker.deleteLater)
        self.scan_count_thread.finished.connect(self.scan_count_thread.deleteLater)

        self.scan_count_thread.start()

    def update_total_scan_count_label(self, count):
        self.view.total_num_scans_label.setText(f"Total No. of Scans Performed: {count}")

    def get_total_num_vulnerabilities_detected(self):
        self.vuln_worker = TotalNumberOfVulnerabilityDetectedWorker()
        self.vuln_thread = QThread()
        self.vuln_worker.moveToThread(self.vuln_thread)

        self.vuln_worker.result_ready.connect(self.update_total_vulnerabilities)
        self.vuln_worker.error.connect(self.handle_vuln_error)
        self.vuln_worker.finished.connect(self.vuln_thread.quit)
        self.vuln_thread.started.connect(self.vuln_worker.run)

        self.vuln_thread.start()

    def update_total_vulnerabilities(self, data):
        _, total = data
        self.view.total_num_vulnerabilities_label.setText(f"Total Vulnerabilities Detected: {total}")

    def handle_vuln_error(self, message):
        self.view.total_num_vulnerabilities_label.setText("Error loading vulnerabilities")
        print("Error:", message)

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
        
