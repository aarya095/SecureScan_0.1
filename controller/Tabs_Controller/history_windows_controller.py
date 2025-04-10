from PyQt6.QtCore import QThread, QUrl
from PyQt6.QtCore import pyqtSlot
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox
from GUI.main_window_ui.full_scan_history import FullScanHistoryWindow
from GUI.main_window_ui.custom_scan_history import CustomScanHistoryWindow
from Worker.UI_tab_workers.home_quick_scan_worker import GeneratePDFWorker
from Worker.UI_tab_workers.history_tab_worker import RetrieveFullScanResultsWorker
from Worker.UI_tab_workers.history_tab_worker import RetrieveCustomScanResultsWorker
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtCore import Qt, QMetaObject

from Database.db_connection import DatabaseConnection

class FullScanHistoryWindowController:

    def __init__(self, view: FullScanHistoryWindow, db_connection):
        self.view = view
        self.db_connection = db_connection

        self.view.view_pdf_callback.connect(self.generate_pdf_report)
        
        # Create a thread and worker
        self.thread = QThread()
        self.worker = RetrieveFullScanResultsWorker(self.db_connection)
        self.worker.moveToThread(self.thread)

        # Connect signals
        self.worker.data_fetched.connect(self.update_scan_history_table)
        self.worker.error_occurred.connect(self.handle_error)

        # Connect thread start to the worker's fetch method
        self.thread.started.connect(self.worker.fetch_scan_history)

        # Optional: Clean up thread when done
        self.worker.data_fetched.connect(self.thread.quit)
        self.worker.error_occurred.connect(self.thread.quit)

        self.fetch_scan_history()
        

    def fetch_scan_history(self):
        """Trigger the worker to fetch the scan history in a new thread."""
        self.thread.start()

    def update_scan_history_table(self, scan_history):
        print("Loading scan history into view")
        self.view.load_scan_history(scan_history)

    def handle_error(self, error_message):
        QMetaObject.invokeMethod(
            self.view,
            "show_error_message",
            Qt.ConnectionType.QueuedConnection,
            QtCore.Q_ARG(str, error_message)
        )


    def generate_pdf_report(self, scan_id):
        print(f"📝 Generating PDF for scan_id: {scan_id}")
        self.pdf_thread = QThread()
        self.pdf_worker = GeneratePDFWorker(scan_id)
        self.pdf_worker.moveToThread(self.pdf_thread)

        self.pdf_thread.started.connect(self.pdf_worker.run)
        self.pdf_worker.finished.connect(self.open_pdf)
        self.pdf_worker.error.connect(lambda msg: QMessageBox.critical(self.view, "PDF Error", msg))
        self.pdf_worker.finished.connect(self.pdf_thread.quit)
        self.pdf_worker.finished.connect(self.pdf_worker.deleteLater)
        self.pdf_thread.finished.connect(self.pdf_thread.deleteLater)

        self.pdf_thread.start()

    def open_pdf(self, path):
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

class CustomScanHistoryWindowController:

    def __init__(self, view: CustomScanHistoryWindow, db_connection):
        self.view = view
        self.db_connection = db_connection

        self.view.view_pdf_callback.connect(self.generate_pdf_report)

        # Create thread and worker ONCE
        self.results_table_thread = QThread()
        self.results_table_worker = RetrieveCustomScanResultsWorker(self.db_connection)
        self.results_table_worker.moveToThread(self.results_table_thread)

        # Connect signals
        self.results_table_thread.started.connect(self.results_table_worker.fetch_scan_history)
        self.results_table_worker.data_fetched.connect(self.update_scan_history_table)
        self.results_table_worker.error_occurred.connect(self.handle_error)

        # Clean up thread after it's done
        self.results_table_worker.data_fetched.connect(self.results_table_thread.quit)
        self.results_table_worker.data_fetched.connect(self.results_table_worker.deleteLater)
        self.results_table_thread.finished.connect(self.results_table_thread.deleteLater)

        self.fetch_scan_history()

    def fetch_scan_history(self):
        print("[Controller] Starting scan history thread...")
        self.results_table_thread.start()

    def update_scan_history_table(self, scan_history):
        print("[Controller] update_scan_history_table() received:", scan_history)
        self.view.load_scan_history(scan_history)

    def handle_error(self, error_message):
        print("[Controller] handle_error() received:", error_message)
        QMetaObject.invokeMethod(
            self.view,
            "show_error_message",
            Qt.ConnectionType.QueuedConnection,
            QtCore.Q_ARG(str, error_message)
        )

    def view_pdf(self, scan):
        print(f"Opening PDF for scan at {scan['timestamp']}...")

    def generate_pdf_report(self, scan_id):
        print(f"📝 Generating PDF for scan_id: {scan_id}")
        self.pdf_thread = QThread()
        self.pdf_worker = GeneratePDFWorker(scan_id)
        self.pdf_worker.moveToThread(self.pdf_thread)

        self.pdf_thread.started.connect(self.pdf_worker.run)
        self.pdf_worker.finished.connect(self.open_pdf)
        self.pdf_worker.error.connect(lambda msg: QMessageBox.critical(self.view, "PDF Error", msg))
        self.pdf_worker.finished.connect(self.pdf_thread.quit)
        self.pdf_worker.finished.connect(self.pdf_worker.deleteLater)
        self.pdf_thread.finished.connect(self.pdf_thread.deleteLater)

        self.pdf_thread.start()

    def open_pdf(self, path):
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))