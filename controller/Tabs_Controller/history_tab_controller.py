from PyQt6.QtCore import QThread
from PyQt6.QtWidgets import QMessageBox
from Worker.UI_tab_workers.history_tab_worker import VulnerabilityDistributionWorker
from GUI.main_window_ui.tabs.history_tab import HistoryTab

class HistoryTabController:

    """
    Controller class to manage interaction between QuickScanTab UI and scan logic.
    """
    def __init__(self, view: HistoryTab):
        self.view = view

    def load_pie_chart_async(self):
        self.worker_thread = QThread()
        self.worker = VulnerabilityDistributionWorker(include_custom=True)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.result_ready.connect(self.view.display_pie_chart)
        self.worker.error.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker_thread.finished.connect(self.worker_thread.deleteLater)

        self.worker_thread.start()

    