import re
from PyQt6.QtCore import QThread, Qt
from PyQt6.QtWidgets import QMessageBox
from GUI.main_window_ui.tabs.custom_scan_tab import CustomScanTab
from Worker.UI_tab_workers.custom_scan_worker import CustomScanWorker

class CustomScanController:
    """
    Controller class to manage interaction between CustomScanTab UI and scan logic.
    """
    def __init__(self, view: CustomScanTab):
        self.view = view
        self.thread = None
        self.worker = None
        self.scan_running = False

        self.connect_signals()

    def connect_signals(self):
        self.view.custom_scan_pushButton.clicked.connect(self.run_custom_scan)

    def run_custom_scan(self):
        if self.scan_running:
            self.display_output("⚠️ A scan is already in progress. Please wait...\n")
            return

        url = self.view.custom_scan_lineEdit.text().strip()
        if not self.validate_url(url):
            return

        if not self.view.selected_scanners:
            self.display_output("❌ Please select at least one scanner before starting.\n")
            return

        self.start_scan(url, self.view.selected_scanners)

    def start_scan(self, url, scanners):
        self.thread = QThread()
        self.worker = CustomScanWorker(url, scanners)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.display_output, type=Qt.ConnectionType.QueuedConnection)
        self.worker.finished.connect(self.scan_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()
        self.scan_running = True
        self.display_output(f"🚀 Starting scan on {url} with: {', '.join(scanners)}...\n")

    def scan_finished(self, results):
        self.display_output("✅ Custom scan completed.\n")
        self.scan_running = False
        # Future: Update history panel here if needed

    def display_output(self, message):
        self.view.custom_scan_output_textBrowser.append(message)

    def validate_url(self, url):
        if not url:
            self.display_output("❌ Please enter a URL before starting the scan.\n")
            return False

        if not (url.startswith("http://") or url.startswith("https://")):
            self.display_output("❌ URL must start with 'http://' or 'https://'.\n")
            return False

        url_pattern = re.compile(
            r'^(https?://)'                   
            r'((localhost)|'                 
            r'(\d{1,3}(\.\d{1,3}){3})|'      
            r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'  
            r'(:\d+)?'                       
            r'(\/[^\s]*)?$'                 
        )

        if not url_pattern.match(url):
            self.display_output("❌ Please enter a valid URL format.\n")
            return False

        return True
