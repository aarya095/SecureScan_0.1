import re
from PyQt6.QtCore import QThread, Qt
from Worker.UI_tab_workers.home_quick_scan_worker import ScanWorker
from GUI.main_window_ui.tabs.home_quick_scan import QuickScanTab

class QuickScanController:
    """
    Controller class to manage interaction between QuickScanTab UI and scan logic.
    """
    def __init__(self, view: QuickScanTab):
        self.view = view
        self.thread = None          # 🧠 Track background thread
        self.worker = None          # Worker object
        self.scan_running = False   # 🟢 Flag to prevent re-trigger
        self.connect_signals()

    def connect_signals(self):
        self.view.quick_scan_pushButton.clicked.connect(self.run_full_scan)

    def run_full_scan(self):
        if self.scan_running:
            self.display_output("⚠️ Scan already in progress. Please wait...\n")
            return

        url = self.view.url_lineEdit.text().strip()
        if not self.validate_url(url):
            return

        self.start_full_scan(url)

    def start_full_scan(self, url):
        self.thread = QThread()
        self.worker = ScanWorker(url)
        self.worker.moveToThread(self.thread)

        # 🔁 Signal-slot connections
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.display_output, type=Qt.ConnectionType.QueuedConnection)
        self.worker.finished.connect(self.scan_finished)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()
        self.scan_running = True  # 🔒 Lock scanning
        self.display_output("🚀 Starting full scan...\n")

    def scan_finished(self):
        self.display_output("✅ Scan process finished.\n")
        self.scan_running = False  # 🔓 Unlock

    def display_output(self, text):
        self.view.quick_scan_output_textBrowser.append(text)

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
