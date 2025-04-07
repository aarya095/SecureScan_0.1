import re
from PyQt6.QtCore import QThread, Qt
from PyQt6.QtCore import QTimer
from Worker.UI_tab_workers.home_quick_scan_worker import ScanWorker
from Worker.UI_tab_workers.home_quick_scan_worker import GetScanCountWorker
from GUI.main_window_ui.tabs.home_quick_scan import QuickScanTab
from scan_engine.execution.full_scan.full_scan_website import SecurityScanManager

class QuickScanController:
    """
    Controller class to manage interaction between QuickScanTab UI and scan logic.
    """
    def __init__(self, view: QuickScanTab):
        self.view = view
        self.thread = None         
        self.worker = None         
        self.scan_running = False  
        self.connect_signals()
        self.update_total_scan_count()

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
        self.scan_running = True  
        self.display_output("🚀 Starting full scan...\n")

    def scan_finished(self):
        self.display_output("✅ Scan process finished.\n")
        self.scan_running = False  
        self.update_total_scan_count()

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
    
    def update_total_scan_count(self):
        self.count_worker = GetScanCountWorker()
        self.count_thread = QThread()
        
        self.count_worker.moveToThread(self.count_thread)
        self.count_thread.started.connect(self.count_worker.run)
        self.count_worker.finished.connect(self.on_scan_count_ready)
        self.count_worker.finished.connect(self.count_thread.quit)
        self.count_worker.finished.connect(self.count_worker.deleteLater)
        self.count_thread.finished.connect(self.count_thread.deleteLater)

        self.count_thread.start()


    def on_scan_count_ready(self, count):
        self.view.num_of_quick_scan_label.setText(f"Total No. of Full Scans: {count}")

