import re
from PyQt6.QtCore import QThread, Qt, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QMessageBox
from GUI.main_window_ui.tabs.custom_scan_tab import CustomScanTab
from Worker.UI_tab_workers.custom_scan_worker import CustomScanWorker
from Worker.UI_tab_workers.custom_scan_worker import GetScanCountWorker
from Worker.UI_tab_workers.custom_scan_worker import FetchRecentScansWorker
from Worker.UI_tab_workers.custom_scan_worker import GeneratePDFWorker

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
        self.update_total_scan_count()
        self.fetch_recent_scans()

    def connect_signals(self):
        self.view.custom_scan_pushButton.clicked.connect(self.run_custom_scan)
        self.view.pdf_requested.connect(self.generate_pdf_report)
        self.view.refresh_requested.connect(self.fetch_recent_scans)

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
        #self.view.custom_scan_output_textBrowser.clear() wondering if should clear before each scan or not!
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
        self.update_total_scan_count()
        self.fetch_recent_scans()

    def display_output(self, message):
        self.view.custom_scan_output_textBrowser.append(message)
        self.view.custom_scan_output_textBrowser.verticalScrollBar().setValue(
        self.view.custom_scan_output_textBrowser.verticalScrollBar().maximum()
    )

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
        self.view.num_of_custom_scan_label.setText(f"Total No. of Full Scans: {count}")

    def fetch_recent_scans(self):
        print("🛠️ Fetching recent scans...")
        self.view.refresh_button.setEnabled(False)
        self.scan_list_worker = FetchRecentScansWorker()
        self.scan_list_thread = QThread()

        self.scan_list_worker.moveToThread(self.scan_list_thread)
        self.scan_list_thread.started.connect(self.scan_list_worker.run)
        self.scan_list_worker.finished.connect(self.on_recent_scans_fetched)
        self.scan_list_worker.finished.connect(self.scan_list_thread.quit)
        self.scan_list_worker.finished.connect(self.scan_list_worker.deleteLater)
        self.scan_list_thread.finished.connect(self.scan_list_thread.deleteLater)

        self.scan_list_thread.start()

    def on_recent_scans_fetched(self, scans):
        self.view.load_recent_scans(scans)
        self.view.refresh_button.setEnabled(True)

    def generate_pdf_report(self, scan_id, is_custom=True):
        print(f"📝 Generating PDF for scan_id: {scan_id} (Custom: {is_custom})")
        self.pdf_thread = QThread()
        self.pdf_worker = GeneratePDFWorker(scan_id, is_custom=is_custom)  # 👈 pass it here
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
