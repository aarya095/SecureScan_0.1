from PyQt6.QtCore import QObject, QThread, pyqtSignal
import time

class ScanWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        from scan_engine.execution.full_scan.full_scan_website import SecurityScanManager
        manager = SecurityScanManager()

        # Step 1: Crawl
        self.progress.emit("🕷️ Crawling website...")
        time.sleep(0.05)
        manager.run_crawler(self.url)

        # Step 2: Run scanners
        self.progress.emit("🛡️ Running security scanners...")
        time.sleep(0.05)
        manager.run_scanners()

        # Step 3: Combine results and store in DB
        self.progress.emit("🗃️ Storing results in database...")
        time.sleep(0.05)
        manager.store_results()

        # All done
        self.progress.emit("✅ All tasks completed!")
        self.finished.emit()
