from PyQt6.QtCore import QObject, pyqtSignal
from contextlib import redirect_stdout, redirect_stderr
import sys

class EmittingStream(QObject):
    text_written = pyqtSignal(str)

    def write(self, text):
        if text.strip():  # avoid empty lines
            self.text_written.emit(str(text))

    def flush(self):
        pass  # Needed for compatibility

class ScanWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        from scan_engine.execution.full_scan.full_scan_website import SecurityScanManager
        manager = SecurityScanManager()
        stream = EmittingStream()
        stream.text_written.connect(self.progress)

        try:
            with redirect_stdout(stream), redirect_stderr(stream):
                print("🚀 Running Crawler...\n")
                manager.run_crawler(self.url)

                print("\n🚀 Running Security Scanners...\n")
                manager.run_scanners()

                print("\n🚀 Storing Results...")
                manager.store_results()

                print("✅ All tasks completed!\n")

        except Exception as e:
            self.progress.emit(f"❌ Error during scan: {e}")

        self.finished.emit()

class GetScanCountWorker(QObject):
    finished = pyqtSignal(int)

    def run(self):
        from Database.db_connection import DatabaseConnection
        db = DatabaseConnection()
        try:
            db.connect()
            query = "SELECT COUNT(*) FROM scan_results"
            result = db.fetch_one(query)
            db.close()
            self.finished.emit(result[0] if result else 0)
        except Exception as e:
            print(f"❌ Error fetching scan count: {e}")
            self.finished.emit(0)

