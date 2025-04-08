from PyQt6.QtCore import QObject, pyqtSignal
from contextlib import redirect_stdout, redirect_stderr
import sys
import time

class EmittingStream(QObject):
    text_written = pyqtSignal(str)

    def write(self, text):
        if text.strip():
            self.text_written.emit(str(text))

    def flush(self):
        pass

class ScanWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, target_url):
        super().__init__()
        self.target_url = target_url 

    def run(self):
        from scan_engine.execution.full_scan.full_scan_website import SecurityScanManager
        manager = SecurityScanManager()
        stream = EmittingStream()
        stream.text_written.connect(self.progress)

        try:
            with redirect_stdout(stream), redirect_stderr(stream):
                print("🚀 Running Crawler...\n")
                manager.run_crawler(self.target_url)

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

class FetchRecentScansWorker(QObject):
    finished = pyqtSignal(list)

    def run(self):
        from Database.db_connection import DatabaseConnection
        db = DatabaseConnection()
        try:
            db.connect()
            query = """
                SELECT scan_id, scanned_url, scan_timestamp 
                FROM scan_results 
                ORDER BY scan_timestamp DESC 
                LIMIT 5
            """
            result = db.fetch_all(query)
            db.close()

            scans = [
                {
                    "scan_id": row[0],
                    "scanned_url": row[1],
                    "scan_timestamp": row[2].strftime("%Y-%m-%d %H:%M:%S")
                }
                for row in result
            ]

            self.finished.emit(scans)

        except Exception as e:
            print(f"❌ Error fetching recent scans: {e}")
            self.finished.emit([])

class GeneratePDFWorker(QObject):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, scan_id):
        super().__init__()
        self.scan_id = scan_id

    def run(self):
        from scan_engine.reports.scan_report.report_generator import generate_report
        try:
            path = generate_report(self.scan_id)
            self.finished.emit(path)
        except Exception as e:
            self.error.emit(str(e))

