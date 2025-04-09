from PyQt6.QtCore import QObject, pyqtSignal
from scan_engine.execution.custom_scan.custom_scan_website import CustomSecurityScanner
from contextlib import redirect_stdout, redirect_stderr

class EmittingStream(QObject):
    text_written = pyqtSignal(str)

    def write(self, text):
        if text.strip():
            self.text_written.emit(str(text))

    def flush(self):
        pass

class CustomScanWorker(QObject):
    """
    Worker that runs custom scans in a separate thread.
    """
    progress = pyqtSignal(str)             
    finished = pyqtSignal(dict)            
    error = pyqtSignal(str)                 

    def __init__(self, url: str, scanners: list[str]):
        super().__init__()
        self.url = url
        self.scanners = scanners

    def run(self):
        stream = EmittingStream()
        stream.text_written.connect(self.progress)

        try:
            with redirect_stdout(stream), redirect_stderr(stream):
                print("🔍 Initializing custom scan...\n")

                scanner = CustomSecurityScanner(self.url, self.scanners)

                for update in scanner.run_custom_scan():  
                    self.progress.emit(update)

                self.progress.emit("🎉 Scan completed successfully!\n")
                results = scanner.get_results()  
                self.finished.emit(results)

        except Exception as e:
            self.progress.emit(f"❌ Scan failed: {str(e)}\n")
            self.error.emit(str(e))
            self.finished.emit({})  

class GetScanCountWorker(QObject):
    finished = pyqtSignal(int)

    def run(self):
        from Database.db_connection import DatabaseConnection
        db = DatabaseConnection()
        try:
            db.connect()
            query = "SELECT COUNT(*) FROM custom_scans"
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
                FROM custom_scans 
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

    def __init__(self, scan_id, is_custom=True):
        super().__init__()
        self.scan_id = scan_id
        self.is_custom = is_custom

    def run(self):
        from scan_engine.reports.scan_report.report_generator import generate_report
        try:
            path = generate_report(self.scan_id, is_custom=self.is_custom)
            self.finished.emit(path)
        except Exception as e:
            self.error.emit(str(e))
