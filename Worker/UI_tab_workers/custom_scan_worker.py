from PyQt6.QtCore import QObject, pyqtSignal
from scan_engine.execution.custom_scan.custom_scan_website import CustomSecurityScanner


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
        try:
            self.progress.emit("🔍 Initializing custom scan...\n")
            scanner = CustomSecurityScanner(self.url, self.scanners)

            for update in scanner.run():  
                self.progress.emit(update)

            self.progress.emit("🎉 Scan completed successfully!\n")
            results = scanner.get_results()  
            self.finished.emit(results)

        except Exception as e:
            self.progress.emit(f"❌ Scan failed: {str(e)}\n")
            self.error.emit(str(e))
            self.finished.emit({})  
