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
