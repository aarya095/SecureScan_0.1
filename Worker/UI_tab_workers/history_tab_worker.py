from PyQt6.QtCore import QObject, pyqtSignal
from collections import Counter
import json
from Database.db_connection import DatabaseConnection


class VulnerabilityDistributionWorker(QObject):
    result_ready = pyqtSignal(Counter)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, include_custom=True):
        super().__init__()
        self.include_custom = include_custom

    def run(self):
        try:
            db = DatabaseConnection()
            db.connect()

            all_data = []

            full_query = "SELECT scan_data FROM scan_results"
            full_results = db.fetch_all(full_query)
            all_data.extend(full_results)

            db.close()

            vuln_counter = Counter()

            for (raw_data,) in all_data:
                if isinstance(raw_data, str):
                    scan_data = json.loads(raw_data)
                else:
                    scan_data = raw_data

                scans = scan_data.get("scans", {})

                for scan_type, scan_info in scans.items():
                    scan_results = scan_info.get("scans", {})

                    for scanner_name, scanner_results in scan_results.items():
                        for url, data in scanner_results.items():
                            if isinstance(data, list):  # List of issues
                                for issue in data:
                                    severity = issue.get("severity")
                                    if severity:
                                        vuln_counter[scan_type] += 1
                            elif isinstance(data, dict):
                                # Check nested severities
                                for key, value in data.items():
                                    if "severity" in key.lower() and isinstance(value, str):
                                        vuln_counter[scan_type] += 1

            self.result_ready.emit(vuln_counter)

        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()

