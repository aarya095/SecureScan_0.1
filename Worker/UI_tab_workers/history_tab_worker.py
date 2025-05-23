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

class RetrieveFullScanResultsWorker(QObject):
    data_fetched = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, db_connection):
        super().__init__()
        self.db_connection = db_connection

    def fetch_scan_history(self):
        db = DatabaseConnection()
        db.connect()
        query = """
        SELECT scan_id, scan_timestamp, scanned_url, execution_time, vulnerabilities_found
        FROM scan_results
        """
        try:
            scan_history = db.fetch_all(query)
            db.close()
            if scan_history:
                formatted_history = [
                    {
                        'id': row[0],
                        'timestamp': row[1],
                        'url': row[2],
                        'execution_time': row[3],
                        'vulnerabilities_detected': row[4]
                    }
                    for row in scan_history
                ]
                self.data_fetched.emit(formatted_history)
            else:
                self.error_occurred.emit("No scan history found in the database.")
        except Exception as e:
            self.error_occurred.emit(f"Error fetching scan history: {e}")


class RetrieveCustomScanResultsWorker(QObject):
    # Signal to pass data to the main thread
    data_fetched = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, db_connection):
        super().__init__()
        self.db_connection = db_connection

    def fetch_scan_history(self):
        db = DatabaseConnection()
        db.connect()
        query = """
        SELECT scan_id, scan_timestamp, scanned_url, execution_time, vulnerabilities_found
        FROM custom_scans
        """
        try:
            scan_history = db.fetch_all(query)
            db.close()
            if scan_history:
                formatted_history = [
                    {
                        'id': row[0],
                        'timestamp': row[1],
                        'url': row[2],
                        'execution_time': row[3],
                        'vulnerabilities_detected': row[4]
                    }
                    for row in scan_history
                ]
                self.data_fetched.emit(formatted_history)
                
            else:
                self.error_occurred.emit("No scan history found in the database.")
        except Exception as e:
            self.error_occurred.emit(f"Error fetching scan history: {e}")

class GetTotalScanCountWorker(QObject):
    finished = pyqtSignal(int)

    def run(self):
        from Database.db_connection import DatabaseConnection
        db = DatabaseConnection()
        try:
            db.connect()
            query1 = "SELECT COUNT(*) FROM custom_scans"
            query2 = "SELECT COUNT(*) FROM scan_results"

            custom_count = db.fetch_one(query1)[0]
            full_count = db.fetch_one(query2)[0]

            total_count = custom_count + full_count

            db.close()
            self.finished.emit(total_count)
        except Exception as e:
            print(f"❌ Error fetching total scan count: {e}")
            self.finished.emit(0)

class TotalNumberOfVulnerabilityDetectedWorker(QObject):
    result_ready = pyqtSignal(tuple)
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

            self.result_ready.emit((vuln_counter, sum(vuln_counter.values())))

        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()            