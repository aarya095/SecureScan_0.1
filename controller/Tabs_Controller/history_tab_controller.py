from collections import Counter
import json
from Database.db_connection import DatabaseConnection

class HistoryTabController:


    def get_vulnerability_distribution():
        db = DatabaseConnection()
        db.connect()

        all_data = []

        # Fetch full scan data
        full_query = "SELECT scan_data FROM scan_results"
        full_results = db.fetch_all(full_query)
        all_data.extend(full_results)

        # Fetch custom scan data
        custom_query = "SELECT scan_data FROM custom_scans"
        custom_results = db.fetch_all(custom_query)
        all_data.extend(custom_results)

        db.close()

        # Count vulnerabilities
        vuln_counter = Counter()

        for (raw_data,) in all_data:
            if isinstance(raw_data, str):
                scan_data = json.loads(raw_data)
            else:
                scan_data = raw_data

            for section in scan_data.values():
                if isinstance(section, dict):
                    for key in section:
                        vuln_counter[key] += 1
                elif isinstance(section, list):
                    for item in section:
                        if isinstance(item, dict):
                            for key in item:
                                vuln_counter[key] += 1

        return vuln_counter