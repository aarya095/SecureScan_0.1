import json
from datetime import datetime
from Database.db_connection import DatabaseConnection

class CustomScanResultHandler:
    """Handles saving custom scan results to the database."""

    def __init__(self, json_file):
        self.json_file = json_file
        self.db = DatabaseConnection()

    def load_scan_results(self):
        """Load custom scan results from JSON."""
        try:
            with open(self.json_file, "r") as file:
                scan_results = json.load(file)
            return scan_results
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"❌ Error: Unable to read scan results file. {e}")
            return None

    def store_custom_scan_results(self):
        """Save custom scan results into the database."""
        scan_results = self.load_scan_results()
        if not scan_results:
            return

        # Extract website URL and total vulnerabilities
        website_url = scan_results.get("website_url", "Unknown")
        total_vulnerabilities = scan_results.get("total_vulnerabilities", 0)
        execution_time = scan_results.get("execution_time", None)
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Insert into `custom_scans` table
        scan_query = """
            INSERT INTO custom_scans (website_url, execution_time, vulnerabilities_found, scan_time)
            VALUES (%s, %s, %s, %s)
        """
        scan_values = (website_url, execution_time, total_vulnerabilities, scan_time)

        try:
            self.db.connect()
            scan_id = self.db.insert_scan(website_url, execution_time, total_vulnerabilities) 

            # Insert each scanner's result into `custom_scan_results`
            for scanner_name, scanner_result in scan_results.get("scans", {}).items():
                risk_level = scanner_result.get("risk_level", "Info")  # Default to 'Info'

                self.db.insert_scan_result(scan_id, scanner_name, scanner_result, risk_level)

            self.db.close()
            print(f"✅ Custom scan results saved successfully for {website_url}!")

        except Exception as e:
            print(f"❌ Error storing custom scan results: {e}")
            self.db.close()


if __name__ == "__main__":
    custom_scan_handler = CustomScanResultHandler("security_scan_results.json")
    custom_scan_handler.store_custom_scan_results()
