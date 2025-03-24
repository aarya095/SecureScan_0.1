import json
from datetime import datetime
from Database.db_connection import DatabaseConnection

class ScanResultHandler:
    """Handles saving scan results to the database."""

    def __init__(self, json_file):
        """Initialize with the JSON file containing scan results."""
        self.json_file = json_file
        self.db = DatabaseConnection()

    def load_scan_results(self):
        """Load scan results from the JSON file and format scan_time."""
        try:
            with open(self.json_file, "r") as file:
                scan_results = json.load(file)

            # Ensure scan_time is correctly formatted
            scan_results["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return scan_results

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"❌ Error: Unable to read scan results file. {e}")
            return None

    def store_scan_results(self):
        """Save scan results to the database, including total execution time."""
        scan_results = self.load_scan_results()
        if not scan_results:
            return

        # Importing the `run_scanners` module directly inside the method to ensure it works in the context
        try:
            from scanner.run_scanners import SecurityScanner
            vulnerability_count = SecurityScanner.count_vulnerabilities(scan_results)
        except ImportError as e:
            print(f"❌ Error: Unable to import run_scanners module. {e}")
            return

        # Add the vulnerability count to the scan results
        scan_results["vulnerability_count"] = vulnerability_count

        # Extract website URL from the JSON data (default to "Unknown" if missing)
        website_url = next(iter(scan_results.get("scans", {}).keys()), "Unknown")

        # Extract total scan time from the execution_times section
        total_scan_time = scan_results.get("execution_times", {}).get("total_scan_time", None)

        # Convert the scan results dictionary into a JSON string for storage
        scan_json = json.dumps(scan_results)

        # Insert query including total execution time
        query = """
            INSERT INTO scan_results (
                website_url, scan_data, execution_time, vulnerabilities_found,
                high_risk_vulnerabilities, medium_risk_vulnerabilities, low_risk_vulnerabilities
            ) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (
            website_url,
            scan_json,
            total_scan_time,
            vulnerability_count["vulnerabilities_found"],
            vulnerability_count["high_risk_vulnerabilities"],
            vulnerability_count["medium_risk_vulnerabilities"],
            vulnerability_count["low_risk_vulnerabilities"]
        )

        # Execute the query to store the results in the database
        try:
            self.db.connect()
            self.db.execute_query(query, values)
            self.db.close()

            # Display success messages
            print(f"✅ Scan result stored successfully for {website_url}!")
            print(f"🕒 Total Scan Time Stored: {total_scan_time:.2f} seconds")
            print(f"⚠️ Total Vulnerabilities Found: {vulnerability_count['vulnerabilities_found']}")
            print(f"🔴 High Risk Vulnerabilities: {vulnerability_count['high_risk_vulnerabilities']}")
            print(f"🟠 Medium Risk Vulnerabilities: {vulnerability_count['medium_risk_vulnerabilities']}")
            print(f"🟢 Low Risk Vulnerabilities: {vulnerability_count['low_risk_vulnerabilities']}")

        except Exception as e:
            print(f"❌ Error while executing the query or saving results to the database: {e}")
            self.db.close()

if __name__ == "__main__":
    scan_handler = ScanResultHandler("security_scan_results.json")
    scan_handler.store_scan_results()
