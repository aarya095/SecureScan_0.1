import json
import os
from datetime import datetime
from Database.db_connection import DatabaseConnection

class FullScanResultHandler:
    """Handles combining scan results from multiple JSON files and saving to the database."""

    def __init__(self, json_files):
        """Initialize with the list of JSON files containing scan results."""
        self.json_files = json_files  # List of JSON files
        self.db = DatabaseConnection()

    def load_scan_results(self):
        """Load and combine scan results from multiple JSON files."""
        combined_results = {"scans": {}, "execution_times": {}, "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        
        for file in self.json_files:
            if not os.path.exists(file):
                print(f"⚠️ Warning: {file} not found. Skipping...")
                continue
            
            try:
                with open(file, "r") as f:
                    scan_data = json.load(f)

                # Merge scan data into combined_results
                combined_results["scans"][file.replace(".json", "")] = scan_data.get("scans", {})

                # Merge execution times if available
                if "execution_times" in scan_data:
                    combined_results["execution_times"].update(scan_data["execution_times"])

            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"❌ Error: Unable to read {file}. {e}")
        
        return combined_results

    def store_scan_results(self):
        """Save the combined scan results to the database."""
        scan_results = self.load_scan_results()
        if not scan_results or not scan_results["scans"]:
            print("❌ Error: No valid scan data found.")
            return

        # Count vulnerabilities using SecurityScanner
        try:
            from scan_engine.execution.full_scan.run_all_scanners import SecurityScanner
            vulnerability_count = SecurityScanner.count_vulnerabilities(scan_results)
        except ImportError as e:
            print(f"❌ Error: Unable to import run_all_scanners module. {e}")
            return

        # Extract website URL (default to "Unknown" if missing)
        website_url = next(iter(scan_results["scans"].keys()), "Unknown")

        # Extract total scan time if available
        total_scan_time = scan_results.get("execution_times", {}).get("total_scan_time", None)

        # Convert scan results dictionary into a JSON string
        scan_json = json.dumps(scan_results, indent=4)

        # Insert query
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

        # Execute query
        try:
            self.db.connect()
            self.db.execute_query(query, values)
            self.db.close()

            # Success messages
            print(f"✅ Scan result stored successfully for {website_url}!")
            print(f"🕒 Total Scan Time Stored: {total_scan_time:.2f} seconds" if total_scan_time else "🕒 Total Scan Time: Not Available")
            print(f"⚠️ Total Vulnerabilities Found: {vulnerability_count['vulnerabilities_found']}")
            print(f"🔴 High Risk Vulnerabilities: {vulnerability_count['high_risk_vulnerabilities']}")
            print(f"🟠 Medium Risk Vulnerabilities: {vulnerability_count['medium_risk_vulnerabilities']}")
            print(f"🟢 Low Risk Vulnerabilities: {vulnerability_count['low_risk_vulnerabilities']}")

        except Exception as e:
            print(f"❌ Error while executing the query or saving results to the database: {e}")
            self.db.close()

if __name__ == "__main__":
    json_files = ["scan_results_json/http.json", "scan_results_json/sql_injection.json", "scan_results_json/xss_injection.json", "scan_results_json/broken_authentication.json", "scan_results_json/csrf.json"]
    scan_handler = FullScanResultHandler(json_files)
    scan_handler.store_scan_results()
