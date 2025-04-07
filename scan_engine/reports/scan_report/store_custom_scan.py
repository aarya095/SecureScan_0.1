import json
from datetime import datetime
from Database.db_connection import DatabaseConnection

class CustomScanResultHandler:
    """Handles saving custom scan results to the database."""

    def __init__(self, json_file):
        """Initialize with the JSON file containing scan results."""
        self.json_file = json_file
        self.db = DatabaseConnection()

    def load_scan_results(self):
        """Load custom scan results from JSON."""
        try:
            with open(self.json_file, "r") as file:
                scan_results = json.load(file)

            # Ensure scan_time is correctly formatted
            scan_results["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return scan_results

        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"❌ Error: Unable to read scan results file. {e}")
            return None

    def extract_website_url(self, scan_results):
        """Extract the first website URL found in scan results."""
        for scanner_name, scan_data in scan_results.get("scans", {}).items():
            for url in scan_data.keys():
                return url  # Return the first URL found
        return "Unknown"

    def count_vulnerabilities(self, scan_results):
        """Count vulnerabilities while ensuring only valid data is processed."""
        
        count = {
            "vulnerabilities_found": 0,
            "high_risk_vulnerabilities": 0,
            "medium_risk_vulnerabilities": 0,
            "low_risk_vulnerabilities": 0
        }

        for scanner_name, scan_data in scan_results.get("scans", {}).items():
            for url, vulnerabilities in scan_data.items():
                for vuln in vulnerabilities:
                    if not isinstance(vuln, dict) or "severity" not in vuln:
                        print(f"⚠️ Warning: Skipping invalid vulnerability data: {vuln}")
                        continue  

                    count["vulnerabilities_found"] += 1
                    severity = vuln["severity"].strip().lower()

                    if severity == "high":
                        count["high_risk_vulnerabilities"] += 1
                    elif severity == "medium":
                        count["medium_risk_vulnerabilities"] += 1
                    elif severity == "low":
                        count["low_risk_vulnerabilities"] += 1

        return count


    def store_custom_scan_results(self):
        """Save custom scan results to the database."""
        scan_results = self.load_scan_results()
        if not scan_results:
            return

        # Extract data correctly
        website_url = self.extract_website_url(scan_results)
        execution_time = scan_results.get("execution_times", {}).get("total_scan_time", 0.0)
        vulnerability_count = self.count_vulnerabilities(scan_results)

        # Convert scan results into JSON string
        scan_json = json.dumps(scan_results, indent=4)

        # Insert query with proper values
        query = """
            INSERT INTO custom_scans (
                website_url, execution_time, vulnerabilities_found, 
                high_risk_vulnerabilities, medium_risk_vulnerabilities, 
                low_risk_vulnerabilities, scan_time, scan_data
            ) 
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s)
        """
        values = (
            website_url,
            execution_time,
            vulnerability_count["vulnerabilities_found"],
            vulnerability_count["high_risk_vulnerabilities"],
            vulnerability_count["medium_risk_vulnerabilities"],
            vulnerability_count["low_risk_vulnerabilities"],
            scan_json
        )

        try:
            self.db.connect()

            # ✅ Insert into `custom_scans` and retrieve the scan ID
            scan_id = self.db.execute_query(query, values, return_last_insert_id=True)

            if scan_id:
                print(f"✅ Custom Scan recorded successfully with ID {scan_id}!")
                print(f"✅ Custom scan results saved successfully for {website_url}!")
                print(f"🕒 Total Scan Time Stored: {execution_time:.2f} seconds")
                print(f"⚠️ Total Vulnerabilities Found: {vulnerability_count['vulnerabilities_found']}")
                print(f"🔴 High Risk Vulnerabilities: {vulnerability_count['high_risk_vulnerabilities']}")
                print(f"🟠 Medium Risk Vulnerabilities: {vulnerability_count['medium_risk_vulnerabilities']}")
                print(f"🟢 Low Risk Vulnerabilities: {vulnerability_count['low_risk_vulnerabilities']}")

                # ✅ Now Insert individual scan results into `custom_scan_results`
                self.store_scan_results(scan_id, scan_results)

            else:
                print("❌ Failed to store scan results.")

            self.db.close()

        except Exception as e:
            print(f"❌ Error while executing the query or saving results to the database: {e}")
            self.db.close()

    def store_scan_results(self, scan_id, scan_results):
        """Save individual scanner results to custom_scan_results table."""
        for scanner_name, scan_data in scan_results.get("scans", {}).items():
            for url, vulnerabilities in scan_data.items():  # Iterate through URLs
                for vuln in vulnerabilities:
                    if not isinstance(vuln, dict):  # Ensure valid dictionary format
                        print(f"⚠️ Warning: Skipping invalid data: {vuln}")
                        continue  

                    risk_level = vuln.get("severity", "Info").strip()  # Extract severity

                    # ✅ Convert vulnerability dictionary to JSON string
                    scanner_result_json = json.dumps(vuln, indent=4)

                    # ✅ Insert into custom_scan_results
                    try:
                        query = """
                            INSERT INTO custom_scan_results (
                                scan_id, scanner_name, scanner_result, risk_level
                            ) VALUES (%s, %s, %s, %s)
                        """
                        values = (scan_id, scanner_name, scanner_result_json, risk_level)

                        self.db.execute_query(query, values)

                        print(f"✅ Inserted result for {scanner_name} at {url}")

                    except Exception as e:
                        print(f"❌ Error inserting scan result: {e}")

    def run(self):
        """Run the complete custom scan result handling pipeline."""
        print("🚀 Running Custom Scan Result Handler...")
        self.store_custom_scan_results()
        print("✅ Custom Scan Result Handler execution complete.")


if __name__ == "__main__":
    custom_scan_handler = CustomScanResultHandler("security_scan_results.json")
    custom_scan_handler.store_custom_scan_results()
