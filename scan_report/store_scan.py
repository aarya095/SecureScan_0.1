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
        
        except (FileNotFoundError, json.JSONDecodeError):
            print("❌ Error: Unable to read scan results file.")
            return None

    def store_scan_results(self):
        """Save scan results to the database, including total execution time."""
        scan_results = self.load_scan_results()
        if not scan_results:
            return

        # Extract website URL from the JSON data (default to "Unknown" if missing)
        website_url = next(iter(scan_results.get("scans", {}).keys()), "Unknown")

        # Extract total execution time from "execution_times"
        total_execution_time = scan_results.get("execution_times", {}).get("total_scan_time", None)

        # Convert scan results to JSON string for storage
        scan_json = json.dumps(scan_results)

        # Insert query including total execution time
        query = "INSERT INTO scan_results (website_url, scan_data, execution_time) VALUES (%s, %s, %s)"
        values = (website_url, scan_json, total_execution_time)

        # Connect, execute, and close
        self.db.connect()
        self.db.execute_query(query, values)
        self.db.close()

        print(f"✅ Scan result stored successfully for {website_url}!")
        if total_execution_time is not None:
            print(f"🕒 Total Execution Time Stored: {total_execution_time} seconds")


# Example usage
if __name__ == "__main__":
    scan_handler = ScanResultHandler("security_scan_results.json")
    scan_handler.store_scan_results()
