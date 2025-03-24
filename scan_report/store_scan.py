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
        
        except FileNotFoundError:
            print("❌ Error: Scan results file not found.")
            return None
        except json.JSONDecodeError:
            print("❌ Error: Invalid JSON format in scan results file.")
            return None

    def store_scan_results(self):
        """Save scan results to the database."""
        scan_results = self.load_scan_results()
        if not scan_results:
            return

        # Extract the first URL key instead of looking for 'target_url'
        website_url = next(iter(scan_results.keys()), "Unknown")

        # Convert scan results to JSON string for storage
        scan_json = json.dumps(scan_results)

        # Insert query
        query = "INSERT INTO scan_results (website_url, scan_data) VALUES (%s, %s)"
        values = (website_url, scan_json)

        # Connect, execute, and close
        self.db.connect()
        self.db.execute_query(query, values)
        self.db.close()

        print(f"✅ Scan result stored successfully for {website_url}!")


# Example usage
if __name__ == "__main__":
    scan_handler = ScanResultHandler("security_scan_results.json")
    scan_handler.store_scan_results()
