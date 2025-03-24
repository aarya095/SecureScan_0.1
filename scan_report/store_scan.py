import json
from datetime import datetime
import os
import sys
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
import Database.db_connection as db

# Connect to the database
db.connect_to_database()

# Load scan results from JSON file
with open("security_scan_results.json", "r") as file:
    scan_results = json.load(file)

# Ensure scan_time is correctly formatted
scan_results["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Convert scan result to JSON string for storage
scan_json = json.dumps(scan_results)

# Insert query
query = "INSERT INTO scan_results (website_url, scan_data) VALUES (%s, %s)"
values = (scan_results.get("target_url", "Unknown"), scan_json)

# Execute the query
db.execute_query(query, values)

print("Scan result stored successfully!")

# Close the database connection
db.close_connection()
