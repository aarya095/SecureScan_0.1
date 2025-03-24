import json
from datetime import datetime
from Database.db_connection import connect_to_database, close_connection, execute_query

# Connect to the database
connect_to_database()

# Load scan results from JSON file
with open("security_scan_results.json", "r") as file:
    scan_results = json.load(file)

# Ensure scan_time is correctly formatted
scan_results["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Convert scan result to JSON string for storage
scan_json = json.dumps(scan_results)

# Insert query
query = "INSERT INTO scan_results (website_url, scan_data) VALUES (%s, %s)"
values = (scan_results["website"], scan_json)

# Execute the query
execute_query(query, values)

print("Scan result stored successfully!")

# Close the database connection
close_connection()
