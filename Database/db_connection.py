import mysql.connector
import os
from mysql.connector import Error

class DatabaseConnection:
    def __init__(self):
        """Initialize database connection using environment variables."""
        self.host = os.getenv('DB_HOST', 'localhost')
        self.user = os.getenv('DB_USER')
        self.password = os.getenv('DB_PASSWORD')
        self.database = os.getenv('DB_NAME')

        if not all([self.host, self.user, self.password, self.database]):
            raise ValueError("❌ Missing database environment variables!")

        self.connection = None
        self.cursor = None  # ✅ Prevent AttributeError

    def connect(self):
        """Establish a connection to the database."""
        try:
            print("🔌 Connecting to the database...")
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            if self.connection.is_connected():
                self.cursor = self.connection.cursor()
                print("✅ Successfully connected to the database.")
            else:
                print("❌ Failed to connect to the database.")
                self.connection = None
        except Error as e:
            print(f"❌ Error connecting to MySQL: {e}")
            self.connection = None

    def close(self):
        """Close the database connection."""
        if self.connection and self.connection.is_connected():
            if self.cursor:
                self.cursor.close()
            self.connection.close()
            print("🔒 Connection closed.")

    def execute_query(self, query, params=None, return_last_insert_id=False):
        """Execute an SQL query (INSERT, UPDATE, DELETE)."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            self.connection.commit()
            if return_last_insert_id:
                return cursor.lastrowid
        except Error as e:
            print(f"❌ Error executing query: {e}")
        finally:
            cursor.close()  # ✅ Close cursor manually

    def fetch_all(self, query, params=None):
        """Fetch all results from a SELECT query."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            return result
        except Error as e:
            print(f"❌ Database error: {e}")
            return None
        finally:
            cursor.close()

    def fetch_one(self, query, params=None):
        """Fetch a single row from a SELECT query."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()
        except Error as e:
            print(f"❌ Database error: {e}")
            return None
        finally:
            cursor.close()

    def fetch_user_email(self, username):
        """Fetch user email based on username."""
        query = "SELECT email FROM login WHERE username = %s"
        result = self.fetch_all(query, (username,))
        return result[0][0] if result else None

    def insert_scan(self, website_url, execution_time, vulnerabilities_found):
        """Insert a new custom scan and return its ID."""
        query = """
        INSERT INTO custom_scans (website_url, execution_time, vulnerabilities_found) 
        VALUES (%s, %s, %s)
        """
        return self.execute_query(query, (website_url, execution_time, vulnerabilities_found), return_last_insert_id=True)

    def insert_scan_result(self, scan_id, scanner_name, scanner_result, risk_level):
        """Insert a scan result linked to a scan ID."""
        query = """
        INSERT INTO custom_scan_results (scan_id, scanner_name, scanner_result, risk_level) 
        VALUES (%s, %s, %s, %s)
        """
        self.execute_query(query, (scan_id, scanner_name, scanner_result, risk_level))