import mysql.connector
import os
from mysql.connector import Error

class Database:
    def __init__(self):
        """Initialize database connection using environment variables."""
        self.host = os.getenv('DB_HOST')
        self.user = os.getenv('DB_USER')
        self.password = os.getenv('DB_PASSWORD')
        self.database = os.getenv('DB_NAME')
        self.connection = None

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
            self.connection.close()
            print("🔒 Connection closed.")

    def execute_query(self, query, params=None):
        """Execute an SQL query (INSERT, UPDATE, DELETE)."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        cursor = self.connection.cursor()

        try:
            cursor.execute(query, params)
            self.connection.commit()
        except Error as e:
            print(f"❌ Error executing query: {e}")
        finally:
            cursor.close()

    def fetch_all(self, query, params=None):
        """Fetch all results from a SELECT query."""
        if not self.connection:
            raise ValueError("❌ Database connection is not established.")
        try:
            cursor = self.connection.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            cursor.close()
            return result
        except Error as e:
            print(f"❌ Database error: {e}")
            return None

    def fetch_user_email(self, username):
        """Fetch user email based on username."""
        query = "SELECT email FROM login WHERE username = %s"
        result = self.fetch_all(query, (username,))
        return result[0][0] if result else None


# Example usage
if __name__ == "__main__":
    db = Database()
    db.connect()
    
    # Example: Fetch user email
    email = db.fetch_user_email("testuser")
    if email:
        print(f"📧 User email: {email}")
    else:
        print("❌ User not found.")

    db.close()
