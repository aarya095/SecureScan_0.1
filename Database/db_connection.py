import mysql.connector
import os
from mysql.connector import Error

host = os.getenv('DB_HOST')
user = os.getenv('DB_USER')
password = os.getenv('DB_PASSWORD')
database = os.getenv('DB_NAME')

connection = None

def connect_to_database():
    global connection
    try:
        print("Connecting to the database...")
        connection = mysql.connector.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        if connection.is_connected():
            print("Successfully connected to the database.")
        else:
            print("Failed to connect to the database.")
            connection = None
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        connection = None

def close_connection():
    global connection
    if connection and connection.is_connected():
        connection.close()
        print("Connection closed.")

def get_connection():
    return connection

def execute_query(query, params=None):
    global connection
    if not connection:
        raise ValueError("Database connection is not established.")
    cursor = connection.cursor()

    try:
        cursor.execute(query, params)
        connection.commit()
    except Error as e:
        print(f"Error executing query: {e}")
    finally:
        cursor.close()

def fetch_all(query, params=None):
    global connection
    if not connection:
        raise ValueError("Database connection is not established.")

    try:
        cursor = connection.cursor()
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return result
    except Error as e:
        print(f"Database error: {e}")
        return None

def fetch_user_email(username):
    query = "SELECT email FROM login WHERE username = %s"
    result = fetch_all(query, (username,))
    if result:
        return result[0][0] 
    return None
