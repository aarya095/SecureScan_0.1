import bcrypt
from Database.db_connection import DatabaseConnection

class LoginLogic:
    """Handles login authentication logic."""

    def __init__(self):
        self.db = DatabaseConnection()

    def verify_user_credentials(self, username: str, password: str) -> bool:
        """
        Verifies user credentials against the database.

        :param username: The entered username.
        :param password: The entered password.
        :return: True if credentials are correct, False otherwise.
        """
        if not username or not password:
            return False  # Empty fields

        self.db.connect()
        if not self.db.connection:
            return False  # Database connection failure

        query = "SELECT password FROM login WHERE username=%s"
        result = self.db.fetch_all(query, (username,))
        self.db.close()

        if result:
            stored_hashed_password = result[0][0]
            return bcrypt.checkpw(password.encode(), stored_hashed_password.encode())

        return False  # No matching username

