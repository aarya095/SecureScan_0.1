from user_authentication.login.login_logic import LoginLogic

class LoginViewModel:
    """Handles data processing and communication between UI and Logic."""

    def __init__(self):
        self.logic = LoginLogic()

    def authenticate_user(self, username: str, password: str) -> bool:
        """Calls logic to verify user credentials."""
        return self.logic.verify_user_credentials(username, password)
