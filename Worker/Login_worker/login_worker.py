from PyQt6.QtCore import QObject, pyqtSignal
from user_authentication.login.login_logic import LoginLogic

class LoginWorker(QObject):
    finished = pyqtSignal(bool, str)  

    def __init__(self, username, password):
        super().__init__()
        self.username = username
        self.password = password

    def run(self):
        print("👷 Worker thread started")
        try:
            model = LoginLogic()
            success = model.verify_user_credentials(self.username, self.password)
            if success:
                self.finished.emit(True, "Login successful!")
            else:
                self.finished.emit(False, "Invalid username or password.")
        except Exception as e:
            self.finished.emit(False, str(e))
        finally:
            print("✅ Worker thread finished")
