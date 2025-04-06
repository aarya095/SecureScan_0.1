from PyQt6.QtCore import QObject, pyqtSignal
from user_authentication.login.forgot_password import ResetPasswordLogic

class ResetPasswordWorker(QObject):
    success = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, username, new_password, confirm_password):
        super().__init__()
        self.username = username
        self.new_password = new_password
        self.confirm_password = confirm_password

    def run(self):
        try:
            logic = ResetPasswordLogic(self.username)
            result = logic.reset_password(self.new_password, self.confirm_password)

            if result == "Password reset successfully.":
                self.success.emit(result)
            else:
                self.error.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()
