from PyQt6.QtCore import QObject, pyqtSignal
from user_authentication.login.forgot_password import ForgotPasswordLogic

class ForgotPasswordWorker(QObject):
    success = pyqtSignal(str)         
    error = pyqtSignal(str)           
    finished = pyqtSignal()          

    def __init__(self, username, logic:ForgotPasswordLogic):
        super().__init__()
        self.username = username
        self.logic = logic  
        
    def run(self):
        try:
            otp, err = self.logic.send_otp(self.username)
            if otp:
                self.success.emit(otp)
            else:
                self.error.emit(err or "Unknown error occurred.")
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()
